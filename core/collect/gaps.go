package collect

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// dissentReasonMarker is the ISOLATED, BRITTLE-PARSE hook onto the unstructured
// consensus-dissent signal. Consensus dissent is NOT a structured field today —
// the fanout merge (core/agent/fanout.go) only records it as free text inside a
// Resolution.Reason, in two forms:
//
//	"… Dissent (<names>) cited; confidence penalized 0.10."   (majority-resolve)
//	"…; dissent (<names>) cited"                              (majority-escalate)
//
// The substring ") cited" is common to BOTH and survives the "(%s)" name
// expansion, so a Reason containing it carries a dissent signal. This is a v1
// brittle parse: it is isolated HERE so a future structured dissent field on the
// resolution can replace this single constant, and TestDissentMarkerDriftGuard
// FAILS if the marker ever leaves fanout.go's source (drift caught at build time,
// not silently in production).
const dissentReasonMarker = ") cited"

// GapKind enumerates the three detection-gap flavors DetectorGaps surfaces.
type GapKind string

const (
	// GapDetectMiss is a real production false-negative: an expected-escalate
	// scenario where detect emitted ZERO findings (exam-detect DETECT-MISS).
	GapDetectMiss GapKind = "detect_miss"
	// GapOverrideFP is a human-override disagreement: a suppress directive whose
	// human verb differs from the agent's stored decision on the same finding.
	GapOverrideFP GapKind = "override_fp"
	// GapDissent is a consensus-dissent cluster: a resolution whose reason carries
	// the fanout dissent marker (the panel did not agree unanimously).
	GapDissent GapKind = "dissent"
)

// GapEvidence is the STRUCTURED, enumerated evidence attached to a GapCandidate.
// It carries only derived / classifier-controlled fields — NEVER raw untrusted
// free text (a resolution reason, a raw payload) — so a proposal built from it
// cannot smuggle attacker-influenced content downstream.
type GapEvidence struct {
	// detect_miss provenance (from the exam-detect fidelity row).
	ScenarioID       string   `json:"scenario_id,omitempty"`
	ExpectedAction   string   `json:"expected_action,omitempty"`
	ExpectedActor    string   `json:"expected_actor,omitempty"`
	EmittedDetectors []string `json:"emitted_detectors,omitempty"`
	// override_fp provenance: the canonical (escalate|resolve) verbs that disagreed.
	HumanVerb   string `json:"human_verb,omitempty"`
	AgentAction string `json:"agent_action,omitempty"`
	// dissent provenance: the marker constant that matched (NOT the raw reason).
	DissentMarker string `json:"dissent_marker,omitempty"`
}

// GapCandidate is a proposer-ready detection-gap record. Plain data with json
// tags — it crosses the module boundary into mallcop-pro's proposer unchanged,
// which turns it into an add-only proposal (a new detector rule, a widened gate,
// a re-vote). It carries no raw untrusted free text; all evidence is structured.
type GapCandidate struct {
	// Kind is which gap flavor this is.
	Kind GapKind `json:"kind"`
	// Source is the finding/detector source id (e.g. "detector:unusual-login").
	// Empty for a detect_miss (no finding was emitted).
	Source string `json:"source,omitempty"`
	// EventType is the event type the gap concerns, when known. Empty when the
	// upstream signal (a fidelity row, a resolution) does not carry it.
	EventType string `json:"event_type,omitempty"`
	// DetectorFamily is the detector family the gap concerns (e.g. "unusual-login",
	// "priv-escalation" — the expected family on a miss, the finding's family
	// otherwise).
	DetectorFamily string `json:"detector_family,omitempty"`
	// Severity is the finding severity, when a finding exists. Empty on detect_miss.
	Severity string `json:"severity,omitempty"`
	// FindingIDs are the finding ids this gap references. Empty on detect_miss.
	FindingIDs []string `json:"finding_ids,omitempty"`
	// SampleEventIDs are event ids for provenance, when available.
	SampleEventIDs []string `json:"sample_event_ids,omitempty"`
	// Evidence is the structured, no-free-text evidence for this gap.
	Evidence GapEvidence `json:"evidence"`
}

// DetectorGaps combines three offline, deterministic gap sources into one ranked
// slice of GapCandidate:
//
//	(a) DETECT-MISS rows on expected-escalate scenarios (real false-negatives) —
//	    from the passed-in exam-detect fidelity rows;
//	(b) human_override != agent_decision FPs — join each suppress directive's
//	    Meta.finding_id/verb to the resolution stream by FindingID/Action;
//	(c) consensus-dissent clusters — resolutions whose Reason carries the fanout
//	    dissent marker.
//
// It is a pure read of st (resolutions + directives) plus the caller's rows — no
// inference, no network. Output ordering is deterministic (see gapSortKey).
func DetectorGaps(st *store.Store, rows []eval.DetectFidelityRow) ([]GapCandidate, error) {
	var out []GapCandidate

	// (a) Real false-negatives: exam-detect DETECT-MISS on an expected-escalate
	// scenario (a DETECT-MISS on an expected-resolve is the CORRECT "nothing
	// flagged" outcome and is not a gap).
	for _, r := range rows {
		if r.Outcome != eval.OutcomeDetectMiss || !expectsEscalate(r.ExpectedAction) {
			continue
		}
		out = append(out, GapCandidate{
			Kind:           GapDetectMiss,
			DetectorFamily: r.ExpectedDetector,
			Evidence: GapEvidence{
				ScenarioID:       r.ScenarioID,
				ExpectedAction:   r.ExpectedAction,
				ExpectedActor:    r.ExpectedActor,
				EmittedDetectors: r.EmittedDetectors,
			},
		})
	}

	// Load the resolution stream once (shared by (b) and (c)).
	resRaw, err := st.Load(store.KindResolutions)
	if err != nil {
		return nil, fmt.Errorf("collect: load resolutions: %w", err)
	}
	resolutions := make([]resolution.Resolution, 0, len(resRaw))
	for i, raw := range resRaw {
		var res resolution.Resolution
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("collect: decode resolution %d: %w", i, err)
		}
		resolutions = append(resolutions, res)
	}
	// First resolution wins per finding id (deterministic; the store replays
	// oldest-first).
	byFinding := make(map[string]resolution.Resolution, len(resolutions))
	for _, r := range resolutions {
		if _, ok := byFinding[r.FindingID]; !ok {
			byFinding[r.FindingID] = r
		}
	}

	// (b) Human-override false-positives: a suppress directive references a
	// finding via Meta.finding_id; if the human verb disagrees with the agent's
	// stored decision, that is an override the loop should learn from.
	dirs, err := st.LoadDirectives()
	if err != nil {
		return nil, fmt.Errorf("collect: load directives: %w", err)
	}
	for _, d := range dirs {
		if !strings.EqualFold(strings.TrimSpace(d.Op), "suppress") {
			continue
		}
		var meta struct {
			FindingID string `json:"finding_id"`
			Verb      string `json:"verb"`
		}
		if len(d.Meta) > 0 {
			_ = json.Unmarshal(d.Meta, &meta)
		}
		if meta.FindingID == "" {
			continue
		}
		res, ok := byFinding[meta.FindingID]
		if !ok {
			continue // directive references a finding not in this scan's stream
		}
		human := canonVerb(meta.Verb)
		if human == "" {
			human = "resolve" // a suppress directive is, by default, "dismiss/benign"
		}
		agentVerb := canonVerb(res.Action)
		if human == agentVerb {
			continue // human and agent agree — no gap
		}
		out = append(out, GapCandidate{
			Kind:           GapOverrideFP,
			Source:         res.Source,
			DetectorFamily: familyFromSource(res.Source),
			Severity:       res.Severity,
			FindingIDs:     []string{meta.FindingID},
			Evidence:       GapEvidence{HumanVerb: human, AgentAction: agentVerb},
		})
	}

	// (c) Consensus-dissent clusters: resolutions whose reason carries the fanout
	// dissent marker. We surface the finding, NOT the raw reason (no free text).
	for _, r := range resolutions {
		if !strings.Contains(r.Reason, dissentReasonMarker) {
			continue
		}
		out = append(out, GapCandidate{
			Kind:           GapDissent,
			Source:         r.Source,
			DetectorFamily: familyFromSource(r.Source),
			Severity:       r.Severity,
			FindingIDs:     []string{r.FindingID},
			Evidence:       GapEvidence{DissentMarker: dissentReasonMarker},
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return gapSortKey(out[i]) < gapSortKey(out[j])
	})
	return out, nil
}

// gapSortKey builds a stable, total ordering key for a GapCandidate:
// kind | primary-id | source. The primary id is the first finding id, or the
// scenario id for a detect_miss (which has no finding).
func gapSortKey(g GapCandidate) string {
	id := g.Evidence.ScenarioID
	if len(g.FindingIDs) > 0 {
		id = g.FindingIDs[0]
	}
	return string(g.Kind) + "|" + id + "|" + g.Source
}

// expectsEscalate reports whether an expected chain_action demands an escalate
// (mirrors eval.actionIsEscalate, reimplemented here to avoid exporting it).
func expectsEscalate(action string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	return a == "escalated" || a == "escalate-or-stronger"
}

// canonVerb collapses the store/directive action vocabularies onto the two
// canonical decisions the gap join compares: "escalate" and "resolve". An
// unrecognized verb is returned lowered/trimmed (so a novel verb still compares
// consistently, it just never spuriously matches escalate/resolve).
func canonVerb(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "escalate", "escalated", "escalate-or-stronger", "alert", "block":
		return "escalate"
	case "resolve", "resolved", "suppress", "ignore", "benign", "proceed":
		return "resolve"
	default:
		return strings.ToLower(strings.TrimSpace(a))
	}
}

// familyFromSource strips the "detector:" prefix off a finding source to yield
// the bare detector family token (e.g. "detector:unusual-login" -> "unusual-login").
func familyFromSource(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "detector:")
}
