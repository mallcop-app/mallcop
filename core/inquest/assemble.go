// assemble.go — deterministic evidence assembly. Every function here is PURE
// Go over data the caller already holds (store, baseline, event slices); NO
// model call anywhere in this file. Each of the six sections is fault-
// isolated: a panic OR a returned error inside one section fills that
// section's own Error field and the other five still ship (see the
// safeAssemble* wrappers).
package inquest

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/tools"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// Evidence is the deterministic evidence chain assembled for one finding.
type Evidence struct {
	Identity        IdentityEvidence        `json:"identity"`
	Neighbors       NeighborsEvidence       `json:"neighbors"`
	Recurrence      RecurrenceEvidence      `json:"recurrence"`
	Baseline        BaselineEvidence        `json:"baseline"`
	ScanCorrelation ScanCorrelationEvidence `json:"scan_correlation"`
	OrgContext      OrgContextEvidence      `json:"org_context"`
}

// IdentityEvidence is the finding's underlying event's provenance fields,
// extracted from the SAME redacted+capped payload tools.GetRawEvent returns —
// this package never builds a second scrub path.
type IdentityEvidence struct {
	Caller      string `json:"caller"`
	SessionName string `json:"session_name"`
	SourceIP    string `json:"source_ip"`
	Target      string `json:"target"`
	Actor       string `json:"actor"`
	// Grantor/Grantee/Capability describe the ACTION a trust/access-change
	// finding represents, in direction-explicit terms: Grantor is the side
	// that already held the authority and extended it; Grantee is the side that
	// newly gained access; Capability names, in plain language, what the grantee
	// can now do. They are populated ONLY for grant-aware finding types (see
	// resolveGrantDirection) and left empty otherwise (omitempty) — a login/
	// exfil/timing finding carries no grant, so no direction is invented for it.
	Grantor    string `json:"grantor,omitempty"`
	Grantee    string `json:"grantee,omitempty"`
	Capability string `json:"capability,omitempty"`
	// FieldPaths records which path supplied each populated field (auditable,
	// and it teaches the narrative to cite verbatim) — only keys that were
	// actually resolved are present.
	FieldPaths map[string]string `json:"field_paths"`
	Error      string            `json:"error,omitempty"`
}

// NeighborEvent is one nearby event's envelope projection — id/source/type/
// actor/target/timestamp plus its offset from the subject event. No payload.
type NeighborEvent struct {
	ID            string  `json:"id"`
	Source        string  `json:"source"`
	Type          string  `json:"type"`
	Actor         string  `json:"actor"`
	Target        string  `json:"target"`
	Timestamp     string  `json:"timestamp"`
	OffsetSeconds float64 `json:"offset_seconds"`
}

// NeighborsEvidence is every OTHER event within Window of the subject event,
// nearest-first, capped.
type NeighborsEvidence struct {
	Window string          `json:"window"`
	Total  int             `json:"total"`
	Events []NeighborEvent `json:"events"`
	Error  string          `json:"error,omitempty"`
}

// PriorInvestigation is one earlier finding's recorded verdict — the evidence
// that lets the narrate prompt reference-and-refresh instead of contradict.
type PriorInvestigation struct {
	FindingID  string  `json:"finding_id"`
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	UpdatedAt  string  `json:"updated_at"`
}

// RecurrenceEvidence is the actor+type recurrence pattern for the subject
// finding, plus prior findings/investigations of the same (actor, type).
type RecurrenceEvidence struct {
	Occurrences int    `json:"occurrences"`
	FirstSeen   string `json:"first_seen,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
	// CadenceSecondsMedian/CadenceLabel are zero-value when Occurrences < 2 —
	// there is no inter-arrival gap to compute a cadence from.
	CadenceSecondsMedian float64              `json:"cadence_seconds_median,omitempty"`
	CadenceLabel         string               `json:"cadence_label,omitempty"`
	PriorFindingIDs      []string             `json:"prior_finding_ids,omitempty"`
	PriorInvestigations  []PriorInvestigation `json:"prior_investigations,omitempty"`
	Error                string               `json:"error,omitempty"`
}

// BaselineEvidence is the known-ness of the finding's actor against the SAME
// baseline the scan gated detection on.
type BaselineEvidence struct {
	KnownActor      bool   `json:"known_actor"`
	HasLoginProfile bool   `json:"has_login_profile"`
	KnownHour       bool   `json:"known_hour"`
	KnownRole       bool   `json:"known_role"`
	ActorFirstSeen  string `json:"actor_first_seen,omitempty"`
	ActorEventCount int    `json:"actor_event_count"`
	Error           string `json:"error,omitempty"`
}

// ScanCorrelationEvidence is whether the finding's recurrence pattern lines
// up with mallcop's OWN scan schedule (e.g. "fires ~2min after every hourly
// scan" — the forge-proxy motivating case).
type ScanCorrelationEvidence struct {
	ScanCount           int     `json:"scan_count"`
	RegisterSince       string  `json:"register_since,omitempty"`
	MedianOffsetSeconds float64 `json:"median_offset_seconds"`
	MatchedFraction     float64 `json:"matched_fraction"`
	Correlated          bool    `json:"correlated"`
	Error               string  `json:"error,omitempty"`
}

// OwnedMatch is one identity field's resolved match against the operator's
// configured owned entities — the matched Config.OwnedEntities entry's own
// Match/Name/Relationship, unchanged, so the narrate prompt can cite the
// exact configured relationship phrase.
type OwnedMatch struct {
	Match        string `json:"match"`
	Name         string `json:"name"`
	Relationship string `json:"relationship"`
}

// OrgContextEvidence is section 6: which of the finding's identity fields
// (caller, target, actor, grantor, grantee) match an operator-configured
// owned entity, so the narrate prompt can name the relationship instead of
// describing an owned account/role/relay as an unknown external actor.
// Grantor/Grantee matter as much as Caller/Target/Actor: for a direction-
// explicit trust/access-change finding, the owned counterparty often appears
// ONLY in Grantor or Grantee (e.g. the member/assumed-role ARN that received
// trust), never in Caller/Target/Actor (mallcoppro-995). Each field is nil
// when no configured entity matches — this is informational only, never a
// verdict override (see narrate.go's systemPrompt clause).
type OrgContextEvidence struct {
	CallerOwned  *OwnedMatch `json:"caller_owned,omitempty"`
	TargetOwned  *OwnedMatch `json:"target_owned,omitempty"`
	ActorOwned   *OwnedMatch `json:"actor_owned,omitempty"`
	GrantorOwned *OwnedMatch `json:"grantor_owned,omitempty"`
	GranteeOwned *OwnedMatch `json:"grantee_owned,omitempty"`
	Error        string      `json:"error,omitempty"`
}

// correlatedMinScanCount/correlatedMatchTolerance/correlatedMinMatchedFraction
// are the fixed thresholds ScanCorrelationEvidence.Correlated gates on (design
// §evidenceAssembly/5): at least 5 observed scans, a per-occurrence offset
// within ±90s of the group's median counted as "matched", and at least 70% of
// occurrences matched.
const (
	correlatedMinScanCount       = 5
	correlatedMatchTolerance     = 90 * time.Second
	correlatedMinMatchedFraction = 0.7
)

// assemble runs all six evidence sections for one escalated finding, each
// under its own panic/error isolation (safeAssemble*), and returns the whole
// Evidence chain — always, even when every section degraded.
func assemble(st *store.Store, allEvents []event.Event, bl *baseline.Baseline, ef EscalatedFinding, cfg Config) Evidence {
	f := ef.Finding

	window := cfg.NeighborWindow
	if window <= 0 {
		window = time.Hour
	}
	maxNeighbors := cfg.MaxNeighbors
	if maxNeighbors <= 0 {
		maxNeighbors = 50
	}
	corrWindow := cfg.CorrelationWindow
	if corrWindow <= 0 {
		corrWindow = 10 * time.Minute
	}

	identity := safeAssembleIdentity(st, f)
	neighbors := safeAssembleNeighbors(allEvents, f, window, maxNeighbors)

	occurrences := actorTypeTimestamps(allEvents, f.Actor, occurrenceEventType(allEvents, f))
	recurrence := safeAssembleRecurrence(st, occurrences, f)
	baselineEv := safeAssembleBaseline(bl, allEvents, f, identity)
	correlation := safeAssembleScanCorrelation(st, occurrences, corrWindow)
	orgContext := safeAssembleOrgContext(cfg.OwnedEntities, f.Actor, identity)

	return Evidence{
		Identity:        identity,
		Neighbors:       neighbors,
		Recurrence:      recurrence,
		Baseline:        baselineEv,
		ScanCorrelation: correlation,
		OrgContext:      orgContext,
	}
}

// --- section 1: IDENTITY -----------------------------------------------

// safeAssembleIdentity isolates assembleIdentity's panics into the section's
// own Error field.
func safeAssembleIdentity(st *store.Store, f finding.Finding) (out IdentityEvidence) {
	defer func() {
		if r := recover(); r != nil {
			out = IdentityEvidence{Actor: f.Actor, FieldPaths: map[string]string{}, Error: fmt.Sprintf("panic: %v", r)}
		}
	}()
	return assembleIdentity(st, f)
}

// resolveIdentityEvent resolves the ONE event assembleIdentity extracts
// identity fields from. It prefers the finding's first-class EventIDs
// (mallcoppro-323) — the first id in that list, since identity extraction
// reads a single representative event's payload — and falls back to the
// legacy f.ID-based resolution (tools.GetRawEvent's own eventIDCandidates
// finding-/bare lenience plus git-style unique-prefix resolution) only when
// EventIDs is empty: an older stored finding predating this field, or a
// (should no longer exist, but defensively handled) detector that fires with
// no event linkage at all. This is the SAME tools.GetRawEvent call either
// way — only the id fed into it differs — so the credential scrub and size
// cap apply identically regardless of which path resolved the id.
func resolveIdentityEvent(st *store.Store, f finding.Finding) (tools.GetRawEventOutput, error) {
	if len(f.EventIDs) > 0 {
		return tools.GetRawEvent(st, tools.GetRawEventInput{ID: f.EventIDs[0]})
	}
	return tools.GetRawEvent(st, tools.GetRawEventInput{ID: f.ID})
}

// assembleIdentity resolves the finding's underlying event via
// tools.GetRawEvent — deliberately the SAME function get_raw_event uses, so
// the credential scrub (sessionToken/secretAccessKey redaction) and the 64KB
// cap apply identically; this package builds no second redaction path — then
// extracts identity fields in deterministic order: NEW FORMAT flat keys
// first (caller/session_name/source_ip/target — the connectors v0.9.0
// promotion), then OLD FORMAT raw CloudTrail-style fallbacks. FieldPaths
// records which path supplied each populated value.
//
// Event resolution itself is resolveIdentityEvent (mallcoppro-323): the
// first-class f.EventIDs is tried FIRST, falling back to the legacy
// f.ID-based lenience path only when EventIDs is empty — see that function's
// doc comment for why.
func assembleIdentity(st *store.Store, f finding.Finding) IdentityEvidence {
	out := IdentityEvidence{Actor: f.Actor, FieldPaths: map[string]string{}}

	// The ACTION (trust direction + granted capability) is derived from the
	// detector's OWN semantically-labeled evidence blob (f.Evidence), NOT the
	// raw event payload the identity fields below read — so it is resolved
	// FIRST, independent of whether the underlying event still resolves, and
	// survives the early-return degradation paths below. Non-grant findings
	// leave all three empty; a malformed/absent grant blob degrades ONLY these
	// three sub-fields (no Error), never the whole identity section.
	if grantor, grantee, capability := resolveGrantDirection(f); grantor != "" || grantee != "" || capability != "" {
		out.Grantor, out.Grantee, out.Capability = grantor, grantee, capability
		if grantor != "" {
			out.FieldPaths["grantor"] = "finding.evidence (grant direction resolved by finding.type/event_type)"
		}
		if grantee != "" {
			out.FieldPaths["grantee"] = "finding.evidence (grant direction resolved by finding.type/event_type)"
		}
		if capability != "" {
			out.FieldPaths["capability"] = "finding.evidence (granted capability in plain language)"
		}
	}

	res, err := resolveIdentityEvent(st, f)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if !res.Found {
		out.Error = fmt.Sprintf("no underlying event found for finding id %q", f.ID)
		return out
	}

	var payload map[string]any
	if err := json.Unmarshal(res.Payload, &payload); err != nil {
		out.Error = "payload is not a JSON object: " + err.Error()
		return out
	}

	// NEW FORMAT: flat keys at the payload root.
	if v, ok := stringField(payload, "caller"); ok {
		out.Caller, out.FieldPaths["caller"] = v, "payload.caller"
	}
	if v, ok := stringField(payload, "session_name"); ok {
		out.SessionName, out.FieldPaths["session_name"] = v, "payload.session_name"
	}
	if v, ok := stringField(payload, "source_ip"); ok {
		out.SourceIP, out.FieldPaths["source_ip"] = v, "payload.source_ip"
	}
	if v, ok := stringField(payload, "target"); ok {
		out.Target, out.FieldPaths["target"] = v, "payload.target"
	}

	// OLD FORMAT fallback: raw CloudTrail-style nested paths. caller tries
	// userIdentity.arn first, then the assumed-role session issuer's arn.
	raw, _ := payload["raw"].(map[string]any)
	if out.Caller == "" {
		if v, ok := nestedStringField(raw, "userIdentity", "arn"); ok {
			out.Caller, out.FieldPaths["caller"] = v, "payload.raw.userIdentity.arn"
		} else if v, ok := nestedStringField(raw, "userIdentity", "sessionContext", "sessionIssuer", "arn"); ok {
			out.Caller, out.FieldPaths["caller"] = v, "payload.raw.userIdentity.sessionContext.sessionIssuer.arn"
		}
	}
	if out.SessionName == "" {
		if v, ok := nestedStringField(raw, "requestParameters", "roleSessionName"); ok {
			out.SessionName, out.FieldPaths["session_name"] = v, "payload.raw.requestParameters.roleSessionName"
		}
	}
	if out.SourceIP == "" {
		if v, ok := nestedStringField(raw, "sourceIPAddress"); ok {
			out.SourceIP, out.FieldPaths["source_ip"] = v, "payload.raw.sourceIPAddress"
		}
	}

	return out
}

// grantAwareFindingTypes are the finding types whose evidence blob carries a
// grantor/grantee/capability shape resolveGrantDirection can read. Any other
// type (unusual-login, exfil, timing, …) returns all-empty — the ACTION
// explanation is only synthesized where the detector actually recorded a grant,
// never guessed for an unrelated finding.
var grantAwareFindingTypes = map[string]bool{
	"new-external-access": true,
	"priv-escalation":     true,
}

// grantDetectorEvidence captures every evidence field the two grant-aware
// detectors marshal (core/detect/new_external_access.go and
// core/detect/priv_escalation.go). A json tag that does not match a detector's
// actual key silently degrades to an empty value (fault-isolated), so these
// tags are kept in exact lockstep with what those detectors write.
type grantDetectorEvidence struct {
	Actor           string `json:"actor"`
	Grantee         string `json:"grantee"`
	Permission      string `json:"permission"`
	EventType       string `json:"event_type"`
	Target          string `json:"target"`
	Role            string `json:"role"`
	TargetUser      string `json:"target_user"`
	PermissionLevel string `json:"permission_level"`
	// Member is the raw AWS AssumeRole trust boundary (core/detect/new_external_access.go's
	// "member" evidence key, sourced from mallcop-connectors' aws.go payload "member"
	// field — the assumed role's ARN). Present ONLY on AWS cross-account trust_added
	// events; empty for M365's domain-only trust_added shape ("Set federation
	// settings on domain." in mallcop-connectors' m365.go, which carries
	// domain/domain_name but no member/caller). resolveGrantDirection switches on
	// this to pick the right direction convention for the two event shapes that
	// share event_type "trust_added" (mallcoppro-15e).
	Member string `json:"member"`
}

// resolveGrantDirection reads the detector's own semantically-labeled evidence
// blob and returns the trust DIRECTION (grantor = the side that already held
// the authority; grantee = the side that newly gained access) and the granted
// CAPABILITY in plain language. It is a PURE function: no store, no model call,
// no I/O — it only unmarshals f.Evidence — so it does not weaken assemble.go's
// "deterministic evidence assembly" invariant. Its output feeds the narrate
// user document ONLY (via assembleIdentity -> buildUserMessage); it is never
// read back into any escalation/resolution/verdict path — the committee has
// already escalated the finding upstream in core/detect before this runs.
//
// The grantor/grantee mapping is NOT uniform across grant-aware event shapes,
// so it switches on the evidence's own event_type (one finding.Type,
// "new-external-access", covers several underlying event shapes with different
// direction conventions). A malformed or absent blob returns all-empty rather
// than erroring — this is an advisory augmentation, not a fatal section.
func resolveGrantDirection(f finding.Finding) (grantor, grantee, capability string) {
	if !grantAwareFindingTypes[f.Type] {
		return "", "", ""
	}
	if len(f.Evidence) == 0 {
		return "", "", ""
	}
	var ev grantDetectorEvidence
	if err := json.Unmarshal(f.Evidence, &ev); err != nil {
		return "", "", ""
	}

	// priv-escalation: the performing actor granted a role/permission to a
	// target principal. Direction is unambiguous: actor = grantor, target_user
	// = grantee, role/permission = capability.
	if f.Type == "priv-escalation" {
		return ev.Actor, ev.TargetUser, firstNonEmpty(ev.Role, ev.PermissionLevel)
	}

	// new-external-access. Switch on the UNDERLYING event_type — the direction
	// convention differs per shape.
	switch ev.EventType {
	case "trust_added":
		// event_type "trust_added" covers TWO different underlying event shapes
		// with OPPOSITE direction conventions, distinguished by whether the
		// detector's "member" evidence field is populated (see its doc comment
		// in core/detect/new_external_access.go and the Member field doc above):
		//
		//   - AWS cross-account AssumeRole (member is set, to the assumed
		//     role's ARN): the evidence's "grantee" field is the ASSUMED
		//     role/account — that is the resource whose trust boundary is
		//     exercised, i.e. the GRANTOR. The evidence's "actor" is the
		//     CALLING principal that now holds the capability, i.e. the
		//     GRANTEE. This FLIP is the OPPOSITE of every other branch here.
		//   - M365 domain-only federation trust (member is empty — the
		//     payload carries only domain/domain_name, e.g. "Set federation
		//     settings on domain."): there is no assumed-role trust boundary
		//     to flip around, so this uses the SAME non-flipped convention as
		//     the federation_settings_update branch below — actor (the admin
		//     who configured the trust) is the grantor, the named domain is
		//     the grantee. Routing this shape through the AWS flip reproduces
		//     the exact backwards-direction bug this item exists to fix
		//     (mallcoppro-15e): a reasonable-looking "unify the switch, it
		//     looks redundant" edit that drops the member check silently
		//     reverses every M365 federation-trust finding.
		//
		// The dedicated trust_added regression tests (both shapes) must fail
		// loudly if either branch is undone.
		if ev.Member != "" {
			cap := "can assume this role and act with its permissions"
			if ev.Permission != "" {
				cap = ev.Permission
			}
			return ev.Grantee, ev.Actor, cap
		}
		return ev.Actor, ev.Grantee, "federation/domain trust relationship"
	case "repo.add_collaborator", "org.add_member", "org.member_added", "org.add_outside_collaborator":
		cap := ev.Permission
		if cap == "" {
			cap = "collaborator/member access"
		}
		return ev.Actor, ev.Grantee, cap
	case "federation_settings_update", "domain_trust", "directory_settings_update":
		return ev.Actor, ev.Grantee, "federation/domain trust relationship"
	default:
		return "", "", ""
	}
}

// firstNonEmpty returns the first non-empty string in vals, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func stringField(m map[string]any, key string) (string, bool) {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

// nestedStringField walks m through path and returns the final string value,
// or ("", false) if any hop is missing, not an object, or the leaf is not a
// non-empty string.
func nestedStringField(m map[string]any, path ...string) (string, bool) {
	var cur any = m
	for i, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		v, ok := mm[k]
		if !ok {
			return "", false
		}
		if i == len(path)-1 {
			s, ok := v.(string)
			if !ok || s == "" {
				return "", false
			}
			return s, true
		}
		cur = v
	}
	return "", false
}

// --- section 2: NEIGHBORS -----------------------------------------------

func safeAssembleNeighbors(allEvents []event.Event, f finding.Finding, window time.Duration, maxNeighbors int) (out NeighborsEvidence) {
	defer func() {
		if r := recover(); r != nil {
			out = NeighborsEvidence{Window: window.String(), Error: fmt.Sprintf("panic: %v", r)}
		}
	}()
	return assembleNeighbors(allEvents, f, window, maxNeighbors)
}

// assembleNeighbors is a linear pass over allEvents for every OTHER event
// within window of the subject finding's timestamp, projected to the
// search_events envelope view (tools.EventViewsFor — individually sanitized,
// no payloads), sorted nearest-first, capped at maxNeighbors. Total is
// recorded BEFORE the cap.
func assembleNeighbors(allEvents []event.Event, f finding.Finding, window time.Duration, maxNeighbors int) NeighborsEvidence {
	type candidate struct {
		ev     event.Event
		offset float64 // seconds, signed (ev.Timestamp - f.Timestamp)
	}

	var candidates []candidate
	for _, e := range allEvents {
		if e.ID != "" && e.ID == f.ID {
			continue
		}
		diff := e.Timestamp.Sub(f.Timestamp)
		if diff < -window || diff > window {
			continue
		}
		candidates = append(candidates, candidate{ev: e, offset: diff.Seconds()})
	}

	total := len(candidates)
	sort.SliceStable(candidates, func(i, j int) bool {
		return math.Abs(candidates[i].offset) < math.Abs(candidates[j].offset)
	})
	if len(candidates) > maxNeighbors {
		candidates = candidates[:maxNeighbors]
	}

	evs := make([]event.Event, len(candidates))
	offsetByIndex := make([]float64, len(candidates))
	for i, c := range candidates {
		evs[i] = c.ev
		offsetByIndex[i] = c.offset
	}
	views := tools.EventViewsFor(evs)

	out := NeighborsEvidence{Window: window.String(), Total: total}
	for i, v := range views {
		var offset float64
		if i < len(offsetByIndex) {
			offset = offsetByIndex[i]
		}
		out.Events = append(out.Events, NeighborEvent{
			ID: v.ID, Source: v.Source, Type: v.Type, Actor: v.Actor, Target: v.Target,
			Timestamp: v.Timestamp, OffsetSeconds: offset,
		})
	}
	return out
}

// --- section 3: RECURRENCE CADENCE --------------------------------------

// occurrenceEventType picks the event Type the occurrence set is collected
// by. Findings carry detector-family types ("new-external-access") while
// events carry raw source types ("trust_added") — comparing them directly
// (the original f.Type pass-through) matched zero events for essentially
// every detector, silently zeroing BOTH recurrence and scan-correlation
// (mallcoppro-f4c; live-proven on the first mallcop-deploy v0.16.0 records:
// an actor with 672 baseline events showed occurrences=0, and the narrate
// model — starved of the cadence signal — called the operator's own hourly
// relay a threat). Resolve the finding's SOURCE event via its EventIDs
// linkage (first resolvable id wins) and use THAT event's type; fall back to
// f.Type only when no linked event is present in allEvents, preserving the
// old behavior for legacy findings with no linkage.
func occurrenceEventType(allEvents []event.Event, f finding.Finding) string {
	for _, id := range f.EventIDs {
		for _, e := range allEvents {
			if e.ID == id && e.Type != "" {
				return e.Type
			}
		}
	}
	return f.Type
}

// actorTypeTimestamps returns the sorted timestamps of every event in
// allEvents sharing the finding's (actor, type) — shared between the
// recurrence and scan-correlation sections so they see the identical
// occurrence set.
func actorTypeTimestamps(allEvents []event.Event, actor, typ string) []time.Time {
	var ts []time.Time
	for _, e := range allEvents {
		if e.Actor == actor && e.Type == typ {
			ts = append(ts, e.Timestamp)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	return ts
}

func safeAssembleRecurrence(st *store.Store, occurrences []time.Time, f finding.Finding) (out RecurrenceEvidence) {
	defer func() {
		if r := recover(); r != nil {
			out = RecurrenceEvidence{Error: fmt.Sprintf("panic: %v", r)}
		}
	}()
	return assembleRecurrence(st, occurrences, f)
}

// maxPriorFindingIDs caps the prior-findings list — capped 20, newest.
const maxPriorFindingIDs = 20

// assembleRecurrence computes occurrence/first/last-seen and the median
// inter-arrival cadence from occurrences (already the actor+type-matching
// timestamps, sorted), then scans the store's findings stream for prior
// findings sharing (actor, type), capped to the newest 20, and reads back
// each one's prior investigation record (if any) so the narrate prompt can
// reference-and-refresh instead of contradict.
func assembleRecurrence(st *store.Store, occurrences []time.Time, f finding.Finding) RecurrenceEvidence {
	out := RecurrenceEvidence{Occurrences: len(occurrences)}
	if len(occurrences) > 0 {
		out.FirstSeen = occurrences[0].UTC().Format(time.RFC3339)
		out.LastSeen = occurrences[len(occurrences)-1].UTC().Format(time.RFC3339)
	}
	if len(occurrences) >= 2 {
		deltas := make([]float64, 0, len(occurrences)-1)
		for i := 1; i < len(occurrences); i++ {
			deltas = append(deltas, occurrences[i].Sub(occurrences[i-1]).Seconds())
		}
		median := medianFloat(deltas)
		out.CadenceSecondsMedian = median
		out.CadenceLabel = cadenceLabel(median)
	}

	if st == nil {
		out.Error = "nil store"
		return out
	}
	raws, err := st.Load(store.KindFindings)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	var priorIDs []string
	for _, raw := range raws {
		var pf finding.Finding
		if jerr := json.Unmarshal(raw, &pf); jerr != nil {
			continue
		}
		if pf.ID == f.ID {
			continue
		}
		if pf.Actor == f.Actor && pf.Type == f.Type {
			priorIDs = append(priorIDs, pf.ID)
		}
	}
	// KindFindings is append-only oldest-first, so the tail is newest.
	if len(priorIDs) > maxPriorFindingIDs {
		priorIDs = priorIDs[len(priorIDs)-maxPriorFindingIDs:]
	}
	out.PriorFindingIDs = priorIDs

	for _, id := range priorIDs {
		data, rerr := st.ReadSnapshot(recordPath(id))
		if rerr != nil || len(data) == 0 {
			continue
		}
		var rec Record
		if jerr := json.Unmarshal(data, &rec); jerr != nil {
			continue
		}
		out.PriorInvestigations = append(out.PriorInvestigations, PriorInvestigation{
			FindingID:  rec.FindingID,
			Verdict:    string(rec.Verdict),
			Confidence: rec.Confidence,
			UpdatedAt:  rec.UpdatedAt,
		})
	}
	return out
}

// cadenceLabel buckets seconds into a fixed, human-legible cadence label at
// ±20% tolerance. Anything outside every bucket is "irregular (~Xs)".
func cadenceLabel(seconds float64) string {
	buckets := []struct {
		target float64
		label  string
	}{
		{60, "minutely"},
		{3600, "hourly"},
		{86400, "daily"},
		{604800, "weekly"},
	}
	for _, b := range buckets {
		lo, hi := b.target*0.8, b.target*1.2
		if seconds >= lo && seconds <= hi {
			return b.label
		}
	}
	return fmt.Sprintf("irregular (~%.0fs)", seconds)
}

func medianFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// --- section 4: BASELINE KNOWN-NESS -------------------------------------

func safeAssembleBaseline(bl *baseline.Baseline, allEvents []event.Event, f finding.Finding, identity IdentityEvidence) (out BaselineEvidence) {
	defer func() {
		if r := recover(); r != nil {
			out = BaselineEvidence{Error: fmt.Sprintf("panic: %v", r)}
		}
	}()
	return assembleBaselineEvidence(bl, allEvents, f, identity)
}

// assembleBaselineEvidence calls DIRECTLY on the SAME *baseline.Baseline the
// scan gated detection on — no separate re-derivation. KnownRole uses the
// finding's extracted identity.Target as the role-lookup key: baseline's
// ActorRoles is keyed on the "role:target" composite (mallcoppro-9af), and a
// finding carries no explicit role field of its own, so the target extracted
// by IDENTITY (section 1) is the best available proxy for "was this specific
// grant/target already known for this actor" — a heuristic documented here,
// not a byte-exact mirror of priv-escalation's own role key.
//
// ActorFirstSeen/ActorEventCount are derived from allEvents directly (not
// baseline.UserProfile, which carries only LastSeen — no FirstSeen/Count
// field exists on it) so this section stays correct without requiring a
// baseline schema change.
func assembleBaselineEvidence(bl *baseline.Baseline, allEvents []event.Event, f finding.Finding, identity IdentityEvidence) BaselineEvidence {
	if bl == nil {
		bl = &baseline.Baseline{}
	}
	out := BaselineEvidence{
		KnownActor:      bl.IsKnownActor(f.Actor),
		HasLoginProfile: bl.HasLoginProfile(f.Actor),
		KnownHour:       bl.KnownHour(f.Actor, f.Timestamp.UTC().Hour()),
	}
	if identity.Target != "" {
		out.KnownRole = bl.IsKnownRole(f.Actor, identity.Target)
	}

	var first time.Time
	count := 0
	for _, e := range allEvents {
		if e.Actor != f.Actor {
			continue
		}
		count++
		if first.IsZero() || e.Timestamp.Before(first) {
			first = e.Timestamp
		}
	}
	out.ActorEventCount = count
	if !first.IsZero() {
		out.ActorFirstSeen = first.UTC().Format(time.RFC3339)
	}
	return out
}

// --- section 5: SCAN-SCHEDULE CORRELATION -------------------------------

func safeAssembleScanCorrelation(st *store.Store, occurrences []time.Time, correlationWindow time.Duration) (out ScanCorrelationEvidence) {
	defer func() {
		if r := recover(); r != nil {
			out = ScanCorrelationEvidence{Error: fmt.Sprintf("panic: %v", r)}
		}
	}()
	return assembleScanCorrelation(st, occurrences, correlationWindow)
}

// assembleScanCorrelation unions two deterministic scan-time sources (the
// KindScans register + the git-commit-time historical fallback), clusters
// them (collapsing times within 10 minutes into one anchor), then for each
// recurrence occurrence computes its offset from the nearest PRECEDING scan
// time. Correlated iff scan_count >= 5, the median offset falls within
// [0, correlationWindow], and >= 70% of occurrences land within ±90s of that
// median.
func assembleScanCorrelation(st *store.Store, occurrences []time.Time, correlationWindow time.Duration) ScanCorrelationEvidence {
	out := ScanCorrelationEvidence{}
	if st == nil {
		out.Error = "nil store"
		return out
	}
	scanTimes, err := loadScanTimes(st)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.ScanCount = len(scanTimes)
	if len(scanTimes) == 0 {
		return out
	}
	out.RegisterSince = scanTimes[0].UTC().Format(time.RFC3339)
	if len(occurrences) == 0 {
		return out
	}

	var offsets []float64
	for _, t := range occurrences {
		nearest, ok := nearestPreceding(scanTimes, t)
		if ok {
			offsets = append(offsets, t.Sub(nearest).Seconds())
		}
	}
	if len(offsets) == 0 {
		return out
	}

	median := medianFloat(offsets)
	out.MedianOffsetSeconds = median

	matched := 0
	tolerance := correlatedMatchTolerance.Seconds()
	for _, o := range offsets {
		if math.Abs(o-median) <= tolerance {
			matched++
		}
	}
	out.MatchedFraction = float64(matched) / float64(len(offsets))
	out.Correlated = out.ScanCount >= correlatedMinScanCount &&
		median >= 0 && median <= correlationWindow.Seconds() &&
		out.MatchedFraction >= correlatedMinMatchedFraction
	return out
}

// nearestPreceding returns the latest time in scanTimes that is <= t, or
// (zero, false) when every scan time is after t.
func nearestPreceding(scanTimes []time.Time, t time.Time) (time.Time, bool) {
	var best time.Time
	found := false
	for _, s := range scanTimes {
		if s.After(t) {
			continue
		}
		if !found || s.After(best) {
			best, found = s, true
		}
	}
	return best, found
}

// loadScanTimes unions the KindScans register with the git-commit-time
// historical fallback (CommitTimesFor over the streams a scan always
// touches), then clusters the result within a fixed 10-minute window so a
// single scan's several commits collapse to one anchor time.
func loadScanTimes(st *store.Store) ([]time.Time, error) {
	var times []time.Time

	scans, err := st.LoadScans()
	if err != nil {
		return nil, err
	}
	for _, s := range scans {
		t := s.FinishedAt
		if t.IsZero() {
			t = s.StartedAt
		}
		if !t.IsZero() {
			times = append(times, t)
		}
	}

	commitTimes, err := st.CommitTimesFor("events.jsonl", "baseline.jsonl", "resolutions.jsonl")
	if err != nil {
		return nil, err
	}
	times = append(times, commitTimes...)

	return clusterTimes(times, 10*time.Minute), nil
}

// clusterTimes sorts times ascending and collapses any run of times within
// window of the current cluster's anchor into that one anchor (the anchor is
// the EARLIEST time in each cluster) — so one scan's several near-simultaneous
// stream commits register as one scan time, not several.
func clusterTimes(times []time.Time, window time.Duration) []time.Time {
	if len(times) == 0 {
		return nil
	}
	sorted := append([]time.Time(nil), times...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	out := []time.Time{sorted[0]}
	anchor := sorted[0]
	for _, t := range sorted[1:] {
		if t.Sub(anchor) > window {
			out = append(out, t)
			anchor = t
		}
	}
	return out
}

// --- section 6: ORG CONTEXT ---------------------------------------------

// safeAssembleOrgContext isolates assembleOrgContext's panics into the
// section's own Error field, same pattern as the other five safeAssemble*
// wrappers.
func safeAssembleOrgContext(owned []OwnedEntity, actor string, identity IdentityEvidence) (out OrgContextEvidence) {
	defer func() {
		if r := recover(); r != nil {
			out = OrgContextEvidence{Error: fmt.Sprintf("panic: %v", r)}
		}
	}()
	return assembleOrgContext(owned, actor, identity)
}

// assembleOrgContext is PURE — no store, no model call, no I/O — it only
// substring-matches identity.Caller, identity.Target, identity.Grantor,
// identity.Grantee, and actor against the operator's configured owned
// entities (config-time validated non-empty and at least minOrgMatchLen
// characters, mallcoppro-995). Grantor/Grantee are matched alongside
// Caller/Target/Actor because a direction-explicit trust/access-change
// finding often carries its owned counterparty ONLY in Grantor or Grantee
// (e.g. the member/assumed-role ARN that received trust) — Caller/Target/
// Actor alone miss that case entirely. For each identity field, the FIRST
// configured entity whose Match is a substring of that field wins (config
// order); no match leaves that field nil. Absent owned-entity config
// (nil/empty owned) returns an all-nil, no-error OrgContextEvidence — honest
// evidence for the narrative, not a degraded section (mirrors
// TestAssembleBaselineEvidence_UnknownActor's pattern).
func assembleOrgContext(owned []OwnedEntity, actor string, identity IdentityEvidence) OrgContextEvidence {
	match := func(field string) *OwnedMatch {
		if field == "" {
			return nil
		}
		for _, o := range owned {
			if o.Match != "" && strings.Contains(field, o.Match) {
				return &OwnedMatch{Match: o.Match, Name: o.Name, Relationship: o.Relationship}
			}
		}
		return nil
	}
	return OrgContextEvidence{
		CallerOwned:  match(identity.Caller),
		TargetOwned:  match(identity.Target),
		ActorOwned:   match(actor),
		GrantorOwned: match(identity.Grantor),
		GranteeOwned: match(identity.Grantee),
	}
}
