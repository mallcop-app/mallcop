package collect

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// initRepo creates a REAL git repo in a temp dir and seeds an empty root commit,
// so the collectors are proven against durable, committed store records (invariant
// 10: no stubbed collector output — the fixture store is a real git repo).
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	seed := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "root")
	seed.Dir = dir
	seed.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	return dir
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(initRepo(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return st
}

// unmappedEvent builds a default-bucket event carrying the "unmapped_action" tag
// exactly as the connectors now write it into the flat payload.
func unmappedEvent(t *testing.T, id, source, rawAction string) event.Event {
	t.Helper()
	pl, err := json.Marshal(map[string]any{"unmapped_action": rawAction, "raw": map[string]any{"x": 1}})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return event.Event{
		ID:        id,
		Source:    source,
		Type:      source + "_other",
		Actor:     "someone",
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
		Payload:   pl,
	}
}

func appendRec(t *testing.T, st *store.Store, kind store.Kind, rec any) {
	t.Helper()
	if _, err := st.Append(kind, rec); err != nil {
		t.Fatalf("append %s: %v", kind, err)
	}
}

// TestUnmappedActionsRanksWithSamples proves (i): a fixture store with unmapped
// github actions is ranked by frequency with sample event ids, mapped events are
// excluded, and the suggested vocabulary comes from detect.KnownEventTypes().
func TestUnmappedActionsRanksWithSamples(t *testing.T) {
	st := openStore(t)

	// Two events for repo.transfer, one for org.rename (github), one for a decl
	// "stripe" source — all unmapped. Plus a MAPPED github event that must NOT
	// appear.
	appendRec(t, st, store.KindEvents, unmappedEvent(t, "evt_b", "github", "repo.transfer"))
	appendRec(t, st, store.KindEvents, unmappedEvent(t, "evt_a", "github", "repo.transfer"))
	appendRec(t, st, store.KindEvents, unmappedEvent(t, "evt_c", "github", "org.rename"))
	appendRec(t, st, store.KindEvents, unmappedEvent(t, "evt_d", "stripe", "charge.disputed"))

	mapped := event.Event{
		ID: "evt_mapped", Source: "github", Type: "push", Actor: "dev",
		Timestamp: time.Unix(1_700_000_001, 0).UTC(),
		Payload:   json.RawMessage(`{"action":"git.push"}`),
	}
	appendRec(t, st, store.KindEvents, mapped)

	gaps, err := UnmappedActions(st)
	if err != nil {
		t.Fatalf("UnmappedActions: %v", err)
	}
	if len(gaps) != 3 {
		t.Fatalf("want 3 gaps (repo.transfer, org.rename, charge.disputed), got %d: %+v", len(gaps), gaps)
	}

	// Ranking: repo.transfer (count 2) first; then org.rename and charge.disputed
	// (count 1) ordered by Source asc (github < stripe), RawAction asc.
	if gaps[0].RawAction != "repo.transfer" || gaps[0].Count != 2 {
		t.Fatalf("gap[0] = %+v, want repo.transfer count 2", gaps[0])
	}
	// Samples sorted ascending, both events present.
	if len(gaps[0].SampleEventIDs) != 2 || gaps[0].SampleEventIDs[0] != "evt_a" || gaps[0].SampleEventIDs[1] != "evt_b" {
		t.Fatalf("gap[0] samples = %v, want [evt_a evt_b]", gaps[0].SampleEventIDs)
	}
	if gaps[1].Source != "github" || gaps[1].RawAction != "org.rename" {
		t.Fatalf("gap[1] = %+v, want github/org.rename", gaps[1])
	}
	if gaps[2].Source != "stripe" || gaps[2].RawAction != "charge.disputed" {
		t.Fatalf("gap[2] = %+v, want stripe/charge.disputed", gaps[2])
	}

	// Suggested vocabulary is the known-event-types set (non-empty, sorted, and
	// includes a known gate literal like "push").
	vocab := gaps[0].SuggestedVocabulary
	if len(vocab) == 0 {
		t.Fatal("suggested vocabulary is empty")
	}
	if !sortedStrings(vocab) {
		t.Fatalf("suggested vocabulary not sorted: %v", vocab)
	}
	if !contains(vocab, "push") {
		t.Fatalf("suggested vocabulary %v missing known gate literal 'push'", vocab)
	}

	// The mapped "push" event must not have leaked into any gap.
	for _, g := range gaps {
		for _, id := range g.SampleEventIDs {
			if id == "evt_mapped" {
				t.Fatalf("mapped event leaked into gap %+v", g)
			}
		}
	}
}

// TestDetectorGapsSurfacesAllThree proves (ii): a DETECT-MISS escalate row + a
// suppress-directive-on-escalated-finding + a dissent-marked resolution surface
// as all three gap kinds.
func TestDetectorGapsSurfacesAllThree(t *testing.T) {
	st := openStore(t)

	// Seed the resolution stream. f-escalated: the agent escalated it; a human
	// suppress directive on it is an override FP. f-dissent: reason carries the
	// fanout dissent marker.
	escalated := resolution.Resolution{
		FindingID: "find-esc", Action: "escalate", Reason: "clean escalate, no dissent",
		Actor: "mallory", Severity: "high", Source: "detector:priv-escalation",
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
	}
	dissentRes := resolution.Resolution{
		FindingID: "find-dis", Action: "resolve",
		Reason:    "deep panel majority RESOLVE (2 resolve / 1 escalate). Dissent (malicious) cited; confidence penalized 0.10.",
		Actor:     "dana", Severity: "medium", Source: "detector:unusual-login",
		Timestamp: time.Unix(1_700_000_001, 0).UTC(),
	}
	// A calm resolution that must NOT surface as any gap.
	calm := resolution.Resolution{
		FindingID: "find-calm", Action: "resolve", Reason: "obviously benign",
		Actor: "carol", Severity: "low", Source: "detector:new-actor",
		Timestamp: time.Unix(1_700_000_002, 0).UTC(),
	}
	appendRec(t, st, store.KindResolutions, escalated)
	appendRec(t, st, store.KindResolutions, dissentRes)
	appendRec(t, st, store.KindResolutions, calm)

	// A finding record in the stream (proves reads coexist; not strictly needed).
	appendRec(t, st, store.KindFindings, finding.Finding{
		ID: "find-esc", Source: "detector:priv-escalation", Severity: "high",
		Type: "priv-escalation", Actor: "mallory", Timestamp: time.Unix(1_700_000_000, 0).UTC(),
	})

	// A suppress directive whose human verb (resolve, via Op=suppress) disagrees
	// with the agent's escalate on find-esc → override FP.
	meta, _ := json.Marshal(map[string]any{"finding_id": "find-esc", "verb": "resolve"})
	appendRec(t, st, store.KindDirectives, store.Directive{
		Op: "suppress", Pattern: "detector:priv-escalation", Actor: "operator",
		Reason: "false positive on mallory", Meta: meta,
	})
	// A suppress directive that AGREES with the agent (resolve on find-calm) must
	// NOT surface.
	metaCalm, _ := json.Marshal(map[string]any{"finding_id": "find-calm", "verb": "resolve"})
	appendRec(t, st, store.KindDirectives, store.Directive{
		Op: "suppress", Pattern: "detector:new-actor", Meta: metaCalm,
	})

	// DETECT-MISS row on an expected-escalate scenario → real false-negative.
	rows := []eval.DetectFidelityRow{
		{
			ScenarioID: "PE-09", ExpectedDetector: "priv-escalation",
			ExpectedActor: "mallory", ExpectedAction: "escalate-or-stronger",
			Outcome: eval.OutcomeDetectMiss,
		},
		// A DETECT-MISS on an expected-RESOLVE scenario is the correct "nothing
		// flagged" outcome and must NOT surface.
		{
			ScenarioID: "OK-01", ExpectedDetector: "unusual-login",
			ExpectedActor: "bob", ExpectedAction: "resolved",
			Outcome: eval.OutcomeDetectMiss,
		},
		// A REPRODUCED row is not a gap.
		{
			ScenarioID: "RP-01", ExpectedDetector: "git-oops",
			ExpectedActor: "alice", ExpectedAction: "escalated",
			Outcome: eval.OutcomeReproduced, MatchedFindingID: "find-rp",
		},
	}

	gaps, err := DetectorGaps(st, rows)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}

	var miss, fp, dissent int
	for _, g := range gaps {
		switch g.Kind {
		case GapDetectMiss:
			miss++
			if g.Evidence.ScenarioID != "PE-09" {
				t.Fatalf("detect_miss on wrong scenario: %+v", g)
			}
			if g.DetectorFamily != "priv-escalation" {
				t.Fatalf("detect_miss wrong family: %+v", g)
			}
		case GapOverrideFP:
			fp++
			if len(g.FindingIDs) != 1 || g.FindingIDs[0] != "find-esc" {
				t.Fatalf("override_fp wrong finding: %+v", g)
			}
			if g.Evidence.HumanVerb != "resolve" || g.Evidence.AgentAction != "escalate" {
				t.Fatalf("override_fp evidence = %+v, want human=resolve agent=escalate", g.Evidence)
			}
			if g.DetectorFamily != "priv-escalation" {
				t.Fatalf("override_fp wrong family: %+v", g)
			}
		case GapDissent:
			dissent++
			if len(g.FindingIDs) != 1 || g.FindingIDs[0] != "find-dis" {
				t.Fatalf("dissent wrong finding: %+v", g)
			}
			if g.Evidence.DissentMarker != dissentReasonMarker {
				t.Fatalf("dissent marker = %q, want %q", g.Evidence.DissentMarker, dissentReasonMarker)
			}
			// No raw reason free text leaked into evidence.
			if strings.Contains(g.Evidence.DissentMarker, "malicious") {
				t.Fatalf("raw reason leaked into evidence: %+v", g.Evidence)
			}
		}
	}
	if miss != 1 || fp != 1 || dissent != 1 {
		t.Fatalf("want exactly one of each kind, got miss=%d fp=%d dissent=%d (all=%+v)", miss, fp, dissent, gaps)
	}
	if len(gaps) != 3 {
		t.Fatalf("want 3 gaps total, got %d: %+v", len(gaps), gaps)
	}

	// Deterministic ordering: a second run yields identical output.
	gaps2, err := DetectorGaps(st, rows)
	if err != nil {
		t.Fatalf("DetectorGaps rerun: %v", err)
	}
	if a, b := mustJSON(t, gaps), mustJSON(t, gaps2); a != b {
		t.Fatalf("non-deterministic output:\n%s\n---\n%s", a, b)
	}
}

// TestDissentMarkerDriftGuard is the DRIFT GUARD (invariant 10 / brittle-parse
// isolation): the dissent parse keys on an unstructured marker in
// core/agent/fanout.go. If that marker string ever changes, the dissent collector
// silently stops working — so this test FAILS the moment the marker leaves
// fanout.go's source, forcing whoever changed it to update dissentReasonMarker
// (or replace it with a structured dissent field).
func TestDissentMarkerDriftGuard(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "agent", "fanout.go"))
	if err != nil {
		t.Fatalf("read fanout.go: %v", err)
	}
	if !strings.Contains(string(src), dissentReasonMarker) {
		t.Fatalf("dissent marker %q no longer present in core/agent/fanout.go — the dissent "+
			"collector's brittle parse has drifted; update dissentReasonMarker in gaps.go "+
			"(or replace it with a structured dissent field)", dissentReasonMarker)
	}
}

// --- test helpers -----------------------------------------------------------

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
