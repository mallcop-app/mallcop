package pipeline

import (
	"encoding/json"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestBackstopEventIDs_FillsFromEvidenceWhenEmpty proves the mallcoppro-323
// defense-in-depth backstop: a finding whose detector left EventIDs empty
// (the shape every one of the 5 named suffix-ID families had BEFORE this fix
// — Finding.ID = "finding-"+ev.ID+"-<suffix>", Evidence carrying only
// {"event_id": "..."}) gets EventIDs recovered from its Evidence blob.
func TestBackstopEventIDs_FillsFromEvidenceWhenEmpty(t *testing.T) {
	evidence, _ := json.Marshal(map[string]string{
		"actor":    "mallory",
		"pattern":  "command-injection-chain",
		"event_id": "evt_ab12cd34ef56",
	})
	findings := []finding.Finding{
		{ID: "finding-evt_ab12cd34ef56-inj-command-injection-chain", Actor: "mallory", Evidence: evidence},
	}

	out := backstopEventIDs(findings)

	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if len(out[0].EventIDs) != 1 || out[0].EventIDs[0] != "evt_ab12cd34ef56" {
		t.Errorf("EventIDs = %v, want [evt_ab12cd34ef56]", out[0].EventIDs)
	}
}

// TestBackstopEventIDs_LeavesAlreadyPopulatedUnchanged proves a finding that
// already carries EventIDs (the primary mallcoppro-323 path — the detector
// itself set it) is passed through untouched, never overwritten by whatever
// the Evidence blob happens to say.
func TestBackstopEventIDs_LeavesAlreadyPopulatedUnchanged(t *testing.T) {
	evidence, _ := json.Marshal(map[string]string{"event_id": "evt-from-evidence"})
	findings := []finding.Finding{
		{ID: "finding-evt-real", Actor: "mallory", Evidence: evidence, EventIDs: []string{"evt-real"}},
	}

	out := backstopEventIDs(findings)

	if len(out[0].EventIDs) != 1 || out[0].EventIDs[0] != "evt-real" {
		t.Errorf("EventIDs = %v, want [evt-real] (the detector's own value, unchanged)", out[0].EventIDs)
	}
}

// TestBackstopEventIDs_NoEvidenceLeavesEmpty proves a finding with neither
// EventIDs nor a recoverable Evidence event_id/event_ids stays empty — the
// backstop never fabricates linkage that isn't there.
func TestBackstopEventIDs_NoEvidenceLeavesEmpty(t *testing.T) {
	findings := []finding.Finding{
		{ID: "finding-no-linkage", Actor: "mallory"},
	}

	out := backstopEventIDs(findings)

	if len(out[0].EventIDs) != 0 {
		t.Errorf("EventIDs = %v, want empty (nothing to recover)", out[0].EventIDs)
	}
}

// TestBackstopEventIDs_MultipleFindingsIndependent proves the backstop
// handles a mixed batch correctly: each finding's EventIDs is resolved (or
// left alone) independently of the others.
func TestBackstopEventIDs_MultipleFindingsIndependent(t *testing.T) {
	withEvidence, _ := json.Marshal(map[string]string{"event_id": "evt-2"})
	findings := []finding.Finding{
		{ID: "f1", EventIDs: []string{"evt-1"}},
		{ID: "f2", Evidence: withEvidence},
		{ID: "f3"},
	}

	out := backstopEventIDs(findings)

	if len(out[0].EventIDs) != 1 || out[0].EventIDs[0] != "evt-1" {
		t.Errorf("f1 EventIDs = %v, want [evt-1] unchanged", out[0].EventIDs)
	}
	if len(out[1].EventIDs) != 1 || out[1].EventIDs[0] != "evt-2" {
		t.Errorf("f2 EventIDs = %v, want [evt-2] recovered from evidence", out[1].EventIDs)
	}
	if len(out[2].EventIDs) != 0 {
		t.Errorf("f3 EventIDs = %v, want empty", out[2].EventIDs)
	}
}
