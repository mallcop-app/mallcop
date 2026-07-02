package github

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// TestAuditLogNormalizationFiresDetectors wires the committed audit-log fixtures
// through normalizeAuditEntry — the opt-in (GITHUB_AUDIT_LOG=1) path that shipped
// untested. It proves (a) epoch-ms timestamps parse, (b) every audit action
// normalizes to a non-empty routing type, and (c) the security-relevant
// repo.add_member entry reaches the new-external-access detector gate — the same
// silent-coupling invariant TestNormalizedTypesFireDetectors enforces for the
// events feed. Regression guard: an action mapped to a type no detector
// recognizes (the original "collaborator_added" bug) fails here.
func TestAuditLogNormalizationFiresDetectors(t *testing.T) {
	// (1) the collaborator-add fixture must reach the new-external-access gate.
	var evs []event.Event
	var sawAddMember bool
	for _, raw := range loadAuditFixture(t, "testdata/audit_log_new_collaborator.json") {
		ev, ok := normalizeAuditEntry(raw, "acme-corp", nil)
		if !ok {
			t.Fatalf("normalizeAuditEntry ok=false for %s", raw)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("epoch-ms timestamp did not parse: %s", raw)
		}
		if ev.Type == "" {
			t.Errorf("empty routing type for %s", raw)
		}
		if ev.Actor == "admin-user" && ev.Type == "repo.add_collaborator" {
			sawAddMember = true
			if want := time.UnixMilli(1709740800000).UTC(); !ev.Timestamp.Equal(want) {
				t.Errorf("timestamp = %v, want %v", ev.Timestamp, want)
			}
		}
		evs = append(evs, ev)
	}
	if !sawAddMember {
		t.Fatal("repo.add_member did not normalize to repo.add_collaborator (the new-external-access gate)")
	}
	var sawExternal bool
	for _, f := range detect.Detect(evs, &baseline.Baseline{}) {
		if f.Type == "new-external-access" {
			sawExternal = true
		}
	}
	if !sawExternal {
		t.Fatalf("audit-log repo.add_member produced no new-external-access finding " +
			"(normalized types do not reach the detector gates)")
	}

	// (2) the all-types fixture: every action normalizes with a valid timestamp +
	// a non-empty routing type (exercises classifyAuditAction + epochMS broadly).
	for _, raw := range loadAuditFixture(t, "testdata/audit_log_all_types.json") {
		ev, ok := normalizeAuditEntry(raw, "acme-corp", nil)
		if !ok {
			t.Errorf("normalizeAuditEntry ok=false for %s", raw)
			continue
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("epoch-ms parse failed for %s", raw)
		}
		if ev.Type == "" {
			t.Errorf("empty type for %s", raw)
		}
	}
}

func loadAuditFixture(t *testing.T, path string) []json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return raws
}
