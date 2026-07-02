package github

import (
	"encoding/json"
	"testing"

	"github.com/mallcop-app/mallcop/connect/overlay"
)

// auditRaw builds a raw audit-log entry JSON with the given action.
func auditRaw(t *testing.T, action string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"action":       action,
		"actor":        "octo-admin",
		"org":          "acme-corp",
		"_document_id": "doc-1",
		"@timestamp":   1_700_000_000_000,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestOverlayFillsGithubDefaultBucket proves a previously-unmapped github audit
// action (one classifyAuditAction leaves at "github_other") classifies to the
// overlay target once an overlay maps it — while an absent overlay leaves the
// event byte-identical, and a conflicting overlay key on an already-classified
// action never overrides it (base wins).
func TestOverlayFillsGithubDefaultBucket(t *testing.T) {
	// "repo.rename" is not in auditActionMap -> classifyAuditAction => github_other.
	unmapped := auditRaw(t, "repo.rename")

	// (1) absent overlay: default bucket, byte-identical.
	base, ok := normalizeAuditEntry(unmapped, "acme-corp", nil)
	if !ok {
		t.Fatal("normalizeAuditEntry ok=false")
	}
	if base.Type != defaultEventTy {
		t.Fatalf("no-overlay Type=%q, want %q", base.Type, defaultEventTy)
	}

	// (2) overlay maps repo.rename -> config_change (a KnownEventTypes member).
	ov, err := overlay.ParseLearnedMappings([]byte(`
github:
  repo.rename: config_change
  git.push: role_assignment
`))
	if err != nil {
		t.Fatalf("overlay parse: %v", err)
	}
	filled, ok := normalizeAuditEntry(unmapped, "acme-corp", ov)
	if !ok {
		t.Fatal("normalizeAuditEntry ok=false (overlay)")
	}
	if filled.Type != "config_change" {
		t.Errorf("overlay fill: Type=%q, want config_change", filled.Type)
	}
	// The overlay does not touch anything else about the event.
	if filled.Actor != base.Actor || filled.ID != base.ID {
		t.Errorf("overlay changed more than the type: base=%+v filled=%+v", base, filled)
	}

	// (3) base-wins: git.push is already classified to "push" by the audit map;
	// the conflicting overlay key must NOT override it.
	pushRaw := auditRaw(t, "git.push")
	pushEv, ok := normalizeAuditEntry(pushRaw, "acme-corp", ov)
	if !ok {
		t.Fatal("normalizeAuditEntry ok=false (push)")
	}
	if pushEv.Type != "push" {
		t.Errorf("base-wins violated: git.push Type=%q, want push (not the overlay's role_assignment)", pushEv.Type)
	}
}
