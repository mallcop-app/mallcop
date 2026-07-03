package cli

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// seedFinding initializes a store at dir and appends one finding, returning the
// store path. It uses the CLI's own store-init lifecycle (openOrInitStore).
func seedFinding(t *testing.T, dir string, f finding.Finding) {
	t.Helper()
	st, err := openOrInitStore(dir)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	if _, err := st.Append(store.KindFindings, f); err != nil {
		t.Fatalf("append finding: %v", err)
	}
}

// TestFeedbackDismiss_WritesDirectiveReadableByLoadDirectives proves the CLI
// persists a suppress directive that LoadDirectives can read back — the bridge
// between the operator's decision and the next scan honoring it.
func TestFeedbackDismiss_WritesDirectiveReadableByLoadDirectives(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{
		ID:        "finding-e1-secret-github-pat",
		Source:    "detector:secrets-exposure",
		Type:      "secrets-exposure",
		Actor:     "alice",
		Severity:  "critical",
		Timestamp: time.Now().UTC(),
		Reason:    "github pat in payload",
	}
	seedFinding(t, dir, f)

	err := runFeedback([]string{f.ID, "dismiss", "--store", dir, "--reason", "known-good", "--by", "baron"})
	if err != nil {
		t.Fatalf("runFeedback dismiss: %v", err)
	}

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	directives, err := st.LoadDirectives()
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(directives))
	}
	d := directives[0]
	if d.Op != "suppress" {
		t.Fatalf("Op = %q, want suppress", d.Op)
	}
	wantPattern := "detector:secrets-exposure/secrets-exposure/alice"
	if d.Pattern != wantPattern {
		t.Fatalf("Pattern = %q, want %q", d.Pattern, wantPattern)
	}
	if d.Actor != "baron" {
		t.Fatalf("Actor = %q, want baron", d.Actor)
	}
	if d.Reason != "known-good" {
		t.Fatalf("Reason = %q, want known-good", d.Reason)
	}
	// Meta records the verb distinctly for the audit trail.
	var meta map[string]string
	if err := json.Unmarshal(d.Meta, &meta); err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	if meta["verb"] != "dismiss" {
		t.Fatalf("meta verb = %q, want dismiss", meta["verb"])
	}
}

// TestFeedbackApprove_RecordsVerbDistinctly proves approve also persists a
// suppress directive but tags the verb as approve.
func TestFeedbackApprove_RecordsVerbDistinctly(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{
		ID:     "finding-e9-new-actor-bob",
		Source: "detector:new-actor",
		Type:   "new-actor",
		Actor:  "bob",
	}
	seedFinding(t, dir, f)

	if err := runFeedback([]string{f.ID, "approve", "--store", dir, "--by", "baron"}); err != nil {
		t.Fatalf("runFeedback approve: %v", err)
	}

	st, _ := store.Open(dir)
	directives, _ := st.LoadDirectives()
	if len(directives) != 1 || directives[0].Op != "suppress" {
		t.Fatalf("approve did not persist a suppress directive: %+v", directives)
	}
	var meta map[string]string
	_ = json.Unmarshal(directives[0].Meta, &meta)
	if meta["verb"] != "approve" {
		t.Fatalf("meta verb = %q, want approve", meta["verb"])
	}
}

// TestFeedback_BadFindingIDErrorsCleanly proves an unknown finding-id fails with
// a clear error and writes NO directive.
func TestFeedback_BadFindingIDErrorsCleanly(t *testing.T) {
	dir := t.TempDir()
	seedFinding(t, dir, finding.Finding{ID: "finding-real", Source: "s", Type: "t", Actor: "a"})

	err := runFeedback([]string{"finding-does-not-exist", "dismiss", "--store", dir})
	if err == nil {
		t.Fatal("expected error for unknown finding-id, got nil")
	}

	st, _ := store.Open(dir)
	directives, _ := st.LoadDirectives()
	if len(directives) != 0 {
		t.Fatalf("no directive should be written on a bad finding-id, got %d", len(directives))
	}
}

func TestFeedback_BadVerbErrors(t *testing.T) {
	dir := t.TempDir()
	seedFinding(t, dir, finding.Finding{ID: "finding-real", Source: "s", Type: "t", Actor: "a"})
	if err := runFeedback([]string{"finding-real", "frobnicate", "--store", dir}); err == nil {
		t.Fatal("expected error for unknown verb")
	}
}

func TestFeedback_MissingStoreErrors(t *testing.T) {
	if err := runFeedback([]string{"finding-real", "dismiss"}); err == nil {
		t.Fatal("expected error when --store is missing")
	}
}
