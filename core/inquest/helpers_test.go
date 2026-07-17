package inquest

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// newTempStore git-inits a temp repo (with a root commit so HEAD resolves)
// and opens a real core/store over it — mirrors core/tools/tools_test.go's
// helper of the same name (this package intentionally builds no fake store).
func newTempStore(t *testing.T) *store.Store {
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
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

// seedEvent appends one event to the store's KindEvents stream.
func seedEvent(t *testing.T, s *store.Store, ev event.Event) {
	t.Helper()
	if _, err := s.Append(store.KindEvents, ev); err != nil {
		t.Fatalf("append event %s: %v", ev.ID, err)
	}
}

// seedFinding appends one finding to the store's KindFindings stream.
func seedFinding(t *testing.T, s *store.Store, f finding.Finding) {
	t.Helper()
	if _, err := s.Append(store.KindFindings, f); err != nil {
		t.Fatalf("append finding %s: %v", f.ID, err)
	}
}

// rawEventPayload builds a minimal, VALID new-format event payload as raw
// JSON.
func rawEventPayload(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// mustParseTime parses an RFC3339 timestamp or fails the test.
func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tm
}
