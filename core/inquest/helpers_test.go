package inquest

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
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

// corruptHeadCommitObjectForTest overwrites the CURRENT HEAD commit's loose
// object bytes with garbage, then returns a restore func. This is the ONLY
// way to make store.Store.ReadSnapshot return a REAL (non-"not found") error
// from this package's tests: Input.Store is a concrete *store.Store, not an
// interface, so there is no mock seam.
//
// `git rev-parse HEAD` (store.head, which ReadSnapshot uses for its
// not-found short-circuit) only resolves the ref chain — it never opens the
// commit object — so it keeps succeeding after this corruption. `git cat-file
// -p HEAD:path` (store.blobAt, which does the actual content read) DOES need
// to open the commit object and fails with "fatal: loose object ... is
// corrupt", a message that (unlike a merely-missing path) does NOT match any
// of blobAt's not-found heuristics ("does not exist" / "Not a valid object
// name" / "exists on disk, but not in") — so it surfaces as a genuine error,
// simulating a transient git-pull/read failure on an otherwise-healthy repo.
//
// The caller MUST invoke the returned restore func before making any further
// store calls in the test (a write during the corrupted window would either
// fail outright or build on top of a HEAD whose content nothing can verify).
func corruptHeadCommitObjectForTest(t *testing.T, s *store.Store) func() {
	t.Helper()
	shaOut, err := exec.Command("git", "-C", s.Path(), "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v", err)
	}
	sha := strings.TrimSpace(string(shaOut))
	objPath := s.Path() + "/.git/objects/" + sha[:2] + "/" + sha[2:]

	info, err := os.Stat(objPath)
	if err != nil {
		t.Fatalf("stat commit object %s: %v", objPath, err)
	}
	orig, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatalf("read commit object %s: %v", objPath, err)
	}
	if err := os.Chmod(objPath, 0o644); err != nil {
		t.Fatalf("chmod commit object %s: %v", objPath, err)
	}
	if err := os.WriteFile(objPath, []byte("corrupted-for-test-not-a-valid-git-object"), 0o644); err != nil {
		t.Fatalf("corrupt commit object %s: %v", objPath, err)
	}
	return func() {
		if err := os.WriteFile(objPath, orig, info.Mode()); err != nil {
			t.Fatalf("restore commit object %s: %v", objPath, err)
		}
		if err := os.Chmod(objPath, info.Mode()); err != nil {
			t.Fatalf("restore commit object mode %s: %v", objPath, err)
		}
	}
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
