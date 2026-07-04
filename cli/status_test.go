package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
)

// initStatusRepo creates a REAL git-backed store dir (matching
// core/store's own initRepo test helper) so runStatus exercises the actual
// git plumbing, not a fake.
func initStatusRepo(t *testing.T) string {
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

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// TestRunStatus_DecisionsWording proves `mallcop status` labels the total
// recorded-resolutions count "Decisions:", not "Resolved:" — the terminology
// fix that disambiguates it from `mallcop scan`'s per-run "Resolved: N"
// summary line (which counts only the non-escalate subset of ONE scan, not
// every decision ever recorded in the store).
func TestRunStatus_DecisionsWording(t *testing.T) {
	repo := initStatusRepo(t)

	st, err := store.Open(repo)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	// Two resolutions recorded, both escalations (so a scan over this data
	// would itself report "Resolved: 0" while status still has decisions to
	// show — the exact confusion the wording fix resolves).
	for i := 0; i < 2; i++ {
		if _, err := st.Append(store.KindResolutions, map[string]string{
			"finding_id": "f-1", "action": "escalate",
		}); err != nil {
			t.Fatalf("append resolution: %v", err)
		}
	}

	out := captureStdout(t, func() {
		if err := runStatus([]string{"--store", filepath.Clean(repo)}); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	if !bytes.Contains([]byte(out), []byte("Decisions:  2 recorded")) {
		t.Errorf("expected %q in output, got:\n%s", "Decisions:  2 recorded", out)
	}
	if bytes.Contains([]byte(out), []byte("Resolved:")) {
		t.Errorf("status output must not say \"Resolved:\" (ambiguous with scan's per-run summary word); got:\n%s", out)
	}
}
