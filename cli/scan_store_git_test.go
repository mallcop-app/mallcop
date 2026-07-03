package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestScan_StoreGitStatusCleanAfterScan is the regression test for
// mallcoppro-4fe: `mallcop scan` leaves the store/ repo's REAL git index
// staged-DELETED (and the stream files physically absent) after a successful
// run, because commitAppend/WriteSnapshot advance HEAD entirely through a
// per-attempt TEMPORARY index (see core/store/store.go's buildTree) and never
// touch the repo's real index/work tree. Any git command that looks at the
// real index then sees every stream file as staged-deleted relative to HEAD's
// tree — and a follow-on `git add -A && git commit` COMMITS that deletion,
// replacing real history with git's empty tree.
//
// This reproduces the confirmed-live repro from wave-4 f3b: a plain
// mallcop.yaml + events.jsonl, `mallcop scan`, then plain `git -C store
// status`. It asserts BOTH halves of the fix: `git status --porcelain` must
// be clean, AND every stream file the scan wrote must physically exist in the
// store's work tree (not just be reachable via `git show HEAD:<file>`).
func TestScan_StoreGitStatusCleanAfterScan(t *testing.T) {
	dir := t.TempDir()

	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEvent)

	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeFile(t, cfgPath, `version: 1
inference:
  mode: offline
  endpoint: ""
  key_env: MALLCOP_API_KEY
  model: mallcop-default
store:
  path: `+storePath+`
  baseline: ""
connectors:
  - kind: file
    id: local-events
    path: `+eventsPath+`
detectors:
  builtin:
    enabled: true
    disable: []
learning:
  dir: detectors
  autonomy: non
  enforce_pin: false
sovereignty:
  tier: open
  contribute_back: false
budgets:
  max_findings: 25
  scan_timeout: 10m
  selfext_spend_cap_usd: 25
`)

	err := runScan([]string{"--config", cfgPath})
	if !isFindingsError(err) {
		t.Fatalf("scan: want findings sentinel, got %v", err)
	}

	// (1) `git -C store status --porcelain` must be clean — no staged
	// deletions, no unstaged deletions, nothing untracked among the streams.
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = storePath
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git status: %v: %s", err, out)
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		t.Fatalf("store/ has a dirty git status after a clean scan (mallcoppro-4fe):\n%s", s)
	}

	// (2) Every stream file the scan wrote must physically exist on disk —
	// not just be reachable via `git show HEAD:<file>`.
	for _, f := range []string{"events.jsonl", "findings.jsonl", "findings.json", "resolutions.jsonl"} {
		p := filepath.Join(storePath, f)
		fi, statErr := os.Stat(p)
		if statErr != nil {
			t.Fatalf("stream file %s missing from store work tree after scan: %v", f, statErr)
		}
		if fi.Size() == 0 {
			t.Fatalf("stream file %s exists but is empty on disk after scan", f)
		}
	}
}
