package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// initFixtureRepo creates a throwaway git repo with one commit and returns its
// path plus the initial commit SHA. No network, no opencode.
func initFixtureRepo(t *testing.T) (repo, sha string) {
	t.Helper()
	repo = t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		// Isolate from any ambient git config that could break commits in CI.
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "main")
	run("config", "user.email", "fixture@example.com")
	run("config", "user.name", "Fixture")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-m", "initial")

	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-parse HEAD: %v", err)
	}
	return repo, strings.TrimSpace(string(out))
}

// TestWorktreeLifecycle exercises Open → write → CommitAuthored → Diff → Close.
func TestWorktreeLifecycle(t *testing.T) {
	ctx := context.Background()
	repo, baseSHA := initFixtureRepo(t)

	j := &Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if wt.BaseSHA != baseSHA {
		t.Errorf("BaseSHA=%q, want %q", wt.BaseSHA, baseSHA)
	}

	// The worktree exists and carries the base content.
	if fi, err := os.Stat(wt.Dir); err != nil || !fi.IsDir() {
		t.Fatalf("worktree dir not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(wt.Dir, "README.md")); err != nil {
		t.Errorf("base content missing from worktree: %v", err)
	}

	// It is detached (no symbolic HEAD).
	if _, err := runGit(ctx, wt.Dir, "symbolic-ref", "-q", "HEAD"); err == nil {
		t.Errorf("expected detached HEAD (symbolic-ref should fail)")
	}

	// Author a file, commit, and diff.
	if err := os.WriteFile(filepath.Join(wt.Dir, "authored.txt"), []byte("authored line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	head, err := wt.CommitAuthored(ctx, "author: add authored.txt")
	if err != nil {
		t.Fatalf("CommitAuthored: %v", err)
	}
	if head == "" || head == wt.BaseSHA {
		t.Errorf("HEAD did not advance: head=%q base=%q", head, wt.BaseSHA)
	}

	diff, err := wt.Diff(ctx)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	ds := string(diff)
	if !strings.Contains(ds, "authored.txt") || !strings.Contains(ds, "+authored line") {
		t.Errorf("diff missing authored change:\n%s", ds)
	}

	// Close removes the worktree even though HEAD advanced.
	if err := wt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(wt.Dir); !os.IsNotExist(err) {
		t.Errorf("worktree dir still exists after Close: %v", err)
	}
	// git no longer tracks the worktree.
	out, err := runGit(ctx, repo, "worktree", "list")
	if err != nil {
		t.Fatalf("worktree list: %v", err)
	}
	if strings.Contains(string(out), wt.Dir) {
		t.Errorf("git still lists removed worktree:\n%s", out)
	}
}

// TestScrubbedEnvOmitsOperatorCredentials proves the exec env allowlist:
// only PATH/HOME/TMPDIR/OPENCODE_CONFIG_CONTENT survive, and no operator
// credential leaks through even when present in the parent environment.
func TestScrubbedEnvOmitsOperatorCredentials(t *testing.T) {
	ctx := context.Background()
	repo, _ := initFixtureRepo(t)

	// Poison the parent environment with credentials that must NOT leak.
	forbidden := []string{
		"FORGE_API_KEY",
		"OP_SERVICE_ACCOUNT_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"CF_HOME",
	}
	for _, k := range forbidden {
		t.Setenv(k, "SECRET-"+k)
	}

	j := &Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	const subkey = "mallcop-sk-testtoken123"
	env := wt.ScrubbedEnv(subkey, "https://forge.example.com")

	keys := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("malformed env entry: %q", kv)
		}
		if _, dup := keys[k]; dup {
			t.Errorf("duplicate env var %q", k)
		}
		keys[k] = v
	}

	// Only the allowlist may appear.
	allowed := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "OPENCODE_CONFIG_CONTENT": true}
	for k := range keys {
		if !allowed[k] {
			t.Errorf("scrubbed env contains non-allowlisted var %q", k)
		}
	}
	for k := range allowed {
		if _, ok := keys[k]; !ok {
			t.Errorf("scrubbed env missing required var %q", k)
		}
	}

	// No operator credential leaked, by key OR by value.
	for _, k := range forbidden {
		if _, ok := keys[k]; ok {
			t.Errorf("scrubbed env leaked credential var %q", k)
		}
	}
	for _, kv := range env {
		for _, k := range forbidden {
			if strings.Contains(kv, "SECRET-"+k) {
				t.Errorf("scrubbed env leaked credential value for %q in %q", k, kv)
			}
		}
	}

	// HOME/TMPDIR are throwaway dirs inside the jail, not the operator's real home.
	if !strings.Contains(keys["HOME"], "selfext-jail-") {
		t.Errorf("HOME is not a throwaway jail dir: %q", keys["HOME"])
	}
	if !strings.Contains(keys["TMPDIR"], "selfext-jail-") {
		t.Errorf("TMPDIR is not a throwaway jail dir: %q", keys["TMPDIR"])
	}

	// The run key is delivered ONLY inside the provider config, with the /v1 base URL.
	cfg := keys["OPENCODE_CONFIG_CONTENT"]
	if !strings.Contains(cfg, subkey) {
		t.Errorf("provider config missing subkey")
	}
	if !strings.Contains(cfg, "https://forge.example.com/v1") {
		t.Errorf("provider config missing /v1 base URL: %s", cfg)
	}
	// The run key must not appear as a bare env var (only inside the config blob).
	for _, kv := range env {
		if strings.HasPrefix(kv, "OPENCODE_CONFIG_CONTENT=") {
			continue
		}
		if strings.Contains(kv, subkey) {
			t.Errorf("subkey leaked outside the provider config in %q", kv)
		}
	}
}

// TestOpenRejectsNonRepo proves Open validates the target is a git repo before
// creating anything.
func TestOpenRejectsNonRepo(t *testing.T) {
	dir := t.TempDir() // not a git repo
	j := &Jail{TargetRepo: dir, BaseRef: "main"}
	if _, err := j.Open(context.Background()); err == nil {
		t.Fatalf("Open on non-repo: expected error, got nil")
	}
}

// TestOpenRejectsUnknownRef proves an unresolvable base ref fails cleanly
// without leaving a dangling worktree registration.
func TestOpenRejectsUnknownRef(t *testing.T) {
	ctx := context.Background()
	repo, _ := initFixtureRepo(t)
	j := &Jail{TargetRepo: repo, BaseRef: "no-such-ref"}
	if _, err := j.Open(ctx); err == nil {
		t.Fatalf("Open with unknown ref: expected error, got nil")
	}
	// No worktree should have been registered.
	out, err := runGit(ctx, repo, "worktree", "list")
	if err != nil {
		t.Fatalf("worktree list: %v", err)
	}
	if strings.Count(strings.TrimSpace(string(out)), "\n") != 0 {
		t.Errorf("expected only the main worktree, got:\n%s", out)
	}
}

// TestCloseIsBestEffortIdempotent proves Close does not panic or hard-fail when
// called after the worktree is already gone (defer-safety).
func TestCloseIsBestEffortIdempotent(t *testing.T) {
	ctx := context.Background()
	repo, _ := initFixtureRepo(t)
	j := &Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := wt.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close: worktree + tmp are already gone. It must not panic; an
	// error is acceptable (best-effort), but the temp dir removal is a no-op.
	_ = wt.Close()
	if _, err := os.Stat(wt.tmpRoot); !os.IsNotExist(err) {
		t.Errorf("tmpRoot still present after Close: %v", err)
	}
}
