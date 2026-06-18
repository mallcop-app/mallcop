// reporoot.go — self-resolving config root for the data-driven floor
// (portable-agent-architecture.md §3.5).
//
// The floor reads its escalate-route corpus from agents/rules/operator-
// decisions.yaml. To find that file the floor locates the project root by
// walking UP from the binary's own location to a project marker — NOT from CWD
// (the agent runner relocates CWD to a sandbox / worktree / /tmp) and NOT from
// an env var that "should be set" (the sandbox strips the environment). This is
// the same discipline core/tools/findConfigRoot uses; it is duplicated here
// rather than imported because core/agent must stay free of any dependency that
// could let the floor path reach inference (the import-lint enforces that).
package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// repoRootOverride is the LEGACY global test seam (SetRepoRootForTest), retained
// for the eval harness. When set, it takes precedence over the walk. Production
// never sets it; the walk and the MALLCOP_REPO_ROOT env fallback cover real
// deployments.
//
// IMPORTANT: the CASCADE no longer depends on this global being stable across a
// resolve. ResolveFindingWith resolves the corpus root EXACTLY ONCE at entry
// (preferring the per-invocation CascadeOptions.RepoRoot, else this override via
// resolveRepoRoot) into an immutable local that is threaded through the floor.
// So a concurrent test's SetRepoRootForTest("") cleanup can no longer clear the
// root mid-resolve and flip the corpus — that was the §11 logical-race flake.
// New tests pin CascadeOptions.RepoRoot per-call and never touch this global.
//
// Guarded by repoRootMu so any remaining reader (and the -race detector) observe
// a consistent value: the override is mutated only by the legacy seam and read
// once per resolve in resolveRepoRoot when no per-call RepoRoot is supplied.
var (
	repoRootMu       sync.RWMutex
	repoRootOverride string
)

// setRepoRootForTest sets/clears the override. Tests defer a clear to it.
func setRepoRootForTest(dir string) {
	repoRootMu.Lock()
	repoRootOverride = dir
	repoRootMu.Unlock()
}

// SetRepoRootForTest is the EXPORTED test-only seam. It exists so the external
// black-box test package (agent_test, which drives the assembled cascade through
// the public API and therefore cannot reach the unexported setRepoRootForTest)
// can pin the floor's corpus root DETERMINISTICALLY — instead of relying on the
// MALLCOP_REPO_ROOT env var, whose value is only honored AFTER the
// os.Executable() walk and is therefore shadowed whenever `go test` happens to
// place the test binary inside a marked repo tree (the non-deterministic
// flake: the resolved root then depends on where the toolchain puts the binary,
// flipping the cascade's corpus — and its verdicts — with zero code change).
//
// Pinning the override removes that ambiguity: the override is checked FIRST in
// resolveRepoRoot, so the corpus root is whatever the test set, regardless of
// binary placement or environment. It also lets tests avoid t.Setenv entirely
// (which is incompatible with t.Parallel and leaks across the shared process).
//
// Production never calls this; the walk + env fallback cover real deployments.
// It panics if dir is non-empty and does not contain the corpus, so a typo in a
// test fails loudly instead of silently resolving an empty floor.
func SetRepoRootForTest(dir string) {
	if dir != "" {
		if _, err := os.Stat(filepath.Join(dir, corpusRelPath)); err != nil {
			panic(fmt.Sprintf("SetRepoRootForTest(%q): no corpus at %s: %v",
				dir, filepath.Join(dir, corpusRelPath), err))
		}
	}
	setRepoRootForTest(dir)
	// A root change invalidates any memoized routes keyed at the old path.
	invalidateRoutesCache()
}

// resolveRepoRoot returns the project root that holds the escalate-route corpus.
//
// Resolution order:
//  1. repoRootOverride (test-only seam).
//  2. The walk up from os.Executable() — the PRIMARY production path,
//     CWD- and env-independent.
//  3. MALLCOP_REPO_ROOT env override — last resort, only when the walk fails
//     (e.g. `go test` builds the test binary into a temp dir with no marker
//     above it). Checked AFTER the walk so a stale env var cannot shadow a
//     correct walk result.
func resolveRepoRoot() (string, error) {
	repoRootMu.RLock()
	override := repoRootOverride
	repoRootMu.RUnlock()
	if override != "" {
		return override, nil
	}

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for {
			if hasProjectMarker(dir) {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break // filesystem root
			}
			dir = parent
		}
	}

	if v := os.Getenv("MALLCOP_REPO_ROOT"); v != "" {
		if abs, err := filepath.Abs(v); err == nil {
			return abs, nil
		}
		return v, nil
	}

	return "", errors.New("resolveRepoRoot: no project marker (agents/rules/operator-decisions.yaml, go.mod, or .git) found walking up from binary, and MALLCOP_REPO_ROOT unset")
}

// hasProjectMarker reports whether dir carries any recognised project-root
// marker: the shipped rule corpus, a go.mod, or a .git directory.
func hasProjectMarker(dir string) bool {
	for _, m := range []string{
		filepath.Join("agents", "rules", "operator-decisions.yaml"),
		"go.mod",
		".git",
	} {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return false
}
