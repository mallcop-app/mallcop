// reporoot.go — self-resolving repo root for the eval harness
// (portable-agent-architecture.md §3.5, §4 determinism via SetRepoRootForTest).
//
// The harness reads the scenario corpus from exams/scenarios/ under the repo
// root. When nothing pins the root explicitly it walks UP from the binary's
// own location to a project marker — NOT from CWD (the runner relocates CWD).
// An EXPLICITLY-set MALLCOP_REPO_ROOT is an operator/orchestrator decision and
// takes precedence over that heuristic walk (explicit config beats discovery
// — see RepoRoot's doc for why the old walk-first order was a bug). A
// test-only override (SetRepoRootForTest) pins the root DETERMINISTICALLY so
// `go test -count=N -race` always resolves the same corpus regardless of
// where the toolchain places the test binary — the same flake-closing seam
// core/agent uses.
package eval

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var (
	repoRootMu       sync.RWMutex
	repoRootOverride string
)

// SetRepoRootForTest pins the repo root the harness resolves, taking precedence
// over the os.Executable() walk. It panics if dir is non-empty and does not
// contain exams/scenarios, so a typo fails loudly instead of silently resolving
// an empty corpus. Tests defer SetRepoRootForTest("") to clear it.
//
// Production never calls this; the MALLCOP_REPO_ROOT env pin + the walk cover
// real deployments. Pinning the override (checked FIRST in RepoRoot) removes the
// non-determinism where the resolved root depends on binary placement — the
// reason the determinism harness (-count=10 + -race) needs an explicit seam.
func SetRepoRootForTest(dir string) {
	if dir != "" {
		if fi, err := os.Stat(filepath.Join(dir, scenariosRelPath)); err != nil || !fi.IsDir() {
			panic("SetRepoRootForTest(" + dir + "): no " + scenariosRelPath + " under it")
		}
	}
	repoRootMu.Lock()
	repoRootOverride = dir
	repoRootMu.Unlock()
}

// RepoRoot returns the project root that holds exams/scenarios.
//
// Resolution order (§3.5, revised per PR #191 review):
//  1. SetRepoRootForTest override (test-only seam, deterministic).
//  2. MALLCOP_REPO_ROOT env override — an EXPLICIT pin set by a person or an
//     orchestrating process (e.g. core/selfgate's runTreeExam, or
//     core/investigate's run-eval self-exec) wins over the heuristic walk:
//     explicit config beats discovery. The old walk-first order made the pin
//     silently ignorable — whenever the binary happened to sit under ANY
//     marker-bearing directory, the walk's answer shadowed the caller's
//     explicit choice and eval graded the WRONG root (e.g. a silently-empty
//     local scenarios/ union) with no error anywhere.
//  3. The walk up from os.Executable() — the production default when nothing
//     pins the root explicitly (the scaffolded GHA runtime path: no env var
//     is set there, the pinned release binary is installed inside the deploy
//     repo checkout, and the walk resolves it).
func RepoRoot() (string, error) {
	repoRootMu.RLock()
	override := repoRootOverride
	repoRootMu.RUnlock()
	if override != "" {
		return override, nil
	}

	if v := os.Getenv("MALLCOP_REPO_ROOT"); v != "" {
		if abs, err := filepath.Abs(v); err == nil {
			return abs, nil
		}
		return v, nil
	}

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for {
			if hasRepoMarker(dir) {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return "", errors.New("eval.RepoRoot: MALLCOP_REPO_ROOT unset and no project marker (exams/scenarios, go.mod, or .git) found walking up from binary")
}

// hasRepoMarker reports whether dir carries a repo-root marker: the scenario
// corpus, a go.mod, or a .git directory.
func hasRepoMarker(dir string) bool {
	for _, m := range []string{scenariosRelPath, "go.mod", ".git"} {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return false
}
