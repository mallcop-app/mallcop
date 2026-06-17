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
	"os"
	"path/filepath"
)

// repoRootOverride lets tests point the floor at a temp corpus tree. When set,
// it takes precedence over the walk. Production never sets it; the walk and the
// MALLCOP_REPO_ROOT env fallback cover real deployments.
var repoRootOverride string

// setRepoRootForTest sets/clears the override. Tests defer a clear to itself.
func setRepoRootForTest(dir string) { repoRootOverride = dir }

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
	if repoRootOverride != "" {
		return repoRootOverride, nil
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
