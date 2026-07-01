// tools_heal_allowlist.go — Repo allowlist + subtree pathspec enforcement for
// the embedded self-extension engine (write allowlist for agent-authored data).
//
// Design source: docs/design/heal-broaden.md §10 constraints C1-C2, §4.4.
//
// # Constraints (from §10 ruling)
//
//   - C1: Repo allowlist hard-coded in tool binary, default-deny.
//   - C2: Legion + mallcop-pro hard-excluded by absolute path.
//
// This file implements the allowlist + subtree validation library.
// It does NOT register a dispatchActionTool case — this is consumed by the
// embedded self-extension engine, not callable as
// a standalone --tool mode.
package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// healRepoAllowlist maps a repo alias to its absolute path on this machine.
// Heal can only fork/branch/PR against repos in this map (C1: default-deny).
//
// v1 ships with repos that exist on the operator's machine. Connector repos
// are added here as connectors are built and their directories exist.
// v2 may move this to chart config when there is appetite for operator-managed
// scope expansion.
var healRepoAllowlist = map[string]string{
	// alias                  → absolute path
	"mallcop":                "/home/baron/projects/mallcop",
	"mallcop-legion-prompts": "/home/baron/projects/mallcop-legion", // subtree-restricted — see healSubtreePathspecs
}

// healRepoExclusions are absolute paths that are ALWAYS rejected, even if
// accidentally added to the allowlist (C2: hard exclusions).
//
// These are the operator-facing infra and tenant-layer repos that must never
// be modified by the autonomous heal path. Changes to these repos require
// human review only.
var healRepoExclusions = []string{
	"/home/baron/projects/legion",
	"/home/baron/projects/mallcop-pro",
}

// healSubtreePathspecs maps repo aliases that have partial-allowlist scope to
// the gitignore-style pathspecs (matching git pathspec syntax). For these
// repos, heal can only modify files matching at least one of the pathspecs.
// Repos absent from this map have full-repo scope (within the allowed tree).
var healSubtreePathspecs = map[string][]string{
	"mallcop-legion-prompts": {"agents/*/POST.md", "chart/*", "prompts/*"},
}

// resolveHealRepo looks up a repo alias in the allowlist and returns its
// absolute path and subtree pathspecs (nil if full-repo scope).
//
// Errors:
//   - "repo_not_allowed": alias is absent from the allowlist.
//   - "repo_not_allowed": resolved absolute path is in healRepoExclusions.
func resolveHealRepo(alias string) (absPath string, subtree []string, err error) {
	path, ok := healRepoAllowlist[alias]
	if !ok {
		return "", nil, fmt.Errorf("repo_not_allowed: alias %q is not in the heal repo allowlist", alias)
	}

	// Normalize to absolute path (the map values should already be absolute,
	// but we call Abs for safety).
	path, err = filepath.Abs(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve abs path for alias %q: %w", alias, err)
	}

	// C2: reject even allowlisted entries whose path resolves to an exclusion.
	for _, excl := range healRepoExclusions {
		exclAbs, absErr := filepath.Abs(excl)
		if absErr != nil {
			continue
		}
		if path == exclAbs || strings.HasPrefix(path, exclAbs+string(filepath.Separator)) {
			return "", nil, fmt.Errorf("repo_not_allowed: alias %q resolves to excluded path %q", alias, path)
		}
	}

	// Look up subtree restriction (nil if no restriction).
	specs := healSubtreePathspecs[alias]
	return path, specs, nil
}

// validateHealPath confirms that a relative path within a repo is permitted
// by the subtree pathspec (if any). For repos without a subtree restriction,
// any relative path is accepted.
//
// Errors:
//   - "path_outside_subtree": path does not match any of the repo's subtree pathspecs.
func validateHealPath(repoAlias, relPath string) error {
	specs := healSubtreePathspecs[repoAlias]
	if len(specs) == 0 {
		// Full-repo allowlist — any path is permitted.
		return nil
	}

	for _, spec := range specs {
		if matchGlobPathspec(spec, relPath) {
			return nil
		}
	}
	return fmt.Errorf("path_outside_subtree: %q does not match any subtree pathspec for repo %q (allowed: %v)",
		relPath, repoAlias, specs)
}

// validateHealDiff validates every path listed in git diff --name-only output
// against the subtree pathspec for the given repo alias. Returns the first
// violation error, or nil if all paths pass.
func validateHealDiff(repoAlias string, gitDiffOutput []byte) error {
	lines := strings.Split(strings.TrimSpace(string(gitDiffOutput)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := validateHealPath(repoAlias, line); err != nil {
			return err
		}
	}
	return nil
}

// matchGlobPathspec reports whether relPath matches a gitignore-style pathspec.
// Supported pattern forms (matching git pathspec glob behaviour):
//
//   - "prefix/*"       — any immediate child of prefix/
//   - "prefix/*/file"  — file inside any immediate subdirectory of prefix/
//   - literal path     — exact match
//
// This is a minimal implementation covering the pathspecs used in this file.
// It does NOT implement full gitignore glob semantics (no double-star, no
// negation patterns) — extend if future pathspecs require them.
func matchGlobPathspec(pattern, relPath string) bool {
	// Use filepath.Match which supports ?, *, and character classes.
	// filepath.Match treats "/" as a literal separator, matching git pathspec
	// single-star semantics (no cross-directory match).
	matched, err := filepath.Match(pattern, relPath)
	if err != nil {
		// Malformed pattern — fail closed.
		return false
	}
	return matched
}
