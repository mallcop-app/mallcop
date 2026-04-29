// tools_heal_allowlist_test.go — Tests for heal repo allowlist + subtree
// pathspec enforcement (mallcoppro-8b1).
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHealAllowlist_KnownAlias_ResolvesAbsPath verifies that every entry in
// the allowlist resolves to a non-empty absolute path. Disk-presence is asserted
// only when the host's actual filesystem includes the path — CI runners do not
// have the operator's project tree, so the existence check is per-entry skipped
// rather than failed. The resolution logic (alias → path, err semantics) is
// asserted unconditionally.
func TestHealAllowlist_KnownAlias_ResolvesAbsPath(t *testing.T) {
	for alias := range healRepoAllowlist {
		t.Run(alias, func(t *testing.T) {
			absPath, _, err := resolveHealRepo(alias)
			if err != nil {
				t.Fatalf("resolveHealRepo(%q) returned error: %v", alias, err)
			}
			if absPath == "" {
				t.Fatalf("resolveHealRepo(%q) returned empty absPath", alias)
			}
			if !filepath.IsAbs(absPath) {
				t.Fatalf("resolveHealRepo(%q) returned non-absolute path: %q", alias, absPath)
			}
			info, statErr := os.Stat(absPath)
			if statErr != nil {
				// Path does not exist on this host — common on CI runners that
				// don't have the operator's project tree. Resolution succeeded;
				// presence is operator-machine-only.
				t.Skipf("alias %q resolves to %q which is absent on this host: %v (resolution logic OK; presence check skipped)", alias, absPath, statErr)
			}
			if !info.IsDir() {
				t.Fatalf("path %q for alias %q is not a directory", absPath, alias)
			}
		})
	}
}

// TestHealAllowlist_UnknownAlias_RepoNotAllowed verifies that an alias absent
// from the allowlist returns a repo_not_allowed error.
func TestHealAllowlist_UnknownAlias_RepoNotAllowed(t *testing.T) {
	_, _, err := resolveHealRepo("nope")
	if err == nil {
		t.Fatal("expected error for unknown alias, got nil")
	}
	if !strings.Contains(err.Error(), "repo_not_allowed") {
		t.Fatalf("expected 'repo_not_allowed' in error, got: %v", err)
	}
}

// TestHealAllowlist_ExcludedPath_RejectedEvenIfAdded verifies that adding an
// exclusion path to the allowlist still results in repo_not_allowed being
// returned by resolveHealRepo.
func TestHealAllowlist_ExcludedPath_RejectedEvenIfAdded(t *testing.T) {
	// Inject a test alias pointing at the first exclusion path.
	if len(healRepoExclusions) == 0 {
		t.Fatal("healRepoExclusions is empty — test invariant violated")
	}
	excludedPath := healRepoExclusions[0]

	// Temporarily add the excluded path to the allowlist.
	const testAlias = "__test_excluded_alias__"
	healRepoAllowlist[testAlias] = excludedPath
	t.Cleanup(func() { delete(healRepoAllowlist, testAlias) })

	_, _, err := resolveHealRepo(testAlias)
	if err == nil {
		t.Fatal("expected error for excluded path in allowlist, got nil")
	}
	if !strings.Contains(err.Error(), "repo_not_allowed") {
		t.Fatalf("expected 'repo_not_allowed' in error, got: %v", err)
	}
}

// TestHealSubtree_OutsideSubtree_PathOutsideSubtree verifies subtree pathspec
// enforcement for the mallcop-legion-prompts alias:
//   - "cmd/whatever/main.go" → path_outside_subtree error
//   - "agents/triage/POST.md" → no error (matches "agents/*/POST.md")
func TestHealSubtree_OutsideSubtree_PathOutsideSubtree(t *testing.T) {
	const alias = "mallcop-legion-prompts"

	// Ensure the alias has a subtree restriction.
	specs := healSubtreePathspecs[alias]
	if len(specs) == 0 {
		t.Fatalf("alias %q has no subtree pathspecs — test invariant violated", alias)
	}

	// Path outside subtree must fail.
	err := validateHealPath(alias, "cmd/whatever/main.go")
	if err == nil {
		t.Fatal("expected path_outside_subtree error for cmd/whatever/main.go, got nil")
	}
	if !strings.Contains(err.Error(), "path_outside_subtree") {
		t.Fatalf("expected 'path_outside_subtree' in error, got: %v", err)
	}

	// Path inside subtree must succeed.
	err = validateHealPath(alias, "agents/triage/POST.md")
	if err != nil {
		t.Fatalf("expected nil for agents/triage/POST.md, got: %v", err)
	}
}

// TestHealValidateDiff_FullRepoAlias_AllowsAnyPath verifies that for a
// full-repo allowlisted alias (mallcop), any diff path is accepted.
func TestHealValidateDiff_FullRepoAlias_AllowsAnyPath(t *testing.T) {
	const alias = "mallcop"

	// Ensure alias has no subtree restriction.
	if specs := healSubtreePathspecs[alias]; len(specs) != 0 {
		t.Fatalf("alias %q unexpectedly has subtree pathspecs: %v — test invariant violated", alias, specs)
	}

	diffOutput := []byte("src/mallcop/parsers/nginx.yaml\nsrc/mallcop/detectors/access.yaml\ncmd/whatever/main.go\n")
	if err := validateHealDiff(alias, diffOutput); err != nil {
		t.Fatalf("expected nil for full-repo alias %q, got: %v", alias, err)
	}
}

// TestHealValidateDiff_SubtreeAlias_RejectsOutOfSubtree verifies that for
// mallcop-legion-prompts, a diff touching cmd/whatever/main.go fails.
func TestHealValidateDiff_SubtreeAlias_RejectsOutOfSubtree(t *testing.T) {
	const alias = "mallcop-legion-prompts"

	diffOutput := []byte("agents/triage/POST.md\ncmd/whatever/main.go\n")
	err := validateHealDiff(alias, diffOutput)
	if err == nil {
		t.Fatal("expected path_outside_subtree error for diff containing cmd/whatever/main.go, got nil")
	}
	if !strings.Contains(err.Error(), "path_outside_subtree") {
		t.Fatalf("expected 'path_outside_subtree' in error, got: %v", err)
	}
}
