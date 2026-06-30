package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop"
)

// TestExpectedSHAMatchesEmbed ties expectedOperatorRulesSHA256 to the embedded
// corpus bytes. Because //go:embed bakes the on-disk
// agents/rules/operator-decisions.yaml verbatim, asserting the pin equals
// sha256(embed) simultaneously asserts the pin equals sha256(on-disk). If anyone
// edits the corpus without regenerating the constant, this fails — so the
// SHA-enforce path (MALLCOP_RULES_SHA256_ENFORCE) can never reference a hash that
// disagrees with the corpus the binary actually carries.
//
// Regenerate the constant with: sha256sum agents/rules/operator-decisions.yaml
func TestExpectedSHAMatchesEmbed(t *testing.T) {
	sum := sha256.Sum256(mallcop.OperatorDecisionsYAML)
	got := hex.EncodeToString(sum[:])
	if got != expectedOperatorRulesSHA256 {
		t.Fatalf("expectedOperatorRulesSHA256 (%s) does not match sha256 of embedded corpus (%s); "+
			"regenerate the constant: sha256sum agents/rules/operator-decisions.yaml",
			expectedOperatorRulesSHA256, got)
	}
}

// TestEmbedFallbackOnResolutionFailure proves the production-scan fallback: when
// the root resolver FAILS (simulated by passing a non-nil rootErr, as the /tmp
// standalone binary hits with MALLCOP_REPO_ROOT unset), LoadOperatorRulesResolved
// loads the EMBEDDED corpus rather than returning empty/erroring. The embedded
// corpus is the real shipped policy, so the rule fold still works standalone.
func TestEmbedFallbackOnResolutionFailure(t *testing.T) {
	invalidateRulesCacheForTest()
	t.Cleanup(invalidateRulesCacheForTest)

	rules, err := LoadOperatorRulesResolved("", errors.New("resolveRepoRoot: no marker, env unset"))
	if err != nil {
		t.Fatalf("resolution failure should fall back to embed, not error: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("embed fallback yielded 0 rules; the standalone binary would carry no policy")
	}
}

// TestEmbedDisabledForcesOnDiskOnly proves the MALLCOP_RULES_EMBED_DISABLE escape
// hatch: with it set, a resolution failure no longer falls back to the embed — it
// degrades to "no pre-seeded rules" (empty, no error), the legacy on-disk-only
// behavior. This is the regression guard that the embed cannot become mandatory.
func TestEmbedDisabledForcesOnDiskOnly(t *testing.T) {
	t.Setenv("MALLCOP_RULES_EMBED_DISABLE", "1")
	invalidateRulesCacheForTest()
	t.Cleanup(invalidateRulesCacheForTest)

	rules, err := LoadOperatorRulesResolved("", errors.New("resolveRepoRoot failed"))
	if err != nil {
		t.Fatalf("embed disabled + resolution failure should be empty, not error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("embed disabled should yield 0 rules on resolution failure, got %d", len(rules))
	}
}

// TestDiskWinsOverEmbed is the footgun guard: a PRESENT on-disk corpus must be
// read, never shadowed by the embed. It writes a temp corpus with a single
// sentinel rule whose id does not exist in the shipped/embedded corpus, then
// asserts LoadOperatorRules returns exactly that rule — proving the disk bytes
// (not the embed) were used, which preserves dev edit-and-reload.
func TestDiskWinsOverEmbed(t *testing.T) {
	invalidateRulesCacheForTest()
	t.Cleanup(invalidateRulesCacheForTest)

	root := t.TempDir()
	dir := filepath.Join(root, "agents", "rules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const sentinel = "rules:\n  - id: \"R-DISK-SENTINEL\"\n    applies_to:\n      family: \"disk-sentinel-family\"\n    operator_directive: \"from disk, not embed\"\n"
	if err := os.WriteFile(filepath.Join(dir, "operator-decisions.yaml"), []byte(sentinel), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	rules, err := LoadOperatorRules(root)
	if err != nil {
		t.Fatalf("load disk corpus: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "R-DISK-SENTINEL" {
		t.Fatalf("expected the on-disk sentinel rule, got %d rules %+v — the embed shadowed the disk corpus", len(rules), rules)
	}
}

// TestRealIOErrorPropagates proves a real (non-ErrNotExist) read error is NOT
// masked by the embed. A directory at the corpus path makes os.ReadFile fail with
// an "is a directory" error; the loader must surface it rather than silently
// substituting the baked-in policy over a corrupt deployment.
func TestRealIOErrorPropagates(t *testing.T) {
	invalidateRulesCacheForTest()
	t.Cleanup(invalidateRulesCacheForTest)

	root := t.TempDir()
	// Create a DIRECTORY where the corpus file should be → ReadFile errors with
	// EISDIR, which is not os.ErrNotExist.
	if err := os.MkdirAll(rulesCachePath(root), 0o755); err != nil {
		t.Fatalf("mkdir corpus-as-dir: %v", err)
	}

	_, err := LoadOperatorRules(root)
	if err == nil {
		t.Fatal("a real read error (EISDIR) must propagate, not fall back to the embed")
	}
}
