package overlay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOverlayTargetCanonicalizedOnStore proves emission soundness for the learned-
// mapping lane: a validated-but-non-canonical target (" Config_Change " — spaces +
// mixed case, accepted because IsKnownEventType normalizes the QUERY) is STORED and
// APPLIED in canonical form ("config_change"), the exact spelling the typed
// detectors gate on. Without canonicalization Apply would return " Config_Change ",
// which the case-sensitive gates would never match — a validated-but-dead mapping.
func TestOverlayTargetCanonicalizedOnStore(t *testing.T) {
	ov, err := ParseLearnedMappings([]byte("acme:\n  brand_new: \" Config_Change \"\n"))
	if err != nil {
		t.Fatalf("ParseLearnedMappings: %v", err)
	}
	if got := ov.Apply("acme", "brand_new", "acme_other"); got != "config_change" {
		t.Errorf("Apply returned %q, want canonical %q so the typed gate matches", got, "config_change")
	}
}

// TestApplyBaseWinsStructurally proves the base-wins rule: an overlay entry for
// an action the connector already classified (baseType != default bucket) is
// unreachable; only a fall-through to "<sourceID>_other" is filled.
func TestApplyBaseWinsStructurally(t *testing.T) {
	ov, err := ParseLearnedMappings([]byte(`
github:
  git.push: role_assignment
  repo.some_new_action: config_change
`))
	if err != nil {
		t.Fatalf("ParseLearnedMappings: %v", err)
	}

	// git.push is ALREADY classified by the connector to "push" (base wins).
	if got := ov.Apply("github", "git.push", "push"); got != "push" {
		t.Errorf("base-wins violated: Apply(github, git.push, push) = %q, want push", got)
	}
	// repo.some_new_action fell through to the default bucket — overlay fills it.
	if got := ov.Apply("github", "repo.some_new_action", "github_other"); got != "config_change" {
		t.Errorf("overlay fill failed: Apply(github, repo.some_new_action, github_other) = %q, want config_change", got)
	}
	// A default-bucket action with NO overlay entry stays default.
	if got := ov.Apply("github", "totally.unknown", "github_other"); got != "github_other" {
		t.Errorf("unmapped default action = %q, want github_other", got)
	}
	// A different source is not consulted.
	if got := ov.Apply("gitlab", "repo.some_new_action", "gitlab_other"); got != "gitlab_other" {
		t.Errorf("cross-source leak: %q, want gitlab_other", got)
	}
}

// TestNilOverlayIsNoOp proves a nil *Overlay (absent file) returns baseType
// unchanged for every call — the byte-identical-behavior guarantee.
func TestNilOverlayIsNoOp(t *testing.T) {
	var ov *Overlay
	for _, base := range []string{"push", "github_other", "login"} {
		if got := ov.Apply("github", "anything", base); got != base {
			t.Errorf("nil overlay Apply(..,%q) = %q, want %q", base, got, base)
		}
	}
}

// TestLoadValidatesTargets proves an unknown target event_type is rejected
// fail-loud, naming the offending source/action/target.
func TestLoadValidatesTargets(t *testing.T) {
	_, err := ParseLearnedMappings([]byte(`
github:
  repo.some_new_action: not_a_real_event_type
`))
	if err == nil {
		t.Fatal("expected an error for an unknown target event_type, got nil")
	}
	for _, want := range []string{"repo.some_new_action", "not_a_real_event_type", "unknown event_type"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestLoadRejectsNonStringShape proves a malformed shape (non-string value) is a
// decode error, not a silent pass.
func TestLoadRejectsNonStringShape(t *testing.T) {
	if _, err := ParseLearnedMappings([]byte("github:\n  action:\n    nested: bad\n")); err == nil {
		t.Fatal("expected a decode error for a non-string mapping value, got nil")
	}
}

// TestEmptyDocIsEmptyOverlay proves an empty/comment-only document yields a
// non-nil no-op overlay.
func TestEmptyDocIsEmptyOverlay(t *testing.T) {
	ov, err := ParseLearnedMappings([]byte("# only a comment\n"))
	if err != nil {
		t.Fatalf("ParseLearnedMappings(empty): %v", err)
	}
	if ov == nil {
		t.Fatal("empty doc returned nil overlay; want a non-nil empty overlay")
	}
	if got := ov.Apply("github", "x", "github_other"); got != "github_other" {
		t.Errorf("empty overlay filled a default bucket: %q", got)
	}
}

// TestLoadLearnedMappingsEmptyPathAndFile covers the file-path seam: empty path
// => nil overlay; a real file loads and validates.
func TestLoadLearnedMappingsEmptyPathAndFile(t *testing.T) {
	ov, err := LoadLearnedMappings("")
	if err != nil || ov != nil {
		t.Fatalf("empty path: got (%v, %v), want (nil, nil)", ov, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "learned_mappings.yaml")
	if err := os.WriteFile(path, []byte("github:\n  repo.new: config_change\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	ov, err = LoadLearnedMappings(path)
	if err != nil {
		t.Fatalf("LoadLearnedMappings: %v", err)
	}
	if got := ov.Apply("github", "repo.new", "github_other"); got != "config_change" {
		t.Errorf("loaded overlay Apply = %q, want config_change", got)
	}

	// A named-but-missing file is fail-loud.
	if _, err := LoadLearnedMappings(filepath.Join(dir, "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing named file, got nil")
	}
}
