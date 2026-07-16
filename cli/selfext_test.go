package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveBYOK_Required proves BYOK is REQUIRED in the OSS binary: both
// --inference-url and --inference-key-env must be present and the named env var
// must resolve non-empty. There is NO donut fallback — the OSS binary has no
// commercial billing rail.
func TestResolveBYOK_Required(t *testing.T) {
	getenv := func(k string) string {
		if k == "MY_KEY" {
			return "sk-user-secret"
		}
		return ""
	}

	t.Run("both present + key set → ok", func(t *testing.T) {
		url, key, err := resolveBYOK("https://api.example", "MY_KEY", getenv)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if url != "https://api.example" || key != "sk-user-secret" {
			t.Fatalf("got (%q,%q)", url, key)
		}
	})

	t.Run("neither → error naming BYOK", func(t *testing.T) {
		_, _, err := resolveBYOK("", "", getenv)
		if err == nil {
			t.Fatal("expected error when neither flag set")
		}
		if !strings.Contains(err.Error(), "BYOK") {
			t.Fatalf("error should name BYOK: %v", err)
		}
	})

	t.Run("only url → error", func(t *testing.T) {
		if _, _, err := resolveBYOK("https://api.example", "", getenv); err == nil {
			t.Fatal("expected error when only --inference-url set")
		}
	})

	t.Run("only key-env → error", func(t *testing.T) {
		if _, _, err := resolveBYOK("", "MY_KEY", getenv); err == nil {
			t.Fatal("expected error when only --inference-key-env set")
		}
	})

	t.Run("key-env names empty/unset var → error", func(t *testing.T) {
		if _, _, err := resolveBYOK("https://api.example", "UNSET_VAR", getenv); err == nil {
			t.Fatal("expected error when the named env var is empty/unset")
		}
	})
}

// TestRunSelfext_ModeSelection locks the mode XOR: exactly one of --run,
// --propose, --scaffold-gha.
func TestRunSelfext_ModeSelection(t *testing.T) {
	t.Run("no mode → error", func(t *testing.T) {
		if err := runSelfext([]string{}); err == nil {
			t.Fatal("expected error when no mode flag is passed")
		}
	})
	t.Run("two modes → error", func(t *testing.T) {
		if err := runSelfext([]string{"--run", "--scaffold-gha"}); err == nil {
			t.Fatal("expected error when two mode flags are passed")
		}
	})
}

// TestRunSelfext_RunRequiresBYOK proves --run without BYOK inference flags fails
// clearly and never silently falls back to a billing rail.
func TestRunSelfext_RunRequiresBYOK(t *testing.T) {
	err := runSelfext([]string{
		"--run",
		"--target-repo", t.TempDir(),
		"--detector-id", "authored-x",
		"--event-type", "github.push",
	})
	if err == nil {
		t.Fatal("expected --run without BYOK flags to error")
	}
	if !strings.Contains(err.Error(), "BYOK") {
		t.Fatalf("error should name BYOK: %v", err)
	}
}

// TestRunSelfextRun_MissingTargetAndGap covers the up-front validation before
// any inference is resolved.
func TestRunSelfextRun_MissingTargetAndGap(t *testing.T) {
	t.Run("missing target repo", func(t *testing.T) {
		t.Setenv("MALLCOP_TARGET_REPO", "")
		err := runSelfextRun(runArgs{detectorID: "d", eventType: "e"})
		if err == nil || !strings.Contains(err.Error(), "target-repo") {
			t.Fatalf("want target-repo error, got %v", err)
		}
	})
	t.Run("missing detector id / event type", func(t *testing.T) {
		err := runSelfextRun(runArgs{targetRepo: t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), "detector-id") {
			t.Fatalf("want detector-id/event-type error, got %v", err)
		}
	})
}

// TestRunSelfextScaffold writes the CODE-lane runtime templates + the operator
// checklist with NO Forge key. It is the offline, no-inference product surface.
func TestRunSelfextScaffold(t *testing.T) {
	t.Run("empty out → error", func(t *testing.T) {
		if err := runSelfextScaffold(""); err == nil {
			t.Fatal("expected error for empty --out")
		}
	})

	t.Run("writes the canonical template set", func(t *testing.T) {
		out := t.TempDir()
		if err := runSelfextScaffold(out); err != nil {
			t.Fatalf("scaffold: %v", err)
		}
		want := []string{
			".github/workflows/mallcop-selfext-code.yml",
			".github/workflows/selfext-code-reusable.yml",
			".github/CODEOWNERS",
			".github/MALLCOP_SELFEXT_SETUP.md",
		}
		for _, rel := range want {
			p := filepath.Join(out, filepath.FromSlash(rel))
			if _, err := os.Stat(p); err != nil {
				t.Errorf("expected scaffolded file %s: %v", rel, err)
			}
		}
	})
}

// TestRunSelfextPropose_Validation covers the propose-mode up-front guards
// before any inference is resolved.
func TestRunSelfextPropose_Validation(t *testing.T) {
	t.Run("missing collect-json", func(t *testing.T) {
		err := runSelfextPropose(proposeArgs{storeRepo: t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), "collect-json") {
			t.Fatalf("want collect-json error, got %v", err)
		}
	})
	t.Run("missing store-repo", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "gaps.json")
		if err := os.WriteFile(f, []byte(`{"schema_version":1,"mapping_gaps":[],"gap_candidates":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		err := runSelfextPropose(proposeArgs{collectJSON: f})
		if err == nil || !strings.Contains(err.Error(), "store-repo") {
			t.Fatalf("want store-repo error, got %v", err)
		}
	})
	t.Run("propose without BYOK flags → error after guards", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "gaps.json")
		if err := os.WriteFile(f, []byte(`{"schema_version":1,"mapping_gaps":[],"gap_candidates":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		err := runSelfextPropose(proposeArgs{collectJSON: f, storeRepo: t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), "BYOK") {
			t.Fatalf("want BYOK error, got %v", err)
		}
	})
}
