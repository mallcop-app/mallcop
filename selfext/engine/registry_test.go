package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/sandbox"
)

// setupRegistryRepo creates a git repo with a base registry.go and returns a
// Worktree-like handle (Dir + BaseSHA) pointing at it.
func setupRegistryRepo(t *testing.T, baseContent string) *sandbox.Worktree {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-b", "main")
	git("config", "user.email", "t@t")
	git("config", "user.name", "t")
	reg := filepath.Join(dir, "core", "detect", "authored")
	if err := os.MkdirAll(reg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reg, "registry.go"), []byte(baseContent), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	git("commit", "-m", "base")
	return &sandbox.Worktree{Dir: dir, BaseSHA: git("rev-parse", "HEAD")}
}

func regContent(t *testing.T, wt *sandbox.Worktree) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(wt.Dir, authoredRegistryPath))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRegisterAuthoredPackage_AppendsBlankImport: the engine appends exactly one
// blank import into the existing import block, producing valid Go.
func TestRegisterAuthoredPackage_AppendsBlankImport(t *testing.T) {
	wt := setupRegistryRepo(t, "package authored\n\nimport (\n)\n")
	if err := registerAuthoredPackage(context.Background(), wt, "deployburst"); err != nil {
		t.Fatalf("register: %v", err)
	}
	got := regContent(t, wt)
	if !strings.Contains(got, `_ "github.com/mallcop-app/mallcop/core/detect/authored/deployburst"`) {
		t.Errorf("blank import not appended:\n%s", got)
	}
	if !strings.HasPrefix(got, "package authored") {
		t.Errorf("package clause lost:\n%s", got)
	}
}

// TestRegisterAuthoredPackage_DiscardsModelEdit: even if the model overwrote
// registry.go with a bare unparseable fragment (the real failure),
// the engine restores the base and appends cleanly.
func TestRegisterAuthoredPackage_DiscardsModelEdit(t *testing.T) {
	wt := setupRegistryRepo(t, "package authored\n\nimport (\n)\n")
	// Simulate the model's botched overwrite: a bare fragment, no package clause.
	bad := "_ \"github.com/mallcop-app/mallcop/core/detect/authored/deployburst\""
	if err := os.WriteFile(filepath.Join(wt.Dir, authoredRegistryPath), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := registerAuthoredPackage(context.Background(), wt, "deployburst"); err != nil {
		t.Fatalf("register after model edit: %v", err)
	}
	got := regContent(t, wt)
	if !strings.HasPrefix(got, "package authored") {
		t.Errorf("model's malformed edit not discarded:\n%s", got)
	}
	// exactly one occurrence of the import (not duplicated, not the bare fragment)
	if n := strings.Count(got, "authored/deployburst"); n != 1 {
		t.Errorf("expected 1 deployburst import, got %d:\n%s", n, got)
	}
}

// TestRegisterAuthoredPackage_Idempotent: registering an already-present package
// is a no-op (no duplicate import).
func TestRegisterAuthoredPackage_Idempotent(t *testing.T) {
	base := "package authored\n\nimport (\n\t_ \"github.com/mallcop-app/mallcop/core/detect/authored/deployburst\"\n)\n"
	wt := setupRegistryRepo(t, base)
	if err := registerAuthoredPackage(context.Background(), wt, "deployburst"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if n := strings.Count(regContent(t, wt), "authored/deployburst"); n != 1 {
		t.Errorf("idempotency broken, got %d imports", n)
	}
}
