package lint

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// authoredRel is the canonical repo-relative root of the authored detector
// tree the allow-list gate governs.
const authoredRel = "detectors"

// moduleRoot locates the repo root (the go.mod directory) by walking up from
// the test's working directory — the same self-locating discipline coreRoot
// in imports_test.go uses, but returning the module root rather than core/.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// TestAuthoredDetectorImportAllowList is the LIVE gate: it runs the allow-list
// checker over the real authored detector tree in this repo and fails on any
// Violation.
//
// DELIBERATE DIVERGENCE from imports_test.go: that gate fatals when it checks
// 0 files, because core/ always has production sources and an empty scan means
// the layout changed under the lint. The authored tree is different — it
// STARTS empty (the self-extension loop populates detectors/ at runtime), so
// "detectors/ absent" and "detectors/ has no .go files" are both healthy
// states and this test logs and PASSES. Do not "fix" this back to a
// checked==0 fatal; an empty authored tree is trivially pure.
func TestAuthoredDetectorImportAllowList(t *testing.T) {
	root := moduleRoot(t)
	modulePath, err := ModulePath(root)
	if err != nil {
		t.Fatalf("module path: %v", err)
	}

	authored := filepath.Join(root, authoredRel)
	if _, err := os.Stat(authored); errors.Is(err, fs.ErrNotExist) {
		t.Logf("%s/ absent — authored tree starts empty; allow-list gate trivially green", authoredRel)
		return
	} else if err != nil {
		t.Fatalf("stat %s: %v", authored, err)
	}

	checked := 0
	err = filepath.WalkDir(authored, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && isProductionGoFile(d.Name()) {
			checked++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", authored, err)
	}
	if checked == 0 {
		t.Logf("%s/ has no production .go files yet — allow-list gate trivially green", authoredRel)
		return
	}

	violations, err := CheckAuthoredDetectorTree(root, modulePath, authoredRel)
	if err != nil {
		t.Fatalf("CheckAuthoredDetectorTree: %v", err)
	}
	for _, v := range violations {
		t.Errorf("%s imports %q — %s (via %v): authored detectors may import only the exact "+
			"stdlib allow list, the framework surface, and authored helpers",
			v.File, v.Import, v.Reason, v.Via)
	}
	t.Logf("allow-list gate scanned %d authored production files under %s/", checked, authoredRel)
}

// testModule mirrors the real module identity so synthetic trees exercise the
// exact framework-surface and authored-prefix strings production will see.
const testModule = "github.com/mallcop-app/mallcop"

// writeTree materializes a synthetic module tree in a t.TempDir. Keys are
// repo-relative slash paths.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

const testGoMod = "module " + testModule + "\n\ngo 1.25.0\n"

// TestAllowListNegativeControl is the proof-of-life for the gate, one subtest
// per banned import family: a planted detector importing the banned path (plus
// legitimate framework imports) MUST be flagged, and a clean twin importing
// only allowed paths MUST pass — proving the gate both fires and does not just
// reject everything. It runs against the REAL checker over a real on-disk
// module tree; nothing is stubbed.
func TestAllowListNegativeControl(t *testing.T) {
	bannedFamilies := []string{
		"os",
		"os/exec",
		"net",
		"net/http",
		"syscall",
		"io",
		"bufio",
		"reflect",
		"unsafe",
		"plugin",
		"runtime/cgo",
		"C",
	}

	for _, banned := range bannedFamilies {
		banned := banned
		t.Run(strings.NewReplacer("/", "_").Replace(banned), func(t *testing.T) {
			// FAIL case: planted detector smuggles the banned import alongside
			// legitimate framework imports.
			plantedRoot := writeTree(t, map[string]string{
				"go.mod": testGoMod,
				"detectors/planted/planted.go": "package planted\n\nimport (\n" +
					"\t_ \"" + banned + "\"\n" +
					"\t_ \"" + testModule + "/pkg/event\"\n" +
					")\n",
			})
			modulePath, err := ModulePath(plantedRoot)
			if err != nil {
				t.Fatalf("module path from synthetic go.mod: %v", err)
			}
			if modulePath != testModule {
				t.Fatalf("ModulePath = %q, want %q", modulePath, testModule)
			}
			violations, err := CheckAuthoredDetectorTree(plantedRoot, modulePath, authoredRel)
			if err != nil {
				t.Fatalf("check planted tree: %v", err)
			}
			found := false
			for _, v := range violations {
				if v.Import == banned {
					found = true
				}
			}
			if !found {
				t.Fatalf("negative control DID NOT fire: banned import %q slipped past the "+
					"allow-list gate (violations: %v)", banned, violations)
			}

			// PASS case: the clean twin imports only allowed paths. The
			// framework packages do not exist in the temp tree — passing here
			// also proves framework matches are TERMINAL (no resolution).
			cleanRoot := writeTree(t, map[string]string{
				"go.mod": testGoMod,
				"detectors/planted/planted.go": "package planted\n\nimport (\n" +
					"\t_ \"strings\"\n" +
					"\t_ \"" + testModule + "/pkg/event\"\n" +
					"\t_ \"" + testModule + "/core/detect\"\n" +
					")\n",
			})
			violations, err = CheckAuthoredDetectorTree(cleanRoot, modulePath, authoredRel)
			if err != nil {
				t.Fatalf("check clean tree: %v", err)
			}
			if len(violations) != 0 {
				t.Fatalf("false positive: clean detector flagged: %v", violations)
			}
		})
	}
}

// TestAllowListTransitiveSmuggle proves a banned import cannot be laundered
// through an authored helper package: detectors/evil imports
// MODULE/detectors/helper, and helper imports os/exec. The gate must flag it
// with a Via chain naming the smuggling path through helper.
func TestAllowListTransitiveSmuggle(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": testGoMod,
		"detectors/evil/evil.go": "package evil\n\nimport (\n" +
			"\t_ \"" + testModule + "/detectors/helper\"\n" +
			"\t_ \"" + testModule + "/pkg/finding\"\n" +
			")\n",
		"detectors/helper/helper.go": "package helper\n\nimport _ \"os/exec\"\n",
	})
	modulePath, err := ModulePath(root)
	if err != nil {
		t.Fatalf("module path: %v", err)
	}
	violations, err := CheckAuthoredDetectorTree(root, modulePath, authoredRel)
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	var transitive *Violation
	for i := range violations {
		v := &violations[i]
		if v.Import == "os/exec" && len(v.Via) > 0 {
			transitive = v
			break
		}
	}
	if transitive == nil {
		t.Fatalf("no transitive violation for os/exec with a Via chain; got: %v", violations)
	}
	via := strings.Join(transitive.Via, " -> ")
	if !strings.Contains(via, "detectors/helper") {
		t.Fatalf("Via chain does not name the smuggling helper: %q", via)
	}
	if !strings.Contains(via, "detectors/evil/evil.go") {
		t.Fatalf("Via chain does not name the root file that imported the helper: %q", via)
	}
	if transitive.File != "detectors/helper/helper.go" {
		t.Fatalf("violation File = %q, want the file containing the contraband import "+
			"(detectors/helper/helper.go)", transitive.File)
	}
}

// TestAllowListRejectsNonFrameworkInModule proves the framework surface is
// EXACT: an in-module import outside the four framework packages and the
// authored tree (here MODULE/core/agent) is a Violation even though it lives
// in the same module.
func TestAllowListRejectsNonFrameworkInModule(t *testing.T) {
	target := testModule + "/core/agent"
	root := writeTree(t, map[string]string{
		"go.mod": testGoMod,
		"detectors/planted/planted.go": "package planted\n\nimport (\n" +
			"\t_ \"" + target + "\"\n" +
			"\t_ \"" + testModule + "/pkg/event\"\n" +
			")\n",
	})
	modulePath, err := ModulePath(root)
	if err != nil {
		t.Fatalf("module path: %v", err)
	}
	violations, err := CheckAuthoredDetectorTree(root, modulePath, authoredRel)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	found := false
	for _, v := range violations {
		if v.Import == target {
			found = true
			if !strings.Contains(v.Reason, "framework surface") {
				t.Errorf("violation reason should explain the framework-surface rule, got %q", v.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("in-module non-framework import %q was not flagged; violations: %v", target, violations)
	}
}
