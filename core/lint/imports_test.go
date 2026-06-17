package lint

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bannedImportSubstrings are the import-path families NO production file under
// core/ may depend on. The product runtime must carry no agent-orchestration
// framework: the model is reachable only through core/agent's hand-rolled
// anthropic.Client interface, threaded in by the caller. If this test fails,
// someone pulled a framework / transport / vendor-SDK dependency into the
// shipped runtime — remove the import, do not relax the test.
//
// The families, and why each is forbidden in core/:
//
//   - "campfire" / "internal/cf" / "cfexec" — the coordination transport. core/
//     is pure product logic; it does not talk to a campfire.
//   - "3dl-dev/legion" — the legion (ClankerOS) automaton engine. The product
//     runtime is not an automaton and must not link the orchestrator.
//   - "claude-code" / "agent-orchestration" / "langchain" / "autogen" /
//     "crewai" — agent-orchestration frameworks. core/ owns its own minimal
//     loop; no framework.
//   - "anthropics/" / "anthropic-sdk" / "openai/" / "bedrock" / "aws-sdk" —
//     vendor LLM/cloud SDKs. Inference is reached only via the Client interface;
//     a real SDK is a different (non-core) package the caller wires in.
var bannedImportSubstrings = []string{
	"campfire",
	"internal/cf",
	"cfexec",
	"3dl-dev/legion",
	"claude-code",
	"agent-orchestration",
	"langchain",
	"autogen",
	"crewai",
	"anthropics/",
	"anthropic-sdk",
	"openai/",
	"bedrock",
	"aws-sdk",
}

// coreRoot locates the repo's core/ directory by walking up from this test's
// working directory to the go.mod marker — the same self-locating discipline
// §3.5 of the architecture brief prescribes for config. It does not trust CWD
// to already be the package dir (it is, under `go test`, but the walk is robust
// to where the test binary runs).
func coreRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			root := filepath.Join(dir, "core")
			if _, err := os.Stat(root); err != nil {
				t.Fatalf("found go.mod at %s but no core/ dir under it", dir)
			}
			return root
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// TestNoForbiddenImportsAcrossCore walks EVERY production .go file under core/
// (recursively, all packages) and fails if any imports a banned family. This is
// the repo-level CI gate the per-package imports_test.go files cannot provide on
// their own — it covers core/lint's own future siblings, any new core/<pkg>, and
// catches a framework dependency introduced anywhere in the subtree.
func TestNoForbiddenImportsAcrossCore(t *testing.T) {
	root := coreRoot(t)
	fset := token.NewFileSet()
	checked := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		// Skip test files: tests may legitimately import frameworks/SDKs to drive
		// a spy or fixture. The production constraint is what the SHIPPED runtime
		// links.
		if strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		checked++
		rel, _ := filepath.Rel(root, path)
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, banned := range bannedImportSubstrings {
				if strings.Contains(p, banned) {
					t.Errorf("core/%s imports forbidden package %q (matches %q): the product "+
						"runtime must depend on NO agent framework/transport/vendor SDK — the model "+
						"is reached only via the anthropic.Client interface", rel, p, banned)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk core/: %v", err)
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 production source files under core/; layout changed?")
	}
	t.Logf("import-lint scanned %d production files under core/", checked)
}

// TestNegativeControl_PlantedBannedImportFails is the proof-of-life for the
// guard: it plants a synthetic source file that imports each banned family and
// asserts the SAME parse+match logic the live scan uses flags it. Run as a
// subtest per banned family so a regression in any single substring is visible.
//
// This is the "make a banned import fail, then pass" demonstration: the planted
// file is detected (fail-if-shipped), and the corresponding clean file is not
// (pass). We do it against the real parser/matcher rather than against the live
// tree so the negative control cannot itself pollute the build graph.
func TestNegativeControl_PlantedBannedImportFails(t *testing.T) {
	bannedExamples := map[string]string{
		"campfire":            "github.com/3dl-dev/campfire/internal/cf",
		"internal/cf":         "github.com/mallcop-app/mallcop/internal/cf",
		"cfexec":              "github.com/mallcop-app/mallcop/internal/cfexec",
		"3dl-dev/legion":      "github.com/3dl-dev/legion/internal/inference",
		"claude-code":         "github.com/anthropics/claude-code/sdk",
		"agent-orchestration": "example.com/agent-orchestration/runtime",
		"langchain":           "github.com/tmc/langchaingo/llms",
		"autogen":             "github.com/microsoft/autogen/go",
		"crewai":              "example.com/crewai/core",
		"anthropics/":         "github.com/anthropics/anthropic-sdk-go",
		"anthropic-sdk":       "github.com/foo/anthropic-sdk-go-fork",
		"openai/":             "github.com/sashabaranov/go-openai/openai/internal",
		"bedrock":             "github.com/aws/aws-sdk-go-v2/service/bedrockruntime",
		"aws-sdk":             "github.com/aws/aws-sdk-go-v2/config",
	}

	fset := token.NewFileSet()

	for family, importPath := range bannedExamples {
		family, importPath := family, importPath
		t.Run(family, func(t *testing.T) {
			// Plant a banned import and assert the matcher catches it (FAIL case).
			banned := plantedSource(importPath)
			if hits := matchSource(t, fset, "planted_banned_"+sanitizeName(family)+".go", banned); len(hits) == 0 {
				t.Fatalf("negative control DID NOT fire: banned import %q (family %q) slipped past the lint — "+
					"the guard is not protecting against this family", importPath, family)
			}

			// Plant a clean stdlib import and assert the matcher passes (PASS case),
			// proving the lint does not just reject everything.
			clean := plantedSource("strings")
			if hits := matchSource(t, fset, "planted_clean_"+sanitizeName(family)+".go", clean); len(hits) != 0 {
				t.Fatalf("false positive: clean import flagged as banned: %v", hits)
			}
		})
	}
}

// plantedSource returns the bytes of a minimal Go file importing importPath.
func plantedSource(importPath string) []byte {
	return []byte("package planted\n\nimport _ \"" + importPath + "\"\n")
}

// matchSource parses synthetic source bytes and returns the banned-substring
// hits — the exact logic TestNoForbiddenImportsAcrossCore applies to real files,
// run here against in-memory bytes so the negative control never touches the
// build graph.
func matchSource(t *testing.T, fset *token.FileSet, name string, src []byte) []string {
	t.Helper()
	f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse synthetic %s: %v", name, err)
	}
	var hits []string
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		for _, banned := range bannedImportSubstrings {
			if strings.Contains(p, banned) {
				hits = append(hits, p+" ~ "+banned)
			}
		}
	}
	return hits
}

// sanitizeName makes a family string safe for use in a synthetic filename.
func sanitizeName(s string) string {
	return strings.NewReplacer("/", "_", "-", "_").Replace(s)
}
