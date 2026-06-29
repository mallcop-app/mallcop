package toolrun

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bannedImportSubstrings mirrors the repo-wide core/ ban list (core/lint). The
// production ToolRunner must carry NO agent-orchestration framework, coordination
// transport, or vendor LLM/cloud SDK: it is pure read logic over core/store +
// core/tools + pkg/baseline + core/observe. If this test fails, someone pulled
// side-effecting machinery into the runtime tool layer — fix the import, do not
// relax the test. (Defense-in-depth: core/toolrun is already covered by
// TestNoForbiddenImportsAcrossCore in core/lint.)
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
	"inference",
	"channel",
}

func TestNoForbiddenImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, banned := range bannedImportSubstrings {
				if strings.Contains(p, banned) {
					t.Errorf("%s imports forbidden package %q (matches %q): "+
						"core/toolrun is pure read logic; no framework/transport/SDK", name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}

// TestDoesNotImportEval guards the DI seam from the other direction: the production
// runner must NOT pull the eval HARNESS into the shipped runtime. The shared logic
// lives in core/observe; core/eval is test/harness only.
func TestDoesNotImportEval(t *testing.T) {
	entries, _ := os.ReadDir(".")
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.HasSuffix(p, "/core/eval") {
				t.Errorf("%s imports core/eval — the production runner must not link the harness", name)
			}
		}
	}
}
