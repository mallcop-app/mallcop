package decl

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bannedImportSubstrings mirrors the core import-lint banned families
// (connect/github/imports_test.go). The declarative engine lives OUTSIDE core/
// — net/http is legitimate here — but it must NEVER pull in a vendor LLM SDK, a
// cloud SDK, or an agent-orchestration / coordination framework.
var bannedImportSubstrings = []string{
	"anthropics/",
	"anthropic-sdk",
	"openai/",
	"bedrock",
	"aws-sdk",
	"langchain",
	"autogen",
	"crewai",
	"claude-code",
	"agent-orchestration",
	"campfire",
	"cfexec",
	"internal/cf",
	"3dl-dev/legion",
}

// TestNoForbiddenImports asserts no production file in this package pulls a
// banned family.
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
					t.Errorf("%s imports forbidden package %q (matches %q): the declarative "+
						"connector must carry no vendor SDK / orchestration / coordination dependency", name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}
