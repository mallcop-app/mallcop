package inference

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bannedImportSubstrings are the families core/inference must never depend on.
// This package is DELIBERATELY allowed net/http + encoding/json — it is the
// network seam — but it must carry NO vendor LLM SDK and NO agent-orchestration
// framework. The Anthropic wire shape is hand-rolled; pulling a real SDK in here
// would defeat the whole reason this package exists (and the repo-level core/lint
// gate would also fail). This per-package guard catches the regression at the
// source file that introduces it, with a pointed message.
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

// TestNoForbiddenImports parses every non-test .go file in this package and
// asserts none imports a banned family. net/http and encoding/json are NOT
// banned here — they are exactly what a hand-rolled HTTP client uses.
func TestNoForbiddenImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
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
					t.Errorf("%s imports forbidden package %q (matches %q): core/inference is the "+
						"network seam but must hand-roll the wire shape — no vendor SDK / framework / transport",
						name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}
