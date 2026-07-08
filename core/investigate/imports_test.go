package investigate

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bannedImportSubstrings are the package families core/investigate must never
// depend on directly. This package is the tool-calling LOOP: it consumes an
// injected agent.Client (the interface, never a concrete transport), the
// git-backed store, and the pure core/tools functions. It must not import the
// concrete inference transport (core/inference), raw networking, or any
// channel/campfire coordination machinery — those are the CLI's job to wire
// in (cli/investigate.go builds the concrete inference.DirectClient and
// passes it in as an agent.Client). Keeping this boundary means a test can
// swap in any agent.Client double without core/investigate itself ever
// reaching the network.
var bannedImportSubstrings = []string{
	"channel",
	"campfire",
	"cfexec",
	"internal/cf",
	"core/inference",
	"net/http",
	"net/url",
	"bedrock",
	"aws-sdk",
	"anthropic-sdk",
}

// TestNoForbiddenImports parses every non-test .go file in this package and
// asserts none of its import paths contain a banned substring.
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
		// Skip test files: they legitimately spin up an httptest server and
		// git-init a temp store. The production constraint is about what the
		// SHIPPED package pulls in.
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
					t.Errorf("%s imports forbidden package %q (matches %q): "+
						"core/investigate must not depend on transport/channel/campfire machinery directly",
						name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}
