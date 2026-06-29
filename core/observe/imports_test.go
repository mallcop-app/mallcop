package observe

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bannedImportSubstrings mirrors the core/tools ban list. core/observe holds PURE
// observable predicates: each function reads only its (actor, *baseline.Baseline,
// []tools.EventView) inputs and returns booleans + audit strings. It performs no
// inference, opens no channel, and never reaches into the campfire / cf transport.
// tools + baseline are NOT banned (the predicates legitimately read EventView and
// Relationship/Baseline), so the repo-wide import-lint (core/lint) stays green.
// If this test fails, someone pulled side-effecting machinery into a pure
// predicate package — fix the import, do not relax the test.
var bannedImportSubstrings = []string{
	"channel",
	"campfire",
	"inference",
	"cfexec",
	"internal/cf",
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
						"core/observe must depend only on core/tools + pkg/baseline",
						name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}

// TestObserveImportsAreAllowlistedOnly is the positive guard: the ONLY in-module
// imports core/observe is allowed to carry are core/tools and pkg/baseline. Any
// other mallcop-app import (core/agent, core/eval, core/store, core/pipeline,
// exam, …) would reintroduce a dependency cycle or pull orchestration into the
// pure predicate layer — fail loudly.
func TestObserveImportsAreAllowlistedOnly(t *testing.T) {
	const modulePrefix = "github.com/mallcop-app/mallcop/"
	allowed := map[string]struct{}{
		"core/tools":   {},
		"pkg/baseline": {},
	}
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
			if !strings.HasPrefix(p, modulePrefix) {
				continue
			}
			rel := strings.TrimPrefix(p, modulePrefix)
			if _, ok := allowed[rel]; !ok {
				t.Errorf("%s imports in-module package %q which is NOT on the core/observe allowlist (core/tools, pkg/baseline)", name, p)
			}
		}
	}
}
