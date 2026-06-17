package agent

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bannedImportSubstrings are the package families the pre-LLM floor must never
// depend on. core/agent holds the hard-constraint gate + the anthropic.Client
// INTERFACE. The model is reachable ONLY through that interface, threaded in by
// the caller — never by the package reaching out to inference, the network, or
// transport machinery on its own.
//
// If a production source in this package imports any of these, the floor path
// could reach inference before (or instead of) checkHardConstraints — exactly
// the bypass this package exists to prevent. The import-lint makes that a build
// failure, not a code-review hope.
//
// Note: "net/http" and "net" themselves are banned — the floor does no I/O. The
// inference DirectClient (a different package, later wave) owns all networking
// and satisfies Client; it is not imported here.
var bannedImportSubstrings = []string{
	"inference",
	"net/http",
	"net/url",
	"channel",
	"campfire",
	"cfexec",
	"internal/cf",
	"anthropic-sdk", // no real SDK in the floor; the interface is hand-rolled
	"bedrock",
	"aws-sdk",
}

// TestNoForbiddenImports parses every non-test .go file in this package and
// asserts none of its import paths contain a banned substring. AST inspection of
// the real import paths is more robust than a textual grep.
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
		// Skip test files: a spy that implements Client is legitimate test code.
		// The production constraint is about what the SHIPPED floor pulls in.
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
					t.Errorf("%s imports forbidden package %q (matches %q): the pre-LLM "+
						"floor must reach the model only via the Client interface, never by "+
						"importing inference/network/transport machinery", name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}

// TestImportLintCoversOwnModuleDeps additionally fails if any production import
// pulls in another package WITHIN this module whose path lands under a banned
// family — catching a transitively-introduced internal dependency (e.g. an
// internal/cf helper, or a future internal/inference package) that a substring
// match on the leaf import might otherwise miss.
func TestImportLintCoversOwnModuleDeps(t *testing.T) {
	const modulePrefix = "github.com/mallcop-app/mallcop/"
	fset := token.NewFileSet()
	entries, _ := os.ReadDir(".")
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if !strings.HasPrefix(p, modulePrefix) {
				continue
			}
			rel := strings.TrimPrefix(p, modulePrefix)
			for _, banned := range bannedImportSubstrings {
				if strings.Contains(rel, banned) {
					t.Errorf("%s imports in-module package %q under banned family %q",
						name, p, banned)
				}
			}
		}
	}
}
