package tools

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bannedImportSubstrings are the package families core/tools must never depend
// on. core/tools holds PURE read/lookup tools: each function reads from
// core/store (or an in-memory typed value) and returns data. It performs no
// inference, opens no channel, and never reaches into the campfire / work:create
// / heal-spawn machinery. The agent loop, channels, campfire transport, and
// inference all CONSUME these tools; the tools consume none of them. If this
// test fails, someone pulled side-effecting machinery into a pure tool — fix the
// import, do not relax the test.
var bannedImportSubstrings = []string{
	"channel",
	"campfire",
	"inference",
	"cfexec",
	"internal/cf",
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
		// Skip test files: tests legitimately import os/exec to git-init a temp
		// store. The production constraint is about what the SHIPPED package
		// pulls in.
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
						"core/tools must not depend on channel/campfire/inference/cf machinery",
						name, p, banned)
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
// internal/cf helper) that a substring on the leaf import might miss.
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
