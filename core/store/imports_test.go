package store

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bannedImportSubstrings are the package families core/store must never depend
// on. The store is the BOTTOM of the dependency graph: the agent loop, the
// pipeline, channels, campfire transport, inference, and connectors all CONSUME
// the store; the store consumes none of them. If this test fails, someone
// inverted the dependency — fix the import, do not relax the test.
var bannedImportSubstrings = []string{
	"channel",
	"campfire",
	"inference",
	"connect",
}

// TestNoForbiddenImports parses every non-test .go file in this package and
// asserts none of its import paths contain a banned substring. This is the
// import-lint guard: a //go:build check alternative would be brittle, so we
// inspect the real AST.
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
		// Skip test files: tests may legitimately import os/exec etc., and the
		// production constraint is about what the SHIPPED package pulls in.
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
						"core/store must not depend on %s/campfire/inference/connect",
						name, p, banned, banned)
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
// internal/connect helper) that a substring on the leaf import might miss.
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
