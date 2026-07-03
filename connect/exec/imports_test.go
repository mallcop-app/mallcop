package exec

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bannedImportSubstrings mirrors the core import-lint banned families (core/lint,
// core/connect, connect/github). The exec connector lives OUTSIDE
// core/ — os/exec is legitimate and load-bearing here (the process boundary is
// the whole point) — but it must NEVER pull in a vendor LLM SDK, a cloud SDK, or
// an agent-orchestration / coordination framework. The cloud SDK stays in the
// sibling binary's own module; mallcop only forks a process and reads bytes.
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
// banned family — os/exec is deliberately NOT on the list.
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
					t.Errorf("%s imports forbidden package %q (matches %q): the exec connector "+
						"must carry no vendor SDK / orchestration / coordination dependency — the cloud "+
						"SDK belongs in the sibling binary's module, not in mallcop", name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}

// TestOutsideCore proves this package lives OUTSIDE core/ — the reason it may
// legitimately import os/exec (the core/connect purity lint forbids it inside
// core/). If someone relocates this package under core/, this test fails and the
// core purity gate would (correctly) start rejecting the os/exec import.
func TestOutsideCore(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Walk up to the module root (go.mod) and confirm this package's path is
	// connect/exec, not core/....
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
	rel, err := filepath.Rel(dir, wd)
	if err != nil {
		t.Fatalf("rel: %v", err)
	}
	if strings.HasPrefix(filepath.ToSlash(rel)+"/", "core/") {
		t.Fatalf("connect/exec must NOT live under core/ (found at %q): os/exec would trip the core purity lint", rel)
	}
	if filepath.ToSlash(rel) != "connect/exec" {
		t.Logf("note: package at %q (expected connect/exec)", rel)
	}
}
