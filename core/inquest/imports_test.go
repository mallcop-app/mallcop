package inquest

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// allowedModuleImports is the CLOSED set of in-module import paths
// core/inquest's production (non-test) source may depend on: the abstract
// inference seam (core/agent.Client — never a concrete transport), the store,
// the pure evidence-read tools (core/tools — reusing GetRawEvent's
// redaction+cap so inquest never builds a second scrub path), and the shared
// wire types. The ONLY way inquest reaches a model is the Client interface
// threaded into RunAll by the caller (core/pipeline) — never a concrete
// config/transport/SDK dependency of its own.
var allowedModuleImports = map[string]bool{
	"github.com/mallcop-app/mallcop/core/agent":     true,
	"github.com/mallcop-app/mallcop/core/store":     true,
	"github.com/mallcop-app/mallcop/core/tools":     true,
	"github.com/mallcop-app/mallcop/pkg/event":      true,
	"github.com/mallcop-app/mallcop/pkg/finding":    true,
	"github.com/mallcop-app/mallcop/pkg/baseline":   true,
	"github.com/mallcop-app/mallcop/pkg/resolution": true,
}

// bannedStdlib are standard-library packages banned even though stdlib is
// otherwise unrestricted: inquest must reach a model ONLY through the
// injected agent.Client, never a concrete transport of its own.
var bannedStdlib = []string{"net/http", "net/rpc", "net/smtp"}

const modulePrefix = "github.com/mallcop-app/mallcop/"

// TestImportAllowlist parses every non-test .go file in this package and
// fails if it imports an in-module package outside allowedModuleImports, or
// any banned stdlib package. AST inspection of the real import paths is more
// robust than a textual grep.
func TestImportAllowlist(t *testing.T) {
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

			for _, banned := range bannedStdlib {
				if p == banned {
					t.Errorf("%s imports forbidden package %q: core/inquest must reach a model "+
						"ONLY through the injected core/agent.Client, never a concrete transport", name, p)
				}
			}

			if !strings.HasPrefix(p, modulePrefix) {
				continue // stdlib (other than bannedStdlib) is unrestricted
			}
			if !allowedModuleImports[p] {
				t.Errorf("%s imports %q — not in core/inquest's closed allowlist (%v); "+
					"inquest is a pure evidence-assembly + single-model-call package, "+
					"it must not grow a dependency on core/pipeline, core/config, or any "+
					"transport/SDK package", name, p, allowedModuleImports)
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}

// TestNoCascadeInvocation enforces — as a machine-checked guard, not merely the
// record.go doc-comment convention it used to be — that no production source in
// this package invokes core/agent's cascade or any committee-vote entry point.
// core/inquest is a pure evidence-assembly + single-narrate-call package; the
// detection-time investigation must NEVER run the resolution cascade, or a
// committee re-vote, from inside inquest — that is exactly the write path to a
// disposition the consensus invariant forbids here (the low-confidence re-vote,
// mallcoppro-09a, lives in core/pipeline + core/agent, never in inquest). This is
// a TEXTUAL scan (the allowlist above already keeps core/agent importable for its
// Client interface, so an import check alone cannot catch a call): a future
// contributor cannot casually add ResolveFindingWith / RunRevoteGate /
// runConsensusGate here without this test explaining — and blocking — the
// boundary.
func TestNoCascadeInvocation(t *testing.T) {
	bannedCalls := []string{
		"ResolveFindingWith(",
		"ResolveFinding(",
		"RunRevoteGate(",
		"runConsensusGate(",
		"RunConsensusGate(",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		checked++
		for _, banned := range bannedCalls {
			if strings.Contains(string(src), banned) {
				t.Errorf("%s calls %q — core/inquest must NEVER run the resolution cascade or a "+
					"committee re-vote (the consensus invariant, mallcoppro-09a): the low-confidence "+
					"deeper-pass + re-vote orchestration belongs in core/pipeline + core/agent, and "+
					"inquest only assembles evidence and makes its ONE narrate call", name, banned)
			}
		}
	}
	if checked == 0 {
		t.Fatal("cascade-invocation scan checked 0 source files; package layout changed?")
	}
}
