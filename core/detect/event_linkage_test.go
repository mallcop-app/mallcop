// event_linkage_test.go — the mallcoppro-323 enforcement gate: every detector
// in this package that constructs a finding.Finding{} composite literal must
// set the EventIDs field, so a finding can always be chained back to its
// underlying event(s) (core/inquest's assembleIdentity, the id-lenience event
// lookup, and any future consumer that resolves "what event(s) produced
// this?").
//
// Mirrors vocab_test.go's mechanical go/ast-scan discipline (this package's
// established pattern for "re-derive the invariant from source, don't trust a
// hand-maintained list"): rather than enumerating every detector file and
// hoping the list stays current, this scans EVERY non-test .go file in the
// package for finding.Finding{...} composite literals (both value and
// pointer/&-form — ast.Inspect visits the CompositeLit node regardless of an
// enclosing UnaryExpr) and fails if any of them omits the EventIDs key.
//
// This is a MECHANICAL, syntactic check — it does not verify EventIDs is
// non-empty or correct, only that the constructing code sets it at all. That
// is deliberately the right level of enforcement for this gate: what
// mallcoppro-323 fixed was detectors that never wrote to the field in the
// first place (the value they'd compute — []string{ev.ID}, or an aggregate's
// full contributing set — is detector-specific and not something a generic
// scan can validate), and a hypothetical new detector that forgets the field
// entirely is exactly what this test must catch.
package detect

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// findingLiteralViolation is one finding.Finding{} composite literal that
// omits the EventIDs key.
type findingLiteralViolation struct {
	file string
	line int
}

// scanFindingLiteralsForEventLinkage walks every finding.Finding{...}
// composite literal in the given parsed file and returns one violation per
// literal that has no EventIDs: key among its elements.
func scanFindingLiteralsForEventLinkage(fset *token.FileSet, filename string, f *ast.File) []findingLiteralViolation {
	var violations []findingLiteralViolation
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if !isFindingFindingType(cl.Type) {
			return true
		}
		if !hasEventIDsKey(cl) {
			pos := fset.Position(cl.Pos())
			violations = append(violations, findingLiteralViolation{file: filename, line: pos.Line})
		}
		return true
	})
	return violations
}

// isFindingFindingType reports whether e is the type expression
// `finding.Finding` (a SelectorExpr with package ident "finding" and selector
// "Finding") — the exact qualified type every core/detect file uses, since
// they all import "github.com/mallcop-app/mallcop/pkg/finding" as "finding".
func isFindingFindingType(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkgIdent.Name == "finding" && sel.Sel != nil && sel.Sel.Name == "Finding"
}

// hasEventIDsKey reports whether the composite literal has an `EventIDs:`
// keyed field among its elements.
func hasEventIDsKey(cl *ast.CompositeLit) bool {
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if key.Name == "EventIDs" {
			return true
		}
	}
	return false
}

// TestDetectorFindingsCarryEventLinkage is the mallcoppro-323 merge gate: it
// scans every non-test core/detect/*.go source file and fails if any
// finding.Finding{} literal omits EventIDs. A detector that mints a finding
// from an event MUST record which event(s) it came from — this is what makes
// identity resolution (core/inquest/assemble.go's assembleIdentity), the
// chat/investigate "chain to event_ids" grounding, and the id-lenience event
// lookup possible pipeline-wide, not just for the detectors that happened to
// also write "event_id" into their Evidence blob.
func TestDetectorFindingsCarryEventLinkage(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	var violations []findingLiteralViolation
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		violations = append(violations, scanFindingLiteralsForEventLinkage(fset, name, f)...)
	}
	if scanned == 0 {
		t.Fatal("event-linkage lint scanned 0 source files; package layout changed?")
	}
	for _, v := range violations {
		t.Errorf("%s:%d: finding.Finding{} literal has no EventIDs field — every detector-minted "+
			"finding must carry the event(s) it was derived from (mallcoppro-323); set "+
			"EventIDs: []string{ev.ID} for a single-event detector, or the full contributing "+
			"event-id set for an aggregate detector", v.file, v.line)
	}
	t.Logf("event-linkage lint scanned %d source files, found %d finding.Finding{} literals missing EventIDs", scanned, len(violations))
}

// TestDetectorFindingsCarryEventLinkage_NegativeControl proves the scanner
// actually catches an omission: parsed directly from an in-memory source
// snippet (not a file on disk), so the gate's own correctness does not depend
// on every real detector staying clean forever. Mirrors vocab_test.go /
// deadtokens_test.go's negative-control discipline (a lint gate is only worth
// having if a test proves it FIRES on a planted violation, not just that it
// passes on today's clean tree).
func TestDetectorFindingsCarryEventLinkage_NegativeControl(t *testing.T) {
	const withoutEventIDs = `package detect

import "github.com/mallcop-app/mallcop/pkg/finding"

func forgetful(ev struct{ ID string }) finding.Finding {
	return finding.Finding{
		ID: "finding-" + ev.ID,
	}
}
`
	const withEventIDs = `package detect

import "github.com/mallcop-app/mallcop/pkg/finding"

func remembers(ev struct{ ID string }) finding.Finding {
	return finding.Finding{
		ID:       "finding-" + ev.ID,
		EventIDs: []string{ev.ID},
	}
}
`
	const pointerFormWithEventIDs = `package detect

import "github.com/mallcop-app/mallcop/pkg/finding"

func remembersPointer(ev struct{ ID string }) *finding.Finding {
	return &finding.Finding{
		ID:       "finding-" + ev.ID,
		EventIDs: []string{ev.ID},
	}
}
`

	cases := []struct {
		name     string
		src      string
		wantViol int
	}{
		{name: "missing EventIDs is caught", src: withoutEventIDs, wantViol: 1},
		{name: "present EventIDs (value form) passes clean", src: withEventIDs, wantViol: 0},
		{name: "present EventIDs (pointer form) passes clean", src: pointerFormWithEventIDs, wantViol: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "synthetic.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse synthetic source: %v", err)
			}
			got := scanFindingLiteralsForEventLinkage(fset, "synthetic.go", f)
			if len(got) != tc.wantViol {
				t.Fatalf("violations = %d, want %d (%+v)", len(got), tc.wantViol, got)
			}
		})
	}
}
