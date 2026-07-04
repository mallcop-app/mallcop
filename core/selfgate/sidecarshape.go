// sidecarshape.go — the CUSTOMER-TREE SIDECAR-SHAPE AST gate (mallcoppro-97b,
// orchestrator ruling on the mallcoppro-72d/mallcoppro-97b design collision).
//
// authoredast.go's K7 L3 gate polices the IN-TREE additive detector lane
// (core/detect/authored/<name>/: package <name>, init()+detect.Register(T{})).
// This file polices the SIBLING, CUSTOMER-TREE lane a THIN-EMBED proposal
// tree uses: detectors/<name>/, package main, a wasip1 sidecar built and
// loaded through pkg/detectorhost + detecthost (see customerexam.go). The two
// shapes are structurally incompatible (own-package init()+Register vs.
// package main + func main()), so this is deliberately a SEPARATE gate, not a
// generalization of authoredast.go's — see guard.go's RuleCodeFrozen doc for
// why the K7 shape gate cannot simply be reused here.
//
// CUSTOMER-TREE MODE ONLY: this gate runs from Guard() ONLY when the
// TRUSTED CALLER selected customer-tree mode (Options.ExamRepo set,
// mallcop-pro's engine passing --exam-repo alongside --customer-tree — see
// validate.go's Options doc and guard.go's customerTreeMode parameter). It is
// NEVER inferred from the target tree's own contents: an untrusted proposal
// tree cannot opt itself into the looser sidecar rules by merely looking
// customer-shaped. In DEFAULT mode a .go Add/Modify/Delete under detectors/ is
// STILL the RuleCodeFrozen blanket deny, unchanged from mallcoppro-72d.
//
// THREAT MODEL this gate closes, mirroring (not weakening) the K7 shape
// gate's spirit:
//
//   - Import surface: restricted to the exact-match pure-computation stdlib
//     set core/lint's authored-detector allow-list already trusts (see
//     sidecarAllowedStdlib — evidence: this is the SAME set, for the SAME
//     "pure computation only" reason), plus the four framework packages a
//     real sidecar needs (pkg/event, pkg/finding, pkg/baseline,
//     pkg/detectorhost — evidence: examples/sidecar-detector's main.go and
//     customergate_test.go's fixture detector import exactly these), plus
//     "os" — CONDITIONALLY: see the os-confinement note below. net, net/*,
//     os/exec, syscall, unsafe, plugin, cgo, and any filesystem/DB/HTTP
//     capable package are hard-excluded by simply never appearing on the
//     allow list (fail-closed exact match, same posture as core/lint).
//   - os IS NOT a blanket allow. A wasip1 sidecar main legitimately needs
//     `os.Exit(detectorhost.Run(d))` (detectorhost.Run returns the process
//     exit code; the sidecar main only place a Detector is normally handed to
//     the host — see pkg/detectorhost's doc). But "os" unconditionally
//     allowed would hand every top-level func in the package os.ReadFile /
//     os.Remove / os.Environ / os.Getenv etc. — a real capability leak MERELY
//     because the file needs os.Exit. checkSidecarMainAndOS closes this: it
//     walks EVERY file in the package and requires every os.* selector
//     reference, across the WHOLE package, to be the exact one os.Exit(...)
//     call wrapping main()'s single detectorhost.Run(...) statement. An
//     extra os call anywhere else — a helper func, the Detect method, a
//     second file — is a violation even though "os" is import-legal.
//     Symmetrically, pkg/detectorhost's own surface (Run, RunIO, Input) is
//     confined to the single Run call in main — RunIO takes explicit
//     io.Reader/Writer args a customer could otherwise redirect away from
//     the real stdio wire protocol; forbidding every OTHER detectorhost.*
//     reference closes that off structurally, the same "confine the
//     framework touch to the one sanctioned call" pattern
//     checkDetectReferences uses for core/detect in the in-tree lane.
//   - Shape: exactly one func main() (no receiver) anywhere in the package
//     directory, whose body is exactly one statement — detectorhost.Run(x),
//     optionally wrapped in os.Exit(...) — and whose argument x is a LOCAL
//     detector literal (T{} / &T{}, a bare, non-import-qualified identifier)
//     or a LOCAL zero-argument constructor call (a bare identifier resolving
//     to a func declared in the same package, called with no arguments).
//     This is deliberately NOT "the detector impl may only have one func" —
//     the detector implementation's Name()/Detect() methods and any private
//     helper funcs are expected and unrestricted in COUNT (see the doc note
//     on RuleSidecarMainShape below for why a func-count floor would be
//     over-strict and is not part of this gate).
//   - No init(): banned outright (any file, any package). init() runs before
//     main()'s single verified statement and is invisible to the main-shape
//     check — the same "runs before/outside the one thing we verified"
//     hazard the confinement rules above close for os/detectorhost, but for
//     an entire function body instead of a symbol reference. A package-level
//     var/const initializer that evaluates a function call or literal (the
//     same impureInitializer authoredast.go's checkPackageInitializers uses)
//     is the same hazard through a different syntax and is banned too.
//   - No build constraints, no compiler directives, no cgo, no
//     provably-unbounded loop (`for {}` with no break/return/goto/panic, or
//     empty `select{}`) — the same defence-in-depth authoredast.go applies to
//     the in-tree lane, reused here via the shared bodyHasExit helper.
//
// The exported entry point is CheckSidecarDetectorShape(paths, sources) — one
// detectors/<name>/ directory's file paths + HEAD-blob contents in, a
// Violation slice out. It never touches disk or git itself (guard.go's
// checkSidecarDetectorDir owns the git blob reads); this keeps the shape
// rules a pure, directly-unit-testable AST function.
package selfgate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// RuleSidecarShape is the single dedicated GuardFinding.Rule id for EVERY
// sidecar-shape violation surfaced through Guard (guard.go's
// checkSidecarDetectorDir) — the finer sub-rule below is folded into
// GuardFinding.Detail as "<sub-rule>: <detail>", mirroring exactly how
// validate.go folds authoredast.go's Violation.Rule into RuleAuthoredShape
// findings.
const RuleSidecarShape = "sidecar-shape"

// Sub-rule identifiers folded into GuardFinding.Detail (as "<rule>: <detail>")
// under the single dedicated top-level GuardFinding.Rule = RuleSidecarShape.
const (
	// RuleSidecarParse — a sidecar package file could not be parsed. Fail
	// closed: an unparseable file is a violation, never a silent pass.
	RuleSidecarParse = "sidecar-parse-error"
	// RuleSidecarPackageClause — a file whose package clause is not `main`.
	RuleSidecarPackageClause = "sidecar-package-clause"
	// RuleSidecarImport — an import outside the allow list.
	RuleSidecarImport = "sidecar-import-not-allowed"
	// RuleSidecarInit — an init() function, or an impure package-level
	// var/const initializer (the same hazard, different syntax).
	RuleSidecarInit = "sidecar-init-forbidden"
	// RuleSidecarMainShape — the func-main-count, main-body, Run-argument, or
	// os/detectorhost confinement rules. See the file doc for why this is
	// deliberately NOT a func-count restriction on the whole package.
	RuleSidecarMainShape = "sidecar-main-shape"
	// RuleSidecarUnboundedLoop — a provably non-terminating construct.
	RuleSidecarUnboundedLoop = "sidecar-unbounded-loop"
	// RuleSidecarBuildConstraint — a `//go:build` / `// +build` line.
	RuleSidecarBuildConstraint = "sidecar-build-constraint"
	// RuleSidecarCompilerDirective — a `//go:` compiler pragma.
	RuleSidecarCompilerDirective = "sidecar-compiler-directive"
	// RuleSidecarCgo — an `import "C"`.
	RuleSidecarCgo = "sidecar-cgo-import"
)

// sidecarDetectorhostImportPath is the ONE import path the sidecar-shape gate
// recognizes as "the detectorhost framework surface" — the fixed mallcop
// module's own pkg/detectorhost, never the customer tree's OWN module (a
// customer-tree go.mod names a DIFFERENT module and requires mallcop as a
// dependency — see customergate_test.go's buildCustomerShapedRepo — so unlike
// authoredast.go's frameworkSurface(modulePath), this is NOT parametrized by
// the proposal repo's own module path).
const sidecarDetectorhostImportPath = "github.com/mallcop-app/mallcop/pkg/detectorhost"

// sidecarAllowedStdlib is the EXACT-match pure-computation stdlib set a
// customer-tree sidecar detector may import. Evidence: this is the IDENTICAL
// set core/lint.allowedStdlib already trusts for the in-tree authored lane
// (mirroring the pure-detector philosophy per the orchestrator ruling) — a
// sidecar detector's Detect method does exactly the same class of work
// (string/regex matching, time comparisons, JSON (un)marshalling) as an
// in-tree authored one. "os" is NOT here: see checkSidecarMainAndOS — it is
// conditionally allowed and separately confined to the single os.Exit(...)
// wrapper, never a blanket stdlib grant.
var sidecarAllowedStdlib = map[string]bool{
	"fmt":             true,
	"sort":            true,
	"strings":         true,
	"strconv":         true,
	"time":            true,
	"math":            true,
	"unicode":         true,
	"unicode/utf8":    true,
	"regexp":          true,
	"encoding/json":   true,
	"encoding/base64": true,
}

// sidecarFrameworkSurface is the EXACT-match set of in-module (mallcop
// module) packages a sidecar detector needs to implement core/detect.Detector
// and hand itself to the host. Evidence: examples/sidecar-detector's
// exampledetector.go imports pkg/event + pkg/finding + pkg/baseline (its
// main.go separately imports pkg/detectorhost); customergate_test.go's
// customerFixtureDetectorMainSrc — the ground-truth fixture for what a real
// customer detector's main.go looks like — imports exactly these four
// (os, pkg/baseline, pkg/detectorhost, pkg/event, pkg/finding) and NOTHING
// else. Notably core/detect is NOT here: a sidecar detector implements the
// detect.Detector interface STRUCTURALLY (Name() string + Detect(...)
// matching methods) and never needs to name the interface type itself —
// detectorhost.Run's parameter type is core/detect.Detector, but the CALLER
// (the customer's main.go) does not need to import the package defining an
// interface to satisfy it. Confirmed empirically: none of the fixtures import
// core/detect.
var sidecarFrameworkSurface = map[string]bool{
	"github.com/mallcop-app/mallcop/pkg/event":    true,
	"github.com/mallcop-app/mallcop/pkg/finding":  true,
	"github.com/mallcop-app/mallcop/pkg/baseline": true,
	sidecarDetectorhostImportPath:                 true,
}

// CheckSidecarDetectorShape parses every file in paths (production .go files
// of ONE detectors/<name>/ directory, in the same order as sources) and
// returns a Violation for each shape defect. It never returns an error —
// an unparseable file is a RuleSidecarParse Violation (fail closed), exactly
// like authoredast.go's CheckAuthoredDetectorShape.
func CheckSidecarDetectorShape(paths []string, sources [][]byte) []Violation {
	fset := token.NewFileSet()
	var violations []Violation
	var files []*ast.File
	var okPaths []string

	for i, p := range paths {
		f, err := parser.ParseFile(fset, p, sources[i], parser.ParseComments)
		if err != nil {
			violations = append(violations, Violation{
				File:   p,
				Rule:   RuleSidecarParse,
				Detail: fmt.Sprintf("sidecar detector file is unparseable: %v", err),
			})
			continue
		}
		if f.Name.Name != "main" {
			violations = append(violations, Violation{
				File:   p,
				Rule:   RuleSidecarPackageClause,
				Detail: fmt.Sprintf("package clause is %q, want \"main\" — a customer-tree sidecar detector is a real Go program built to a wasip1 .wasm module", f.Name.Name),
			})
		}
		violations = append(violations, checkSidecarFileDirectives(p, f)...)
		violations = append(violations, checkSidecarImportsC(p, f)...)
		violations = append(violations, checkSidecarDotImports(p, f)...)
		violations = append(violations, checkSidecarInitFuncs(p, f)...)
		violations = append(violations, checkSidecarPackageInitializers(p, f)...)
		violations = append(violations, checkSidecarUnboundedLoops(p, f)...)
		files = append(files, f)
		okPaths = append(okPaths, p)
	}

	if len(files) == 0 {
		return violations
	}

	violations = append(violations, checkSidecarImportAllowlist(okPaths, files)...)
	violations = append(violations, checkSidecarMainAndOS(okPaths, files)...)

	return violations
}

// checkSidecarImportAllowlist flags any import outside sidecarAllowedStdlib /
// sidecarFrameworkSurface. "os" is deliberately NOT flagged here even though
// it is not on either map — it is conditionally legal, and
// checkSidecarMainAndOS enforces the (much narrower) condition.
func checkSidecarImportAllowlist(paths []string, files []*ast.File) []Violation {
	var violations []Violation
	for i, f := range files {
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "os" || sidecarAllowedStdlib[p] || sidecarFrameworkSurface[p] {
				continue
			}
			violations = append(violations, Violation{
				File:   paths[i],
				Rule:   RuleSidecarImport,
				Detail: fmt.Sprintf("illegal import %q — a customer-tree sidecar detector may import only the pure-computation stdlib set, the detector-framework packages (pkg/event, pkg/finding, pkg/baseline, pkg/detectorhost), and os (confined to a single os.Exit(...) wrapping main's detectorhost.Run call); net, net/*, os/exec, syscall, unsafe, plugin, cgo, and any filesystem/database/HTTP-capable package are hard-excluded", p),
			})
		}
	}
	return violations
}

// checkSidecarFileDirectives rejects build constraints and compiler
// directives — a sidecar detector is unconditionally compiled to wasip1/wasm.
func checkSidecarFileDirectives(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, group := range f.Comments {
		for _, c := range group.List {
			t := c.Text
			switch {
			case strings.HasPrefix(t, "//go:build"):
				violations = append(violations, Violation{
					File: path, Rule: RuleSidecarBuildConstraint,
					Detail: fmt.Sprintf("build constraint %q — a sidecar detector is unconditionally compiled (GOOS=wasip1 GOARCH=wasm), never build-variant", t),
				})
			case strings.HasPrefix(t, "//go:"):
				violations = append(violations, Violation{
					File: path, Rule: RuleSidecarCompilerDirective,
					Detail: fmt.Sprintf("compiler directive %q — sidecar detectors may carry no //go: pragmas", t),
				})
			default:
				trimmed := strings.TrimSpace(strings.TrimPrefix(t, "//"))
				if strings.HasPrefix(trimmed, "+build") {
					violations = append(violations, Violation{
						File: path, Rule: RuleSidecarBuildConstraint,
						Detail: fmt.Sprintf("build constraint %q — a sidecar detector is unconditionally compiled, never build-variant", t),
					})
				}
			}
		}
	}
	return violations
}

// checkSidecarImportsC rejects cgo. wasip1/wasm has no cgo support anyway;
// this stands alone so the shape gate never depends on the import allow-list
// alone to catch it.
func checkSidecarImportsC(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "C" {
			violations = append(violations, Violation{
				File: path, Rule: RuleSidecarCgo,
				Detail: `import "C" (cgo) is forbidden in a sidecar detector`,
			})
		}
	}
	return violations
}

// checkSidecarDotImports rejects dot imports of ANY package. A dot import of
// an allowlisted package (import . "os") passes the path allowlist but renders
// its symbols as bare identifiers — os.ReadFile becomes ReadFile — which the
// SelectorExpr-based os/detectorhost confinement never inspects. There is no
// legitimate reason for a sidecar to dot-import anything, so the ban is total
// rather than per-package.
func checkSidecarDotImports(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, imp := range f.Imports {
		if imp.Name != nil && imp.Name.Name == "." {
			violations = append(violations, Violation{
				File: path, Rule: RuleSidecarImport,
				Detail: "dot import of " + imp.Path.Value + " is forbidden in a sidecar detector: it hides the package's symbols from the confinement checks (os.Exit-only, detectorhost.Run-only)",
			})
		}
	}
	return violations
}

// checkSidecarInitFuncs rejects any init() anywhere in the package: it runs
// before main()'s single verified statement, invisible to checkSidecarMainAndOS.
func checkSidecarInitFuncs(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "init" {
			continue
		}
		violations = append(violations, Violation{
			File: path, Rule: RuleSidecarInit,
			Detail: "init() is forbidden in a customer-tree sidecar detector: it runs before main()'s single verified detectorhost.Run(...) statement and could perform side effects the shape gate can never see",
		})
	}
	return violations
}

// checkSidecarPackageInitializers bans an impure package-level var/const
// initializer — the same init()-before-main hazard through different syntax.
// Reuses authoredast.go's impureInitializer/declKeyword helpers (pure,
// generic AST utilities — not authored-lane-specific in behavior).
func checkSidecarPackageInitializers(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, v := range vs.Values {
				if kind, found := impureInitializer(v); found {
					violations = append(violations, Violation{
						File: path, Rule: RuleSidecarInit,
						Detail: fmt.Sprintf("package-level %s initializer runs code at package-initialization time (contains a %s) — the same side-effect-before-main hazard init() is banned for; use literal/composite-literal initializers and compute inside Detect", declKeyword(gd.Tok), kind),
					})
				}
			}
		}
	}
	return violations
}

// checkSidecarUnboundedLoops rejects a provably non-terminating construct.
// Reuses authoredast.go's bodyHasExit (a pure, generic AST utility).
func checkSidecarUnboundedLoops(path string, f *ast.File) []Violation {
	var violations []Violation
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ForStmt:
			if s.Cond == nil && !bodyHasExit(s.Body) {
				violations = append(violations, Violation{
					File: path, Rule: RuleSidecarUnboundedLoop,
					Detail: "condition-less for-loop with no break/return/goto/panic — a sidecar Detect may not spin forever",
				})
			}
		case *ast.SelectStmt:
			if s.Body == nil || len(s.Body.List) == 0 {
				violations = append(violations, Violation{
					File: path, Rule: RuleSidecarUnboundedLoop,
					Detail: "empty select{} blocks forever — a sidecar Detect may not block",
				})
			}
		}
		return true
	})
	return violations
}

// sidecarImportAliases returns the set of local identifier names bound to an
// import of importPath anywhere across files (aliased or not).
func sidecarImportAliases(files []*ast.File, importPath string) map[string]bool {
	aliases := map[string]bool{}
	for _, f := range files {
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) != importPath {
				continue
			}
			alias := importPath[strings.LastIndex(importPath, "/")+1:]
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			aliases[alias] = true
		}
	}
	return aliases
}

// checkSidecarMainAndOS is the core of the sidecar shape gate: exactly one
// func main() across the whole package, whose body is exactly one statement
// — detectorhost.Run(x), optionally wrapped in os.Exit(...) — whose argument
// x is a local detector literal or local zero-arg constructor call, AND every
// OTHER reference to the imported os / pkg/detectorhost packages anywhere in
// the package is forbidden (confinement — see the file doc).
//
// Deliberately NOT enforced: a func-count restriction on the package as a
// whole. The detector implementation (Name()/Detect() methods, private
// helpers) needs its own functions — the SHAPE constraint this gate polices
// is main()'s body, the import surface, and the os/detectorhost confinement,
// never "how many funcs exist." An extra top-level helper function that
// touches only the allowed import surface has no attack surface beyond what
// the import allow-list and os/detectorhost confinement already bound (see
// TestGuard_CustomerTreeSidecarShape_ExtraHelperFuncAllowed in guard_test.go
// — the orchestrator ruling's own hint: "the SHAPE constraint is main()'s
// body + imports + package, not a func count").
func checkSidecarMainAndOS(paths []string, files []*ast.File) []Violation {
	osAliases := sidecarImportAliases(files, "os")
	dhAliases := sidecarImportAliases(files, sidecarDetectorhostImportPath)

	type mainRef struct {
		path string
		fn   *ast.FuncDecl
	}
	var mains []mainRef
	for i, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != "main" {
				continue
			}
			mains = append(mains, mainRef{path: paths[i], fn: fn})
		}
	}
	firstPath := ""
	if len(paths) > 0 {
		firstPath = paths[0]
	}
	if len(mains) != 1 {
		return []Violation{{
			File: firstPath, Rule: RuleSidecarMainShape,
			Detail: fmt.Sprintf("a customer-tree sidecar detector package must have exactly one func main(), found %d", len(mains)),
		}}
	}
	m := mains[0]

	if m.fn.Body == nil || len(m.fn.Body.List) != 1 {
		return []Violation{{
			File: m.path, Rule: RuleSidecarMainShape,
			Detail: "main() must contain exactly one statement: a single detectorhost.Run(...) call, optionally wrapped in os.Exit(...)",
		}}
	}
	exprStmt, ok := m.fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return []Violation{{File: m.path, Rule: RuleSidecarMainShape, Detail: "main()'s only statement must be a call expression"}}
	}
	outer, ok := exprStmt.X.(*ast.CallExpr)
	if !ok {
		return []Violation{{File: m.path, Rule: RuleSidecarMainShape, Detail: "main()'s statement must be a function call"}}
	}

	var runCall *ast.CallExpr
	var osExitSel *ast.SelectorExpr
	if sel, ok := outer.Fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok && osAliases[id.Name] && sel.Sel.Name == "Exit" {
			if len(outer.Args) != 1 {
				return []Violation{{File: m.path, Rule: RuleSidecarMainShape, Detail: "os.Exit must take exactly one argument: the detectorhost.Run(...) call"}}
			}
			inner, ok := outer.Args[0].(*ast.CallExpr)
			if !ok {
				return []Violation{{File: m.path, Rule: RuleSidecarMainShape, Detail: "os.Exit's argument must be a detectorhost.Run(...) call expression"}}
			}
			osExitSel = sel
			runCall = inner
		}
	}
	if runCall == nil {
		runCall = outer
	}

	runSel, ok := runCall.Fun.(*ast.SelectorExpr)
	if !ok {
		return []Violation{{File: m.path, Rule: RuleSidecarMainShape, Detail: "main() must call detectorhost.Run(...), optionally wrapped in os.Exit(...)"}}
	}
	runPkgIdent, ok := runSel.X.(*ast.Ident)
	if !ok || !dhAliases[runPkgIdent.Name] || runSel.Sel.Name != "Run" {
		return []Violation{{File: m.path, Rule: RuleSidecarMainShape, Detail: "main() must call <detectorhost>.Run(...) on the imported pkg/detectorhost package, optionally wrapped in os.Exit(...)"}}
	}
	if len(runCall.Args) != 1 {
		return []Violation{{File: m.path, Rule: RuleSidecarMainShape, Detail: "detectorhost.Run must take exactly one argument: the detector value"}}
	}

	var violations []Violation
	if !isLocalDetectorArg(runCall.Args[0], files) {
		violations = append(violations, Violation{
			File: m.path, Rule: RuleSidecarMainShape,
			Detail: "detectorhost.Run's argument must be a local detector literal (T{} / &T{}) or a local zero-argument constructor call — never an imported value, a variable, or a call into another package",
		})
	}

	// Confine EVERY os / detectorhost reference anywhere in the package to
	// the exact two AST nodes just verified. See the file doc: this is what
	// stops "os" being a de-facto blanket grant once the file needs it for
	// os.Exit, and stops a second, unrelated detectorhost.Run/RunIO call.
	for i, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case osAliases[id.Name]:
				if sel == osExitSel {
					return true
				}
				violations = append(violations, Violation{
					File: paths[i], Rule: RuleSidecarMainShape,
					Detail: fmt.Sprintf("reference to %s.%s — os's ONLY sanctioned use in a sidecar detector is the single os.Exit(...) wrapping main's detectorhost.Run(...) call; any other os reference (file I/O, environment, process control) is forbidden even though \"os\" is an allowed import", id.Name, sel.Sel.Name),
				})
			case dhAliases[id.Name]:
				if sel == runSel {
					return true
				}
				violations = append(violations, Violation{
					File: paths[i], Rule: RuleSidecarMainShape,
					Detail: fmt.Sprintf("reference to %s.%s — a sidecar detector's ONLY sanctioned pkg/detectorhost use is the single %s.Run(...) call in main()", id.Name, sel.Sel.Name, id.Name),
				})
			}
			return true
		})
	}
	return violations
}

// isLocalDetectorArg reports whether arg is a package-local detector literal
// (T{} or &T{}, where T is a bare, non-import-qualified identifier — a
// package-qualified composite literal like other pkg.T{} would parse as a
// SelectorExpr Type, not an Ident, so this structurally excludes foreign
// types without needing full type-checking) or a package-local zero-argument
// constructor call (a bare identifier resolving to a func declared in the
// same package, called with no arguments).
func isLocalDetectorArg(arg ast.Expr, files []*ast.File) bool {
	e := arg
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	switch v := e.(type) {
	case *ast.CompositeLit:
		_, ok := v.Type.(*ast.Ident)
		return ok
	case *ast.CallExpr:
		id, ok := v.Fun.(*ast.Ident)
		if !ok || len(v.Args) != 0 {
			return false
		}
		return packageDeclaresFunc(files, id.Name)
	default:
		return false
	}
}

// packageDeclaresFunc reports whether name is a top-level (no receiver) func
// declared in any of files.
func packageDeclaresFunc(files []*ast.File, name string) bool {
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && fn.Name.Name == name {
				return true
			}
		}
	}
	return false
}
