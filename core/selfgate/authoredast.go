// authoredast.go — the K7 L3 ADDITIVE-SHAPE AST GATE for agent-authored
// detectors. Where the K2a import allow-list (core/lint) governs what an
// authored detector may LINK, this gate governs its SHAPE: an authored detector
// must be a pure, additive, self-registering leaf and nothing else. It is
// diff/proposal-gate machinery, so it lives beside the guard and
// ValidateProposal in core/selfgate, and it fails closed — an unparseable or
// unexpected authored package is a violation, never a silent pass.
//
// The threat it closes is §5 L1: a new detector's init() reaching out to mutate
// a sibling detector's package state (narrowing a security-critical detector),
// or smuggling non-additive behavior through build tags, cgo, compiler
// directives, or a runtime-computed detector Name. L1's own-package layout
// already makes same-package mutation structurally impossible; this gate is the
// defence-in-depth AST proof, and it additionally forbids ANY assignment to a
// non-local identifier, a non-literal Name(), duplicate authored Names, and any
// build/compiler directive.
//
// The exported entry point is CheckAuthoredDetectorShape(dir) — one authored
// detector package directory in, per-violation slice out.
// CheckAuthoredDetectorTreeShape(root) runs it over every authored package
// directly under root AND enforces cross-package Name uniqueness.
package selfgate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/mallcop-app/mallcop/core/detect"
)

// RuleAuthoredShape is the stable Rule identifier carried on GuardFinding when
// an authored-detector shape violation is surfaced through ValidateProposal.
// The finer sub-rule lives in Violation.Rule (and is folded into the finding
// Detail).
const RuleAuthoredShape = "authored-detector-shape"

// Sub-rule identifiers carried on Violation.Rule.
const (
	// RuleShapeBuildConstraint — a `//go:build` / `// +build` line: authored
	// detectors are unconditionally-compiled leaves, never build-variant.
	RuleShapeBuildConstraint = "build-constraint"
	// RuleShapeCompilerDirective — a `//go:` compiler pragma (linkname, embed,
	// cgo, noescape, ...): non-additive escape hatches.
	RuleShapeCompilerDirective = "compiler-directive"
	// RuleShapeCgo — an `import "C"` (or any cgo): authored code is pure Go.
	RuleShapeCgo = "cgo-import"
	// RuleShapeInit — the package does not have exactly one init() whose body
	// is a single detect.Register(T{}) call.
	RuleShapeInit = "init-shape"
	// RuleShapeNonLocalAssign — an assignment (or address-of) whose target is
	// not a locally-declared identifier: the same-package-mutation defence.
	RuleShapeNonLocalAssign = "nonlocal-assign"
	// RuleShapeNonLiteralName — Name() does not return a single compile-time
	// string literal.
	RuleShapeNonLiteralName = "nonliteral-name"
	// RuleShapePackageClause — a file whose package clause is not the expected
	// own-package name (the directory base name).
	RuleShapePackageClause = "package-clause"
	// RuleShapeDuplicateName — two authored detectors register the same Name.
	RuleShapeDuplicateName = "duplicate-name"
	// RuleShapeParse — the authored package could not be read/parsed. Fail
	// closed.
	RuleShapeParse = "parse-error"
	// RuleShapeFrameworkRef — a reference to the imported core/detect package
	// OTHER than the single detect.Register(T{}) in init(). Most dangerously a
	// call to a framework MUTATOR (detect.ApplyTuning, which widens shared
	// priv-escalation package state), but ANY other core/detect member is
	// forbidden: an authored detector's only sanctioned framework touch is
	// self-registration.
	RuleShapeFrameworkRef = "framework-reference"
	// RuleShapeUnboundedLoop — a provably non-terminating construct in authored
	// code: a condition-less `for { ... }` with no break/return/goto/panic exit,
	// or an empty `select {}`. Either hangs the scan until the L4 per-detector
	// deadline fires and LEAKS a goroutine.
	RuleShapeUnboundedLoop = "unbounded-loop"
)

// frameworkRegistryOrigin is the origin string recorded for a Name seeded from
// the live framework detector registry, so a collision diagnostic reads
// "already registered by the framework detector registry (core/detect)".
const frameworkRegistryOrigin = "the framework detector registry (core/detect)"

// Violation is one authored-detector shape defect. File is the offending file
// path (as provided to the checker — absolute in production, since callers pass
// an on-disk directory). Rule is one of the RuleShape* sub-rules. Detail is the
// human-readable explanation.
type Violation struct {
	File   string
	Rule   string
	Detail string
}

// CheckAuthoredDetectorShape parses every non-test .go file in ONE authored
// detector package directory and returns a Violation for each shape defect. It
// returns an error only for an I/O failure reading the directory; an
// unparseable source file is reported as a RuleShapeParse Violation (fail
// closed), not an error, so a single bad file cannot make the whole gate
// inconclusive.
func CheckAuthoredDetectorShape(dir string) ([]Violation, error) {
	_, violations, err := shapeCheckPackage(dir)
	return violations, err
}

// CheckAuthoredDetectorTreeShape runs CheckAuthoredDetectorShape over every
// immediate subdirectory of root (each is one authored detector's own package)
// and additionally enforces that no two authored detectors register the same
// Name. Files sitting directly in root (e.g. the aggregator registry.go) are
// NOT detector packages and are skipped — they are gated by the guard's
// append-only registry rule, not this shape gate. An error is returned only if
// root cannot be read.
func CheckAuthoredDetectorTreeShape(root string) ([]Violation, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var violations []Violation
	// nameFirstSeen maps a registered detector Name to the package dir that
	// first declared it, so a collision points at the offending sibling.
	nameFirstSeen := map[string]string{}
	// Seed with the FRAMEWORK detector names (K7 HOLE 2). detect.Register panics
	// at binary startup on a duplicate Name, so an authored detector whose Name()
	// collides with a built-in (e.g. "injection-probe") would crash cmd/mallcop
	// at init — an unrecovered panic surfaced only when stage-3 exam-detect execs
	// the crashing binary. Seeding the uniqueness set turns that into a
	// DETERMINISTIC pre-merge RuleShapeDuplicateName rejection. We use the
	// checked-in framework list (detect.FrameworkDetectorNames), NOT the live
	// registry: this gate also runs inside cmd/mallcop, which links the authored
	// aggregator, so a live-registry seed would re-discover an already-merged
	// authored detector that is ALSO on disk in the head tree and flag it as
	// colliding with itself. Authored-vs-authored collisions are caught by the
	// tree walk's own accumulating dedup below.
	for _, name := range detect.FrameworkDetectorNames() {
		nameFirstSeen[name] = frameworkRegistryOrigin
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgDir := filepath.Join(root, e.Name())
		name, vs, cerr := shapeCheckPackage(pkgDir)
		if cerr != nil {
			return nil, cerr
		}
		violations = append(violations, vs...)
		if name == "" {
			continue
		}
		if prev, ok := nameFirstSeen[name]; ok {
			violations = append(violations, Violation{
				File:   pkgDir,
				Rule:   RuleShapeDuplicateName,
				Detail: fmt.Sprintf("authored detector Name %q is already registered by %s — authored Names must be unique", name, prev),
			})
			continue
		}
		nameFirstSeen[name] = pkgDir
	}
	return violations, nil
}

// collectAuthoredDetectorNames returns the set of registered detector Names
// declared by the authored-detector packages directly under root (each immediate
// subdirectory is one own-package detector). Names are extracted the same way the
// shape gate does — the single compile-time string-literal Name() — so a package
// whose Name cannot be statically determined contributes nothing. It is used to
// compute which authored detectors a PROPOSAL adds (head names minus base names),
// which the mandatory benign-twin check keys on. The error return is for root I/O
// only; a missing root (fs.ErrNotExist) is the caller's signal that no authored
// tree exists at that ref.
func collectAuthoredDetectorNames(root string) (map[string]bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name, _, cerr := shapeCheckPackage(filepath.Join(root, e.Name()))
		if cerr != nil {
			return nil, cerr
		}
		if name != "" {
			names[name] = true
		}
	}
	return names, nil
}

// shapeCheckPackage is the shared implementation: it returns the registered
// detector Name literal (empty if it could not be determined) alongside the
// violations. The error return is for directory I/O only.
func shapeCheckPackage(dir string) (name string, violations []Violation, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, err
	}

	wantPkg := filepath.Base(dir)
	fset := token.NewFileSet()
	var files []*ast.File
	var filePaths []string

	for _, e := range entries {
		if e.IsDir() || !isProductionGoFile(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		f, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			violations = append(violations, Violation{
				File:   p,
				Rule:   RuleShapeParse,
				Detail: fmt.Sprintf("authored detector file is unparseable: %v", perr),
			})
			continue
		}
		files = append(files, f)
		filePaths = append(filePaths, p)

		if f.Name.Name != wantPkg {
			violations = append(violations, Violation{
				File:   p,
				Rule:   RuleShapePackageClause,
				Detail: fmt.Sprintf("package clause is %q, want %q (an authored detector is its own package named after its directory)", f.Name.Name, wantPkg),
			})
		}

		violations = append(violations, checkFileDirectives(p, f)...)
		violations = append(violations, checkFileImportsC(p, f)...)
		violations = append(violations, checkFileAssignments(p, f)...)
		violations = append(violations, checkParamWrites(p, f)...)
		violations = append(violations, checkPackageInitializers(p, f)...)
		violations = append(violations, checkUnboundedLoops(p, f)...)
	}

	if len(files) == 0 {
		// No production Go in this directory: not a detector package. Nothing to
		// register, nothing to police.
		return "", violations, nil
	}

	// The ONLY sanctioned core/detect reference is the single Register in init();
	// any other detect.* (esp. the ApplyTuning knob mutator) is a violation.
	violations = append(violations, checkDetectReferences(filePaths, files)...)

	// Exactly-one-init + single detect.Register(T{}) call, and Name() literal.
	regType, initViolations := checkRegistration(filePaths, files)
	violations = append(violations, initViolations...)
	if regType != "" {
		nm, nameViolations := checkNameLiteral(filePaths, files, regType)
		violations = append(violations, nameViolations...)
		name = nm
	}

	return name, violations, nil
}

// checkFileDirectives rejects build constraints and compiler directives. An
// authored detector is an unconditionally-compiled, pure-Go leaf: it has no
// legitimate use for `//go:build` / `// +build`, `//go:linkname`, `//go:embed`,
// `//go:cgo_*`, or any other `//go:` pragma.
func checkFileDirectives(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, group := range f.Comments {
		for _, c := range group.List {
			t := c.Text
			switch {
			case strings.HasPrefix(t, "//go:build"):
				violations = append(violations, Violation{
					File:   path,
					Rule:   RuleShapeBuildConstraint,
					Detail: fmt.Sprintf("build constraint %q — authored detectors are unconditionally compiled", t),
				})
			case strings.HasPrefix(t, "//go:"):
				violations = append(violations, Violation{
					File:   path,
					Rule:   RuleShapeCompilerDirective,
					Detail: fmt.Sprintf("compiler directive %q — authored detectors may carry no //go: pragmas", t),
				})
			default:
				trimmed := strings.TrimSpace(strings.TrimPrefix(t, "//"))
				if strings.HasPrefix(trimmed, "+build") {
					violations = append(violations, Violation{
						File:   path,
						Rule:   RuleShapeBuildConstraint,
						Detail: fmt.Sprintf("build constraint %q — authored detectors are unconditionally compiled", t),
					})
				}
			}
		}
	}
	return violations
}

// checkFileImportsC rejects cgo (import "C"). The import allow-list also bans
// it; this gate is independent so shape verification stands alone.
func checkFileImportsC(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "C" {
			violations = append(violations, Violation{
				File:   path,
				Rule:   RuleShapeCgo,
				Detail: `import "C" (cgo) is forbidden in authored detectors`,
			})
		}
	}
	return violations
}

// checkFileAssignments walks every function AND every package-level var/const
// initializer expression in the file and flags any assignment (=, op-assign),
// IncDec (++/--), or address-of (&) whose target resolves to an identifier that
// is NOT locally declared within the enclosing scope. A package-scope var, an
// imported-package selector, or a deref/index rooted at either is a non-local
// target and a violation — the same-package-mutation defence, applied even
// though L1 makes it structurally impossible.
//
// Package-level initializers are covered because a func literal invoked (or
// merely nested) inside one runs at package-initialization time and is NOT
// contained in any top-level FuncDecl body, so `var _ = func(){ sibling = nil
// }()` would otherwise slip past the FuncDecl-only walk. checkPackageInitializers
// independently forbids the presence of that init-time code; this is the
// non-local-write half of the same defence applied to it.
func checkFileAssignments(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body == nil {
				continue
			}
			violations = append(violations, nonLocalWrites(path, d.Body, collectLocals(d))...)
		case *ast.GenDecl:
			if d.Tok != token.VAR && d.Tok != token.CONST {
				continue
			}
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, v := range vs.Values {
					violations = append(violations, nonLocalWrites(path, v, collectLocalsInNode(v))...)
				}
			}
		}
	}
	return violations
}

// nonLocalWrites reports a RuleShapeNonLocalAssign Violation for every write
// target within node whose root identifier is not in locals.
func nonLocalWrites(path string, node ast.Node, locals map[string]bool) []Violation {
	var violations []Violation
	for _, tgt := range collectAssignmentTargets(node) {
		if bad, detail := targetIsNonLocal(tgt.expr, locals); bad {
			violations = append(violations, Violation{
				File:   path,
				Rule:   RuleShapeNonLocalAssign,
				Detail: detail,
			})
		}
	}
	return violations
}

// checkParamWrites flags any write whose target is a COMPOUND lvalue — a field
// selector, index, pointer deref, or the address-of one — rooted at a function
// PARAMETER or RECEIVER. This is the K7 HOLE 1b shape gate: detect.Detect threads
// ONE events slice and ONE *baseline.Baseline through every registered detector,
// so an authored Detect that writes THROUGH its arguments (events[i].Payload =
// nil, (&events[i]).Actor = "", bl.KnownActors = nil, *bl = baseline.Baseline{})
// mutates the SHARED input and silences every later security detector. An
// authored detector must treat its args as READ-ONLY.
//
// Only writes THROUGH a parameter are flagged, not a bare rebinding of the
// parameter identifier itself (events = someLocal): reassigning the local
// parameter variable does not touch the caller's backing data. Writes through a
// LOCAL variable (a slice/map the detector allocated itself) are likewise fine —
// the root there is a `:=`/var-declared local, never a parameter.
//
// The walk descends into nested func literals (ast.Inspect), so a write through
// an outer parameter captured by a closure is caught too; the param set is the
// union of every enclosing FuncDecl/FuncLit receiver+parameter, an
// over-approximation that is sound (it can only flag more, never fewer, writes
// through argument-derived state).
func checkParamWrites(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		params := collectParamAndReceiverNames(fn)
		if len(params) == 0 {
			continue
		}
		for _, tgt := range collectAssignmentTargets(fn.Body) {
			if !isCompoundLValue(tgt.expr) {
				continue // a bare-ident rebind of a param is not a write THROUGH it
			}
			root := rootIdent(tgt.expr)
			if root == nil || !params[root.Name] {
				continue
			}
			violations = append(violations, Violation{
				File:   path,
				Rule:   RuleShapeNonLocalAssign,
				Detail: fmt.Sprintf("write through parameter %q — an authored detector must treat its events/baseline arguments as READ-ONLY; mutating them (through an index, field, or deref) corrupts the shared input and silences every later detector", root.Name),
			})
		}
	}
	return violations
}

// collectParamAndReceiverNames gathers the receiver, parameter, AND every nested
// func-literal parameter name for a function. Named RESULTS are deliberately
// excluded: a named return value is writable local output, not shared caller
// state. This is the "which identifiers name an incoming argument" set that
// checkParamWrites tests write-through targets against.
func collectParamAndReceiverNames(fn *ast.FuncDecl) map[string]bool {
	params := map[string]bool{}
	addFieldNames(fn.Recv, params)
	if fn.Type != nil {
		addFieldNames(fn.Type.Params, params)
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if fl, ok := n.(*ast.FuncLit); ok && fl.Type != nil {
			addFieldNames(fl.Type.Params, params)
		}
		return true
	})
	return params
}

// isCompoundLValue reports whether e is an lvalue that reaches THROUGH a variable
// — a field selector, index, or pointer deref (and the address-of / parenthesized
// forms of those) — as opposed to a bare identifier. A bare identifier target is
// a rebinding of the variable itself; a compound target mutates the pointee /
// element / field the variable refers to.
func isCompoundLValue(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.IndexListExpr, *ast.StarExpr:
		return true
	case *ast.ParenExpr:
		return isCompoundLValue(x.X)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return isCompoundLValue(x.X)
		}
	}
	return false
}

// checkPackageInitializers enforces the "the only init-time code is a single
// detect.Register" invariant against package-level var/const declarations: any
// initializer that IS or CONTAINS a function call or a function literal executes
// code during package initialization and is a RuleShapeInit violation. That
// closes two bypasses of the FuncDecl-only registration check — a package-var
// initializer that smuggles a second detect.Register (`var _ = func(){
// detect.Register(evil{}) }()`) and one that runs any other init-time side
// effect. Pure literal / composite-literal / operator initializers over
// constants (thresholds, pattern slices, marker strings) are permitted; a
// detector computes inside Detect, never at package init.
func checkPackageInitializers(path string, f *ast.File) []Violation {
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
						File:   path,
						Rule:   RuleShapeInit,
						Detail: fmt.Sprintf("package-level %s initializer runs code at package initialization (contains a %s) — an authored detector's only init-time code is the single detect.Register(T{}) in init(); use literal/composite-literal initializers and compute inside Detect", declKeyword(gd.Tok), kind),
					})
				}
			}
		}
	}
	return violations
}

// impureInitializer reports whether expr evaluates any code — it IS or CONTAINS
// a function call or a function literal anywhere within it. A pure literal,
// composite-literal, or operator expression over constants returns false.
func impureInitializer(expr ast.Expr) (kind string, found bool) {
	ast.Inspect(expr, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.CallExpr:
			kind, found = "function call", true
			return false
		case *ast.FuncLit:
			kind, found = "function literal", true
			return false
		}
		return true
	})
	return kind, found
}

// declKeyword renders a GenDecl token as its source keyword for diagnostics.
func declKeyword(tok token.Token) string {
	if tok == token.CONST {
		return "const"
	}
	return "var"
}

// assignTarget is one lvalue expression that a statement writes through.
type assignTarget struct{ expr ast.Expr }

// collectAssignmentTargets gathers every write target reachable from node (a
// function body or a package-level initializer expression, including any func
// literals nested within it): the LHS of ASSIGN/op-assign AssignStmts (DEFINE
// `:=` introduces locals, not targets, so it is skipped), IncDecStmt operands,
// and address-of (&) operands that are lvalues.
func collectAssignmentTargets(node ast.Node) []assignTarget {
	var targets []assignTarget
	ast.Inspect(node, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if s.Tok != token.DEFINE {
				for _, lhs := range s.Lhs {
					targets = append(targets, assignTarget{expr: lhs})
				}
			}
		case *ast.IncDecStmt:
			targets = append(targets, assignTarget{expr: s.X})
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if isLValue(s.X) {
					targets = append(targets, assignTarget{expr: s.X})
				}
			}
		}
		return true
	})
	return targets
}

// isLValue reports whether e is an addressable identifier/selector/index chain
// (as opposed to a composite/call/other expression), so &e is a mutation
// vector worth checking. This keeps `&T{}` and `&f()` from being treated as
// targets.
func isLValue(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return true
	case *ast.IndexExpr:
		return isLValue(x.X)
	case *ast.IndexListExpr:
		return isLValue(x.X)
	case *ast.StarExpr:
		return isLValue(x.X)
	case *ast.ParenExpr:
		return isLValue(x.X)
	case *ast.UnaryExpr:
		return x.Op == token.AND && isLValue(x.X)
	default:
		return false
	}
}

// targetIsNonLocal classifies a write target. It resolves to the leftmost
// identifier of the lvalue chain: `x`, `x.f`, `x[i]`, `*x`, `(x)` all root at
// `x`. If that root is a locally-declared name (or the blank identifier) the
// write is local state and permitted; otherwise it is a package-scope var or an
// imported package selector — a violation. An unrecognized target shape fails
// closed.
func targetIsNonLocal(e ast.Expr, locals map[string]bool) (bool, string) {
	root := rootIdent(e)
	if root == nil {
		return true, "assignment to an unrecognized target expression — fail closed"
	}
	if root.Name == "_" || locals[root.Name] {
		return false, ""
	}
	return true, fmt.Sprintf("assignment to non-local identifier %q — authored detectors must be pure and may not mutate package-scope or imported state", root.Name)
}

// rootIdent returns the leftmost identifier of an lvalue chain, or nil for a
// non-ident-rooted expression.
func rootIdent(e ast.Expr) *ast.Ident {
	switch x := e.(type) {
	case *ast.Ident:
		return x
	case *ast.SelectorExpr:
		return rootIdent(x.X)
	case *ast.IndexExpr:
		return rootIdent(x.X)
	case *ast.IndexListExpr:
		return rootIdent(x.X)
	case *ast.StarExpr:
		return rootIdent(x.X)
	case *ast.ParenExpr:
		return rootIdent(x.X)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return rootIdent(x.X)
		}
		return nil
	default:
		return nil
	}
}

// collectLocals gathers every identifier name that is locally declared within a
// function: its receiver, parameters, and results, plus every name introduced
// by a `:=` define, a `var`/`const` declaration, a range key/value, or a type
// switch guard anywhere in its body (including nested function literals, whose
// bindings are locals of the enclosing closure). This is an over-approximation
// of "local", which is sound for the non-local-write defence: a package-scope
// var or imported selector is never in this set, so writes to them are always
// caught.
func collectLocals(fn *ast.FuncDecl) map[string]bool {
	locals := map[string]bool{}
	addFieldNames(fn.Recv, locals)
	if fn.Type != nil {
		addFieldNames(fn.Type.Params, locals)
		addFieldNames(fn.Type.Results, locals)
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		collectLocalName(n, locals)
		return true
	})
	return locals
}

// collectLocalsInNode is collectLocals for an arbitrary node with no enclosing
// FuncDecl — e.g. a package-level var/const initializer expression. Any name a
// func literal nested inside the expression declares (its params/results, `:=`
// defines, inner var/const, range keys/values, type-switch guards) is a local
// of that closure; everything else the expression writes is package-scope or
// imported state and therefore non-local.
func collectLocalsInNode(node ast.Node) map[string]bool {
	locals := map[string]bool{}
	ast.Inspect(node, func(n ast.Node) bool {
		collectLocalName(n, locals)
		return true
	})
	return locals
}

// collectLocalName adds the names a single node introduces into the locals set.
// It is the shared body of collectLocals / collectLocalsInNode: `:=` defines,
// var/const declarations, range keys/values, type-switch guards, and func
// literal params/results. This over-approximates "local", which is sound for
// the non-local-write defence — a package-scope var or imported selector is
// never in this set, so writes to them are always caught.
func collectLocalName(n ast.Node, locals map[string]bool) {
	switch s := n.(type) {
	case *ast.AssignStmt:
		if s.Tok == token.DEFINE {
			for _, lhs := range s.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					locals[id.Name] = true
				}
			}
		}
	case *ast.GenDecl:
		if s.Tok == token.VAR || s.Tok == token.CONST {
			for _, spec := range s.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, id := range vs.Names {
						locals[id.Name] = true
					}
				}
			}
		}
	case *ast.RangeStmt:
		if s.Tok == token.DEFINE {
			if id, ok := s.Key.(*ast.Ident); ok {
				locals[id.Name] = true
			}
			if id, ok := s.Value.(*ast.Ident); ok {
				locals[id.Name] = true
			}
		}
	case *ast.TypeSwitchStmt:
		if as, ok := s.Assign.(*ast.AssignStmt); ok && as.Tok == token.DEFINE {
			for _, lhs := range as.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					locals[id.Name] = true
				}
			}
		}
	case *ast.FuncLit:
		addFieldNames(s.Type.Params, locals)
		addFieldNames(s.Type.Results, locals)
	}
}

// addFieldNames adds every declared name in a field list (params/results/
// receiver) to the set. Anonymous fields contribute nothing.
func addFieldNames(fl *ast.FieldList, set map[string]bool) {
	if fl == nil {
		return
	}
	for _, field := range fl.List {
		for _, id := range field.Names {
			set[id.Name] = true
		}
	}
}

// detectImportAliases returns the set of local names any file binds to an import
// of .../core/detect (the bare "detect" name, or an explicit import alias). It is
// the shared "which identifier names the framework package" set used by both the
// registration check and the framework-reference gate. Collecting across all
// files over-approximates per-file aliasing, which is sound for a fail-closed
// gate — it can only widen what counts as a framework reference.
func detectImportAliases(files []*ast.File) map[string]bool {
	aliases := map[string]bool{}
	for _, f := range files {
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "core/detect" || strings.HasSuffix(p, "/core/detect") {
				alias := "detect"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
				aliases[alias] = true
			}
		}
	}
	return aliases
}

// checkDetectReferences enforces that the ONLY reference to the imported
// core/detect package anywhere in an authored detector is the single
// detect.Register(T{}) call inside init(). Every other core/detect selector is a
// RuleShapeFrameworkRef violation — most importantly detect.ApplyTuning, the
// exported knob MUTATOR that widens shared priv-escalation package state, but
// also detect.Detect, detect.Detectors, or any other member.
//
// WHY (the write-side of the tuning race): an authored detector is a pure
// additive leaf — it registers itself in init() and computes inside Detect over
// its (per-detector cloned, read-only) events/baseline. It has no legitimate
// reason to reach back into the framework package. A "pure additive leaf" that
// calls ApplyTuning could mutate shared detection state, and a LEAKED authored
// goroutine (the documented detectorTimeout tradeoff) that holds a reference to
// a framework mutator could race a concurrent scan. Forbidding every non-Register
// detect.* reference closes that at MERGE: linked authored code can never NAME a
// framework mutator, so the leaked-goroutine tradeoff is safe — a stuck authored
// goroutine can touch nothing but its own clones.
func checkDetectReferences(paths []string, files []*ast.File) []Violation {
	aliases := detectImportAliases(files)
	if len(aliases) == 0 {
		return nil
	}
	var violations []Violation
	for i, f := range files {
		path := paths[i]
		for _, decl := range f.Decls {
			fn, isFn := decl.(*ast.FuncDecl)
			inInit := isFn && fn.Recv == nil && fn.Name.Name == "init"
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || !aliases[id.Name] {
					return true
				}
				// The single sanctioned reference: detect.Register inside init().
				// (checkRegistration independently proves init() is EXACTLY that one
				// call, so allowing Register here cannot admit a second use.)
				if inInit && sel.Sel.Name == "Register" {
					return true
				}
				violations = append(violations, Violation{
					File:   path,
					Rule:   RuleShapeFrameworkRef,
					Detail: fmt.Sprintf("reference to %s.%s — an authored detector's ONLY sanctioned core/detect use is the single %s.Register(T{}) in init(); reaching any other framework member (especially the %s.ApplyTuning knob mutator) lets authored code touch shared, mutable detection state and reopens the tuning race", id.Name, sel.Sel.Name, id.Name, id.Name),
				})
				return true
			})
		}
	}
	return violations
}

// checkUnboundedLoops rejects the two constructs that provably never terminate
// and would therefore hang an authored Detect until the L4 per-detector deadline
// fires — LEAKING the goroutine (the documented detectorTimeout tradeoff): a
// condition-less `for { ... }` whose body contains NO exit statement at all
// (break, return, goto, or panic), and an empty `select {}` (zero comm clauses
// block forever). A pure detector loops over a bounded input (range) or a real
// condition and returns.
//
// The check is SOUND: it flags only loops that provably cannot exit, so a
// legitimate `for i := 0; i < n; i++`, `for cond {}`, or any loop with a
// reachable break/return is left alone. It may MISS some infinite loops (e.g. a
// `for {}` whose only "exit" is an inner loop's break), which is acceptable —
// the runtime L4 deadline still quarantines those; this gate closes the blatant
// DoS shapes before merge.
func checkUnboundedLoops(path string, f *ast.File) []Violation {
	var violations []Violation
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ForStmt:
			if s.Cond == nil && !bodyHasExit(s.Body) {
				violations = append(violations, Violation{
					File:   path,
					Rule:   RuleShapeUnboundedLoop,
					Detail: "condition-less for-loop with no break/return/goto/panic — an authored detector may not spin forever; it hangs the scan until the per-detector deadline fires and LEAKS a goroutine",
				})
			}
		case *ast.SelectStmt:
			if s.Body == nil || len(s.Body.List) == 0 {
				violations = append(violations, Violation{
					File:   path,
					Rule:   RuleShapeUnboundedLoop,
					Detail: "empty select{} blocks forever — an authored detector may not block; it hangs the scan and LEAKS a goroutine",
				})
			}
		}
		return true
	})
	return violations
}

// bodyHasExit reports whether a block contains any statement that could
// terminate an enclosing condition-less for-loop: a break or goto BranchStmt, a
// return, or a panic() call, anywhere within it (including nested blocks). It is
// used ONLY to avoid flagging a `for {}` that has a reachable exit, so the
// over-approximation is sound for checkUnboundedLoops — finding any exit
// statement suppresses the flag, so the check never false-positives.
func bodyHasExit(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.BranchStmt:
			if s.Tok == token.BREAK || s.Tok == token.GOTO {
				found = true
			}
		case *ast.ReturnStmt:
			found = true
		case *ast.CallExpr:
			if id, ok := s.Fun.(*ast.Ident); ok && id.Name == "panic" {
				found = true
			}
		}
		return !found
	})
	return found
}

// checkRegistration enforces that the package has EXACTLY ONE init() function
// whose body is a single ExprStmt calling <pkg>.Register(T{}) or
// <pkg>.Register(&T{}), where <pkg> is an imported package whose path ends in
// core/detect. It returns the registered struct type name (empty on any
// violation) so the caller can locate its Name() method.
func checkRegistration(paths []string, files []*ast.File) (regType string, violations []Violation) {
	var inits []*ast.FuncDecl
	var initFiles []string
	// detectAliases: local names bound to an import of .../core/detect.
	detectAliases := detectImportAliases(files)
	for i, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != "init" {
				continue
			}
			inits = append(inits, fn)
			initFiles = append(initFiles, paths[i])
		}
	}

	if len(inits) != 1 {
		file := ""
		if len(paths) > 0 {
			file = paths[0]
		}
		return "", []Violation{{
			File:   file,
			Rule:   RuleShapeInit,
			Detail: fmt.Sprintf("authored detector package must have exactly one init(), found %d", len(inits)),
		}}
	}

	fn := inits[0]
	file := initFiles[0]
	if fn.Body == nil || len(fn.Body.List) != 1 {
		return "", []Violation{{
			File:   file,
			Rule:   RuleShapeInit,
			Detail: "init() must contain exactly one statement: a single detect.Register(T{}) call",
		}}
	}
	exprStmt, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return "", []Violation{{
			File:   file,
			Rule:   RuleShapeInit,
			Detail: "init()'s only statement must be a detect.Register(...) call expression",
		}}
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	if !ok {
		return "", []Violation{{File: file, Rule: RuleShapeInit, Detail: "init() must call detect.Register(...)"}}
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Register" {
		return "", []Violation{{File: file, Rule: RuleShapeInit, Detail: "init() must call <detect>.Register(...)"}}
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || !detectAliases[pkgIdent.Name] {
		return "", []Violation{{File: file, Rule: RuleShapeInit, Detail: "init()'s Register call must be on the imported core/detect package"}}
	}
	if len(call.Args) != 1 {
		return "", []Violation{{File: file, Rule: RuleShapeInit, Detail: "detect.Register must take exactly one argument"}}
	}
	typeName := registeredTypeName(call.Args[0])
	if typeName == "" {
		return "", []Violation{{
			File:   file,
			Rule:   RuleShapeInit,
			Detail: "detect.Register's argument must be a struct literal T{} or &T{} so its Name() can be verified statically",
		}}
	}
	return typeName, nil
}

// registeredTypeName extracts the type name from a Register argument of the
// form T{} or &T{}. Returns "" for any other shape.
func registeredTypeName(arg ast.Expr) string {
	if u, ok := arg.(*ast.UnaryExpr); ok && u.Op == token.AND {
		arg = u.X
	}
	cl, ok := arg.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	if id, ok := cl.Type.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// checkNameLiteral finds the Name() method for the registered type and verifies
// it returns a single compile-time string literal. A computed, concatenated,
// const-backed, or var-backed return is a violation. Returns the literal value
// (unquoted) on success.
func checkNameLiteral(paths []string, files []*ast.File, regType string) (name string, violations []Violation) {
	var method *ast.FuncDecl
	methodFile := ""
	for i, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "Name" {
				continue
			}
			if receiverTypeName(fn.Recv) != regType {
				continue
			}
			method = fn
			methodFile = paths[i]
		}
	}
	if method == nil {
		file := ""
		if len(paths) > 0 {
			file = paths[0]
		}
		return "", []Violation{{
			File:   file,
			Rule:   RuleShapeNonLiteralName,
			Detail: fmt.Sprintf("no Name() method found on the registered type %q", regType),
		}}
	}
	if method.Body == nil || len(method.Body.List) != 1 {
		return "", []Violation{{
			File:   methodFile,
			Rule:   RuleShapeNonLiteralName,
			Detail: "Name() must be a single `return \"...\"` of a string literal",
		}}
	}
	ret, ok := method.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return "", []Violation{{
			File:   methodFile,
			Rule:   RuleShapeNonLiteralName,
			Detail: "Name() must return exactly one value: a string literal",
		}}
	}
	lit, ok := ret.Results[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", []Violation{{
			File:   methodFile,
			Rule:   RuleShapeNonLiteralName,
			Detail: "Name() must return a single compile-time string literal (no concatenation, no const/var reference, no computation)",
		}}
	}
	unquoted := strings.Trim(lit.Value, "`\"")
	return unquoted, nil
}

// receiverTypeName returns the base type name of a method receiver, stripping a
// leading pointer. Returns "" if it cannot be determined.
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) != 1 {
		return ""
	}
	t := recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// isProductionGoFile reports whether name is a non-test Go source file. (A
// sibling of the identically-named helper in core/lint; kept local so selfgate
// does not depend on lint's unexported surface.)
func isProductionGoFile(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}
