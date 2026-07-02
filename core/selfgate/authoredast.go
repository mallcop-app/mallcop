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
)

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
	}

	if len(files) == 0 {
		// No production Go in this directory: not a detector package. Nothing to
		// register, nothing to police.
		return "", violations, nil
	}

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

// checkFileAssignments walks every function in the file and flags any
// assignment (=, op-assign), IncDec (++/--), or address-of (&) whose target
// resolves to an identifier that is NOT locally declared within the enclosing
// function. A package-scope var, an imported-package selector, or a deref/index
// rooted at either is a non-local target and a violation — the
// same-package-mutation defence, applied even though L1 makes it structurally
// impossible.
func checkFileAssignments(path string, f *ast.File) []Violation {
	var violations []Violation
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		locals := collectLocals(fn)
		targets := collectAssignmentTargets(fn.Body)
		for _, tgt := range targets {
			if bad, detail := targetIsNonLocal(tgt.expr, locals); bad {
				violations = append(violations, Violation{
					File:   path,
					Rule:   RuleShapeNonLocalAssign,
					Detail: detail,
				})
			}
		}
	}
	return violations
}

// assignTarget is one lvalue expression that a statement writes through.
type assignTarget struct{ expr ast.Expr }

// collectAssignmentTargets gathers every write target in a function body: the
// LHS of ASSIGN/op-assign AssignStmts (DEFINE `:=` introduces locals, not
// targets, so it is skipped), IncDecStmt operands, and address-of (&) operands
// that are lvalues.
func collectAssignmentTargets(body *ast.BlockStmt) []assignTarget {
	var targets []assignTarget
	ast.Inspect(body, func(n ast.Node) bool {
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
		return true
	})
	return locals
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

// checkRegistration enforces that the package has EXACTLY ONE init() function
// whose body is a single ExprStmt calling <pkg>.Register(T{}) or
// <pkg>.Register(&T{}), where <pkg> is an imported package whose path ends in
// core/detect. It returns the registered struct type name (empty on any
// violation) so the caller can locate its Name() method.
func checkRegistration(paths []string, files []*ast.File) (regType string, violations []Violation) {
	var inits []*ast.FuncDecl
	var initFiles []string
	// detectAliases: local names bound to an import of .../core/detect.
	detectAliases := map[string]bool{}
	for i, f := range files {
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "core/detect" || strings.HasSuffix(p, "/core/detect") {
				alias := "detect"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
				detectAliases[alias] = true
			}
		}
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
