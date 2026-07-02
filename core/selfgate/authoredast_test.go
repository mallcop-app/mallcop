// authoredast_test.go — PROOF tests for the K7 L3 additive-shape AST gate.
//
// Invariant 10 (ground-source testing): the clean-detector proof runs against
// the REAL reference authored detector committed to this repo
// (core/detect/authored/synthmarker), so a shape change to the reference
// detector fails these tests loudly. The rejection proofs plant each forbidden
// shape a compromised or drifting self-extension loop would emit — a sibling
// package-var write, a second init(), a compiler directive, a runtime-computed
// Name, a duplicate Name — and assert the exact sub-rule fires.
package selfgate

import (
	"os"
	"path/filepath"
	"testing"
)

// writeShapePkg materializes one authored-detector package as
// <tmp>/<dirName>/<dirName>.go and returns the package directory. dirName is
// the package's own directory (CheckAuthoredDetectorShape derives the expected
// package clause from it).
func writeShapePkg(t *testing.T, dirName, src string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, dirName+".go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

// requireShapeRule asserts at least one Violation carries the given sub-rule.
func requireShapeRule(t *testing.T, violations []Violation, rule string) {
	t.Helper()
	for _, v := range violations {
		if v.Rule == rule {
			return
		}
	}
	t.Fatalf("expected a %q shape violation, got %+v", rule, violations)
}

// requireNoShapeViolations asserts a clean pass.
func requireNoShapeViolations(t *testing.T, violations []Violation) {
	t.Helper()
	if len(violations) != 0 {
		t.Fatalf("expected a clean shape pass, got %d violation(s): %+v", len(violations), violations)
	}
}

// cleanDetectorSrc is a well-shaped authored detector: own package, one init()
// that is a single detect.Register(T{}), a Name() returning a string literal,
// and a pure Detect that mutates only local state.
const cleanDetectorSrc = `package good

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(good{}) }

type good struct{}

func (good) Name() string { return "good-detector" }

func (good) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type == "marker" {
			out = append(out, finding.Finding{ID: ev.ID})
		}
	}
	return out
}
`

// TestAuthoredShape_CleanDetectorPasses proves the gate does not just reject
// everything: a well-shaped authored detector passes with zero violations.
func TestAuthoredShape_CleanDetectorPasses(t *testing.T) {
	dir := writeShapePkg(t, "good", cleanDetectorSrc)
	violations, err := CheckAuthoredDetectorShape(dir)
	if err != nil {
		t.Fatalf("CheckAuthoredDetectorShape: %v", err)
	}
	requireNoShapeViolations(t, violations)
}

// TestAuthoredShape_RejectsForbiddenShapes plants each forbidden shape and
// asserts the exact sub-rule fires. Every fixture is otherwise well-shaped, so
// only the injected defect is under test.
func TestAuthoredShape_RejectsForbiddenShapes(t *testing.T) {
	cases := []struct {
		name    string
		dirName string
		src     string
		rule    string
	}{
		{
			name:    "assigns to a sibling package var",
			dirName: "sib",
			rule:    RuleShapeNonLocalAssign,
			src: `package sib

import "github.com/mallcop-app/mallcop/core/detect"

var sibling int

func init() { detect.Register(sib{}) }

type sib struct{}

func (sib) Name() string { return "sib-detector" }

func (sib) Detect() { sibling = 42 }
`,
		},
		{
			name:    "takes the address of a package var",
			dirName: "addr",
			rule:    RuleShapeNonLocalAssign,
			src: `package addr

import "github.com/mallcop-app/mallcop/core/detect"

var sink int

func init() { detect.Register(addr{}) }

type addr struct{}

func (addr) Name() string { return "addr-detector" }

func (addr) Detect() { p := &sink; _ = p }
`,
		},
		{
			name:    "two init functions",
			dirName: "twoinit",
			rule:    RuleShapeInit,
			src: `package twoinit

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(twoinit{}) }

func init() {}

type twoinit struct{}

func (twoinit) Name() string { return "twoinit-detector" }
`,
		},
		{
			name:    "go:linkname compiler directive",
			dirName: "linkname",
			rule:    RuleShapeCompilerDirective,
			src: `package linkname

import "github.com/mallcop-app/mallcop/core/detect"

//go:linkname sneak runtime.something
func sneak()

func init() { detect.Register(linkname{}) }

type linkname struct{}

func (linkname) Name() string { return "linkname-detector" }
`,
		},
		{
			name:    "build constraint",
			dirName: "buildtag",
			rule:    RuleShapeBuildConstraint,
			src: `//go:build linux

package buildtag

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(buildtag{}) }

type buildtag struct{}

func (buildtag) Name() string { return "buildtag-detector" }
`,
		},
		{
			name:    "cgo import",
			dirName: "cgo",
			rule:    RuleShapeCgo,
			src: `package cgo

import (
	"C"
	"github.com/mallcop-app/mallcop/core/detect"
)

func init() { detect.Register(cgo{}) }

type cgo struct{}

func (cgo) Name() string { return "cgo-detector" }
`,
		},
		{
			name:    "non-literal Name (concatenation)",
			dirName: "computed",
			rule:    RuleShapeNonLiteralName,
			src: `package computed

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(computed{}) }

type computed struct{}

func (computed) Name() string { return "computed" + "-detector" }
`,
		},
		{
			name:    "non-literal Name (var-backed)",
			dirName: "varname",
			rule:    RuleShapeNonLiteralName,
			src: `package varname

import "github.com/mallcop-app/mallcop/core/detect"

var theName = "varname-detector"

func init() { detect.Register(varname{}) }

type varname struct{}

func (varname) Name() string { return theName }
`,
		},
		{
			name:    "init is not a single Register call",
			dirName: "fatinit",
			rule:    RuleShapeInit,
			src: `package fatinit

import "github.com/mallcop-app/mallcop/core/detect"

func init() {
	detect.Register(fatinit{})
	println("side effect")
}

type fatinit struct{}

func (fatinit) Name() string { return "fatinit-detector" }
`,
		},
		{
			name:    "package clause does not match directory",
			dirName: "mismatch",
			rule:    RuleShapePackageClause,
			src: `package somethingelse

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(mismatch{}) }

type mismatch struct{}

func (mismatch) Name() string { return "mismatch-detector" }
`,
		},
		{
			// Fix #4 regression (a): a func-literal package-var initializer that
			// writes a sibling package var. The write lives in NO top-level
			// FuncDecl, so the FuncDecl-only walk missed it; checkFileAssignments
			// now scans package-level initializer func literals for non-local
			// writes.
			name:    "func-literal package-var initializer writes a non-local",
			dirName: "initwrite",
			rule:    RuleShapeNonLocalAssign,
			src: `package initwrite

import "github.com/mallcop-app/mallcop/core/detect"

var sibling int

var _ = func() int { sibling = 42; return 0 }()

func init() { detect.Register(initwrite{}) }

type initwrite struct{}

func (initwrite) Name() string { return "initwrite-detector" }
`,
		},
		{
			// Fix #4 regression (b): a call-backed package var runs code at
			// package init. checkPackageInitializers flags the impure initializer.
			name:    "call-backed package-var initializer",
			dirName: "callinit",
			rule:    RuleShapeInit,
			src: `package callinit

import "github.com/mallcop-app/mallcop/core/detect"

func sideEffect() int { return 0 }

var sink = sideEffect()

func init() { detect.Register(callinit{}) }

type callinit struct{}

func (callinit) Name() string { return "callinit-detector" }
`,
		},
		{
			// Fix #4 regression (c): a func-literal initializer that invokes code
			// but writes nothing still runs at init and is forbidden.
			name:    "func-literal package-var initializer with a call, no write",
			dirName: "initcall",
			rule:    RuleShapeInit,
			src: `package initcall

import "github.com/mallcop-app/mallcop/core/detect"

var _ = func() int { println("side effect at init"); return 0 }()

func init() { detect.Register(initcall{}) }

type initcall struct{}

func (initcall) Name() string { return "initcall-detector" }
`,
		},
		{
			// Fix #4: a SECOND detect.Register smuggled through a package-var
			// initializer func literal. checkRegistration counts only init()
			// FuncDecls, so this was invisible to the single-init invariant;
			// checkPackageInitializers now rejects the init-time code that carries
			// it.
			name:    "smuggled second detect.Register via package-var initializer",
			dirName: "smuggle",
			rule:    RuleShapeInit,
			src: `package smuggle

import "github.com/mallcop-app/mallcop/core/detect"

var _ = func() int { detect.Register(evil{}); return 0 }()

func init() { detect.Register(smuggle{}) }

type smuggle struct{}

func (smuggle) Name() string { return "smuggle-detector" }

type evil struct{}

func (evil) Name() string { return "evil-detector" }
`,
		},
		{
			// Fix #4 defence-in-depth: taking the address of a sibling package var
			// in a package-level initializer enables later mutation and is a
			// non-local write target.
			name:    "package-var initializer takes address of a package var",
			dirName: "addrinit",
			rule:    RuleShapeNonLocalAssign,
			src: `package addrinit

import "github.com/mallcop-app/mallcop/core/detect"

var sink int

var leak = &sink

func init() { detect.Register(addrinit{}) }

type addrinit struct{}

func (addrinit) Name() string { return "addrinit-detector" }
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeShapePkg(t, tc.dirName, tc.src)
			violations, err := CheckAuthoredDetectorShape(dir)
			if err != nil {
				t.Fatalf("CheckAuthoredDetectorShape: %v", err)
			}
			requireShapeRule(t, violations, tc.rule)
		})
	}
}

// TestAuthoredShape_PureDataInitializersPass proves the hardened package-level
// initializer check does not over-reject: a detector with pure literal and
// composite-literal package vars/consts (thresholds, pattern slices, a marker
// map) — the legitimate way to carry additive config — passes clean. Only
// initializers that RUN code (calls / func literals) are forbidden.
func TestAuthoredShape_PureDataInitializersPass(t *testing.T) {
	const src = `package datacfg

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

const threshold = 5

const markerType = "marker"

var patterns = []string{"alpha", "beta"}

var severities = map[string]string{"marker": "low"}

func init() { detect.Register(datacfg{}) }

type datacfg struct{}

func (datacfg) Name() string { return "datacfg-detector" }

func (datacfg) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	count := 0
	for _, ev := range events {
		if ev.Type == markerType {
			count++
			if count <= threshold {
				out = append(out, finding.Finding{ID: ev.ID, Severity: severities[ev.Type]})
			}
		}
	}
	_ = patterns
	return out
}
`
	dir := writeShapePkg(t, "datacfg", src)
	violations, err := CheckAuthoredDetectorShape(dir)
	if err != nil {
		t.Fatalf("CheckAuthoredDetectorShape: %v", err)
	}
	requireNoShapeViolations(t, violations)
}

// TestAuthoredShape_RejectsDuplicateNames proves the cross-package dedupe: two
// authored detectors that register the same Name are rejected by the tree-level
// shape check (a collision the framework would otherwise only surface as a
// runtime detect.Register panic).
func TestAuthoredShape_RejectsDuplicateNames(t *testing.T) {
	root := t.TempDir()
	pkg := func(name string) string {
		return `package ` + name + `

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(` + name + `{}) }

type ` + name + ` struct{}

func (` + name + `) Name() string { return "collides" }
`
	}
	for _, name := range []string{"aaa", "bbb"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".go"), []byte(pkg(name)), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	violations, err := CheckAuthoredDetectorTreeShape(root)
	if err != nil {
		t.Fatalf("CheckAuthoredDetectorTreeShape: %v", err)
	}
	requireShapeRule(t, violations, RuleShapeDuplicateName)
}

// TestAuthoredShape_RealReferenceDetectorPasses is the ground-source proof: the
// REAL reference authored detector committed to this repo passes the shape gate
// both per-package and via the tree walker, and the tree walker skips the
// aggregator registry.go (it is not a detector package).
func TestAuthoredShape_RealReferenceDetectorPasses(t *testing.T) {
	root := repoUnderTest(t)

	synth := filepath.Join(root, "core", "detect", "authored", "synthmarker")
	violations, err := CheckAuthoredDetectorShape(synth)
	if err != nil {
		t.Fatalf("shape-check the real reference detector: %v", err)
	}
	requireNoShapeViolations(t, violations)

	authoredRoot := filepath.Join(root, "core", "detect", "authored")
	treeViolations, err := CheckAuthoredDetectorTreeShape(authoredRoot)
	if err != nil {
		t.Fatalf("tree shape-check the real authored tree: %v", err)
	}
	requireNoShapeViolations(t, treeViolations)
}
