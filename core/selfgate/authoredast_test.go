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

	"github.com/mallcop-app/mallcop/core/detect"
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
		{
			// K7 HOLE 1b: an authored Detect that writes THROUGH the events
			// parameter (events[i].Payload = nil) would silence every later
			// detector reading that payload. The shape gate rejects the intent —
			// arguments are READ-ONLY — even though HOLE 1a's per-detector input
			// isolation also neutralizes the mutation at runtime (defence in depth).
			name:    "writes through the events parameter (payload silencing)",
			dirName: "silencer",
			rule:    RuleShapeNonLocalAssign,
			src: `package silencer

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(silencer{}) }

type silencer struct{}

func (silencer) Name() string { return "silencer-detector" }

func (silencer) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	for i := range events {
		events[i].Payload = nil
	}
	return nil
}
`,
		},
		{
			// K7 HOLE 1b: writing through the baseline pointer parameter
			// (bl.KnownActors = nil) narrows what every later detector sees.
			name:    "writes through the baseline parameter",
			dirName: "blwriter",
			rule:    RuleShapeNonLocalAssign,
			src: `package blwriter

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(blwriter{}) }

type blwriter struct{}

func (blwriter) Name() string { return "blwriter-detector" }

func (blwriter) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	bl.KnownActors = nil
	return nil
}
`,
		},
		{
			// Fix #1: the write side of the tuning race. An authored Detect that
			// calls detect.ApplyTuning could widen shared priv-escalation package
			// state; a leaked authored goroutine holding that reference could race a
			// concurrent scan. The only sanctioned core/detect use is the single
			// Register in init(), so the framework-mutator reference is rejected.
			name:    "calls the ApplyTuning framework mutator",
			dirName: "tuner",
			rule:    RuleShapeFrameworkRef,
			src: `package tuner

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(tuner{}) }

type tuner struct{}

func (tuner) Name() string { return "tuner-detector" }

func (tuner) Detect() { detect.ApplyTuning(detect.Tuning{}) }
`,
		},
		{
			// Fix #1: any core/detect member other than the init Register is
			// forbidden — here re-entering detect.Detect from an authored detector
			// (which could recurse or reach shared aggregation state).
			name:    "reaches detect.Detect (a non-Register framework member)",
			dirName: "reenter",
			rule:    RuleShapeFrameworkRef,
			src: `package reenter

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(reenter{}) }

type reenter struct{}

func (reenter) Name() string { return "reenter-detector" }

func (reenter) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	return detect.Detect(events, bl)
}
`,
		},
		{
			// Fix #1: a detect.Register call OUTSIDE init() (in Detect) is not the
			// sanctioned self-registration — it is a framework reference and is
			// rejected even though it is a Register.
			name:    "calls detect.Register outside init()",
			dirName: "reg2",
			rule:    RuleShapeFrameworkRef,
			src: `package reg2

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(reg2{}) }

type reg2 struct{}

func (reg2) Name() string { return "reg2-detector" }

func (reg2) Detect() { detect.Register(evil2{}) }

type evil2 struct{}

func (evil2) Name() string { return "evil2-detector" }
`,
		},
		{
			// Fix #3: a condition-less for-loop with no exit spins forever, hanging
			// the scan until the L4 deadline fires and leaking a goroutine.
			name:    "condition-less for-loop that never exits",
			dirName: "spinner",
			rule:    RuleShapeUnboundedLoop,
			src: `package spinner

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(spinner{}) }

type spinner struct{}

func (spinner) Name() string { return "spinner-detector" }

func (spinner) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	n := 0
	for {
		n++
	}
}
`,
		},
		{
			// Fix #3: an empty select{} blocks forever — same leaked-goroutine DoS.
			name:    "empty select blocks forever",
			dirName: "blocker",
			rule:    RuleShapeUnboundedLoop,
			src: `package blocker

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(blocker{}) }

type blocker struct{}

func (blocker) Name() string { return "blocker-detector" }

func (blocker) Detect() { select {} }
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

// TestAuthoredShape_LocalThroughWritesPass proves checkParamWrites does not
// over-reject: a detector that writes THROUGH its own LOCAL slices/maps
// (index/field assignment rooted at a `:=`-declared local, not a parameter) is
// the normal way a pure detector accumulates state and must pass clean. Only
// writes rooted at the events/baseline PARAMETERS are forbidden.
func TestAuthoredShape_LocalThroughWritesPass(t *testing.T) {
	const src = `package localwrite

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(localwrite{}) }

type localwrite struct{}

func (localwrite) Name() string { return "localwrite-detector" }

func (localwrite) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	seen := map[string]int{}
	buf := make([]byte, len(events))
	var out []finding.Finding
	for i, ev := range events {
		seen[ev.Actor]++    // through-write rooted at a LOCAL map
		buf[i] = byte(i)    // through-write rooted at a LOCAL slice
		out = append(out, finding.Finding{ID: ev.ID})
	}
	_ = seen
	_ = buf
	return out
}
`
	dir := writeShapePkg(t, "localwrite", src)
	violations, err := CheckAuthoredDetectorShape(dir)
	if err != nil {
		t.Fatalf("CheckAuthoredDetectorShape: %v", err)
	}
	requireNoShapeViolations(t, violations)
}

// TestAuthoredShape_BoundedLoopsPass proves checkUnboundedLoops does not
// over-reject: a detector that uses a counted for-loop, a condition-ful loop, and
// a condition-less loop WITH a reachable break/return — the normal ways a pure
// detector iterates and terminates — passes clean. Only PROVABLY non-terminating
// constructs are forbidden.
func TestAuthoredShape_BoundedLoopsPass(t *testing.T) {
	const src = `package looper

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(looper{}) }

type looper struct{}

func (looper) Name() string { return "looper-detector" }

func (looper) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for i := 0; i < len(events); i++ { // counted loop
		out = append(out, finding.Finding{ID: events[i].ID})
	}
	i := 0
	for i < len(events) { // condition-ful loop
		i++
	}
	for { // condition-less BUT breaks — terminates, so allowed
		if i <= 0 {
			break
		}
		i--
	}
	for { // condition-less BUT returns
		return out
	}
}
`
	dir := writeShapePkg(t, "looper", src)
	violations, err := CheckAuthoredDetectorShape(dir)
	if err != nil {
		t.Fatalf("CheckAuthoredDetectorShape: %v", err)
	}
	requireNoShapeViolations(t, violations)
}

// TestAuthoredShape_RejectsFrameworkNameCollision proves K7 HOLE 2: an authored
// detector whose Name() collides with an EXISTING FRAMEWORK detector
// ("injection-probe") is a DETERMINISTIC pre-merge RuleShapeDuplicateName
// rejection — not the unrecovered detect.Register panic that would otherwise
// crash cmd/mallcop at init and only surface when stage-3 exam-detect execs the
// crashing binary.
func TestAuthoredShape_RejectsFrameworkNameCollision(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "collider")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Sanity: the name we collide with must actually be a live framework detector.
	if !frameworkNameRegistered(t, "injection-probe") {
		t.Fatal("precondition failed: no framework detector named \"injection-probe\" is registered")
	}
	src := `package collider

import "github.com/mallcop-app/mallcop/core/detect"

func init() { detect.Register(collider{}) }

type collider struct{}

func (collider) Name() string { return "injection-probe" }
`
	if err := os.WriteFile(filepath.Join(dir, "collider.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	violations, err := CheckAuthoredDetectorTreeShape(root)
	if err != nil {
		t.Fatalf("CheckAuthoredDetectorTreeShape: %v", err)
	}
	requireShapeRule(t, violations, RuleShapeDuplicateName)
}

// frameworkNameRegistered reports whether name is a live framework detector, via
// the same registry the shape gate seeds its uniqueness set from.
func frameworkNameRegistered(t *testing.T, name string) bool {
	t.Helper()
	for _, d := range detect.Detectors() {
		if d.Name() == name {
			return true
		}
	}
	return false
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

// TestAuthoredShape_RejectsNestedMaliciousPackage is the K7 re-red-team
// regression: the tree shape gate must be DEPTH-COMPLETE. A malicious authored
// package planted NOT as an immediate child of root but nested deeper
// (root/outer/inner/) still compiles into cmd/mallcop via the aggregator's
// transitive imports, so the shape gate must descend to any depth. Here the
// nested package carries all three headline defects at once — a Name() that
// collides with a framework detector (seeded into the uniqueness set), a
// non-local assignment to a package var, and a condition-less for{} that never
// exits. Before the fix the walk stopped at depth 1 and reported NOTHING; now
// all three sub-rules must fire, proving the nested package was shape-checked.
func TestAuthoredShape_RejectsNestedMaliciousPackage(t *testing.T) {
	if !frameworkNameRegistered(t, "injection-probe") {
		t.Fatal("precondition failed: no framework detector named \"injection-probe\" is registered")
	}
	root := t.TempDir()
	// root/outer holds no production Go (not a package); the malicious package
	// lives two levels down at root/outer/inner/.
	dir := filepath.Join(root, "outer", "inner")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := `package inner

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

var sink int

func init() { detect.Register(inner{}) }

type inner struct{}

func (inner) Name() string { return "injection-probe" }

func (inner) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	sink = 1
	for {
		sink++
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "inner.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	violations, err := CheckAuthoredDetectorTreeShape(root)
	if err != nil {
		t.Fatalf("CheckAuthoredDetectorTreeShape: %v", err)
	}
	requireShapeRule(t, violations, RuleShapeDuplicateName)
	requireShapeRule(t, violations, RuleShapeNonLocalAssign)
	requireShapeRule(t, violations, RuleShapeUnboundedLoop)
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
