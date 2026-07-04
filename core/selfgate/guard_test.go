// guard_test.go — PROOF tests for the K3 static invariant guard.
//
// Invariant 10 (ground-source testing): the rejection proofs run against REAL
// repo content, not synthetic strawmen. Every fixture repo is seeded by
// COPYING THE REAL FILES from the repository under test (located by walking up
// to go.mod), then the "proposal" mutates that real content the way a
// compromised or drifting self-extension loop would. If the real files change
// shape, replaceOnce fails loudly and the proof mutation must be updated — the
// proofs never silently degrade into testing fabricated content.
package selfgate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- fixture: temp git repos seeded from the real repo ----------------------

// repoUnderTest locates the real repository root by walking up from the test's
// working directory to go.mod.
func repoUnderTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
}

// fixture is a temp git repo the tests seed (from real files), commit, mutate,
// and run Guard over.
type fixture struct {
	t    *testing.T
	dir  string // temp git repo
	root string // real repo root (source of the copied files)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "init", "-q")
	return &fixture{t: t, dir: dir, root: repoUnderTest(t)}
}

// copyReal copies the REAL file at rel from the repo under test into the
// fixture repo at the same path and returns its content for mutation.
func (f *fixture) copyReal(rel string) string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(rel)))
	if err != nil {
		f.t.Fatalf("copy real %s: %v", rel, err)
	}
	f.write(rel, string(data))
	return string(data)
}

func (f *fixture) write(rel, content string) {
	f.t.Helper()
	abs := filepath.Join(f.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		f.t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		f.t.Fatalf("write %s: %v", rel, err)
	}
}

func (f *fixture) remove(rel string) {
	f.t.Helper()
	if err := os.Remove(filepath.Join(f.dir, filepath.FromSlash(rel))); err != nil {
		f.t.Fatalf("remove %s: %v", rel, err)
	}
}

// commit stages everything and commits, returning the commit hash.
func (f *fixture) commit(msg string) string {
	f.t.Helper()
	mustGit(f.t, f.dir, "add", "-A")
	mustGit(f.t, f.dir, "commit", "-q", "--no-verify", "-m", msg)
	return strings.TrimSpace(mustGit(f.t, f.dir, "rev-parse", "HEAD"))
}

// guard runs Guard in DEFAULT mode (customerTreeMode=false — byte-for-byte the
// prior mallcoppro-72d behavior) over the fixture and fails the test on
// operational error.
func (f *fixture) guard(base, head string) []GuardFinding {
	f.t.Helper()
	findings, err := Guard(f.dir, base, head, false)
	if err != nil {
		f.t.Fatalf("Guard: %v", err)
	}
	return findings
}

// guardCustomerTree runs Guard in CUSTOMER-TREE mode (mallcoppro-97b) over the
// fixture and fails the test on operational error.
func (f *fixture) guardCustomerTree(base, head string) []GuardFinding {
	f.t.Helper()
	findings, err := Guard(f.dir, base, head, true)
	if err != nil {
		f.t.Fatalf("Guard: %v", err)
	}
	return findings
}

// mustGit runs the package's hermetic git chokepoint and fails the test on
// error.
func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runGit(dir, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

// replaceOnce asserts old occurs EXACTLY once in the real content (so the
// proof mutation is still anchored to reality) and replaces it.
func replaceOnce(t *testing.T, content, old, new string) string {
	t.Helper()
	if n := strings.Count(content, old); n != 1 {
		t.Fatalf("expected exactly 1 occurrence of %q in the real content, found %d — the repo under test changed; update the proof mutation", old, n)
	}
	return strings.Replace(content, old, new, 1)
}

// requireRejected asserts at least one finding with the given rule whose Path
// contains pathFragment.
func requireRejected(t *testing.T, findings []GuardFinding, rule, pathFragment string) {
	t.Helper()
	for _, f := range findings {
		if f.Rule == rule && strings.Contains(f.Path, pathFragment) {
			return
		}
	}
	t.Fatalf("expected a %q finding for path containing %q; got %+v", rule, pathFragment, findings)
}

// requireClean asserts zero findings.
func requireClean(t *testing.T, findings []GuardFinding) {
	t.Helper()
	if len(findings) != 0 {
		t.Fatalf("expected a clean guard pass, got %d finding(s): %+v", len(findings), findings)
	}
}

// requireDetailContains asserts at least one finding with the given rule whose
// Detail contains the substring — used to prove a finding names the right family.
func requireDetailContains(t *testing.T, findings []GuardFinding, rule, sub string) {
	t.Helper()
	for _, f := range findings {
		if f.Rule == rule && strings.Contains(f.Detail, sub) {
			return
		}
	}
	t.Fatalf("expected a %q finding whose detail contains %q; got %+v", rule, sub, findings)
}

// ---- REJECT proofs (real content, real attack shapes) -----------------------

// (a) A hand-fed diff editing the REAL core/agent/hardconstraints.go to add a
// force-escalate constant is rejected: the pre-LLM floor's MECHANISM is a
// protected path — policy lives in data, never in new Go constants.
func TestGuard_RejectsForceEscalateConstantInHardConstraints(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("core/agent/hardconstraints.go")
	base := f.commit("base")

	f.write("core/agent/hardconstraints.go", real+"\n// smuggled by the loop\nconst forceEscalateExtraFamily = \"totally-benign\"\n")
	head := f.commit("proposal: add force-escalate constant")

	requireRejected(t, f.guard(base, head), RuleProtectedPath, "core/agent/hardconstraints.go")
}

// (b) Lowering DefaultConsensusRuns / zeroing the consensus temperature in the
// REAL core/agent/consensus.go — the committee-weakening case — is rejected.
func TestGuard_RejectsWeakeningTheConsensusCommittee(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("core/agent/consensus.go")
	base := f.commit("base")

	mutated := replaceOnce(t, real, "const DefaultConsensusRuns = 3", "const DefaultConsensusRuns = 0")
	mutated = replaceOnce(t, mutated, "const consensusTemperature = 1.0", "const consensusTemperature = 0.0")
	f.write("core/agent/consensus.go", mutated)
	head := f.commit("proposal: weaken consensus")

	requireRejected(t, f.guard(base, head), RuleProtectedPath, "core/agent/consensus.go")
}

// (c) Mutating injectionPatterns in the REAL, EXISTING
// core/detect/injection_probe.go (narrowing a SECURITY-CRITICAL pattern so it
// never fires) is rejected: existing detector code is frozen.
func TestGuard_RejectsMutatingInjectionPatterns(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("core/detect/injection_probe.go")
	base := f.commit("base")

	mutated := replaceOnce(t, real,
		`(?i)\bignore\s+(all\s+)?previous\s+instructions?\b`,
		`(?i)\bignore_nothing_ever\b`)
	f.write("core/detect/injection_probe.go", mutated)
	head := f.commit("proposal: narrow an injection pattern")

	requireRejected(t, f.guard(base, head), RuleDetectCodeFrozen, "core/detect/injection_probe.go")
}

// (d) Adding an entry under the REAL operator-decisions.yaml rules: section (a
// smuggled auto-resolve for a dangerous family) is rejected: the global
// resolution rules are frozen (invariant 1).
func TestGuard_RejectsAddingAResolveRule(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("agents/rules/operator-decisions.yaml")
	base := f.commit("base")

	smuggled := real + `
  - id: "R-999"
    applies_to:
      family: "priv-escalation"
      metadata_match:
        approved: "true"
    operator_directive: |
      Smuggled auto-resolve for privilege escalation.
`
	f.write("agents/rules/operator-decisions.yaml", smuggled)
	head := f.commit("proposal: add resolve rule")

	requireRejected(t, f.guard(base, head), RuleOperatorDecisionsWidenOnly, "operator-decisions.yaml")
}

// (e) Deleting an escalate_route alias from the REAL corpus (an evasion
// spelling stops force-escalating) is rejected: alias sets may only grow.
func TestGuard_RejectsDeletingAnEscalateRouteAlias(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("agents/rules/operator-decisions.yaml")
	base := f.commit("base")

	f.write("agents/rules/operator-decisions.yaml", replaceOnce(t, real, `, "privesc"`, ""))
	head := f.commit("proposal: drop the privesc alias")

	requireRejected(t, f.guard(base, head), RuleOperatorDecisionsWidenOnly, "operator-decisions.yaml")
}

// (f) Adding metadata_match to an EXISTING route in the REAL corpus is
// rejected: the conjunctive predicate NARROWS when the route fires — an
// injection-probe finding without the smuggled marker would stop escalating.
func TestGuard_RejectsAddingMetadataMatchToExistingRoute(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("agents/rules/operator-decisions.yaml")
	base := f.commit("base")

	mutated := replaceOnce(t, real,
		`family: "injection-probe"`,
		"family: \"injection-probe\"\n    metadata_match:\n      probe_source: \"external\"")
	f.write("agents/rules/operator-decisions.yaml", mutated)
	head := f.commit("proposal: narrow E-002 with a predicate")

	requireRejected(t, f.guard(base, head), RuleOperatorDecisionsWidenOnly, "operator-decisions.yaml")
}

// (g) Removing a keyword from the REAL detectors/tuning.yaml (undoing the
// PE-08 poweruser FN-close) is rejected: every base element must survive into
// head.
func TestGuard_RejectsRemovingATuningKeyword(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("detectors/tuning.yaml")
	base := f.commit("base")

	f.write("detectors/tuning.yaml", replaceOnce(t, real, "\n    - poweruser", ""))
	head := f.commit("proposal: drop poweruser keyword")

	requireRejected(t, f.guard(base, head), RuleDetectorDataWidenOnly, "detectors/tuning.yaml")
}

// The guard protects ITSELF: modifying core/selfgate/guard.go (e.g. shrinking
// the protected set) is rejected.
func TestGuard_RejectsEditingTheGuardItself(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("core/selfgate/guard.go")
	base := f.commit("base")

	f.write("core/selfgate/guard.go", real+"\n// loosened\n")
	head := f.commit("proposal: edit the guard")

	requireRejected(t, f.guard(base, head), RuleProtectedPath, "core/selfgate/guard.go")
}

// Representative protected paths (the tool interpreters incl. the
// expectedOperatorRulesSHA256 pin, the CLI entrypoints, the module file): any
// modification of the REAL files is rejected.
func TestGuard_RejectsProtectedPathModifications(t *testing.T) {
	for _, rel := range []string{
		"core/tools/lookup_rules.go",
		"cmd/mallcop/main.go",
		"go.mod",
	} {
		t.Run(rel, func(t *testing.T) {
			f := newFixture(t)
			real := f.copyReal(rel)
			base := f.commit("base")

			f.write(rel, real+"\n// tampered\n")
			head := f.commit("proposal: tamper")

			requireRejected(t, f.guard(base, head), RuleProtectedPath, rel)
		})
	}
}

// Existing exam scenarios are frozen: modifying or deleting a REAL labeled
// scenario is rejected (the grader's ground truth is out of the agent's
// reach).
func TestGuard_RejectsTouchingExistingScenarios(t *testing.T) {
	const scenario = "exams/scenarios/behavioral/UT-02-maintenance-window.yaml"

	t.Run("modify", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal(scenario)
		base := f.commit("base")
		f.write(scenario, real+"\n# nudged ground truth\n")
		head := f.commit("proposal: edit scenario")
		requireRejected(t, f.guard(base, head), RuleScenarioFrozen, scenario)
	})

	t.Run("delete", func(t *testing.T) {
		f := newFixture(t)
		f.copyReal(scenario)
		base := f.commit("base")
		f.remove(scenario)
		head := f.commit("proposal: delete scenario")
		requireRejected(t, f.guard(base, head), RuleScenarioFrozen, scenario)
	})
}

// A BARE corpus.pin repin (no accompanying additive scenario change) is
// rejected: a standalone repin only ever means the pinned corpus drifted.
func TestGuard_RejectsBareCorpusPinRepin(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("exams/scenarios/corpus.pin")
	base := f.commit("base")

	f.write("exams/scenarios/corpus.pin", replaceOnce(t, real, "count 58", "count 57"))
	head := f.commit("proposal: bare repin")

	requireRejected(t, f.guard(base, head), RuleCorpusPinPairing, "corpus.pin")
}

// An unrecognized tuning.yaml shape ("priv_escalation: disabled" — a scalar
// where the section mapping belongs) FAILS CLOSED, even though no list element
// was provably removed.
func TestGuard_RejectsUnrecognizedTuningStructure(t *testing.T) {
	f := newFixture(t)
	f.copyReal("detectors/tuning.yaml")
	base := f.commit("base")

	f.write("detectors/tuning.yaml", "priv_escalation: disabled\n")
	head := f.commit("proposal: disable the section")

	requireRejected(t, f.guard(base, head), RuleDetectorDataWidenOnly, "detectors/tuning.yaml")
}

// mallcoppro-72d (the 7ee7 live-leg probe HOLE): a brand-new .go file ADDED
// under detectors/ must NOT sail through unchecked. Before the fix, the
// detectorsPrefix case's inner switch had no arm for a .go path at all — an
// 'A' status matched none of its cases (D / M-non-YAML / M) and fell straight
// through to the "'A' passes" comment, so this exact proposal shape (a
// customer-tree wasm-sidecar detector add, e.g.
// detectors/authored-force-push-guard/main.go) passed stage-1 with ZERO
// findings. It must now be rejected (RuleCodeFrozen): detectors/ has no
// sanctioned Go code lane, and the authored-lane AST shape gate cannot
// evaluate a `package main` + detectorhost.Run(T{}) sidecar shape anyway.
func TestGuard_RejectsNewGoFileAddedUnderDetectors(t *testing.T) {
	f := newFixture(t)
	f.copyReal("detectors/tuning.yaml") // anchor a real detectors/ tree at base
	base := f.commit("base")

	f.write("detectors/authored-force-push-guard/main.go", `package main

import (
	"os"

	"github.com/mallcop-app/mallcop/pkg/detectorhost"
)

// evilDetector is arbitrary Go content standing in for whatever the 7ee7
// live-leg probe smuggled — the guard must reject this on SHAPE (any Go
// source under detectors/), not on content inspection.
type evilDetector struct{}

func (evilDetector) Name() string { return "authored-force-push-guard" }

func main() {
	os.Exit(detectorhost.Run(evilDetector{}))
}
`)
	head := f.commit("proposal: add a new detector under detectors/")

	requireRejected(t, f.guard(base, head), RuleCodeFrozen, "detectors/authored-force-push-guard/main.go")
}

// A Modify of an existing .go file under detectors/ is ALSO rejected via the
// dedicated .go arm (RuleCodeFrozen), not the pre-existing
// RuleDetectorDataWidenOnly "modification of anything else" arm — proving the
// new .go-suffix case is checked BEFORE (and instead of) the non-YAML-modify
// case for Go paths specifically.
func TestGuard_RejectsModifiedGoFileUnderDetectors(t *testing.T) {
	f := newFixture(t)
	f.write("detectors/existing-detector/main.go", "package main\n\nfunc main() {}\n")
	base := f.commit("base")

	f.write("detectors/existing-detector/main.go", "package main\n\nfunc main() { println(\"tampered\") }\n")
	head := f.commit("proposal: modify an existing detectors/ go file")

	requireRejected(t, f.guard(base, head), RuleCodeFrozen, "detectors/existing-detector/main.go")
}

// ---- CUSTOMER-TREE MODE: the sidecar-shape AST gate (mallcoppro-97b) --------
//
// The tests above prove DEFAULT mode is byte-for-byte unchanged (mallcoppro-72d
// unmodified). These prove the SIBLING lane the orchestrator ruling adds:
// customerTreeMode=true (f.guardCustomerTree) routes a .go Add under
// detectors/<name>/ through the sidecar-shape gate (sidecarshape.go) instead
// of the blanket RuleCodeFrozen deny — and that gate is at least as
// restrictive in spirit as the in-tree K7 shape gate.

// sidecarWellBehavedMainSrc is the baseline well-shaped sidecar detector every
// ACCEPT test below starts from (same shape as customergate_test.go's
// customerFixtureDetectorMainSrc, duplicated here so guard_test.go's proofs
// don't depend on a fixture defined in a different test file).
const sidecarWellBehavedMainSrc = `package main

import (
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type widgetLeakDetector struct{}

func (widgetLeakDetector) Name() string { return "widget-leak" }

func (widgetLeakDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type == "widget-secret-exposed" {
			out = append(out, finding.Finding{ID: "finding-" + ev.ID, Source: "detector:widget-leak"})
		}
	}
	return out
}

func main() { os.Exit(detectorhost.Run(widgetLeakDetector{})) }
`

// anchorCustomerTreeBase seeds a base commit with a real detectors/ tree
// (mirroring the 72d tests' copyReal anchor) so every sidecar-shape test below
// diffs a real "add a detector" proposal, not a from-nothing repo.
func anchorCustomerTreeBase(f *fixture) string {
	f.copyReal("detectors/tuning.yaml")
	return f.commit("base")
}

// TestGuard_CustomerTreeSidecarShape_AcceptsWellBehavedDetector is the
// control: a well-shaped sidecar detector (package main, one func main() whose
// body is `os.Exit(detectorhost.Run(T{}))`, an allow-listed import surface)
// passes CUSTOMER-TREE mode cleanly — and (sanity, mirroring
// TestGuard_RejectsNewGoFileAddedUnderDetectors) is STILL rejected in DEFAULT
// mode on the exact same content, proving the two modes are independent
// knobs, not "customer mode is default mode plus exceptions."
func TestGuard_CustomerTreeSidecarShape_AcceptsWellBehavedDetector(t *testing.T) {
	f := newFixture(t)
	base := anchorCustomerTreeBase(f)

	f.write("detectors/widget-leak/main.go", sidecarWellBehavedMainSrc)
	head := f.commit("proposal: add a well-shaped sidecar detector")

	requireClean(t, f.guardCustomerTree(base, head))
	requireRejected(t, f.guard(base, head), RuleCodeFrozen, "detectors/widget-leak/main.go")
}

// (a) An import outside the allow list (net/http) is rejected — the shape
// gate's import allow-list bites even when everything else about the file
// (package main, the one main()/detectorhost.Run shape) is otherwise correct.
func TestGuard_CustomerTreeSidecarShape_RejectsDisallowedImport(t *testing.T) {
	f := newFixture(t)
	base := anchorCustomerTreeBase(f)

	src := strings.Replace(sidecarWellBehavedMainSrc,
		"\t\"github.com/mallcop-app/mallcop/pkg/baseline\"\n",
		"\t\"net/http\"\n\n\t\"github.com/mallcop-app/mallcop/pkg/baseline\"\n",
		1)
	src = strings.Replace(src,
		"type widgetLeakDetector struct{}\n",
		"type widgetLeakDetector struct{}\n\nvar _ = http.MethodGet // pure reference; proves the import itself is what trips the gate\n",
		1)
	f.write("detectors/widget-leak/main.go", src)
	head := f.commit("proposal: add a detector that imports net/http")

	findings := f.guardCustomerTree(base, head)
	requireRejected(t, findings, RuleSidecarShape, "detectors/widget-leak/main.go")
	requireDetailContains(t, findings, RuleSidecarShape, "sidecar-import-not-allowed")
	requireDetailContains(t, findings, RuleSidecarShape, "net/http")
}

// (b) main() not calling detectorhost.Run at all is rejected — a sidecar that
// never hands itself to the host cannot be the real deployed artifact.
func TestGuard_CustomerTreeSidecarShape_RejectsMissingDetectorhostRun(t *testing.T) {
	f := newFixture(t)
	base := anchorCustomerTreeBase(f)

	f.write("detectors/widget-leak/main.go", "package main\n\nfunc main() { println(\"no detectorhost call here\") }\n")
	head := f.commit("proposal: add a detector whose main() never calls detectorhost.Run")

	findings := f.guardCustomerTree(base, head)
	requireRejected(t, findings, RuleSidecarShape, "detectors/widget-leak/main.go")
	requireDetailContains(t, findings, RuleSidecarShape, "sidecar-main-shape")
}

// (c) DECISION (orchestrator ruling asked to justify): an extra top-level
// helper func is NOT a shape violation. The gate's SHAPE constraint is
// main()'s body + the import surface + the os/detectorhost confinement —
// deliberately NOT a func-count floor on the package, because the detector
// implementation legitimately needs its own helper funcs (here: a classifier
// used by Detect). A func-count restriction would be over-strict and would
// reject ordinary, safe detector code for no security benefit: an uncalled or
// helper func can only reach the same bounded import surface every other file
// in the package is already held to (see checkSidecarImportAllowlist) and
// cannot itself invoke os or detectorhost (see the confinement proof in
// TestGuard_CustomerTreeSidecarShape_RejectsOSMisuseBeyondExit below) — so
// there is no attack surface a bare func count would be closing.
func TestGuard_CustomerTreeSidecarShape_ExtraHelperFuncAllowed(t *testing.T) {
	f := newFixture(t)
	base := anchorCustomerTreeBase(f)

	src := strings.Replace(sidecarWellBehavedMainSrc,
		"\t\"github.com/mallcop-app/mallcop/pkg/event\"\n",
		"\t\"strings\"\n\n\t\"github.com/mallcop-app/mallcop/pkg/event\"\n",
		1)
	src = strings.Replace(src,
		"if ev.Type == \"widget-secret-exposed\" {",
		"if isWidgetSecretEvent(ev.Type) {",
		1)
	src = strings.Replace(src,
		"func main() { os.Exit(detectorhost.Run(widgetLeakDetector{})) }\n",
		"// isWidgetSecretEvent is an extra top-level helper func alongside the\n"+
			"// detector methods and main() — proving the gate does not floor on func count.\n"+
			"func isWidgetSecretEvent(t string) bool { return strings.HasPrefix(t, \"widget-secret-exposed\") }\n\n"+
			"func main() { os.Exit(detectorhost.Run(widgetLeakDetector{})) }\n",
		1)
	f.write("detectors/widget-leak/main.go", src)
	head := f.commit("proposal: add a detector with an extra top-level helper func")

	requireClean(t, f.guardCustomerTree(base, head))
}

// (d) A second .go file in the same detector directory adding an init() with
// side effects is rejected. init() runs before main()'s single verified
// statement and is invisible to the main-shape check — banning it outright is
// the only sound closure (an allow-listed "harmless" init is not distinguishable
// from one with side effects by shape alone).
func TestGuard_CustomerTreeSidecarShape_RejectsInitWithSideEffects(t *testing.T) {
	f := newFixture(t)
	base := anchorCustomerTreeBase(f)

	f.write("detectors/widget-leak/main.go", sidecarWellBehavedMainSrc)
	f.write("detectors/widget-leak/sideeffect.go", "package main\n\nimport \"fmt\"\n\nfunc init() {\n\tfmt.Println(\"side effect at package init, before main ever runs\")\n}\n")
	head := f.commit("proposal: add a well-shaped detector plus a side-effecting init()")

	findings := f.guardCustomerTree(base, head)
	requireRejected(t, findings, RuleSidecarShape, "detectors/widget-leak/sideeffect.go")
	requireDetailContains(t, findings, RuleSidecarShape, "sidecar-init-forbidden")
}

// BONUS (closes the "os is allow-listed so anything os.* goes" bypass a naive
// reading of the import allow-list alone would miss): os is imported (needed
// for the sanctioned os.Exit(...) wrapper) but ALSO used elsewhere in the same
// file (inside Detect) — os.Getenv, reading environment state no detector has
// any legitimate reason to touch. The os-confinement rule (checkSidecarMainAndOS)
// must catch this even though "os" itself is on the allow list.
func TestGuard_CustomerTreeSidecarShape_RejectsOSMisuseBeyondExit(t *testing.T) {
	f := newFixture(t)
	base := anchorCustomerTreeBase(f)

	src := strings.Replace(sidecarWellBehavedMainSrc,
		"\t\tif ev.Type == \"widget-secret-exposed\" {\n",
		"\t\t_ = os.Getenv(\"WIDGET_LEAK_SECRET\") // illicit: os's only sanctioned use is the os.Exit wrapper in main()\n\t\tif ev.Type == \"widget-secret-exposed\" {\n",
		1)
	f.write("detectors/widget-leak/main.go", src)
	head := f.commit("proposal: add a detector that misuses os beyond the Exit wrapper")

	findings := f.guardCustomerTree(base, head)
	requireRejected(t, findings, RuleSidecarShape, "detectors/widget-leak/main.go")
	requireDetailContains(t, findings, RuleSidecarShape, "sidecar-main-shape")
	requireDetailContains(t, findings, RuleSidecarShape, "os.Getenv")
}

// ---- ACCEPT proofs (the widens the loop is FOR) ------------------------------

// (h) The exact K2b-shaped change passes: a new extra_elevated_keywords entry
// in the REAL detectors/tuning.yaml, paired with an additive new scenario file
// and the corpus.pin repin.
func TestGuard_AcceptsK2bShapedTuningWiden(t *testing.T) {
	f := newFixture(t)
	tuning := f.copyReal("detectors/tuning.yaml")
	pin := f.copyReal("exams/scenarios/corpus.pin")
	scenario := f.copyReal("exams/scenarios/behavioral/UT-02-maintenance-window.yaml")
	base := f.commit("base")

	f.write("detectors/tuning.yaml", replaceOnce(t, tuning, "\n    - poweruser", "\n    - poweruser\n    - clusteradmin"))
	f.write("exams/scenarios/privilege/PE-99-clusteradmin-grant.yaml", scenario) // additive new scenario
	f.write("exams/scenarios/corpus.pin", replaceOnce(t, pin, "count 58", "count 59"))
	head := f.commit("proposal: K2b-shaped widen + scenario + repin")

	requireClean(t, f.guard(base, head))
}

// (i) A NEW .go file directly under core/detect/ is REJECTED (RuleDetectCodeFrozen).
// This is the closed §5 L1 break: a new file directly under core/detect/ is
// `package detect` — the SHARED framework package — and its init() could mutate
// a sibling detector's unexported state. The sanctioned additive lane is the
// OWN-PACKAGE tree core/detect/authored/<name>/, not this package.
func TestGuard_RejectsNewFileDirectlyUnderDetect(t *testing.T) {
	f := newFixture(t)
	f.copyReal("core/detect/injection_probe.go")
	base := f.commit("base")

	f.write("core/detect/new_signal_probe.go", "package detect\n\n// a new file in the SHARED framework package — the L1 break, now frozen\n")
	head := f.commit("proposal: new file directly in the shared detect package")

	requireRejected(t, f.guard(base, head), RuleDetectCodeFrozen, "core/detect/new_signal_probe.go")
}

// (j) An additive escalate_routes entry in the REAL corpus, WITHOUT the Go pin
// edit, passes the semantic widen rule. In production the UNCHANGED
// expectedOperatorRulesSHA256 pin (core/tools/lookup_rules.go — a protected
// path the proposal cannot touch) means the corpus SHA check fires at runtime,
// so the widen reaches the HUMAN tier by construction. The second half proves
// the other side: pairing the widen WITH the pin edit is rejected.
func TestGuard_AcceptsAdditiveEscalateRouteWithoutPinEdit(t *testing.T) {
	const newRoute = `  - id: "E-100"
    family: "credential-stuffing"
    aliases: ["cred-stuffing"]
    reason: |
      New dangerous family proposed by the loop; always route to a human.

`
	seed := func(t *testing.T) (*fixture, string, string) {
		f := newFixture(t)
		real := f.copyReal("agents/rules/operator-decisions.yaml")
		f.copyReal("core/tools/lookup_rules.go")
		base := f.commit("base")
		widened := replaceOnce(t, real, "\nrules:\n", "\n"+newRoute+"\nrules:\n")
		f.write("agents/rules/operator-decisions.yaml", widened)
		return f, base, widened
	}

	t.Run("widen without pin edit passes the guard (runtime pin -> human tier)", func(t *testing.T) {
		f, base, _ := seed(t)
		head := f.commit("proposal: additive route only")
		requireClean(t, f.guard(base, head))
	})

	t.Run("widen paired with the pin edit is rejected (no mechanical-pair exception)", func(t *testing.T) {
		f, base, _ := seed(t)
		pinFile, err := os.ReadFile(filepath.Join(f.dir, "core/tools/lookup_rules.go"))
		if err != nil {
			t.Fatalf("read fixture lookup_rules.go: %v", err)
		}
		f.write("core/tools/lookup_rules.go", string(pinFile)+"\n// repinned by the loop\n")
		head := f.commit("proposal: route + pin edit")
		requireRejected(t, f.guard(base, head), RuleProtectedPath, "core/tools/lookup_rules.go")
	})
}

// The consensus-bypass proof: core/observe computes the PRODUCTION
// force-escalate floor (ZeroHistoryAccess / RoleGrantByActor /
// BulkExportNoJustification), core/toolrun wires it into the cascade, and
// core/store backs it — NONE of these were in protectedPrefixes, so the old
// guard let an attacker neuter a predicate (e.g. ZeroHistoryAccess -> false,
// disabling lateral-movement escalation) and pass the whole free tier. The Go
// default-deny floor rejects Modify of ANY existing .go file on the decision
// path, regardless of what the diff content is.
func TestGuard_RejectsModifyingDecisionPathGoCode(t *testing.T) {
	cases := []struct {
		path   string
		mutate func(t *testing.T, real string) string
	}{
		{
			// The exact red-team attack: neuter the lateral-movement predicate
			// so it never force-escalates (return true -> return false).
			path: "core/observe/observe.go",
			mutate: func(t *testing.T, real string) string {
				return replaceOnce(t, real,
					`return true, actor + " → " + target + " (no relationship history)"`,
					`return false, actor + " → " + target + " (no relationship history)"`)
			},
		},
		{
			path:   "core/toolrun/toolrun.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{
			path:   "core/store/store.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{
			path:   "core/store/records.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{
			path:   "core/connect/connect.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{ // non-contract pkg/** (pkg/event, pkg/finding, pkg/baseline are the
			// protected contracts; everything else under pkg/ is code-frozen).
			path:   "pkg/ghauth/ghauth.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{
			path:   "pkg/resolution/resolution.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{ // internal/** is never enumerated in protectedPrefixes — the floor covers it.
			path:   "internal/exam/scenario.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			f := newFixture(t)
			real := f.copyReal(tc.path)
			base := f.commit("base")
			f.write(tc.path, tc.mutate(t, real))
			head := f.commit("proposal: tamper with a decision-path Go file")
			requireRejected(t, f.guard(base, head), RuleCodeFrozen, tc.path)
		})
	}
}

// The sanctioned additive code lane is the OWN-PACKAGE tree
// core/detect/authored/<name>/ ONLY. A NEW .go file anywhere else is code the
// loop may not author: under a protected package it trips RuleProtectedPath;
// under a NON-authored subdirectory of core/detect (core/detect/evil/) it trips
// the Go default-deny floor (RuleCodeFrozen) — that subdir is NOT the lane.
// Both are rejected.
func TestGuard_RejectsNewGoFileOutsideDetectorLane(t *testing.T) {
	cases := []struct{ path, rule string }{
		{"core/agent/smuggled.go", RuleProtectedPath},
		{"core/detect/evil/evil.go", RuleCodeFrozen},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			f := newFixture(t)
			f.copyReal("core/detect/injection_probe.go") // real committed base
			base := f.commit("base")
			f.write(tc.path, "package p\n\n// a new .go file the loop tried to add outside the lane\n")
			head := f.commit("proposal: add a new Go file outside the detector lane")
			requireRejected(t, f.guard(base, head), tc.rule, tc.path)
		})
	}
}

// The sanctioned additive lane is the OWN-PACKAGE core/detect/authored/<name>/
// tree, NOT the shared core/detect package. A NEW .go file directly under
// core/detect/ is `package detect` (the L1 break) and is now frozen.
func TestGuard_FreezesNewFileInSharedDetectPackage(t *testing.T) {
	f := newFixture(t)
	f.copyReal("core/detect/injection_probe.go")
	base := f.commit("base")

	f.write("core/detect/newdet.go", "package detect\n\n// shared framework package — frozen, not the additive lane\n")
	head := f.commit("proposal: new file directly under core/detect")

	requireRejected(t, f.guard(base, head), RuleDetectCodeFrozen, "core/detect/newdet.go")
}

// The OWN-PACKAGE authored-detector lane (K7 L1): a NEW file under
// core/detect/authored/<name>/ is the sanctioned additive code lane (gated
// downstream by K2a + K7 L3), while a .go file sitting directly in the
// aggregator package (core/detect/authored/loose.go) is NOT — only registry.go
// belongs there — so it trips the Go default-deny floor. An existing authored
// detector, once merged, is frozen.
func TestGuard_AuthoredDetectorLane(t *testing.T) {
	t.Run("A of a new own-package authored detector PASSES", func(t *testing.T) {
		f := newFixture(t)
		f.copyReal("core/detect/injection_probe.go")
		base := f.commit("base")
		f.write("core/detect/authored/newsig/newsig.go",
			"package newsig\n\n// a new own-package authored detector — the additive lane\n")
		head := f.commit("proposal: new authored detector own package")
		requireClean(t, f.guard(base, head))
	})

	t.Run("A of a loose .go in the aggregator package is REJECTED", func(t *testing.T) {
		f := newFixture(t)
		f.copyReal("core/detect/injection_probe.go")
		base := f.commit("base")
		f.write("core/detect/authored/loose.go", "package authored\n\n// not registry.go — not allowed directly in the aggregator package\n")
		head := f.commit("proposal: loose file in the aggregator package")
		requireRejected(t, f.guard(base, head), RuleCodeFrozen, "core/detect/authored/loose.go")
	})

	t.Run("M of an existing authored detector is FROZEN", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("core/detect/authored/synthmarker/synthmarker.go")
		base := f.commit("base")
		f.write("core/detect/authored/synthmarker/synthmarker.go", real+"\n// tampered by the loop\n")
		head := f.commit("proposal: modify a merged authored detector")
		requireRejected(t, f.guard(base, head), RuleDetectCodeFrozen, "core/detect/authored/synthmarker/synthmarker.go")
	})

	// K7 re-red-team: a NESTED authored .go file (deeper than one path segment,
	// e.g. core/detect/authored/<name>/<sub>/file.go) compiles into cmd/mallcop
	// through the aggregator's transitive import graph, yet lies outside the
	// one-level own-package lane the shape gate and import allow-list are built
	// around. The guard's allowed surface must never exceed the shape-checked
	// surface, so a deeper authored .go file is FROZEN (RuleCodeFrozen) even when
	// added — it is not a sanctioned additive lane.
	t.Run("A of a deeper NESTED authored .go file is REJECTED", func(t *testing.T) {
		f := newFixture(t)
		f.copyReal("core/detect/injection_probe.go")
		base := f.commit("base")
		f.write("core/detect/authored/newsig/inner/inner.go",
			"package inner\n\n// nested below <name>/ — outside the one-level own-package lane\n")
		head := f.commit("proposal: nested authored package")
		requireRejected(t, f.guard(base, head), RuleCodeFrozen, "core/detect/authored/newsig/inner/inner.go")
	})
}

// The authored-detector registration aggregator (core/detect/authored/registry.go)
// is human-bootstrapped once and thereafter accepts ONLY append-only blank
// imports of packages under core/detect/authored/. Every other shape fails
// closed with RuleAuthoredRegistry.
func TestGuard_AuthoredRegistryAppendOnly(t *testing.T) {
	const synthImport = `_ "github.com/mallcop-app/mallcop/core/detect/authored/synthmarker"`

	t.Run("appending a blank authored import PASSES", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("core/detect/authored/registry.go")
		base := f.commit("base")
		appended := replaceOnce(t, real, synthImport,
			synthImport+"\n\t_ \"github.com/mallcop-app/mallcop/core/detect/authored/example\"")
		f.write("core/detect/authored/registry.go", appended)
		head := f.commit("proposal: append a blank authored import")
		requireClean(t, f.guard(base, head))
	})

	t.Run("adding a func is REJECTED", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("core/detect/authored/registry.go")
		base := f.commit("base")
		f.write("core/detect/authored/registry.go", real+"\nfunc sneaky() {}\n")
		head := f.commit("proposal: smuggle a func into the registry")
		requireRejected(t, f.guard(base, head), RuleAuthoredRegistry, "registry.go")
	})

	t.Run("removing an existing import is REJECTED", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("core/detect/authored/registry.go")
		base := f.commit("base")
		f.write("core/detect/authored/registry.go", replaceOnce(t, real, "\n\t"+synthImport, ""))
		head := f.commit("proposal: remove an authored import")
		requireRejected(t, f.guard(base, head), RuleAuthoredRegistry, "registry.go")
	})

	t.Run("adding a non-blank import is REJECTED", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("core/detect/authored/registry.go")
		base := f.commit("base")
		appended := replaceOnce(t, real, synthImport,
			synthImport+"\n\tother \"github.com/mallcop-app/mallcop/core/detect/authored/example\"")
		f.write("core/detect/authored/registry.go", appended)
		head := f.commit("proposal: add a NAMED (non-blank) import")
		requireRejected(t, f.guard(base, head), RuleAuthoredRegistry, "registry.go")
	})

	t.Run("adding a blank import OUTSIDE core/detect/authored is REJECTED", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("core/detect/authored/registry.go")
		base := f.commit("base")
		appended := replaceOnce(t, real, synthImport,
			synthImport+"\n\t_ \"github.com/mallcop-app/mallcop/core/agent\"")
		f.write("core/detect/authored/registry.go", appended)
		head := f.commit("proposal: blank-import a non-authored package")
		requireRejected(t, f.guard(base, head), RuleAuthoredRegistry, "registry.go")
	})

	t.Run("adding the registry file (A) is REJECTED", func(t *testing.T) {
		f := newFixture(t)
		realRegistry, err := os.ReadFile(filepath.Join(f.root, "core/detect/authored/registry.go"))
		if err != nil {
			t.Fatalf("read real registry.go: %v", err)
		}
		f.copyReal("core/detect/injection_probe.go") // base anchor
		base := f.commit("base")
		f.write("core/detect/authored/registry.go", string(realRegistry))
		head := f.commit("proposal: add the registry from scratch")
		requireRejected(t, f.guard(base, head), RuleAuthoredRegistry, "registry.go")
	})

	t.Run("deleting the registry file (D) is REJECTED", func(t *testing.T) {
		f := newFixture(t)
		f.copyReal("core/detect/authored/registry.go")
		base := f.commit("base")
		f.remove("core/detect/authored/registry.go")
		head := f.commit("proposal: delete the registry")
		requireRejected(t, f.guard(base, head), RuleAuthoredRegistry, "registry.go")
	})
}

// A WELL-SHAPED (mapping→field→list) but loader-unknown section or field in
// detectors/tuning.yaml would sail past the widen subset check (head-only IS
// the widen). The section/field allowlist mirrors core/detect/tuning.go's
// Tuning struct and fails closed at the GUARD layer — it does not defer to
// exam-detect or the loader's strict decode.
func TestGuard_RejectsUnknownTuningSection(t *testing.T) {
	t.Run("unknown top-level section", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("detectors/tuning.yaml")
		base := f.commit("base")
		// A brand-new, structurally valid, but loader-unknown top-level section.
		f.write("detectors/tuning.yaml", real+"\nlateral_movement:\n  extra_elevated_keywords:\n    - clusteradmin\n")
		head := f.commit("proposal: smuggle an unknown top-level tuning section")
		requireRejected(t, f.guard(base, head), RuleDetectorDataWidenOnly, "detectors/tuning.yaml")
	})

	t.Run("unknown field under a known section", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("detectors/tuning.yaml")
		base := f.commit("base")
		// A sibling key under priv_escalation the loader's struct does not declare.
		f.write("detectors/tuning.yaml", real+"  override_elevated_keywords:\n    - poweruser\n")
		head := f.commit("proposal: smuggle an unknown field under a known section")
		requireRejected(t, f.guard(base, head), RuleDetectorDataWidenOnly, "detectors/tuning.yaml")
	})
}

// Paths the guard has no opinion on (docs) pass this layer — the guard
// enforces the enumerated invariants, other layers gate the rest.
func TestGuard_PassesUnprotectedDocChange(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("README.md")
	base := f.commit("base")

	f.write("README.md", real+"\nDocs-only change.\n")
	head := f.commit("proposal: docs")

	requireClean(t, f.guard(base, head))
}

// TestGuard_CustomerTreeSidecarShape_RejectsDotImportOS reproduces the exact
// bypass the veracity adversary found on mallcoppro-97b: `import . "os"`
// passes the path allowlist while rendering os.ReadFile / Exit as bare
// identifiers invisible to the SelectorExpr-based confinement. Dot imports of
// ANY package are now banned outright (checkSidecarDotImports).
func TestGuard_CustomerTreeSidecarShape_RejectsDotImportOS(t *testing.T) {
	f := newFixture(t)
	base := anchorCustomerTreeBase(f)

	f.write("detectors/widget-leak/main.go", `package main

import (
	. "os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type widgetLeakDetector struct{}

func (widgetLeakDetector) Name() string { return "widget-leak" }

func (widgetLeakDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	if b, err := ReadFile("/etc/passwd"); err == nil && len(b) > 0 {
		return nil // exfil-shaped behavior the confinement must not miss
	}
	return nil
}

func main() { Exit(detectorhost.Run(widgetLeakDetector{})) }
`)
	head := f.commit("proposal: add a dot-import sidecar (adversary bypass shape)")

	findings := f.guardCustomerTree(base, head)
	requireRejected(t, findings, RuleSidecarShape, "detectors/widget-leak/main.go")
	requireDetailContains(t, findings, RuleSidecarShape, "dot import")
}
