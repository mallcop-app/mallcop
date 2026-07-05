// customerefficacy_test.go — mandatory proof tests for mallcoppro-f95: the
// customer-tree exam must grade EFFICACY (does the detector prove itself on
// its OWN scenarios), not just REGRESSION against the reference corpus, and
// grading must never mutate the operator's real reference tree.
//
// Invariant 10 (ground-source testing): every test here runs the REAL gate
// end-to-end against a real git repo, a real reference mallcop tree, a real
// `go build`/`go vet` of the authored detector (and its main_test.go), and a
// real grading pass through the real detecthost/wazero host. Nothing here is
// mocked.
package selfgate

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- mandatory test (a): round-5 inert detector rejected -------------------

// buildCustomerShapedRepoNoScenarios is buildCustomerShapedRepo's THIN
// sibling: it deliberately ships NO detectors/<name>/scenarios/ directory at
// all — the EXACT round-5 hole (rd 7ee7 live leg round 5): a detector for a
// novel gap with zero efficacy scenarios of its own, relying entirely on
// "the reference corpus shows no regression" to pass. Before mallcoppro-f95
// this passed VACUOUSLY (the detector was never shown an event of its own
// target type). After the fix it must be REJECTED (RuleCustomerExamFail).
func buildCustomerShapedRepoNoScenarios(t *testing.T, detectorSrc string) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")

	goMod := `module example.com/customer-fixture-inert

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => ` + mallcopRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write customer repo go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("customer deployment repo (inert detector fixture)\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	scratchDir := filepath.Join(dir, "detectors", "tidyscratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		t.Fatalf("mkdir go.sum scratch dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scratchDir, "main.go"), []byte(detectorSrc), 0o644); err != nil {
		t.Fatalf("write go.sum scratch detector: %v", err)
	}
	if stdout, stderr, code, err := runTool(dir, []string{"GOFLAGS=-mod=mod"}, "go", "mod", "tidy"); err != nil || code != 0 {
		t.Fatalf("precompute go.sum via `go mod tidy`: err=%v code=%d\n%s%s", err, code, stdout, stderr)
	}
	if err := os.RemoveAll(scratchDir); err != nil {
		t.Fatalf("remove go.sum scratch dir: %v", err)
	}
	base = commitAll(t, dir, "base: THIN-EMBED scaffold (go.mod/go.sum only, no detector yet)")

	detDir := filepath.Join(dir, "detectors", "widget-leak")
	if err := os.MkdirAll(detDir, 0o755); err != nil {
		t.Fatalf("mkdir detectors/widget-leak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(detDir, "main.go"), []byte(detectorSrc), 0o644); err != nil {
		t.Fatalf("write detector main.go: %v", err)
	}
	// Deliberately NO scenarios/ directory — the round-5 hole this test proves
	// closed.
	head = commitAll(t, dir, "proposal: add widget-leak detector (NO efficacy scenarios shipped)")
	return dir, base, head
}

// TestValidateProposal_CustomerTreeExamRejectsZeroEfficacyScenarios is
// mandatory test (a): a detector shipping no (or ineffective) efficacy
// scenarios of its own must be REJECTED, even though it introduces zero
// regressions against the reference corpus (the exact vacuous-pass hole rd
// 7ee7 round 5 found). See this file's package doc; the manual RED/GREEN
// proof (running this fixture against the PARENT commit before mallcoppro-f95
// vs. HEAD) is recorded in the item's progress notes, not re-derived here —
// reverting a merged fix inside a permanent test is not this repo's pattern
// (c.f. TestStructuralStage_CustomerTreeModeFixesIncompleteGoSum, which flips
// a BOOLEAN PARAMETER of the same function rather than reverting a commit,
// because that mechanism still exists on both sides of ITS fix; the vacuous
// customer-tree accept path this test closes has no such live toggle once
// removed).
func TestValidateProposal_CustomerTreeExamRejectsZeroEfficacyScenarios(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildCustomerShapedRepoNoScenarios(t, customerFixtureDetectorMainSrc)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal must return a REAL verdict, not an operational error: %v", err)
	}
	if res.Passed {
		t.Fatalf("a detector shipping ZERO efficacy scenarios must be REJECTED even with no reference-corpus regression, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	examStage := res.Stages[2]
	if examStage.Passed {
		t.Fatalf("exam-detect stage must be the failing stage, got %+v", examStage)
	}
	requireRejected(t, examStage.Findings, RuleCustomerExamFail, "detectors/widget-leak")
	if !containsAny(findingDetails(examStage.Findings), "ships zero efficacy scenarios") {
		t.Fatalf("expected the zero-efficacy-scenarios detail, got %+v", examStage.Findings)
	}
}

// ---- mandatory test (c): twin-gaming (fire-on-everything) ------------------

// customFixtureFireOnEverythingFamily is deliberately distinct from every
// real mallcop family AND from customFixtureFamily above — this detector
// targets a GENUINELY NOVEL gap the reference corpus has ZERO scenarios for,
// so the reference-corpus regression check alone (Extra==false rows) sees
// NOTHING for this family and would wrongly pass it if checkCustomerEfficacy
// did not exist or were buggy.
const customFixtureFireOnEverythingFamily = "custfixture-fireonall"

// customerFixtureFireOnEverythingDetectorMainSrc is the ADVERSARIAL detector:
// it fires on EVERY event regardless of type — the purest "twin-gaming"
// shape (mandatory test c). Even though its OWN must-fire scenario passes
// (it fires on its target), its OWN benign-twin scenario ALSO fires (it
// fires on everything), so checkCustomerEfficacy's twinPassing check must
// reject it — proving the mechanism catches over-firing on a family the
// reference corpus has no opinion about at all (isolating the efficacy check
// from the regression-vs-baseline path, which sees zero rows for this
// family).
const customerFixtureFireOnEverythingDetectorMainSrc = `package main

import (
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type fireOnEverythingDetector struct{}

func (fireOnEverythingDetector) Name() string { return "` + customFixtureFireOnEverythingFamily + `" }

func (fireOnEverythingDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		out = append(out, finding.Finding{
			ID:     "finding-" + ev.ID + "-fireonall",
			Source: "detector:` + customFixtureFireOnEverythingFamily + `",
			Type:   "` + customFixtureFireOnEverythingFamily + `",
			Actor:  ev.Actor,
		})
	}
	return out
}

func main() { os.Exit(detectorhost.Run(fireOnEverythingDetector{})) }
`

// customFixtureFireOnEverythingMustFireScenario / ...BenignTwinScenario are
// the detector's OWN scenarios/ pair: a must-fire event of one type, and a
// "benign twin" event of a DIFFERENT type that a well-behaved detector would
// stay silent on — but the fire-on-everything detector fires on it too.
const customFixtureFireOnEverythingMustFireScenario = `id: SIDECAR-FIREONALL-01-must-fire
finding:
  id: fnd_fireonall_01
  detector: custfixture-fireonall
  title: 'fixture: fire-on-everything must-fire target'
  severity: high
events:
- id: evt_fireonall_01
  timestamp: '2026-07-01T00:20:00Z'
  source: customer-app
  event_type: fireonall-target
  actor: cust-actor
expected_detection:
  must_fire:
  - custfixture-fireonall
`

const customFixtureFireOnEverythingBenignTwinScenario = `id: SIDECAR-FIREONALL-02-benign-twin
finding:
  id: fnd_fireonall_02
  detector: custfixture-fireonall
  title: 'fixture: fire-on-everything benign twin (should stay silent, does not)'
  severity: warn
events:
- id: evt_fireonall_02
  timestamp: '2026-07-01T00:25:00Z'
  source: customer-app
  event_type: fireonall-routine
  actor: cust-actor
expected_detection:
  must_not_fire:
  - custfixture-fireonall
`

// buildCustomerShapedRepoFireOnEverything builds the THIN-EMBED customer repo
// for the fire-on-everything adversarial detector, shipping its OWN
// scenarios/ pair (both events distinct from any reference-corpus scenario
// type, so the reference-corpus regression path sees nothing for this
// family).
func buildCustomerShapedRepoFireOnEverything(t *testing.T) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")

	goMod := `module example.com/customer-fixture-fireonall

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => ` + mallcopRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write customer repo go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("customer deployment repo (fire-on-everything fixture)\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	scratchDir := filepath.Join(dir, "detectors", "tidyscratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		t.Fatalf("mkdir go.sum scratch dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scratchDir, "main.go"), []byte(customerFixtureFireOnEverythingDetectorMainSrc), 0o644); err != nil {
		t.Fatalf("write go.sum scratch detector: %v", err)
	}
	if stdout, stderr, code, err := runTool(dir, []string{"GOFLAGS=-mod=mod"}, "go", "mod", "tidy"); err != nil || code != 0 {
		t.Fatalf("precompute go.sum via `go mod tidy`: err=%v code=%d\n%s%s", err, code, stdout, stderr)
	}
	if err := os.RemoveAll(scratchDir); err != nil {
		t.Fatalf("remove go.sum scratch dir: %v", err)
	}
	base = commitAll(t, dir, "base: THIN-EMBED scaffold (go.mod/go.sum only, no detector yet)")

	detDir := filepath.Join(dir, "detectors", "fire-on-everything")
	if err := os.MkdirAll(detDir, 0o755); err != nil {
		t.Fatalf("mkdir detectors/fire-on-everything: %v", err)
	}
	if err := os.WriteFile(filepath.Join(detDir, "main.go"), []byte(customerFixtureFireOnEverythingDetectorMainSrc), 0o644); err != nil {
		t.Fatalf("write detector main.go: %v", err)
	}
	scenDir := filepath.Join(detDir, "scenarios")
	if err := os.MkdirAll(scenDir, 0o755); err != nil {
		t.Fatalf("mkdir sidecar scenarios dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "must-fire.yaml"), []byte(customFixtureFireOnEverythingMustFireScenario), 0o644); err != nil {
		t.Fatalf("write sidecar must-fire scenario: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "benign-twin.yaml"), []byte(customFixtureFireOnEverythingBenignTwinScenario), 0o644); err != nil {
		t.Fatalf("write sidecar benign-twin scenario: %v", err)
	}
	head = commitAll(t, dir, "proposal: add fire-on-everything detector (adversarial: ships its own must-fire+twin, twin fires too)")
	return dir, base, head
}

// TestValidateProposal_CustomerTreeExamRejectsFireOnEverythingTwin is
// mandatory test (c): a detector that fires on EVERYTHING — including its
// OWN benign-twin scenario — must be REJECTED via checkCustomerEfficacy, on a
// family the reference corpus has ZERO scenarios for (isolating the efficacy
// check from the reference-corpus regression path, which sees nothing for
// this family and would otherwise let it pass).
func TestValidateProposal_CustomerTreeExamRejectsFireOnEverythingTwin(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildCustomerShapedRepoFireOnEverything(t)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal must return a REAL verdict, not an operational error: %v", err)
	}
	if res.Passed {
		t.Fatalf("a fire-on-everything detector (its own twin fires) must be REJECTED, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	examStage := res.Stages[2]
	if examStage.Passed {
		t.Fatalf("exam-detect stage must be the failing stage, got %+v", examStage)
	}
	requireRejected(t, examStage.Findings, RuleCustomerExamFail, "detectors/fire-on-everything")
	if !containsAny(findingDetails(examStage.Findings), "no passing must_not_fire benign-twin scenario") {
		t.Fatalf("expected a missing/failing benign-twin detail naming the family, got %+v", examStage.Findings)
	}
	if !containsAny(findingDetails(examStage.Findings), customFixtureFireOnEverythingFamily) {
		t.Fatalf("expected the rejection to name family %q, got %+v", customFixtureFireOnEverythingFamily, examStage.Findings)
	}
}

// ---- mandatory test (d): reference tree + corpus.pin never mutated --------

// TestCustomerTreeExamStage_ReferenceTreeAndPinNeverMutated is mandatory test
// (d): grading a customer detector against a REAL reference tree must never
// write into it — no stray `mallcop` binary, no corpus.pin change, no
// exams/scenarios change — because customerTreeExamStage now grades against
// an EPHEMERAL SCRATCH COPY (scratchCopyExamRepo), never the tree the caller
// passed in.
func TestCustomerTreeExamStage_ReferenceTreeAndPinNeverMutated(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildCustomerShapedRepo(t, customerFixtureDetectorMainSrc)

	pinBefore, err := os.ReadFile(filepath.Join(examTree, "exams", "scenarios", "corpus.pin"))
	if err != nil {
		t.Fatalf("read corpus.pin before grading: %v", err)
	}
	// Sanity: the reference tree must not already carry a stray build
	// artifact from some earlier (buggy) run — otherwise "still absent after"
	// would prove nothing.
	if _, err := os.Stat(filepath.Join(examTree, "mallcop")); err == nil {
		t.Fatal("fixture invariant broken: examTree already has a `mallcop` binary before grading")
	}
	// buildReferenceExamTree itself leaves the tree's WORKING DIRECTORY with
	// uncommitted fixture scenario files + a regenerated corpus.pin (that is
	// the fixture setup, not a grading side effect) — capture that baseline
	// status BEFORE grading so the comparison below isolates what GRADING
	// changes, not what the fixture builder already wrote.
	statusBefore := mustGit(t, examTree, "status", "--porcelain")

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal (customer-tree mode): %v", err)
	}
	if !res.Passed {
		t.Fatalf("well-behaved customer detector must pass the gate, got %+v", res)
	}

	pinAfter, err := os.ReadFile(filepath.Join(examTree, "exams", "scenarios", "corpus.pin"))
	if err != nil {
		t.Fatalf("read corpus.pin after grading: %v", err)
	}
	if string(pinBefore) != string(pinAfter) {
		t.Fatalf("corpus.pin MUTATED by grading — before:\n%s\nafter:\n%s", pinBefore, pinAfter)
	}
	if _, err := os.Stat(filepath.Join(examTree, "mallcop")); err == nil {
		t.Fatal("grading wrote a `mallcop` binary straight into the REAL reference tree — it must build only in the ephemeral scratch copy")
	}
	// The reference tree's git status must be IDENTICAL before and after
	// grading — belt-and-suspenders on top of the two direct checks above,
	// isolated from the fixture builder's own (pre-grading) uncommitted
	// writes via the baseline captured above.
	statusAfter := mustGit(t, examTree, "status", "--porcelain")
	if statusBefore != statusAfter {
		t.Fatalf("reference tree's git status changed during grading (must never be mutated):\nbefore:\n%s\nafter:\n%s", statusBefore, statusAfter)
	}
}

// ---- mandatory test (f): go vet catches a non-compiling sidecar test ------

// nonCompilingSidecarMainTestSrc reproduces the EXACT round-5 defect shape
// (rd 7ee7 round 5: detectors/forcepushprotectedbranch/main_test.go) — an
// unused import and a struct VALUE called as if it were a function
// (`d := detector{}()`) — a file that does not compile at all. `go build
// ./...` never touches _test.go files and sails past this untouched; `go
// vet ./...` compiles every _test.go as part of its analysis and must catch
// it.
const nonCompilingSidecarMainTestSrc = `package main

import (
	"testing"

	"github.com/mallcop-app/mallcop/pkg/event"
)

func TestDetectorFires(t *testing.T) {
	d := detector{}()
	_ = d
	_ = event.Event{}
}
`

// buildCustomerShapedRepoNonCompilingTest builds a THIN-EMBED customer repo
// whose head adds a VALID detector main.go (compiles fine) alongside a
// main_test.go that does NOT compile — the round-5 shape.
func buildCustomerShapedRepoNonCompilingTest(t *testing.T) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")

	goMod := `module example.com/customer-fixture-nocompile

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => ` + mallcopRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write customer repo go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("customer deployment repo (non-compiling test fixture)\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	scratchDir := filepath.Join(dir, "detectors", "tidyscratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		t.Fatalf("mkdir go.sum scratch dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scratchDir, "main.go"), []byte(customerFixtureDetectorMainSrc), 0o644); err != nil {
		t.Fatalf("write go.sum scratch detector: %v", err)
	}
	if stdout, stderr, code, err := runTool(dir, []string{"GOFLAGS=-mod=mod"}, "go", "mod", "tidy"); err != nil || code != 0 {
		t.Fatalf("precompute go.sum via `go mod tidy`: err=%v code=%d\n%s%s", err, code, stdout, stderr)
	}
	if err := os.RemoveAll(scratchDir); err != nil {
		t.Fatalf("remove go.sum scratch dir: %v", err)
	}
	base = commitAll(t, dir, "base: THIN-EMBED scaffold (go.mod/go.sum only, no detector yet)")

	detDir := filepath.Join(dir, "detectors", "widget-leak")
	if err := os.MkdirAll(detDir, 0o755); err != nil {
		t.Fatalf("mkdir detectors/widget-leak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(detDir, "main.go"), []byte(customerFixtureDetectorMainSrc), 0o644); err != nil {
		t.Fatalf("write detector main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(detDir, "main_test.go"), []byte(nonCompilingSidecarMainTestSrc), 0o644); err != nil {
		t.Fatalf("write non-compiling main_test.go: %v", err)
	}
	writeSidecarScenarios(t, detDir)
	head = commitAll(t, dir, "proposal: add widget-leak detector with a NON-COMPILING main_test.go (round-5 shape)")
	return dir, base, head
}

// TestValidateProposal_CustomerTreeModeRejectsNonCompilingSidecarTest is
// mandatory test (f): a sidecar whose main_test.go does not compile must
// fail CLOSED. Historically (pre mallcoppro-443) this was proven at the
// STRUCTURAL stage (RuleStructuralVet) — `go build ./...` alone (which
// silently skips _test.go) was not enough, and `go vet ./...` closed the
// gap at stage 2, one stage LATE. mallcoppro-443 (CRITICAL security fix)
// found that lateness was itself a hole: guard's customer-tree .go arm was
// deferring EVERY _test.go, compiling or not, to a sidecarDirs shape-check
// pass that (by design) only shape-checks PRODUCTION .go files
// (isProductionGoFile excludes _test.go) — so a _test.go that DID compile
// (a malicious one, not this fixture's non-compiling one) sailed through
// guard AND structural with zero findings. The fix denies ANY _test.go
// under detectors/ at GUARD (stage 1, RuleCodeFrozen), before structural
// ever runs — a strictly EARLIER and STRONGER floor that also catches this
// fixture's non-compiling main_test.go, so the full end-to-end assertions
// below now expect a stage-1 (guard) rejection and short-circuit, not a
// stage-2 (structural) one. The direct low-level mechanism proof (go build
// skips _test.go, go vet does not; structuralStage on its own still
// surfaces RuleStructuralVet as defense-in-depth if ever invoked past guard)
// is retained unchanged below — it documents a still-true fact about the Go
// toolchain, it just no longer describes the path THIS fixture takes
// through ValidateProposal in customer-tree mode.
func TestValidateProposal_CustomerTreeModeRejectsNonCompilingSidecarTest(t *testing.T) {
	clearInferenceEnv(t)
	customerDir, base, head := buildCustomerShapedRepoNonCompilingTest(t)

	headTree := filepath.Join(t.TempDir(), "headtree")
	if err := addWorktree(customerDir, headTree, head); err != nil {
		t.Fatalf("materialize head worktree: %v", err)
	}
	t.Cleanup(func() { removeWorktree(customerDir, headTree) })

	// Direct mechanism proof: `go build ./...` passes (it skips _test.go);
	// `go vet ./...` fails (it compiles _test.go). Still true; no longer the
	// path ValidateProposal takes for THIS fixture (see doc above), but
	// structuralStage would still catch it here as defense-in-depth if ever
	// reached (e.g. a caller invoking it directly, bypassing Guard).
	buildStdout, buildStderr, buildCode, err := runTool(headTree, []string{"GOFLAGS=-mod=mod"}, "go", "build", "./...")
	if err != nil {
		t.Fatalf("go build: %v", err)
	}
	if buildCode != 0 {
		t.Fatalf("expected `go build ./...` to PASS (it skips _test.go), got exit %d: %s%s", buildCode, buildStdout, buildStderr)
	}
	vetStdout, vetStderr, vetCode, err := runTool(headTree, []string{"GOFLAGS=-mod=mod"}, "go", "vet", "./...")
	if err != nil {
		t.Fatalf("go vet: %v", err)
	}
	if vetCode == 0 {
		t.Fatalf("expected `go vet ./...` to FAIL on the non-compiling main_test.go, got exit 0: %s%s", vetStdout, vetStderr)
	}
	structFindings, structEvidence, serr := structuralStage(headTree, true)
	if serr != nil {
		t.Fatalf("structuralStage: operational error: %v", serr)
	}
	if !hasFinding(structFindings, RuleStructuralVet) {
		t.Fatalf("expected a %s finding for the non-compiling main_test.go, got findings=%+v evidence=%q",
			RuleStructuralVet, structFindings, structEvidence)
	}

	// Full gate proof (mallcoppro-443): ValidateProposal now rejects at
	// GUARD (stage 1) and short-circuits — structural never runs.
	res, verr := ValidateProposal(customerDir, base, head, Options{ExamRepo: repoUnderTest(t)})
	if verr != nil {
		t.Fatalf("ValidateProposal: %v", verr)
	}
	if res.Passed {
		t.Fatalf("gate must REJECT a non-compiling sidecar main_test.go, got %+v", res)
	}
	requireStageNames(t, res, StageGuard)
	if !hasFinding(res.Stages[0].Findings, RuleCodeFrozen) {
		t.Fatalf("expected the guard stage's findings to include %s (mallcoppro-443: _test.go under detectors/ is denied at guard, before structural ever runs), got %+v", RuleCodeFrozen, res.Stages[0])
	}
}
