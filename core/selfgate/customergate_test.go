// customergate_test.go — PROOF tests for stage 3's CUSTOMER-TREE mode
// (mallcoppro-97b): wiring RunCustomerTreeExam (customerexam.go, previously
// zero callers) into ValidateProposal via Options.ExamRepo.
//
// Invariant 10 (ground-source testing): every test here runs the REAL gate
// end-to-end — a real customer-shaped (THIN-EMBED) git repo, a real
// reference mallcop tree (a detached worktree of the repo under test, with
// two new labeled corpus scenarios + a regenerated corpus.pin added directly
// to its working tree), a real `go build` of the authored detector to a real
// wasip1 .wasm module, and a real grading pass through the real
// detecthost/wazero host. Nothing here is mocked — customerexam_test.go
// already proves RunCustomerTreeExam itself never takes an in-process
// shortcut (TestRunCustomerTreeExam_GradesThroughRealWasmHost); these tests
// prove the GATE (ValidateProposal) reaches that same real path and turns
// its verdict into a GateResult.
package selfgate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// customFixtureFamily is the detector family both fixture scenarios below
// grade against — deliberately distinct from every real mallcop detector
// family so this test's corpus additions can never collide with (or be
// excused by) a real scenario's labels.
const customFixtureFamily = "custfixture-leak"

// customFixtureMustFireScenario is the malicious-shaped scenario: a
// "widget-secret-exposed" event the fixture detector must fire on.
const customFixtureMustFireScenario = `id: CUSTFIX-01-widget-secret-exposed
finding:
  id: fnd_custfix_01
  detector: custfixture-leak
  title: 'fixture: widget secret exposed'
  severity: high
events:
- id: evt_custfix_01
  timestamp: '2026-07-01T00:00:00Z'
  source: customer-app
  event_type: widget-secret-exposed
  actor: cust-actor
expected_detection:
  must_fire:
  - custfixture-leak
`

// customFixtureBenignTwinScenario is the benign twin: a
// "widget-secret-rotated" event that LOOKS similar (same source/actor, same
// event family prefix) but is routine key rotation, not a leak. A detector
// proving itself must fire on the must-fire scenario above WITHOUT also
// firing here.
const customFixtureBenignTwinScenario = `id: CUSTFIX-02-widget-secret-rotated-benign
finding:
  id: fnd_custfix_02
  detector: custfixture-leak
  title: 'fixture: widget secret rotated (benign twin)'
  severity: warn
events:
- id: evt_custfix_02
  timestamp: '2026-07-01T00:05:00Z'
  source: customer-app
  event_type: widget-secret-rotated
  actor: cust-actor
expected_detection:
  must_not_fire:
  - custfixture-leak
`

// customerFixtureDetectorMainSrc is the WELL-BEHAVED customer detector: it
// fires ONLY on "widget-secret-exposed" events, correctly staying silent on
// the benign "widget-secret-rotated" twin. Structurally a
// core/detect.Detector (Name + Detect) via pkg/detectorhost, never importing
// core/detect itself — the customer-tree shape.
const customerFixtureDetectorMainSrc = `package main

import (
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type widgetLeakDetector struct{}

func (widgetLeakDetector) Name() string { return "` + customFixtureFamily + `" }

func (widgetLeakDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type == "widget-secret-exposed" {
			out = append(out, finding.Finding{
				ID:     "finding-" + ev.ID + "-custfixtureleak",
				Source: "detector:` + customFixtureFamily + `",
				Type:   "` + customFixtureFamily + `",
				Actor:  ev.Actor,
			})
		}
	}
	return out
}

func main() { os.Exit(detectorhost.Run(widgetLeakDetector{})) }
`

// customerFixtureOverbroadDetectorMainSrc is the DEFECTIVE variant: it fires
// on ANY "widget-secret-*" event, including the benign twin — the
// missing-benign-twin-protection failure mode the gate must catch as a real
// rejection, not an operational error.
const customerFixtureOverbroadDetectorMainSrc = `package main

import (
	"os"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type overbroadWidgetLeakDetector struct{}

func (overbroadWidgetLeakDetector) Name() string { return "` + customFixtureFamily + `" }

func (overbroadWidgetLeakDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if strings.HasPrefix(ev.Type, "widget-secret") {
			out = append(out, finding.Finding{
				ID:     "finding-" + ev.ID + "-custfixtureleak",
				Source: "detector:` + customFixtureFamily + `",
				Type:   "` + customFixtureFamily + `",
				Actor:  ev.Actor,
			})
		}
	}
	return out
}

func main() { os.Exit(detectorhost.Run(overbroadWidgetLeakDetector{})) }
`

// buildReferenceExamTree materializes a detached worktree of the repo under
// test (a REAL mallcop tree: cmd/mallcop, exams/scenarios, corpus.pin) and
// adds the two fixture scenarios above to its corpus, regenerating
// corpus.pin so the sha-pinned integrity interlock accepts the addition. This
// is the CALLER-SUPPLIED reference tree (Options.ExamRepo / --exam-repo) —
// note it is built from the repo under test, NEVER from the customer tree
// under grade, matching the security boundary: the reference tree is chosen
// by the caller, not derived from untrusted proposal content.
func buildReferenceExamTree(t *testing.T) string {
	t.Helper()
	root := repoUnderTest(t)
	examTree := filepath.Join(t.TempDir(), "examtree")
	headSHA := headOf(t, root)
	if err := addWorktree(root, examTree, headSHA); err != nil {
		t.Fatalf("materialize reference exam tree worktree: %v", err)
	}
	t.Cleanup(func() { removeWorktree(root, examTree) })

	scenDir := filepath.Join(examTree, "exams", "scenarios", "customerfixture")
	if err := os.MkdirAll(scenDir, 0o755); err != nil {
		t.Fatalf("mkdir fixture scenario dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "CUSTFIX-01-widget-secret-exposed.yaml"), []byte(customFixtureMustFireScenario), 0o644); err != nil {
		t.Fatalf("write must-fire fixture scenario: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "CUSTFIX-02-widget-secret-rotated-benign.yaml"), []byte(customFixtureBenignTwinScenario), 0o644); err != nil {
		t.Fatalf("write benign-twin fixture scenario: %v", err)
	}

	count, sha := recomputeCorpusPin(t, examTree)
	pin := fmt.Sprintf("# fixture pin (mallcoppro-97b customer-tree exam proof)\ncount %d\nsha256 %s\n", count, sha)
	if err := os.WriteFile(filepath.Join(examTree, "exams", "scenarios", "corpus.pin"), []byte(pin), 0o644); err != nil {
		t.Fatalf("write regenerated corpus.pin: %v", err)
	}
	return examTree
}

// buildCustomerShapedRepo builds a THIN-EMBED customer repo (go.mod pins
// mallcop via a local `replace` back to the repo under test — offline-safe,
// same discipline as buildCustomerProbeModule in customerexam_test.go — NO
// cmd/mallcop of its own) as a real git repo with two commits: base (no
// detector) and head (adds detectors/widget-leak/main.go with detectorSrc).
// Returns the repo dir, base SHA, head SHA.
func buildCustomerShapedRepo(t *testing.T, detectorSrc string) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")

	goMod := fmt.Sprintf(`module example.com/customer-fixture

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => %s
`, mallcopRoot)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write customer repo go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("customer deployment repo (THIN-EMBED fixture)\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	// Precompute go.sum offline via a SCRATCH detector (same framework import
	// set every real detector needs: pkg/baseline, pkg/detectorhost,
	// pkg/event, pkg/finding — GOFLAGS=-mod=mod, same convention
	// buildAndRegisterSourceSidecar uses, see cli/sidecars.go), then remove
	// the scratch file before committing BASE. This mirrors the REAL
	// deployment-repo lifecycle (deployrepo.go's scaffoldDeployAssets commits
	// go.mod up front; go.sum is already complete for the framework surface
	// before any detector is authored) and keeps the go.mod/go.sum PAIR
	// identical across base and head — adding a detector that imports the
	// SAME already-resolved framework surface needs no further go.sum
	// changes, so it never trips the guard's protected-module-files rule.
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
	if err := os.WriteFile(filepath.Join(detDir, "main.go"), []byte(detectorSrc), 0o644); err != nil {
		t.Fatalf("write detector main.go: %v", err)
	}
	head = commitAll(t, dir, "proposal: add widget-leak detector")
	return dir, base, head
}

// TestValidateProposal_CustomerTreeExamAcceptsPassingDetector proves the
// happy path end-to-end: --exam-repo (Options.ExamRepo) routes stage 3
// through RunCustomerTreeExam, which builds the authored detector to a real
// wasip1 .wasm module and grades it through the real detecthost/wazero host
// against the reference tree's corpus — a well-behaved detector (fires on
// its must-fire target, stays silent on the benign twin) passes the gate.
func TestValidateProposal_CustomerTreeExamAcceptsPassingDetector(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildCustomerShapedRepo(t, customerFixtureDetectorMainSrc)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal (customer-tree mode): %v", err)
	}
	if !res.Passed {
		t.Fatalf("well-behaved customer detector must pass the gate, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	examStage := res.Stages[2]
	if !examStage.Passed || len(examStage.Findings) != 0 {
		t.Fatalf("exam-detect stage not clean: %+v", examStage)
	}
	if !strings.Contains(examStage.Evidence, "customer-tree exam") || !strings.Contains(examStage.Evidence, "widget-leak") {
		t.Fatalf("exam-detect evidence should name the customer-tree mode and the detector, got %q", examStage.Evidence)
	}
}

// TestValidateProposal_CustomerTreeExamRejectsDetectorMissingBenignTwinProof
// proves the detector-quality FAIL path: an over-broad detector that fires on
// its own benign twin (the classic missing-benign-twin-protection defect)
// yields a REAL rejection finding (res.Passed == false, err == nil) — never
// folded into an operational error.
func TestValidateProposal_CustomerTreeExamRejectsDetectorMissingBenignTwinProof(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildCustomerShapedRepo(t, customerFixtureOverbroadDetectorMainSrc)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal must return a REAL verdict, not an operational error: %v", err)
	}
	if res.Passed {
		t.Fatalf("the over-broad detector (fires on its own benign twin) must be REJECTED, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	examStage := res.Stages[2]
	if examStage.Passed {
		t.Fatalf("exam-detect stage must be the failing stage, got %+v", examStage)
	}
	requireRejected(t, examStage.Findings, RuleCustomerExamFail, "detectors/widget-leak")
	found := false
	for _, f := range examStage.Findings {
		if strings.Contains(f.Detail, "CUSTFIX-02-widget-secret-rotated-benign") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the benign-twin scenario ID in the rejection detail, got %+v", examStage.Findings)
	}
}

// TestValidateProposal_DefaultModeFailsLoudlyOnCustomerShapedTree proves the
// closed empirical gap (rd 7ee7): a customer-shaped (no cmd/mallcop) tree run
// through the DEFAULT (Options.ExamRepo == "") lane fails with a LOUD,
// actionable operational error naming --exam-repo — never the raw `go build
// ./cmd/mallcop: no such file or directory` failure buried inside runTreeExam.
//
// mallcoppro-97b / mallcoppro-72d COLLISION (orchestrator ruling): DEFAULT
// mode's guard stage is UNCHANGED by the introduction of customer-tree mode —
// a .go Add under detectors/ is STILL the RuleCodeFrozen blanket deny (see
// guard_test.go's TestGuard_RejectsNewGoFileAddedUnderDetectors, which this
// ruling requires to keep passing UNMODIFIED). Diffing base..head where head
// ADDS the detector (the ORIGINAL shape of this test, before 72d) would now be
// rejected AT STAGE 1 for that reason and never reach the hasCmdMallcop check
// this test exists to prove — that is a REAL rejection, not a bug, and
// changing it would silently re-widen the exact hole 72d closed. To isolate
// the invariant this test actually owns, diff base AGAINST ITSELF: a
// legitimate zero-change proposal on the THIN-EMBED scaffold (go.mod/go.sum
// only — no detector, no cmd/mallcop, nothing under detectors/ for the guard
// to have an opinion about), the exact tree shape rd 7ee7 found the raw
// buried error on.
func TestValidateProposal_DefaultModeFailsLoudlyOnCustomerShapedTree(t *testing.T) {
	clearInferenceEnv(t)
	customerDir, base, _ := buildCustomerShapedRepo(t, customerFixtureDetectorMainSrc)

	_, err := ValidateProposal(customerDir, base, base, Options{})
	if err == nil {
		t.Fatal("expected a loud operational error for a customer-shaped tree in default mode, got nil")
	}
	if !strings.Contains(err.Error(), "--exam-repo") && !strings.Contains(err.Error(), "ExamRepo") {
		t.Fatalf("error must name the --exam-repo flag / Options.ExamRepo, got: %v", err)
	}
	if !strings.Contains(err.Error(), "cmd/mallcop") {
		t.Fatalf("error must explain the missing cmd/mallcop, got: %v", err)
	}
}
