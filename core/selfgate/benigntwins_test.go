// benigntwins_test.go — PROOF tests for the K7 L4c MANDATORY BENIGN-TWIN gate.
//
// The gate: a proposal that ADDS an authored detector must ship, in the head exam
// corpus, BOTH a passing must_fire scenario (a true positive) AND a passing
// must_not_fire benign twin (a true negative) for that detector's family. A
// missing benign twin is a gate finding.
//
// Invariant 10 (ground-source testing): the ACCEPT and REJECT proofs run the FULL
// gate end-to-end against a clone of the REAL repo — they author a real own-package
// detector (mirroring the committed reference detector's shape), append its blank
// import to the real registry aggregator, add real labeled scenario files, repin
// the corpus, and run guard + structural + a real exam-detect subprocess. The
// pure-function unit tests additionally pin the enforcement logic's edges.
package selfgate

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ---- pure enforcement-logic proofs (checkAuthoredBenignTwins) ---------------

func TestCheckAuthoredBenignTwins_NoAddedAuthored_IsNoOp(t *testing.T) {
	head := examReport{Rows: []examRow{
		{ScenarioID: "S-1", MustFire: []string{"config-drift"}, Pass: true},
	}}
	if got := checkAuthoredBenignTwins(nil, head); len(got) != 0 {
		t.Fatalf("no added authored detectors must be a no-op, got %+v", got)
	}
}

func TestCheckAuthoredBenignTwins_AcceptsWhenBothPresentAndPassing(t *testing.T) {
	head := examReport{Rows: []examRow{
		{ScenarioID: "FIRE", MustFire: []string{"authored-x"}, Pass: true},
		{ScenarioID: "TWIN", MustNotFire: []string{"authored-x"}, Pass: true},
	}}
	if got := checkAuthoredBenignTwins([]string{"authored-x"}, head); len(got) != 0 {
		t.Fatalf("both must_fire and must_not_fire present and passing must be clean, got %+v", got)
	}
}

func TestCheckAuthoredBenignTwins_RejectsMissingBenignTwin(t *testing.T) {
	// must_fire present + passing, but no must_not_fire twin at all.
	head := examReport{Rows: []examRow{
		{ScenarioID: "FIRE", MustFire: []string{"authored-x"}, Pass: true},
	}}
	got := checkAuthoredBenignTwins([]string{"authored-x"}, head)
	requireRejected(t, got, RuleExamMissingBenignTwin, StageExamDetect)
	for _, f := range got {
		if f.Rule == RuleExamMissingMustFire {
			t.Fatalf("must_fire IS present; unexpected missing-must-fire finding: %+v", f)
		}
	}
}

func TestCheckAuthoredBenignTwins_TwinMustActuallyPass(t *testing.T) {
	// A must_not_fire twin exists but the row FAILS — it does not count.
	head := examReport{Rows: []examRow{
		{ScenarioID: "FIRE", MustFire: []string{"authored-x"}, Pass: true},
		{ScenarioID: "TWIN", MustNotFire: []string{"authored-x"}, Pass: false},
	}}
	got := checkAuthoredBenignTwins([]string{"authored-x"}, head)
	requireRejected(t, got, RuleExamMissingBenignTwin, StageExamDetect)
}

func TestCheckAuthoredBenignTwins_RejectsMissingMustFire(t *testing.T) {
	// Benign twin present + passing, but no passing must_fire scenario.
	head := examReport{Rows: []examRow{
		{ScenarioID: "TWIN", MustNotFire: []string{"authored-x"}, Pass: true},
	}}
	got := checkAuthoredBenignTwins([]string{"authored-x"}, head)
	requireRejected(t, got, RuleExamMissingMustFire, StageExamDetect)
}

// ---- collectAuthoredDetectorNames against the REAL authored tree -------------

// TestCollectAuthoredDetectorNames_RealTree proves the collector reports exactly
// the committed reference detector's registered Name — the ground truth the
// added-authored diff is computed from.
func TestCollectAuthoredDetectorNames_RealTree(t *testing.T) {
	root := filepath.Join(repoUnderTest(t), "core", "detect", "authored")
	names, err := collectAuthoredDetectorNames(root)
	if err != nil {
		t.Fatalf("collectAuthoredDetectorNames: %v", err)
	}
	if !names["authored-synthetic-marker"] {
		t.Fatalf("expected the reference detector name authored-synthetic-marker, got %v", names)
	}
}

// ---- end-to-end: add a real authored detector -------------------------------

// examtwinDetectorSrc is a well-shaped own-package authored detector (mirrors the
// committed reference detector). It fires ONLY on a synthetic marker event type
// absent from the existing corpus, so it perturbs no existing scenario — its only
// footprint is the two new scenarios the proposal adds for it.
const examtwinDetectorSrc = `package examtwin

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(detector{}) }

const markerType = "mallcop.examtwin-marker"

type detector struct{}

func (detector) Name() string { return "authored-examtwin" }

func (detector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type != markerType {
			continue
		}
		out = append(out, finding.Finding{
			ID:        "finding-" + ev.ID + "-examtwin",
			Source:    "detector:authored-examtwin",
			Severity:  "low",
			Type:      "authored-examtwin",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    "examtwin marker observed by the L4c reference authored detector",
		})
	}
	return out
}
`

// examtwinFireScenario is the MUST-FIRE true positive: an event carrying the
// marker type, so the examtwin detector fires and the row passes.
const examtwinFireScenario = `id: ET-01-examtwin-fire
failure_mode: XX
detector: authored-examtwin
category: authored
difficulty: malicious-obvious
finding:
  id: fnd_examtwin_fire
  detector: authored-examtwin
  title: examtwin marker present
  severity: low
  event_ids:
  - evt_et01
  metadata:
    actor: examtwin-bot
    source: internal
events:
- id: evt_et01
  timestamp: '2026-03-10T10:15:00Z'
  source: internal
  event_type: mallcop.examtwin-marker
  actor: examtwin-bot
  action: emit
  target: examtwin/target
  severity: low
  metadata: {}
baseline:
  known_entities:
    actors:
    - examtwin-bot
    sources:
    - internal
expected_detection:
  must_fire:
  - authored-examtwin
  must_not_fire: []
`

// examtwinBenignTwinScenario is the MUST-NOT-FIRE true negative: a benign event
// WITHOUT the marker type, so the examtwin detector correctly stays silent and
// the row passes.
const examtwinBenignTwinScenario = `id: ET-02-examtwin-benign-twin
failure_mode: XX
detector: authored-examtwin
category: authored
difficulty: benign-obvious
finding:
  id: fnd_examtwin_benign
  detector: authored-examtwin
  title: benign event, examtwin must stay silent
  severity: low
  event_ids:
  - evt_et02
  metadata:
    actor: examtwin-bot
    source: internal
events:
- id: evt_et02
  timestamp: '2026-03-10T11:15:00Z'
  source: internal
  event_type: routine_heartbeat
  actor: examtwin-bot
  action: heartbeat
  target: examtwin/target
  severity: low
  metadata: {}
baseline:
  known_entities:
    actors:
    - examtwin-bot
    sources:
    - internal
expected_detection:
  must_fire: []
  must_not_fire:
  - authored-examtwin
`

// applyAuthoredDetectorProposal materializes, into clone's working tree, the
// full shape of a self-extension proposal that adds an authored detector: the
// own-package detector, its append-only blank import in the registry aggregator,
// the must_fire scenario, optionally the benign twin, and the paired corpus.pin
// regen. The caller commits it.
func applyAuthoredDetectorProposal(t *testing.T, clone string, withTwin bool) {
	t.Helper()

	// writeRepoFile does not create intermediate dirs; the two new trees do not
	// exist in the clone yet.
	for _, d := range []string{"core/detect/authored/examtwin", "exams/scenarios/authored"} {
		if err := os.MkdirAll(filepath.Join(clone, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	writeRepoFile(t, clone, "core/detect/authored/examtwin/examtwin.go", examtwinDetectorSrc)

	// Append the blank import to the real registry aggregator (append-only).
	reg := readRepoFile(t, clone, "core/detect/authored/registry.go")
	synthImport := "\t_ \"github.com/mallcop-app/mallcop/core/detect/authored/synthmarker\"\n"
	appended := replaceOnce(t, reg, synthImport,
		synthImport+"\t_ \"github.com/mallcop-app/mallcop/core/detect/authored/examtwin\"\n")
	writeRepoFile(t, clone, "core/detect/authored/registry.go", appended)

	writeRepoFile(t, clone, "exams/scenarios/authored/ET-01-examtwin-fire.yaml", examtwinFireScenario)
	if withTwin {
		writeRepoFile(t, clone, "exams/scenarios/authored/ET-02-examtwin-benign-twin.yaml", examtwinBenignTwinScenario)
	}

	// Repin the corpus over the head working tree (additive scenarios paired with
	// the pin regen — the guard's corpus.pin pairing rule).
	count, sha := recomputeCorpusPin(t, clone)
	writeRepoFile(t, clone, "exams/scenarios/corpus.pin",
		fmt.Sprintf("# fixture pin (L4c authored-detector benign-twin proof)\ncount %d\nsha256 %s\n", count, sha))
}

// TestValidateProposal_AcceptsAuthoredDetectorWithBenignTwin is the ACCEPT proof:
// an authored detector shipped with BOTH a passing must_fire scenario and a
// passing must_not_fire benign twin passes all three free-tier stages.
func TestValidateProposal_AcceptsAuthoredDetectorWithBenignTwin(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)
	base := headOf(t, clone)

	applyAuthoredDetectorProposal(t, clone, true)
	head := commitAll(t, clone, "proposal: add examtwin authored detector + must_fire + benign twin")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	if !res.Passed {
		t.Fatalf("an authored detector with BOTH scenarios must pass, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	for _, stage := range res.Stages {
		if !stage.Passed || len(stage.Findings) != 0 {
			t.Fatalf("stage %q not clean: %+v", stage.Name, stage)
		}
	}
	if res.CoveragePlus != 1 {
		t.Fatalf("CoveragePlus = %d, want 1 (ET-01 newly labeled and passing)", res.CoveragePlus)
	}
	if len(res.NewFirings) != 0 {
		t.Fatalf("NewFirings = %v, want none (examtwin fires only on its synthetic marker)", res.NewFirings)
	}
}

// TestValidateProposal_RejectsAuthoredDetectorMissingBenignTwin is the REJECT
// proof: the SAME authored detector + must_fire scenario, but WITHOUT the benign
// twin, passes guard + structural (the static layers cannot see the gap) and dies
// at exam-detect with the mandatory-benign-twin finding.
func TestValidateProposal_RejectsAuthoredDetectorMissingBenignTwin(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)
	base := headOf(t, clone)

	applyAuthoredDetectorProposal(t, clone, false) // no benign twin
	head := commitAll(t, clone, "proposal: add examtwin authored detector with NO benign twin")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	if res.Passed {
		t.Fatalf("an authored detector missing its benign twin must be REJECTED, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	if !res.Stages[0].Passed || !res.Stages[1].Passed || res.Stages[2].Passed {
		t.Fatalf("want guard+structural PASS and exam-detect FAIL, got %+v", res.Stages)
	}
	requireRejected(t, res.Stages[2].Findings, RuleExamMissingBenignTwin, StageExamDetect)
	// The must_fire IS present (ET-01), so there must be NO missing-must-fire finding.
	for _, f := range res.Stages[2].Findings {
		if f.Rule == RuleExamMissingMustFire {
			t.Fatalf("unexpected missing-must-fire finding — ET-01 provides the must_fire: %+v", f)
		}
	}
	// The coverage gain (ET-01) is real, so the rejection is SPECIFICALLY the
	// missing twin, not a coverage failure.
	if res.CoveragePlus != 1 {
		t.Fatalf("CoveragePlus = %d, want 1 (ET-01 still a real gain; the rejection is the missing twin)", res.CoveragePlus)
	}
}
