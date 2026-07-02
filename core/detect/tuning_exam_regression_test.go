// tuning_exam_regression_test.go — the PERMANENT CI regression for the K2b
// data-only FN close (rd mallcoppro-0357): WITHOUT tuning, the PE-08
// PowerUserAccess grant is a labeled-and-unfixed detection gap (RED in
// exam-detect); WITH the COMMITTED detectors/tuning.yaml applied it flips
// GREEN, and every must_not_fire label in the corpus still passes (widen-only:
// no new firings on benign twins, incl. PE-09's ReadOnlyAccess grant).
//
// This lives in the EXTERNAL detect_test package (not core/eval or cmd/mallcop)
// deliberately: ApplyTuning mutates core/detect package-global knobs, and the
// snapshot/restore seam (SnapshotTuningKnobsForTest, export_test.go) is
// test-only and visible only to tests in this directory — keeping knob
// restoration out of the shipped API. An external test package may import
// core/eval without an import cycle.
package detect_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/eval"
)

const (
	gapScenario    = "PE-08-aws-poweruser-grant"
	benignTwin     = "PE-09-aws-readonly-grant-benign"
	seededVA03Gap  = "VA-03-data-exfil"
	tuningRelPath  = "detectors/tuning.yaml"
	privEscalation = "priv-escalation"
)

// repoRootFromHere walks up from the test's working directory (the package dir
// under `go test`) to the go.mod marker — the same self-locating discipline the
// lint gates use.
func repoRootFromHere(t *testing.T) string {
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
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// examRow returns the exam-detect row for scenarioID, failing if absent.
func examRow(t *testing.T, report eval.ExamDetectReport, scenarioID string) eval.ExamDetectRow {
	t.Helper()
	for _, r := range report.Rows {
		if r.ScenarioID == scenarioID {
			return r
		}
	}
	t.Fatalf("no exam-detect row for %s (labeled rows: %d)", scenarioID, len(report.Rows))
	return eval.ExamDetectRow{}
}

// emittedHas reports whether family tok appears in the row's emitted set.
func emittedHas(row eval.ExamDetectRow, tok string) bool {
	for _, e := range row.Emitted {
		if e == tok {
			return true
		}
	}
	return false
}

// TestTuningClosesPE08GapDataOnly is the end-to-end proof the loop can widen a
// sensor as PURE DATA: the committed tuning.yaml (no code change) flips the
// labeled PE-08 gap RED→GREEN in the REAL exam-detect grader while every
// must_not_fire label keeps passing and the VA-03 seeded gap stays RED
// (tuning touches only priv-escalation knobs).
func TestTuningClosesPE08GapDataOnly(t *testing.T) {
	restore := detect.SnapshotTuningKnobsForTest()
	t.Cleanup(restore)

	root := repoRootFromHere(t)
	eval.SetRepoRootForTest(root)
	t.Cleanup(func() { eval.SetRepoRootForTest("") })

	// --- WITHOUT tuning: PE-08 is a real, labeled false negative (RED). -----
	before, err := eval.RunExamDetect(root)
	if err != nil {
		t.Fatalf("RunExamDetect (no tuning): %v", err)
	}
	gap := examRow(t, before, gapScenario)
	if len(gap.MustFire) != 1 || gap.MustFire[0] != privEscalation {
		t.Fatalf("%s must_fire = %v, want [%s]", gapScenario, gap.MustFire, privEscalation)
	}
	if gap.Pass {
		t.Fatalf("%s PASSED without tuning — the gap this test pins has been closed in code; "+
			"re-point the regression at a real data-only gap (emitted: %v)", gapScenario, gap.Emitted)
	}
	if emittedHas(gap, privEscalation) {
		t.Fatalf("%s emitted priv-escalation yet is red — grader inconsistency (emitted: %v)", gapScenario, gap.Emitted)
	}
	twin := examRow(t, before, benignTwin)
	if !twin.Pass {
		t.Fatalf("%s (benign twin) is RED without tuning (emitted: %v)", benignTwin, twin.Emitted)
	}
	passedBefore := map[string]bool{}
	for _, r := range before.Rows {
		passedBefore[r.ScenarioID] = r.Pass
	}

	// --- Apply the COMMITTED tuning file (the real artifact, not a fixture). --
	tuningPath := filepath.Join(root, filepath.FromSlash(tuningRelPath))
	if _, err := os.Stat(tuningPath); err != nil {
		// Guard the vacuity hole: LoadTuningFile silently falls through on a
		// missing file, which would make the GREEN half of this test test nothing.
		t.Fatalf("committed tuning file %s is missing: %v", tuningRelPath, err)
	}
	tn, err := detect.LoadTuningFile(tuningPath)
	if err != nil {
		t.Fatalf("LoadTuningFile(%s): %v", tuningRelPath, err)
	}
	detect.ApplyTuning(tn)

	// --- WITH tuning: PE-08 GREEN, no must_not_fire regression, VA-03 RED. ---
	after, err := eval.RunExamDetect(root)
	if err != nil {
		t.Fatalf("RunExamDetect (with tuning): %v", err)
	}
	gap = examRow(t, after, gapScenario)
	if !gap.Pass || !emittedHas(gap, privEscalation) {
		t.Fatalf("%s still RED with the committed tuning applied (pass=%v emitted=%v)", gapScenario, gap.Pass, gap.Emitted)
	}

	// Every must_not_fire label in the corpus still holds: tuning may only WIDEN,
	// and the widening must not start firing on any benign twin.
	for _, row := range after.Rows {
		for _, banned := range row.MustNotFire {
			if emittedHas(row, banned) {
				t.Errorf("NEW FIRING under tuning: %s emitted banned family %q (emitted: %v)", row.ScenarioID, banned, row.Emitted)
			}
		}
		// Widen-only at the corpus level: no previously-green row goes red.
		if passedBefore[row.ScenarioID] && !row.Pass {
			t.Errorf("REGRESSION under tuning: %s passed without tuning but fails with it (emitted: %v)", row.ScenarioID, row.Emitted)
		}
	}

	// The VA-03 seeded volume-anomaly gap is untouched by priv-escalation tuning.
	va03 := examRow(t, after, seededVA03Gap)
	if va03.Pass {
		t.Errorf("%s went GREEN under priv-escalation tuning — tuning leaked into another detector family", seededVA03Gap)
	}
}
