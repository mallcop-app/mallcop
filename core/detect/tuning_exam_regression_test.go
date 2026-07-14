// tuning_exam_regression_test.go — the PERMANENT CI regression for the tuning
// mechanism (rd mallcoppro-a07, S3): a committed, widen-only tuning.yaml flips
// a labeled false negative RED→GREEN in the REAL exam-detect grader, no
// must_not_fire label regresses, and no previously-green row regresses.
//
// This test formerly pinned PE-08 (the AWS PowerUserAccess grant,
// detectors/tuning.yaml) as the gap tuning closes — the K2b data-only FN close
// (rd mallcoppro-0357). mallcoppro-a07 promoted "poweruser" into
// builtinElevatedKeywords (core/detect/priv_escalation.go): PE-08 now PASSES
// OUT OF THE BOX, with no tuning file at all, so that pairing is dead by
// design (this is the fix landing, not a regression) — detectors/tuning.yaml's
// poweruser entry is KEPT (core/selfgate/guard_test.go fixtures anchor on it;
// removing it is a separate human decision) but is now redundant for PE-08.
//
// The regression's INTENT survives unchanged, re-pointed at the PURPOSE-BUILT
// synthetic pair S1 introduced exactly so this demonstration never again goes
// stale when a real scenario's gap gets closed in code: SYNTH-PE-01
// must-fire + SYNTH-PE-02 benign twin (exams/synthetic/, see
// core/detect/synthdemo_invariant_test.go) closed by the synthetic keyword
// "mallcopsyntheticelevated" (exams/synthetic/tuning.yaml). That keyword is
// GUARANTEED (by synthdemo_invariant_test.go's tripwire) to never become a
// built-in, so this regression can never again be invalidated by a future
// promotion into the builtin vocabulary the way PE-08's was.
//
// The synthetic pair lives outside exams/scenarios/ (never in the pinned
// corpus, never grades CI on its own) — it is UNIONED into the grading pass
// via eval.RunExamDetectExtra's extra-scenarios-dir mechanism (mallcoppro-f95),
// pointed at a throwaway dir holding just the two synthetic scenario files
// (exams/synthetic/ also holds tuning.yaml, which is not itself a valid
// scenario, so it cannot be passed directly as the extra dir).
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
	gapScenario    = "SYNTH-PE-01-elevated-must-fire"
	benignTwin     = "SYNTH-PE-02-baseline-benign-twin"
	seededVA03Gap  = "VA-03-data-exfil"
	privEscalation = "priv-escalation"

	syntheticTuningRelPath = "exams/synthetic/tuning.yaml"
	syntheticMustFireFile  = "exams/synthetic/SYNTH-PE-01-elevated-must-fire.yaml"
	syntheticTwinFile      = "exams/synthetic/SYNTH-PE-02-baseline-benign-twin.yaml"
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

// syntheticExtraScenariosDir copies the two committed synthetic scenario files
// (exams/synthetic/SYNTH-PE-01-*, SYNTH-PE-02-*) into a fresh temp directory
// and returns its path — the UNIONED extra-scenarios-dir eval.RunExamDetectExtra
// grades alongside the pinned reference corpus. A plain copy of
// exams/synthetic/ itself will not do: that directory also holds tuning.yaml,
// which fails scenario parsing (no id/finding fields) if handed to the corpus
// scanner directly.
func syntheticExtraScenariosDir(t *testing.T, root string) string {
	t.Helper()
	dir := t.TempDir()
	for _, rel := range []string{syntheticMustFireFile, syntheticTwinFile} {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read synthetic scenario %s: %v", rel, err)
		}
		dst := filepath.Join(dir, filepath.Base(rel))
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("write synthetic scenario copy %s: %v", dst, err)
		}
	}
	return dir
}

// TestTuningClosesSyntheticGapDataOnly is the end-to-end proof the loop can
// widen a sensor as PURE DATA: the committed exams/synthetic/tuning.yaml (no
// code change) flips the labeled SYNTH-PE-01 gap RED→GREEN in the REAL
// exam-detect grader while every must_not_fire label keeps passing and the
// VA-03 seeded gap stays untouched (tuning touches only priv-escalation
// knobs).
func TestTuningClosesSyntheticGapDataOnly(t *testing.T) {
	restore := detect.SnapshotTuningKnobsForTest()
	t.Cleanup(restore)

	root := repoRootFromHere(t)
	eval.SetRepoRootForTest(root)
	t.Cleanup(func() { eval.SetRepoRootForTest("") })

	extraDir := syntheticExtraScenariosDir(t, root)

	// --- WITHOUT tuning: SYNTH-PE-01 is a real, labeled false negative (RED). -
	before, err := eval.RunExamDetectExtra(root, extraDir)
	if err != nil {
		t.Fatalf("RunExamDetectExtra (no tuning): %v", err)
	}
	gap := examRow(t, before, gapScenario)
	if len(gap.MustFire) != 1 || gap.MustFire[0] != privEscalation {
		t.Fatalf("%s must_fire = %v, want [%s]", gapScenario, gap.MustFire, privEscalation)
	}
	if gap.Pass {
		t.Fatalf("%s PASSED without tuning — the synthetic gap this test pins is supposed to be "+
			"unclosable without tuning by construction (emitted: %v); re-check exams/synthetic/ and "+
			"core/detect/synthdemo_invariant_test.go for drift", gapScenario, gap.Emitted)
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

	// --- Apply the COMMITTED synthetic tuning file (the real artifact). ------
	tuningPath := filepath.Join(root, filepath.FromSlash(syntheticTuningRelPath))
	if _, err := os.Stat(tuningPath); err != nil {
		// Guard the vacuity hole: LoadTuningFile silently falls through on a
		// missing file, which would make the GREEN half of this test test nothing.
		t.Fatalf("committed synthetic tuning file %s is missing: %v", syntheticTuningRelPath, err)
	}
	tn, err := detect.LoadTuningFile(tuningPath)
	if err != nil {
		t.Fatalf("LoadTuningFile(%s): %v", syntheticTuningRelPath, err)
	}
	detect.ApplyTuning(tn)

	// --- WITH tuning: SYNTH-PE-01 GREEN, no must_not_fire regression. --------
	after, err := eval.RunExamDetectExtra(root, extraDir)
	if err != nil {
		t.Fatalf("RunExamDetectExtra (with tuning): %v", err)
	}
	gap = examRow(t, after, gapScenario)
	if !gap.Pass || !emittedHas(gap, privEscalation) {
		t.Fatalf("%s still RED with the committed synthetic tuning applied (pass=%v emitted=%v)", gapScenario, gap.Pass, gap.Emitted)
	}

	// Every must_not_fire label in the corpus still holds: tuning may only WIDEN,
	// and the widening must not start firing on any benign twin (incl. the
	// synthetic pair's own twin).
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

	// VA-03 (volume-anomaly family) is UNTOUCHED by priv-escalation tuning: its
	// pass state must be identical with and without the tuning applied. This
	// control proves priv-escalation tuning does not LEAK into another detector
	// family and flip it either way.
	va03Before := examRow(t, before, seededVA03Gap)
	va03After := examRow(t, after, seededVA03Gap)
	if va03After.Pass != va03Before.Pass {
		t.Errorf("%s pass state changed under priv-escalation tuning (before=%v after=%v) — tuning leaked into another detector family",
			seededVA03Gap, va03Before.Pass, va03After.Pass)
	}
}
