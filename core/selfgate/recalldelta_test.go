// recalldelta_test.go — unit proofs for the C6 recall/precision deltas
// (recalldelta.go). Pure over synthetic examReport pairs — no subprocess, no
// corpus — so the recall/precision math is proven in isolation from the exam
// harness that feeds it in production.
package selfgate

import (
	"reflect"
	"testing"
)

// mkRow is a compact examRow builder for the delta fixtures.
func mkRow(id string, mustFire, mustNotFire, emitted []string) examRow {
	return examRow{ScenarioID: id, MustFire: mustFire, MustNotFire: mustNotFire, Emitted: emitted}
}

// TestRecallPrecisionDelta_GapCloseNoRegression is the canonical widen: one
// must_fire family goes from missed at base to caught at head (recall +1), the
// benign twin stays silent at both (no precision change). This is the exact
// signal the self-heal loop reads to confirm "the gap closed and recall did not
// regress".
func TestRecallPrecisionDelta_GapCloseNoRegression(t *testing.T) {
	base := examReport{Rows: []examRow{
		mkRow("S1", []string{"priv-escalation"}, nil, nil),           // missed at base
		mkRow("S2", nil, []string{"priv-escalation"}, nil),           // benign, silent
		mkRow("S3", []string{"exfil-pattern"}, nil, []string{"exfil-pattern"}), // already caught
	}}
	head := examReport{Rows: []examRow{
		mkRow("S1", []string{"priv-escalation"}, nil, []string{"priv-escalation"}), // now caught
		mkRow("S2", nil, []string{"priv-escalation"}, nil),                          // still silent
		mkRow("S3", []string{"exfil-pattern"}, nil, []string{"exfil-pattern"}),      // unchanged
	}}

	rd, pd := recallPrecisionDelta(base, head)

	if rd.BaseDetected != 1 || rd.HeadDetected != 2 {
		t.Fatalf("recall totals: base=%d head=%d, want 1/2", rd.BaseDetected, rd.HeadDetected)
	}
	wantNewly := []ScenarioFamily{{ScenarioID: "S1", Family: "priv-escalation"}}
	if !reflect.DeepEqual(rd.NewlyDetected, wantNewly) {
		t.Fatalf("NewlyDetected = %v, want %v", rd.NewlyDetected, wantNewly)
	}
	if len(rd.NewlyMissed) != 0 {
		t.Fatalf("NewlyMissed = %v, want none (no recall regression)", rd.NewlyMissed)
	}
	if pd.BaseClean != 1 || pd.HeadClean != 1 {
		t.Fatalf("precision totals: base=%d head=%d, want 1/1", pd.BaseClean, pd.HeadClean)
	}
	if len(pd.NewlyViolated) != 0 || len(pd.NewlyClean) != 0 {
		t.Fatalf("precision must be unchanged, got violated=%v clean=%v", pd.NewlyViolated, pd.NewlyClean)
	}
}

// TestRecallPrecisionDelta_RecallRegressionAndNewViolation exercises the two
// bad flips the loop must be able to SEE: a previously-caught attack goes silent
// at head (recall regression -> NewlyMissed) and a benign twin starts firing at
// head (precision regression -> NewlyViolated).
func TestRecallPrecisionDelta_RecallRegressionAndNewViolation(t *testing.T) {
	base := examReport{Rows: []examRow{
		mkRow("A1", []string{"priv-escalation"}, nil, []string{"priv-escalation"}), // caught at base
		mkRow("B1", nil, []string{"priv-escalation"}, nil),                          // silent at base
	}}
	head := examReport{Rows: []examRow{
		mkRow("A1", []string{"priv-escalation"}, nil, nil),                           // now missed
		mkRow("B1", nil, []string{"priv-escalation"}, []string{"priv-escalation"}),   // now fires
	}}

	rd, pd := recallPrecisionDelta(base, head)

	wantMissed := []ScenarioFamily{{ScenarioID: "A1", Family: "priv-escalation"}}
	if !reflect.DeepEqual(rd.NewlyMissed, wantMissed) {
		t.Fatalf("NewlyMissed = %v, want %v", rd.NewlyMissed, wantMissed)
	}
	if len(rd.NewlyDetected) != 0 {
		t.Fatalf("NewlyDetected = %v, want none", rd.NewlyDetected)
	}
	wantViolated := []ScenarioFamily{{ScenarioID: "B1", Family: "priv-escalation"}}
	if !reflect.DeepEqual(pd.NewlyViolated, wantViolated) {
		t.Fatalf("NewlyViolated = %v, want %v", pd.NewlyViolated, wantViolated)
	}
	if len(pd.NewlyClean) != 0 {
		t.Fatalf("NewlyClean = %v, want none", pd.NewlyClean)
	}
}

// TestRecallPrecisionDelta_AddedScenarioAttributedToHeadOnly proves a scenario
// present ONLY at head (newly added by the proposal) contributes its caught
// must_fire unit to HeadDetected/NewlyDetected even though it has no base row,
// and a newly-added benign twin that stays silent contributes to HeadClean.
func TestRecallPrecisionDelta_AddedScenarioAttributedToHeadOnly(t *testing.T) {
	base := examReport{Rows: []examRow{
		mkRow("keep", []string{"exfil-pattern"}, nil, []string{"exfil-pattern"}),
	}}
	head := examReport{Rows: []examRow{
		mkRow("keep", []string{"exfil-pattern"}, nil, []string{"exfil-pattern"}),
		mkRow("NEW-fire", []string{"priv-escalation"}, nil, []string{"priv-escalation"}), // added, caught
		mkRow("NEW-twin", nil, []string{"priv-escalation"}, nil),                         // added, silent
	}}

	rd, pd := recallPrecisionDelta(base, head)

	if rd.BaseDetected != 1 || rd.HeadDetected != 2 {
		t.Fatalf("recall totals: base=%d head=%d, want 1/2", rd.BaseDetected, rd.HeadDetected)
	}
	wantNewly := []ScenarioFamily{{ScenarioID: "NEW-fire", Family: "priv-escalation"}}
	if !reflect.DeepEqual(rd.NewlyDetected, wantNewly) {
		t.Fatalf("NewlyDetected = %v, want %v", rd.NewlyDetected, wantNewly)
	}
	if pd.HeadClean != 1 || len(pd.NewlyClean) != 1 || pd.NewlyClean[0].ScenarioID != "NEW-twin" {
		t.Fatalf("added benign twin should be a HeadClean/NewlyClean unit, got clean=%d newlyClean=%v", pd.HeadClean, pd.NewlyClean)
	}
}
