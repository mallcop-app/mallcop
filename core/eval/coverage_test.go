package eval

import (
	"reflect"
	"testing"
)

// famRow is a tiny row builder for the synthetic-report tests.
func famRow(id string, fire, notFire, emitted, reservedPending []string) ExamDetectRow {
	return ExamDetectRow{
		ScenarioID:      id,
		MustFire:        fire,
		MustNotFire:     notFire,
		Emitted:         emitted,
		ReservedPending: reservedPending,
	}
}

// findFam returns the FamilyCoverage for fam, or fails.
func findFam(t *testing.T, m []FamilyCoverage, fam string) FamilyCoverage {
	t.Helper()
	for _, fc := range m {
		if fc.Family == fam {
			return fc
		}
	}
	t.Fatalf("family %q not in coverage matrix %+v", fam, m)
	return FamilyCoverage{}
}

// TestCoverageMatrix_SyntheticReport drives CoverageMatrix over a hand-built
// report exercising every counter (attack/benign labels, missed, false_alarms,
// reserved) and the family-presence semantics.
func TestCoverageMatrix_SyntheticReport(t *testing.T) {
	report := ExamDetectReport{Rows: []ExamDetectRow{
		// priv-escalation must_fire, satisfied (present in emitted).
		famRow("A-fire-hit", []string{"priv-escalation"}, nil,
			[]string{"priv-escalation", "new-actor"}, nil),
		// priv-escalation must_fire, MISSED (absent, not reserved).
		famRow("B-fire-miss", []string{"priv-escalation"}, nil,
			[]string{"new-actor"}, nil),
		// unusual-timing must_fire, RESERVED-pending (unregistered family).
		famRow("C-fire-reserved", []string{"unusual-timing"}, nil,
			nil, []string{"unusual-timing"}),
		// volume-anomaly must_not_fire, correctly SILENT (benign, no false alarm).
		famRow("D-benign-silent", nil, []string{"volume-anomaly"},
			nil, nil),
		// volume-anomaly must_not_fire, FALSE ALARM (present in emitted).
		famRow("E-benign-falsealarm", nil, []string{"volume-anomaly"},
			[]string{"volume-anomaly"}, nil),
		// Multi-family row: both must_fire (present) and must_not_fire (silent).
		famRow("F-multi", []string{"new-actor"}, []string{"priv-escalation"},
			[]string{"new-actor"}, nil),
	}}

	m := CoverageMatrix(report)

	// priv-escalation: 2 must_fire (A hit, B miss) + 1 must_not_fire (F silent).
	pe := findFam(t, m, "priv-escalation")
	if pe.AttackLabels != 2 || pe.Missed != 1 || pe.Reserved != 0 {
		t.Errorf("priv-escalation attack=%d missed=%d reserved=%d, want 2/1/0", pe.AttackLabels, pe.Missed, pe.Reserved)
	}
	if pe.BenignLabels != 1 || pe.FalseAlarms != 0 {
		t.Errorf("priv-escalation benign=%d falseAlarms=%d, want 1/0", pe.BenignLabels, pe.FalseAlarms)
	}

	// unusual-timing: 1 must_fire, reserved-pending (not counted as missed).
	ut := findFam(t, m, "unusual-timing")
	if ut.AttackLabels != 1 || ut.Reserved != 1 || ut.Missed != 0 {
		t.Errorf("unusual-timing attack=%d reserved=%d missed=%d, want 1/1/0", ut.AttackLabels, ut.Reserved, ut.Missed)
	}

	// volume-anomaly: 2 must_not_fire, 1 false alarm.
	va := findFam(t, m, "volume-anomaly")
	if va.BenignLabels != 2 || va.FalseAlarms != 1 || va.AttackLabels != 0 {
		t.Errorf("volume-anomaly benign=%d falseAlarms=%d attack=%d, want 2/1/0", va.BenignLabels, va.FalseAlarms, va.AttackLabels)
	}

	// new-actor: 1 must_fire, satisfied.
	na := findFam(t, m, "new-actor")
	if na.AttackLabels != 1 || na.Missed != 0 {
		t.Errorf("new-actor attack=%d missed=%d, want 1/0", na.AttackLabels, na.Missed)
	}

	// Deterministic, sorted by family token.
	for i := 1; i < len(m); i++ {
		if m[i-1].Family >= m[i].Family {
			t.Errorf("matrix not sorted at %d: %q >= %q", i, m[i-1].Family, m[i].Family)
		}
	}
}

// TestCoverageMatrix_EmptyReport asserts the empty-report shape (no rows -> no
// families), so the JSON `coverage` field is omitted for a zero-row report.
func TestCoverageMatrix_EmptyReport(t *testing.T) {
	m := CoverageMatrix(ExamDetectReport{})
	if len(m) != 0 {
		t.Fatalf("empty report should yield zero coverage rows, got %+v", m)
	}
}

// TestCoverageMatrix_IncidentalEmitNotAFamily asserts a family that only ever
// appears in Emitted (never labeled must_fire/must_not_fire) is NOT a matrix
// row — the matrix tracks the labeled coverage surface, not raw detector output.
func TestCoverageMatrix_IncidentalEmitNotAFamily(t *testing.T) {
	report := ExamDetectReport{Rows: []ExamDetectRow{
		famRow("only-labeled", []string{"priv-escalation"}, nil,
			[]string{"priv-escalation", "new-actor"}, nil),
	}}
	m := CoverageMatrix(report)
	for _, fc := range m {
		if fc.Family == "new-actor" {
			t.Fatalf("new-actor was only emitted incidentally, must not be a matrix row: %+v", m)
		}
	}
}

// TestCoverageMatrix_NormalizesTokens asserts label/emitted tokens are compared
// under the same normalization the grader uses (case/space-insensitive).
func TestCoverageMatrix_NormalizesTokens(t *testing.T) {
	report := ExamDetectReport{Rows: []ExamDetectRow{
		famRow("norm", []string{"  Priv-Escalation "}, nil,
			[]string{"priv-escalation"}, nil),
	}}
	m := CoverageMatrix(report)
	pe := findFam(t, m, "priv-escalation")
	if pe.AttackLabels != 1 || pe.Missed != 0 {
		t.Fatalf("normalized token should count as a hit: %+v", pe)
	}
}

// TestCoverageMatrix_OnRealReport is a smoke test: the matrix derived from the
// live corpus report is internally consistent — every family's Missed <=
// AttackLabels and FalseAlarms <= BenignLabels, and Reserved+Missed <=
// AttackLabels. Grounds the additive JSON field against the real run.
func TestCoverageMatrix_OnRealReport(t *testing.T) {
	root := repoRootForTest(t)
	SetRepoRootForTest(root)
	t.Cleanup(func() { SetRepoRootForTest("") })

	report, err := RunExamDetect(root)
	if err != nil {
		t.Fatalf("RunExamDetect: %v", err)
	}
	if len(report.Coverage) == 0 {
		t.Fatal("live report has an empty coverage matrix — the additive field was not populated")
	}
	if !reflect.DeepEqual(report.Coverage, CoverageMatrix(report)) {
		t.Fatal("report.Coverage differs from CoverageMatrix(report) — populate step drifted")
	}
	for _, fc := range report.Coverage {
		if fc.Missed > fc.AttackLabels {
			t.Errorf("%s: missed %d > attack_labels %d", fc.Family, fc.Missed, fc.AttackLabels)
		}
		if fc.Reserved+fc.Missed > fc.AttackLabels {
			t.Errorf("%s: reserved+missed %d > attack_labels %d", fc.Family, fc.Reserved+fc.Missed, fc.AttackLabels)
		}
		if fc.FalseAlarms > fc.BenignLabels {
			t.Errorf("%s: false_alarms %d > benign_labels %d", fc.Family, fc.FalseAlarms, fc.BenignLabels)
		}
	}
}
