package eval

import (
	"testing"
)

// mustFireRow builds a graded ExamDetectRow for an attack scenario (must_fire),
// with the given emitted family tokens. Pass is derived to match the real
// grader (all must_fire present).
func mustFireRow(id string, mustFire, emitted []string) ExamDetectRow {
	present := map[string]bool{}
	for _, e := range emitted {
		present[e] = true
	}
	pass := true
	for _, f := range mustFire {
		if !present[f] {
			pass = false
		}
	}
	return ExamDetectRow{ScenarioID: id, MustFire: mustFire, Emitted: emitted, Pass: pass}
}

// benignRow builds a graded ExamDetectRow for a must-stay-silent scenario
// (must_not_fire only, no must_fire), with the given emitted families.
func benignRow(id string, mustNotFire, emitted []string) ExamDetectRow {
	present := map[string]bool{}
	for _, e := range emitted {
		present[e] = true
	}
	pass := true
	for _, f := range mustNotFire {
		if present[f] {
			pass = false
		}
	}
	return ExamDetectRow{ScenarioID: id, MustNotFire: mustNotFire, Emitted: emitted, Pass: pass}
}

func findMissed(rr RecallReport, id string) (MissedAttack, bool) {
	for _, m := range rr.Recall.Missed {
		if m.ScenarioID == id {
			return m, true
		}
	}
	return MissedAttack{}, false
}

func findFalseAlarm(rr RecallReport, id string) (FalseAlarm, bool) {
	for _, fa := range rr.Precision.FalseAlarms {
		if fa.ScenarioID == id {
			return fa, true
		}
	}
	return FalseAlarm{}, false
}

// TestRecallFromReport_KnownMiss: a scenario set with a KNOWN missed attack
// reports recall < 100% and NAMES the missed attack with the family it failed to
// fire. This is the fatal-failure path the operator and the self-heal loop must
// see.
func TestRecallFromReport_KnownMiss(t *testing.T) {
	report := ExamDetectReport{Rows: []ExamDetectRow{
		// caught attack
		mustFireRow("AC-01-caught", []string{"new-external-access"}, []string{"new-external-access"}),
		// MISSED attack: must_fire volume-anomaly, emitted nothing
		mustFireRow("VA-03-missed", []string{"volume-anomaly"}, nil),
	}}

	rr := RecallFromReport(report)

	if rr.Recall.MustFire != 2 {
		t.Fatalf("MustFire denominator = %d, want 2", rr.Recall.MustFire)
	}
	if rr.Recall.Detected != 1 {
		t.Fatalf("Detected = %d, want 1", rr.Recall.Detected)
	}
	if rr.Recall.Rate >= 1.0 {
		t.Fatalf("recall rate = %.3f, want < 1.0 with a missed attack", rr.Recall.Rate)
	}
	if want := 0.5; rr.Recall.Rate != want {
		t.Fatalf("recall rate = %.3f, want %.3f", rr.Recall.Rate, want)
	}
	m, ok := findMissed(rr, "VA-03-missed")
	if !ok {
		t.Fatalf("missed attack VA-03-missed not named in %+v", rr.Recall.Missed)
	}
	if len(m.Missing) != 1 || m.Missing[0] != "volume-anomaly" {
		t.Fatalf("missed families = %v, want [volume-anomaly]", m.Missing)
	}
	if m.Reserved {
		t.Fatalf("VA-03-missed marked Reserved, but it is an ordinary (non-reserved) miss")
	}
	// The caught attack must NOT appear in the missed list.
	if _, ok := findMissed(rr, "AC-01-caught"); ok {
		t.Fatalf("AC-01-caught wrongly listed as missed")
	}
}

// TestRecallFromReport_BenignFalseFire: a benign scenario that FIRES a
// must_not_fire family reports precision < 100% and names the false alarm.
func TestRecallFromReport_BenignFalseFire(t *testing.T) {
	report := ExamDetectReport{Rows: []ExamDetectRow{
		// correctly silent benign twin
		benignRow("VA-01-quiet", []string{"volume-anomaly"}, nil),
		// false alarm: labeled must_not_fire volume-anomaly, but it fired
		benignRow("VA-02-falsefire", []string{"volume-anomaly"}, []string{"volume-anomaly"}),
	}}

	rr := RecallFromReport(report)

	if rr.Precision.MustStaySilent != 2 {
		t.Fatalf("MustStaySilent denominator = %d, want 2", rr.Precision.MustStaySilent)
	}
	if rr.Precision.CorrectSilent != 1 {
		t.Fatalf("CorrectSilent = %d, want 1", rr.Precision.CorrectSilent)
	}
	if rr.Precision.Rate >= 1.0 {
		t.Fatalf("precision rate = %.3f, want < 1.0 with a false alarm", rr.Precision.Rate)
	}
	fa, ok := findFalseAlarm(rr, "VA-02-falsefire")
	if !ok {
		t.Fatalf("false alarm VA-02-falsefire not named in %+v", rr.Precision.FalseAlarms)
	}
	if len(fa.Fired) != 1 || fa.Fired[0] != "volume-anomaly" {
		t.Fatalf("fired families = %v, want [volume-anomaly]", fa.Fired)
	}
	// A benign scenario is NOT scored for recall.
	if rr.Recall.MustFire != 0 {
		t.Fatalf("benign scenarios leaked into recall denominator: MustFire = %d", rr.Recall.MustFire)
	}
}

// TestRecallFromReport_AllGreen: perfect corpus → recall 100%, precision 100%,
// nothing named.
func TestRecallFromReport_AllGreen(t *testing.T) {
	report := ExamDetectReport{Rows: []ExamDetectRow{
		mustFireRow("A1", []string{"new-external-access"}, []string{"new-external-access"}),
		benignRow("B1", []string{"volume-anomaly"}, nil),
	}}
	rr := RecallFromReport(report)
	if rr.Recall.Rate != 1.0 || len(rr.Recall.Missed) != 0 {
		t.Fatalf("recall = %.3f missed=%v, want 1.0 / none", rr.Recall.Rate, rr.Recall.Missed)
	}
	if rr.Precision.Rate != 1.0 || len(rr.Precision.FalseAlarms) != 0 {
		t.Fatalf("precision = %.3f false=%v, want 1.0 / none", rr.Precision.Rate, rr.Precision.FalseAlarms)
	}
}

// TestRecallFromReport_MultiFamilyPartialMiss: an attack labeled with TWO
// must_fire families that only emits ONE is a miss, and the missing family is
// named (the other, caught, family is not).
func TestRecallFromReport_MultiFamilyPartialMiss(t *testing.T) {
	report := ExamDetectReport{Rows: []ExamDetectRow{
		mustFireRow("MULTI", []string{"new-external-access", "volume-anomaly"}, []string{"new-external-access"}),
	}}
	rr := RecallFromReport(report)
	if rr.Recall.Detected != 0 {
		t.Fatalf("Detected = %d, want 0 (one of two families missed)", rr.Recall.Detected)
	}
	m, ok := findMissed(rr, "MULTI")
	if !ok {
		t.Fatal("MULTI not listed as missed")
	}
	if len(m.Missing) != 1 || m.Missing[0] != "volume-anomaly" {
		t.Fatalf("missing = %v, want only [volume-anomaly] (new-external-access was caught)", m.Missing)
	}
}

// TestRecallFromReport_ReservedMissFlagged: a reserved-pending must_fire miss
// still counts against recall (the attack is genuinely not caught) but is marked
// Reserved so it reads as a tracked gap, not a regression.
func TestRecallFromReport_ReservedMissFlagged(t *testing.T) {
	report := ExamDetectReport{Rows: []ExamDetectRow{
		{
			ScenarioID:      "RSV-01",
			MustFire:        []string{"future-detector"},
			Emitted:         nil,
			Pass:            false,
			Reserved:        true,
			ReservedPending: []string{"future-detector"},
		},
	}}
	rr := RecallFromReport(report)
	if rr.Recall.MustFire != 1 || rr.Recall.Detected != 0 {
		t.Fatalf("reserved miss not counted in recall: MustFire=%d Detected=%d", rr.Recall.MustFire, rr.Recall.Detected)
	}
	m, ok := findMissed(rr, "RSV-01")
	if !ok {
		t.Fatal("RSV-01 not listed as missed")
	}
	if !m.Reserved {
		t.Fatal("RSV-01 miss should be flagged Reserved (all missing families are reserved-pending)")
	}
}

// TestRecallFromReport_EmptyCorpus: no rows → both rates are the vacuous 1.0
// (no NaN in the JSON).
func TestRecallFromReport_EmptyCorpus(t *testing.T) {
	rr := RecallFromReport(ExamDetectReport{})
	if rr.Recall.Rate != 1.0 || rr.Precision.Rate != 1.0 {
		t.Fatalf("empty corpus rates = %.3f / %.3f, want 1.0 / 1.0", rr.Recall.Rate, rr.Precision.Rate)
	}
}

// TestRecallFromReport_MatchesRealExam ties the split to the REAL committed
// corpus: every labeled row is classified into exactly one of the two buckets
// (their denominators sum to the labeled row count), each bucket balances
// (detected + missed == must-fire; silent + false == must-stay-silent), and the
// named missed/false sets are INDEPENDENTLY recomputed from the report rows so
// the split is proven to surface the real must-fire misses (production
// false-negatives) rather than trusting RecallFromReport's own arithmetic.
func TestRecallFromReport_MatchesRealExam(t *testing.T) {
	report := examDetectReportForTest(t)
	rr := RecallFromReport(report)

	if rr.Recall.MustFire+rr.Precision.MustStaySilent != len(report.Rows) {
		t.Fatalf("bucket denominators %d + %d != labeled rows %d",
			rr.Recall.MustFire, rr.Precision.MustStaySilent, len(report.Rows))
	}
	if rr.Recall.Detected+len(rr.Recall.Missed) != rr.Recall.MustFire {
		t.Fatalf("recall accounting: detected %d + missed %d != must-fire %d",
			rr.Recall.Detected, len(rr.Recall.Missed), rr.Recall.MustFire)
	}
	if rr.Precision.CorrectSilent+len(rr.Precision.FalseAlarms) != rr.Precision.MustStaySilent {
		t.Fatalf("precision accounting: silent %d + false %d != must-stay-silent %d",
			rr.Precision.CorrectSilent, len(rr.Precision.FalseAlarms), rr.Precision.MustStaySilent)
	}

	// Independently recompute, straight off the raw report rows, the set of
	// must-fire scenarios that did not emit every must_fire family — the real
	// missed attacks — and confirm RecallFromReport named exactly those.
	wantMissed := map[string]bool{}
	for _, row := range report.Rows {
		if len(row.MustFire) == 0 {
			continue
		}
		present := map[string]bool{}
		for _, e := range row.Emitted {
			present[normalizeFamilyToken(e)] = true
		}
		for _, fam := range row.MustFire {
			if !present[normalizeFamilyToken(fam)] {
				wantMissed[row.ScenarioID] = true
				break
			}
		}
	}
	gotMissed := map[string]bool{}
	for _, m := range rr.Recall.Missed {
		gotMissed[m.ScenarioID] = true
	}
	if len(gotMissed) != len(wantMissed) {
		t.Fatalf("named missed set size = %d, independently recomputed = %d\n named=%v\n want=%v",
			len(gotMissed), len(wantMissed), gotMissed, wantMissed)
	}
	for id := range wantMissed {
		if !gotMissed[id] {
			t.Fatalf("must-fire miss %s not named by RecallFromReport", id)
		}
	}
}
