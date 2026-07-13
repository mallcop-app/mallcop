package eval

import (
	"reflect"
	"testing"

	"github.com/mallcop-app/mallcop/core/detect"
)

// examDetectReportForTest pins the repo root and runs the exam-detect grader
// over the real committed corpus.
func examDetectReportForTest(t *testing.T) ExamDetectReport {
	t.Helper()
	root := repoRootForTest(t)
	SetRepoRootForTest(root)
	t.Cleanup(func() { SetRepoRootForTest("") })

	report, err := RunExamDetect(root)
	if err != nil {
		t.Fatalf("RunExamDetect: %v", err)
	}
	return report
}

// findRow returns the row for scenarioID, failing the test if absent.
func findRow(t *testing.T, report ExamDetectReport, scenarioID string) ExamDetectRow {
	t.Helper()
	for _, r := range report.Rows {
		if r.ScenarioID == scenarioID {
			return r
		}
	}
	t.Fatalf("no exam-detect row for %s (labeled rows: %d)", scenarioID, len(report.Rows))
	return ExamDetectRow{}
}

// TestRunExamDetect_VolumeContractClosesGap asserts the K1 seeded detection gap
// is now CLOSED (mallcoppro-3c9). VA-03 is labeled must_fire volume-anomaly and
// the spike lives in metadata.blobs_accessed (500 operations) across 8 event
// RECORDS, not in the record count. The detector used to count records (8) vs the
// baseline frequency (10) and never fire — the field/unit contract mismatch. It
// now reads the canonical magnitude field so the metadata-carried spike fires and
// the row is GREEN. This assertion is the flip the earlier RED test promised: if
// the volume contract regresses, VA-03 goes red here.
func TestRunExamDetect_VolumeContractClosesGap(t *testing.T) {
	report := examDetectReportForTest(t)

	row := findRow(t, report, "VA-03-data-exfil")
	if len(row.MustFire) != 1 || row.MustFire[0] != "volume-anomaly" {
		t.Fatalf("VA-03 must_fire = %v, want [volume-anomaly]", row.MustFire)
	}
	if !row.Pass {
		t.Fatalf("VA-03 row is RED — the volume field/unit contract regressed; volume-anomaly no longer fires on a metadata-carried spike (emitted: %v)", row.Emitted)
	}
	var present bool
	for _, tok := range row.Emitted {
		if tok == "volume-anomaly" {
			present = true
		}
	}
	if !present {
		t.Fatalf("VA-03 emitted set %v lacks volume-anomaly yet passed — grader inconsistency", row.Emitted)
	}

	// The sibling metadata-carried volume scenarios cited in the same gap
	// (CO-02 tiny-baseline exfil, VA-04 api-enumeration, ND-01 bulk export) are
	// now labeled and must all fire the same general mechanism — never a
	// per-scenario rule (R9).
	for _, id := range []string{
		"CO-02-benign-events-first",
		"VA-04-api-enumeration",
		"ND-01-authorized-data-export",
	} {
		r := findRow(t, report, id)
		if !r.Pass {
			t.Errorf("%s row is RED — volume-anomaly must fire on its metadata-carried spike (emitted: %v)", id, r.Emitted)
		}
	}
}

// TestRunExamDetect_DistributedSprayFires asserts the auth-failure-burst
// distributed-spray gap is closed (mallcoppro-bcc): AF-02 spreads one failed
// login across five accounts from five IPs so no single account trips the
// per-actor burst threshold — the per-actor loop was blind to it. Cross-actor
// aggregation now fires auth-failure-burst on the coordinated campaign, so the
// labeled row is GREEN.
func TestRunExamDetect_DistributedSprayFires(t *testing.T) {
	report := examDetectReportForTest(t)

	row := findRow(t, report, "AF-02-distributed-spray")
	if len(row.MustFire) != 1 || row.MustFire[0] != "auth-failure-burst" {
		t.Fatalf("AF-02 must_fire = %v, want [auth-failure-burst]", row.MustFire)
	}
	if !row.Pass {
		t.Fatalf("AF-02 row is RED — distributed-spray detection regressed (emitted: %v)", row.Emitted)
	}
	var present bool
	for _, tok := range row.Emitted {
		if tok == "auth-failure-burst" {
			present = true
		}
	}
	if !present {
		t.Fatalf("AF-02 emitted set %v lacks auth-failure-burst yet passed — grader inconsistency", row.Emitted)
	}
}

// TestRunExamDetect_GreenControl asserts the AC-01 control: new-external-access
// IS reproduced by the real detect layer, so its must_fire label passes. This
// pins that the runner grades a working detector GREEN (the RED on VA-03 is a
// detector gap, not a broken grader).
func TestRunExamDetect_GreenControl(t *testing.T) {
	report := examDetectReportForTest(t)

	row := findRow(t, report, "AC-01-external-access-stolen-cred")
	if len(row.MustFire) != 1 || row.MustFire[0] != "new-external-access" {
		t.Fatalf("AC-01 must_fire = %v, want [new-external-access]", row.MustFire)
	}
	if !row.Pass {
		t.Fatalf("AC-01 row is RED — new-external-access no longer fires (emitted: %v)", row.Emitted)
	}
	var present bool
	for _, tok := range row.Emitted {
		if tok == "new-external-access" {
			present = true
		}
	}
	if !present {
		t.Fatalf("AC-01 emitted set %v lacks new-external-access yet passed — grader inconsistency", row.Emitted)
	}
	if report.Totals.Passed < 1 {
		t.Errorf("Totals.Passed = %d, want >= 1 while AC-01 is green", report.Totals.Passed)
	}
}

// TestRunExamDetect_BenignTwinsStaySilent asserts the future no-new-firings
// guard: the benign volume-burst twins are labeled must_not_fire volume-anomaly
// and currently pass. A detector change that starts firing on them turns these
// rows RED — the false-positive interlock for closing the VA-03 gap.
func TestRunExamDetect_BenignTwinsStaySilent(t *testing.T) {
	report := examDetectReportForTest(t)

	for _, id := range []string{
		"VA-01-deploy-burst",
		"VA-02-month-end-batch",
		"VA-05-quarterly-report-burst",
	} {
		row := findRow(t, report, id)
		if len(row.MustNotFire) != 1 || row.MustNotFire[0] != "volume-anomaly" {
			t.Errorf("%s must_not_fire = %v, want [volume-anomaly]", id, row.MustNotFire)
			continue
		}
		if !row.Pass {
			t.Errorf("%s row is RED — volume-anomaly fired on a benign twin (emitted: %v)", id, row.Emitted)
		}
	}
}

// TestRunExamDetect_Deterministic runs the grader twice and asserts identical
// reports — offline, LLM-free, no ambient state (§4.1 determinism).
func TestRunExamDetect_Deterministic(t *testing.T) {
	root := repoRootForTest(t)
	SetRepoRootForTest(root)
	t.Cleanup(func() { SetRepoRootForTest("") })

	first, err := RunExamDetect(root)
	if err != nil {
		t.Fatalf("RunExamDetect (first): %v", err)
	}
	second, err := RunExamDetect(root)
	if err != nil {
		t.Fatalf("RunExamDetect (second): %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("two runs differ:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}

// TestRunExamDetect_VeracityRealDetect proves the runner grades the REAL
// core/detect output (invariant 10 — no stubbed findings): the AC-01 row's
// emitted families must equal what detect.Detect itself returns over the same
// scenario projections.
func TestRunExamDetect_VeracityRealDetect(t *testing.T) {
	root := repoRootForTest(t)
	SetRepoRootForTest(root)
	t.Cleanup(func() { SetRepoRootForTest("") })

	corpus, err := Load(root)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	var want []string
	var found bool
	for _, ls := range corpus.Scenarios {
		if ls.Scenario.ID != "AC-01-external-access-stolen-cred" {
			continue
		}
		found = true
		emitted := detect.Detect(scenarioEvents(ls.Scenario), baselineFromScenario(ls.Scenario))
		if len(emitted) == 0 {
			t.Fatal("real detect.Detect emitted zero findings for AC-01 — the veracity comparison is vacuous")
		}
		for _, f := range emitted {
			want = append(want, findingFamilyToken(f))
		}
	}
	if !found {
		t.Fatal("AC-01-external-access-stolen-cred not in corpus")
	}

	report, err := RunExamDetect(root)
	if err != nil {
		t.Fatalf("RunExamDetect: %v", err)
	}
	row := findRow(t, report, "AC-01-external-access-stolen-cred")
	if !reflect.DeepEqual(row.Emitted, want) {
		t.Fatalf("row.Emitted = %v, want the real detect output %v", row.Emitted, want)
	}
}
