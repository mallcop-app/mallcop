package inquest

import (
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestAssembleRecurrence_MedianAndLabel proves a synthetic hourly series
// yields median 3600s and cadence label "hourly".
func TestAssembleRecurrence_MedianAndLabel(t *testing.T) {
	s := newTempStore(t)
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	f := finding.Finding{ID: "finding-x", Actor: "forge-proxy", Type: "assume_role", Timestamp: base.Add(4 * time.Hour)}

	occ := []time.Time{base, base.Add(time.Hour), base.Add(2 * time.Hour), base.Add(3 * time.Hour), base.Add(4 * time.Hour)}
	out := assembleRecurrence(s, occ, f)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	if out.Occurrences != 5 {
		t.Errorf("Occurrences = %d, want 5", out.Occurrences)
	}
	if out.CadenceSecondsMedian != 3600 {
		t.Errorf("CadenceSecondsMedian = %v, want 3600", out.CadenceSecondsMedian)
	}
	if out.CadenceLabel != "hourly" {
		t.Errorf("CadenceLabel = %q, want %q", out.CadenceLabel, "hourly")
	}
	if out.FirstSeen != base.Format(time.RFC3339) {
		t.Errorf("FirstSeen = %q, want %q", out.FirstSeen, base.Format(time.RFC3339))
	}
}

// TestCadenceLabel_Buckets proves every bucket boundary at ±20% tolerance.
func TestCadenceLabel_Buckets(t *testing.T) {
	cases := []struct {
		seconds float64
		want    string
	}{
		{60, "minutely"},
		{48, "minutely"}, // -20%
		{72, "minutely"}, // +20%
		{3600, "hourly"},
		{2880, "hourly"}, // -20%
		{4320, "hourly"}, // +20%
		{86400, "daily"},
		{604800, "weekly"},
		{100, "irregular (~100s)"},
		{7200, "irregular (~7200s)"}, // between hourly(+20%=4320) and daily(-20%=69120): irregular
	}
	for _, c := range cases {
		got := cadenceLabel(c.seconds)
		if got != c.want {
			t.Errorf("cadenceLabel(%v) = %q, want %q", c.seconds, got, c.want)
		}
	}
}

// TestAssembleRecurrence_FewerThanTwoOccurrences proves cadence fields stay
// zero-value (no fabricated cadence) when there's no inter-arrival gap to
// measure.
func TestAssembleRecurrence_FewerThanTwoOccurrences(t *testing.T) {
	s := newTempStore(t)
	f := finding.Finding{ID: "finding-x", Actor: "a", Type: "t"}

	out0 := assembleRecurrence(s, nil, f)
	if out0.Occurrences != 0 || out0.CadenceSecondsMedian != 0 || out0.CadenceLabel != "" {
		t.Errorf("zero occurrences: got %+v", out0)
	}

	out1 := assembleRecurrence(s, []time.Time{time.Now()}, f)
	if out1.Occurrences != 1 || out1.CadenceSecondsMedian != 0 || out1.CadenceLabel != "" {
		t.Errorf("one occurrence: got %+v", out1)
	}
}

// TestAssembleRecurrence_PriorFindingsAndInvestigations proves prior findings
// sharing (actor, type) are collected (capped 20, newest), excluding the
// finding itself, and prior investigation records are read back via
// ReadSnapshot.
func TestAssembleRecurrence_PriorFindingsAndInvestigations(t *testing.T) {
	s := newTempStore(t)
	f := finding.Finding{ID: "finding-current", Actor: "forge-proxy", Type: "assume_role"}

	// Seed the current finding plus 3 prior findings of the same (actor,type)
	// and one UNRELATED finding (different type) that must not be picked up.
	seedFinding(t, s, f)
	seedFinding(t, s, finding.Finding{ID: "finding-prior-1", Actor: "forge-proxy", Type: "assume_role"})
	seedFinding(t, s, finding.Finding{ID: "finding-prior-2", Actor: "forge-proxy", Type: "assume_role"})
	seedFinding(t, s, finding.Finding{ID: "finding-unrelated", Actor: "forge-proxy", Type: "other_type"})

	// Write a prior investigation record for finding-prior-1 only.
	rec := Record{
		SchemaVersion: SchemaVersion, FindingID: "finding-prior-1", Role: "evidence",
		Verdict: VerdictBenign, Confidence: 0.9, NarrativeStatus: StatusOK, UpdatedAt: "2026-03-01T09:00:00Z",
	}
	if _, err := s.WriteSnapshot(recordPath("finding-prior-1"), rec); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	out := assembleRecurrence(s, nil, f)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	if len(out.PriorFindingIDs) != 2 {
		t.Fatalf("PriorFindingIDs = %v, want 2 entries", out.PriorFindingIDs)
	}
	for _, id := range out.PriorFindingIDs {
		if id != "finding-prior-1" && id != "finding-prior-2" {
			t.Errorf("unexpected prior finding id %q", id)
		}
	}
	if len(out.PriorInvestigations) != 1 {
		t.Fatalf("PriorInvestigations = %v, want 1 entry", out.PriorInvestigations)
	}
	pi := out.PriorInvestigations[0]
	if pi.FindingID != "finding-prior-1" || pi.Verdict != "benign" || pi.Confidence != 0.9 {
		t.Errorf("PriorInvestigations[0] = %+v", pi)
	}
}

// TestAssembleRecurrence_CapsAtTwentyNewest proves more than 20 prior
// findings caps to the newest 20 (KindFindings is append-only oldest-first).
func TestAssembleRecurrence_CapsAtTwentyNewest(t *testing.T) {
	s := newTempStore(t)
	f := finding.Finding{ID: "finding-current", Actor: "a", Type: "t"}
	seedFinding(t, s, f)
	for i := 0; i < 25; i++ {
		seedFinding(t, s, finding.Finding{ID: "finding-p" + string(rune('a'+i)), Actor: "a", Type: "t"})
	}
	out := assembleRecurrence(s, nil, f)
	if len(out.PriorFindingIDs) != 20 {
		t.Fatalf("PriorFindingIDs len = %d, want 20", len(out.PriorFindingIDs))
	}
	// Newest 20 means the earliest 5 ("finding-pa".."finding-pe") are dropped.
	for _, id := range out.PriorFindingIDs {
		if id == "finding-pa" || id == "finding-pb" || id == "finding-pc" || id == "finding-pd" || id == "finding-pe" {
			t.Errorf("expected the OLDEST entries dropped, found %q", id)
		}
	}
}
