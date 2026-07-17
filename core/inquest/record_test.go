package inquest

import (
	"fmt"
	"strings"
	"testing"
)

// bigRecord builds a Record whose evidence deliberately exceeds maxRecordBytes
// via a large synthetic neighbor list and prior-investigation list — a
// direct, deterministic construction (not routed through assemble()) so the
// size-cap trim order itself is what's under test.
func bigRecord(neighborCount, priorCount int) Record {
	rec := Record{
		SchemaVersion: SchemaVersion, FindingID: "finding-big", Role: "evidence",
		Verdict: VerdictBenign, Confidence: 0.5, Narrative: "a real narrative",
		NarrativeStatus: StatusOK,
	}
	for i := 0; i < neighborCount; i++ {
		rec.Evidence.Neighbors.Events = append(rec.Evidence.Neighbors.Events, NeighborEvent{
			ID: fmt.Sprintf("evt-%04d", i), Source: "aws", Type: "assume_role",
			Actor: "some-actor-name-padding-for-size", Target: "some-target-name-padding-for-size",
			Timestamp: "2026-03-01T09:00:00Z", OffsetSeconds: float64(i),
		})
	}
	for i := 0; i < priorCount; i++ {
		rec.Evidence.Recurrence.PriorInvestigations = append(rec.Evidence.Recurrence.PriorInvestigations, PriorInvestigation{
			FindingID: fmt.Sprintf("finding-prior-%04d", i), Verdict: "benign", Confidence: 0.5,
			UpdatedAt: "2026-03-01T09:00:00Z",
		})
		rec.Evidence.Recurrence.PriorFindingIDs = append(rec.Evidence.Recurrence.PriorFindingIDs, fmt.Sprintf("finding-prior-%04d", i))
	}
	return rec
}

// TestEnforceRecordSizeCap_UnderCapUnchanged proves a small record passes
// through untouched.
func TestEnforceRecordSizeCap_UnderCapUnchanged(t *testing.T) {
	rec := bigRecord(2, 1)
	out, b, err := enforceRecordSizeCap(rec)
	if err != nil {
		t.Fatalf("enforceRecordSizeCap: %v", err)
	}
	if len(out.Evidence.Neighbors.Events) != 2 || len(out.Evidence.Recurrence.PriorInvestigations) != 1 {
		t.Errorf("small record was trimmed unexpectedly: %+v", out.Evidence)
	}
	if len(b) > maxRecordBytes {
		t.Errorf("marshaled size %d exceeds cap %d", len(b), maxRecordBytes)
	}
}

// TestEnforceRecordSizeCap_DropsNeighborsFirst proves an oversized record
// with BOTH a huge neighbor list and a huge prior-investigation list drops
// the neighbor tail FIRST — the prior lists survive fully if trimming
// neighbors alone gets the record under cap.
func TestEnforceRecordSizeCap_DropsNeighborsFirst(t *testing.T) {
	rec := bigRecord(2000, 5) // neighbors alone vastly exceed the cap
	out, b, err := enforceRecordSizeCap(rec)
	if err != nil {
		t.Fatalf("enforceRecordSizeCap: %v", err)
	}
	if len(b) > maxRecordBytes {
		t.Fatalf("marshaled size %d exceeds cap %d after trimming", len(b), maxRecordBytes)
	}
	if len(out.Evidence.Neighbors.Events) >= 2000 {
		t.Errorf("expected neighbors to be trimmed, got %d", len(out.Evidence.Neighbors.Events))
	}
	// Prior lists (small: 5 entries) should survive fully — neighbor trimming
	// alone was enough.
	if len(out.Evidence.Recurrence.PriorInvestigations) != 5 {
		t.Errorf("expected all 5 prior investigations to survive (neighbor trim should suffice), got %d",
			len(out.Evidence.Recurrence.PriorInvestigations))
	}
}

// TestEnforceRecordSizeCap_DropsPriorListsAfterNeighborsExhausted proves that
// once EVERY neighbor is gone and the record is still over cap, prior lists
// are trimmed next — and identity/verdict/narrative are NEVER touched.
func TestEnforceRecordSizeCap_DropsPriorListsAfterNeighborsExhausted(t *testing.T) {
	rec := bigRecord(0, 4000) // no neighbors at all; prior lists alone exceed cap
	rec.Evidence.Identity = IdentityEvidence{
		Caller:     "arn:aws:iam::111122223333:role/mallcop-bedrock-relay",
		FieldPaths: map[string]string{"caller": "payload.caller"},
	}
	rec.Narrative = "the narrative text that must survive size trimming untouched"

	out, b, err := enforceRecordSizeCap(rec)
	if err != nil {
		t.Fatalf("enforceRecordSizeCap: %v", err)
	}
	if len(b) > maxRecordBytes {
		t.Fatalf("marshaled size %d exceeds cap %d after trimming", len(b), maxRecordBytes)
	}
	if len(out.Evidence.Recurrence.PriorInvestigations) >= 4000 || len(out.Evidence.Recurrence.PriorFindingIDs) >= 4000 {
		t.Errorf("expected prior lists to be trimmed, got investigations=%d ids=%d",
			len(out.Evidence.Recurrence.PriorInvestigations), len(out.Evidence.Recurrence.PriorFindingIDs))
	}
	if out.Verdict != VerdictBenign {
		t.Errorf("Verdict was altered by size trimming: %v", out.Verdict)
	}
	if out.Narrative != "the narrative text that must survive size trimming untouched" {
		t.Errorf("Narrative was altered by size trimming: %q", out.Narrative)
	}
	if out.Evidence.Identity.Caller != "arn:aws:iam::111122223333:role/mallcop-bedrock-relay" {
		t.Errorf("Identity was altered by size trimming: %+v", out.Evidence.Identity)
	}
}

// TestEnforceRecordSizeCap_MatchesWriteSnapshotEncoding proves the cap is
// enforced against the SAME encoding store.WriteSnapshot actually commits
// (indented, not compact) — trimming against a smaller compact encoding could
// leave a record that re-grows past the cap once indented for the real
// commit.
func TestEnforceRecordSizeCap_MatchesWriteSnapshotEncoding(t *testing.T) {
	rec := bigRecord(500, 5)
	_, b, err := enforceRecordSizeCap(rec)
	if err != nil {
		t.Fatalf("enforceRecordSizeCap: %v", err)
	}
	if !strings.Contains(string(b), "\n  ") {
		t.Error("marshaled bytes do not look indented — enforceRecordSizeCap must size against the same encoding WriteSnapshot commits")
	}
}
