package cases

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func esc(id, typ, actor, sev, entity string, ts time.Time) Escalation {
	return Escalation{FindingID: id, Type: typ, Actor: actor, Severity: sev, Entity: entity, Timestamp: ts}
}

func TestCollapse_NewCluster_CreatesOpenCase(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	out := Collapse(nil, []Escalation{esc("f1", "git-oops", "dev", "high", "", ts)}, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 case, got %d", len(out))
	}
	c := out[0]
	if c.Status != "open" {
		t.Errorf("status = %q, want open", c.Status)
	}
	if c.Count != 1 {
		t.Errorf("count = %d, want 1", c.Count)
	}
	if c.SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %d, want %d", c.SchemaVersion, SchemaVersion)
	}
	if len(c.FindingIDs) != 1 || c.FindingIDs[0] != "f1" {
		t.Errorf("finding_ids = %v, want [f1]", c.FindingIDs)
	}
}

func TestCollapse_SameKeyTwice_RecurringCountTwo(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	out := Collapse(nil, []Escalation{
		esc("f1", "git-oops", "dev", "high", "", ts),
		esc("f2", "git-oops", "dev", "high", "", ts.Add(time.Hour)),
	}, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 case, got %d", len(out))
	}
	c := out[0]
	if c.Status != "recurring" {
		t.Errorf("status = %q, want recurring", c.Status)
	}
	if c.Count != 2 {
		t.Errorf("count = %d, want 2", c.Count)
	}
	if len(c.FindingIDs) != 2 || c.FindingIDs[0] != "f1" || c.FindingIDs[1] != "f2" {
		t.Errorf("finding_ids = %v, want [f1 f2] in arrival order", c.FindingIDs)
	}
}

func TestCollapse_DistinctEntity_DistinctCases(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	out := Collapse(nil, []Escalation{
		esc("f1", "new-external-access", "admin", "critical", "alice", ts),
		esc("f2", "new-external-access", "admin", "critical", "bob", ts),
	}, nil)
	if len(out) != 2 {
		t.Fatalf("want 2 distinct cases, got %d", len(out))
	}
	if out[0].CaseID == out[1].CaseID {
		t.Errorf("want distinct case_ids, both = %q", out[0].CaseID)
	}
}

func TestCollapse_SeverityTakesMax(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	out := Collapse(nil, []Escalation{
		esc("f1", "git-oops", "dev", "critical", "", ts),
		esc("f2", "git-oops", "dev", "low", "", ts.Add(time.Hour)),
	}, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 case, got %d", len(out))
	}
	if out[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical (must not downgrade)", out[0].Severity)
	}
}

func TestCollapse_FindingIDRing_CapsAt50AndDropsOldest(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var escs []Escalation
	for i := 0; i < 51; i++ {
		escs = append(escs, esc(idOf(i), "git-oops", "dev", "high", "", ts.Add(time.Duration(i)*time.Minute)))
	}
	out := Collapse(nil, escs, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 case, got %d", len(out))
	}
	ids := out[0].FindingIDs
	if len(ids) != findingIDRingCap {
		t.Fatalf("finding_ids len = %d, want %d", len(ids), findingIDRingCap)
	}
	if ids[0] == idOf(0) {
		t.Errorf("oldest id %q should have been dropped", idOf(0))
	}
	if ids[len(ids)-1] != idOf(50) {
		t.Errorf("newest id = %q, want %q", ids[len(ids)-1], idOf(50))
	}
}

func idOf(i int) string {
	return "f" + strconv.Itoa(i)
}

// TestCollapse_CadenceSecs_MedianOfLastTwentyOrFewer proves the cadence window
// only considers the most recent cadenceWindow (20) timestamped occurrences: a
// stale first occurrence, whose huge gap to occurrence 2 would otherwise skew
// the median, must NOT be counted once more than 20 occurrences exist.
func TestCollapse_CadenceSecs_MedianOfLastTwentyOrFewer(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var escs []Escalation
	// Occurrence 0 is a huge outlier: 100 days before occurrence 1.
	escs = append(escs, esc(idOf(0), "git-oops", "dev", "high", "", base))
	// Occurrences 1..24 (24 more, total 25) spaced exactly 60s apart, starting
	// 100 days after occurrence 0.
	start := base.Add(100 * 24 * time.Hour)
	for i := 1; i <= 24; i++ {
		escs = append(escs, esc(idOf(i), "git-oops", "dev", "high", "", start.Add(time.Duration(i-1)*60*time.Second)))
	}

	lookup := func(id string) (time.Time, bool) {
		for _, e := range escs {
			if e.FindingID == id {
				return e.Timestamp, true
			}
		}
		return time.Time{}, false
	}

	out := Collapse(nil, escs, lookup)
	if len(out) != 1 {
		t.Fatalf("want 1 case, got %d", len(out))
	}
	// 25 total occurrences means the ring holds all 25 (< cap 50), but the
	// cadence window only takes the LAST 20 — occurrences 5..24, all spaced
	// exactly 60s apart, so the median inter-arrival must be exactly 60,
	// NOT skewed by occurrence 0's 100-day gap.
	got := out[0].CadenceSecs
	if got != 60 {
		t.Errorf("cadence_secs = %v, want 60 (last-20 window must exclude the stale outlier)", got)
	}
}

// TestCollapse_DeterministicOutputOrder proves re-running Collapse over the
// same input twice yields byte-identical JSON — the property
// store.Store.WriteSnapshot's no-op check depends on.
func TestCollapse_DeterministicOutputOrder(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	escs := []Escalation{
		esc("f1", "new-external-access", "admin", "critical", "bob", ts),
		esc("f2", "git-oops", "dev", "high", "", ts),
		esc("f3", "new-external-access", "admin", "critical", "alice", ts),
	}
	out1 := Collapse(nil, escs, nil)
	out2 := Collapse(nil, escs, nil)

	b1, err := json.Marshal(out1)
	if err != nil {
		t.Fatalf("marshal out1: %v", err)
	}
	b2, err := json.Marshal(out2)
	if err != nil {
		t.Fatalf("marshal out2: %v", err)
	}
	if string(b1) != string(b2) {
		t.Errorf("Collapse output not deterministic:\n%s\nvs\n%s", b1, b2)
	}
}
