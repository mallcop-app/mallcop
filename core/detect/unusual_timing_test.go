package detect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// utBaseline mirrors the fixture used elsewhere in this package: alice works
// 09-17 UTC.
func utBaseline() *baseline.Baseline {
	return &baseline.Baseline{
		ActorHours: map[string][]int{
			"alice": {9, 10, 11, 12, 13, 14, 15, 16, 17},
		},
	}
}

func utEvent(id, actor, source, evType string, hour, min int) event.Event {
	return event.Event{
		ID:        id,
		Source:    source,
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, hour, min, 0, 0, time.UTC),
	}
}

// TestUnusualTimingCollapse_SkipGatesUnchanged proves the three original
// skip-gates are byte-for-byte preserved: no baseline data at all, an unknown
// actor, and a known hour all still yield NO findings.
func TestUnusualTimingCollapse_SkipGatesUnchanged(t *testing.T) {
	t.Run("no actor-hours baseline at all", func(t *testing.T) {
		bl := &baseline.Baseline{}
		evs := []event.Event{utEvent("e1", "alice", "github", "push", 3, 0)}
		if got := unusualTimingCollapse(evs, bl); got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})

	t.Run("unknown actor — new-actor's job", func(t *testing.T) {
		bl := utBaseline()
		evs := []event.Event{utEvent("e1", "mallory", "github", "push", 3, 0)}
		if got := unusualTimingCollapse(evs, bl); got != nil {
			t.Fatalf("expected nil for unknown actor, got %+v", got)
		}
	})

	t.Run("known hour — not unusual", func(t *testing.T) {
		bl := utBaseline()
		evs := []event.Event{utEvent("e1", "alice", "github", "push", 10, 0)}
		if got := unusualTimingCollapse(evs, bl); got != nil {
			t.Fatalf("expected nil for a known hour, got %+v", got)
		}
	})
}

// TestUnusualTimingCollapse_SingleEventGroup proves a lone unusual event still
// produces exactly one finding, shaped like the pre-collapse output plus the
// new group fields (event_count=1, event_ids=[the one ID], sources/event_types
// singletons).
func TestUnusualTimingCollapse_SingleEventGroup(t *testing.T) {
	bl := utBaseline()
	evs := []event.Event{utEvent("e1", "alice", "github", "push", 3, 0)}

	got := unusualTimingCollapse(evs, bl)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]

	if f.ID != "finding-e1" {
		t.Errorf("ID = %q, want finding-e1", f.ID)
	}
	if f.Source != "detector:unusual-timing" || f.Severity != "low" || f.Type != "unusual-timing" {
		t.Errorf("finding shape wrong: %+v", f)
	}
	if f.Actor != "alice" {
		t.Errorf("Actor = %q, want alice", f.Actor)
	}
	if !f.Timestamp.Equal(evs[0].Timestamp) {
		t.Errorf("Timestamp = %v, want %v", f.Timestamp, evs[0].Timestamp)
	}

	var ev map[string]any
	if err := json.Unmarshal(f.Evidence, &ev); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if ev["actor"] != "alice" {
		t.Errorf("evidence actor = %v", ev["actor"])
	}
	if ev["hour_utc"] != float64(3) {
		t.Errorf("evidence hour_utc = %v, want 3", ev["hour_utc"])
	}
	if ev["event_id"] != "e1" {
		t.Errorf("evidence event_id = %v, want e1 (backward compat)", ev["event_id"])
	}
	if ev["event_count"] != float64(1) {
		t.Errorf("evidence event_count = %v, want 1", ev["event_count"])
	}
	ids, _ := ev["event_ids"].([]any)
	if len(ids) != 1 || ids[0] != "e1" {
		t.Errorf("evidence event_ids = %v, want [e1]", ids)
	}
	sources, _ := ev["sources"].([]any)
	if len(sources) != 1 || sources[0] != "github" {
		t.Errorf("evidence sources = %v, want [github]", sources)
	}
	types, _ := ev["event_types"].([]any)
	if len(types) != 1 || types[0] != "push" {
		t.Errorf("evidence event_types = %v, want [push]", types)
	}
}

// TestUnusualTimingCollapse_GroupsAcrossSources is the headline fan-out fix:
// several events for the SAME (actor, hour) but DIFFERENT sources collapse
// into ONE finding, with sources sorted (not duplicated) in the evidence.
func TestUnusualTimingCollapse_GroupsAcrossSources(t *testing.T) {
	bl := utBaseline()
	evs := []event.Event{
		utEvent("e1", "alice", "github", "push", 3, 0),
		utEvent("e2", "alice", "azure", "login", 3, 5),
		utEvent("e3", "alice", "github", "comment", 3, 10),
	}

	got := unusualTimingCollapse(evs, bl)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 collapsed finding across sources, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.ID != "finding-e1" {
		t.Errorf("ID = %q, want finding-e1 (first-seen event)", f.ID)
	}

	var ev map[string]any
	if err := json.Unmarshal(f.Evidence, &ev); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if ev["event_count"] != float64(3) {
		t.Errorf("event_count = %v, want 3", ev["event_count"])
	}
	sources, _ := ev["sources"].([]any)
	if len(sources) != 2 || sources[0] != "azure" || sources[1] != "github" {
		t.Errorf("sources = %v, want sorted [azure github] (deduped)", sources)
	}
	types, _ := ev["event_types"].([]any)
	if len(types) != 3 || types[0] != "comment" || types[1] != "login" || types[2] != "push" {
		t.Errorf("event_types = %v, want sorted [comment login push]", types)
	}
	ids, _ := ev["event_ids"].([]any)
	if len(ids) != 3 || ids[0] != "e1" || ids[1] != "e2" || ids[2] != "e3" {
		t.Errorf("event_ids = %v, want [e1 e2 e3] in first-seen order", ids)
	}
}

// TestUnusualTimingCollapse_TwoHoursTwoFindings proves distinct hours for the
// SAME actor are NOT collapsed together — each (actor, hour) is its own group,
// in first-seen order.
func TestUnusualTimingCollapse_TwoHoursTwoFindings(t *testing.T) {
	bl := utBaseline()
	evs := []event.Event{
		utEvent("e1", "alice", "github", "push", 3, 0),
		utEvent("e2", "alice", "github", "push", 4, 0),
	}

	got := unusualTimingCollapse(evs, bl)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (one per hour), got %d: %+v", len(got), got)
	}
	if got[0].ID != "finding-e1" || got[1].ID != "finding-e2" {
		t.Errorf("finding order/IDs = [%s %s], want [finding-e1 finding-e2] (first-seen order)", got[0].ID, got[1].ID)
	}

	var ev0, ev1 map[string]any
	json.Unmarshal(got[0].Evidence, &ev0)
	json.Unmarshal(got[1].Evidence, &ev1)
	if ev0["hour_utc"] != float64(3) || ev1["hour_utc"] != float64(4) {
		t.Errorf("hour_utc pair = (%v, %v), want (3, 4)", ev0["hour_utc"], ev1["hour_utc"])
	}
}

// TestUnusualTimingCollapse_EventIDsCappedAtTen proves the evidence's
// event_ids sample is capped at 10 even when a group has far more events,
// while event_count still reflects the TRUE total.
func TestUnusualTimingCollapse_EventIDsCappedAtTen(t *testing.T) {
	bl := utBaseline()
	var evs []event.Event
	for i := 0; i < 15; i++ {
		id := "e" + string(rune('a'+i))
		evs = append(evs, utEvent(id, "alice", "github", "push", 3, i))
	}

	got := unusualTimingCollapse(evs, bl)
	if len(got) != 1 {
		t.Fatalf("expected 1 collapsed finding, got %d", len(got))
	}

	var ev map[string]any
	if err := json.Unmarshal(got[0].Evidence, &ev); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if ev["event_count"] != float64(15) {
		t.Errorf("event_count = %v, want 15 (true total, uncapped)", ev["event_count"])
	}
	ids, _ := ev["event_ids"].([]any)
	if len(ids) != 10 {
		t.Errorf("event_ids length = %d, want 10 (capped sample)", len(ids))
	}
	if ids[0] != "ea" {
		t.Errorf("event_ids[0] = %v, want ea (first-seen)", ids[0])
	}
}

// TestUnusualTimingCollapse_MixedKnownAndUnknownHours proves the per-event
// gate still applies WITHIN a batch: events at a known hour are dropped from
// consideration entirely and never bleed into an unrelated group.
func TestUnusualTimingCollapse_MixedKnownAndUnknownHours(t *testing.T) {
	bl := utBaseline()
	evs := []event.Event{
		utEvent("e1", "alice", "github", "push", 10, 0), // known hour — skipped
		utEvent("e2", "alice", "github", "push", 3, 0),  // unusual
		utEvent("e3", "alice", "github", "push", 3, 5),  // unusual, same hour as e2
	}

	got := unusualTimingCollapse(evs, bl)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (hour 10 dropped, hour 3 collapsed), got %d: %+v", len(got), got)
	}
	if got[0].ID != "finding-e2" {
		t.Errorf("ID = %q, want finding-e2", got[0].ID)
	}
	var ev map[string]any
	json.Unmarshal(got[0].Evidence, &ev)
	if ev["event_count"] != float64(2) {
		t.Errorf("event_count = %v, want 2", ev["event_count"])
	}
}

// TestUnusualTimingCollapse_TwoActorsSameHourNotMerged proves the grouping key
// is (actor, hour) — not hour alone. Two actors sharing the same novel hour in
// one scan must produce TWO findings, one per actor, each carrying only that
// actor's events. A regression that dropped `actor` from unusualTimingKey
// would silently merge these into a single finding and misattribute one
// actor's events under the other actor's Actor field — this pins per-actor
// grouping explicitly, with events interleaved across actors to also pin
// first-seen ordering.
func TestUnusualTimingCollapse_TwoActorsSameHourNotMerged(t *testing.T) {
	bl := &baseline.Baseline{
		ActorHours: map[string][]int{
			"actor-a": {9, 10, 11},
			"actor-b": {9, 10, 11},
		},
	}
	evs := []event.Event{
		utEvent("e1", "actor-a", "github", "push", 3, 0), // actor-a, first-seen
		utEvent("e2", "actor-b", "github", "push", 3, 1), // actor-b, first-seen
		utEvent("e3", "actor-a", "github", "push", 3, 2),
		utEvent("e4", "actor-b", "github", "push", 3, 3),
		utEvent("e5", "actor-b", "github", "push", 3, 4),
	}

	got := unusualTimingCollapse(evs, bl)
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 findings (one per actor), got %d: %+v", len(got), got)
	}

	fa, fb := got[0], got[1]
	if fa.ID != "finding-e1" {
		t.Errorf("first finding ID = %q, want finding-e1 (actor-a's first-seen event)", fa.ID)
	}
	if fb.ID != "finding-e2" {
		t.Errorf("second finding ID = %q, want finding-e2 (actor-b's first-seen event)", fb.ID)
	}
	if fa.Actor != "actor-a" {
		t.Errorf("first finding Actor = %q, want actor-a", fa.Actor)
	}
	if fb.Actor != "actor-b" {
		t.Errorf("second finding Actor = %q, want actor-b", fb.Actor)
	}

	var eva, evb map[string]any
	if err := json.Unmarshal(fa.Evidence, &eva); err != nil {
		t.Fatalf("unmarshal actor-a evidence: %v", err)
	}
	if err := json.Unmarshal(fb.Evidence, &evb); err != nil {
		t.Fatalf("unmarshal actor-b evidence: %v", err)
	}

	if eva["actor"] != "actor-a" {
		t.Errorf("actor-a evidence actor = %v, want actor-a", eva["actor"])
	}
	if evb["actor"] != "actor-b" {
		t.Errorf("actor-b evidence actor = %v, want actor-b", evb["actor"])
	}
	if eva["event_count"] != float64(2) {
		t.Errorf("actor-a event_count = %v, want 2", eva["event_count"])
	}
	if evb["event_count"] != float64(3) {
		t.Errorf("actor-b event_count = %v, want 3", evb["event_count"])
	}

	idsA, _ := eva["event_ids"].([]any)
	if len(idsA) != 2 || idsA[0] != "e1" || idsA[1] != "e3" {
		t.Errorf("actor-a event_ids = %v, want [e1 e3] (only actor-a's events)", idsA)
	}
	idsB, _ := evb["event_ids"].([]any)
	if len(idsB) != 3 || idsB[0] != "e2" || idsB[1] != "e4" || idsB[2] != "e5" {
		t.Errorf("actor-b event_ids = %v, want [e2 e4 e5] (only actor-b's events)", idsB)
	}
}

// TestUnusualTimingCollapse_EmptyFirstEventID_NoCollision proves the
// empty-ID finding guard: when a group's first-seen event carries no ID (a
// connector or test fixture that assigns none — the same legitimate case
// pipeline.dedupeEvents guards for), the finding ID must NOT collapse to the
// literal "finding-" for every such group. Two DIFFERENT actors, each with an
// empty-ID first event at their own novel hour, must still mint two DISTINCT
// finding IDs — proving no cross-group collision even though first.ID is
// empty in both groups.
func TestUnusualTimingCollapse_EmptyFirstEventID_NoCollision(t *testing.T) {
	bl := &baseline.Baseline{
		ActorHours: map[string][]int{
			"actor-a": {9, 10, 11},
			"actor-b": {9, 10, 11},
		},
	}
	evs := []event.Event{
		utEvent("", "actor-a", "github", "push", 3, 0), // empty ID, first-seen for actor-a
		utEvent("", "actor-b", "github", "push", 5, 0), // empty ID, first-seen for actor-b (DIFFERENT hour)
	}

	got := unusualTimingCollapse(evs, bl)
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 findings, got %d: %+v", len(got), got)
	}
	if got[0].ID == "" || got[1].ID == "" {
		t.Fatalf("finding ID must never be empty, got %q and %q", got[0].ID, got[1].ID)
	}
	if got[0].ID == got[1].ID {
		t.Fatalf("two DIFFERENT groups with empty-ID first events collided on the same finding ID %q — the empty-ID guard must fall back to the (actor,hour) group key, not the empty first.ID", got[0].ID)
	}
	if got[0].ID == "finding-" || got[1].ID == "finding-" {
		t.Errorf("finding ID must not be the bare \"finding-\" literal (first.ID was used unguarded): got %q, %q", got[0].ID, got[1].ID)
	}
}

// TestUnusualTimingCollapse_EmptyFirstEventID_StableWithinGroup proves the
// empty-ID fallback still keys on the group (actor, hour), not per-call
// randomness: re-running collapse over the SAME input yields the SAME finding
// ID both times (determinism the rest of the pipeline — sorted-by-finding-ID
// writes — depends on).
func TestUnusualTimingCollapse_EmptyFirstEventID_StableWithinGroup(t *testing.T) {
	bl := utBaseline()
	evs := []event.Event{utEvent("", "alice", "github", "push", 3, 0)}

	got1 := unusualTimingCollapse(evs, bl)
	got2 := unusualTimingCollapse(evs, bl)
	if len(got1) != 1 || len(got2) != 1 {
		t.Fatalf("expected exactly 1 finding per call, got %d and %d", len(got1), len(got2))
	}
	if got1[0].ID != got2[0].ID {
		t.Fatalf("empty-ID fallback is not deterministic: %q vs %q", got1[0].ID, got2[0].ID)
	}
	if got1[0].ID != "finding-actor-alice-hour-03" {
		t.Errorf("expected the (actor,hour)-keyed fallback ID, got %q", got1[0].ID)
	}
}
