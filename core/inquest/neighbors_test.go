package inquest

import (
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestAssembleNeighbors_WindowCapOrder proves neighbor assembly (a) excludes
// events outside the window, (b) excludes the subject event itself, (c)
// orders results nearest-first by |offset|, (d) caps the returned list while
// (e) still reporting Total as the PRE-cap count.
func TestAssembleNeighbors_WindowCapOrder(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	all := []event.Event{
		{ID: "subject", Timestamp: base}, // excluded: same ID as the finding's underlying event
		{ID: "far-before", Source: "aws", Type: "x", Actor: "a", Timestamp: base.Add(-2 * time.Hour)}, // outside window
		{ID: "far-after", Source: "aws", Type: "x", Actor: "a", Timestamp: base.Add(2 * time.Hour)},   // outside window
		{ID: "near-1", Source: "aws", Type: "x", Actor: "a", Timestamp: base.Add(5 * time.Minute)},    // offset +300s
		{ID: "near-2", Source: "aws", Type: "x", Actor: "b", Timestamp: base.Add(-1 * time.Minute)},   // offset -60s (nearest)
		{ID: "edge-in", Source: "aws", Type: "x", Actor: "c", Timestamp: base.Add(59 * time.Minute)},  // inside 1h window
		{ID: "edge-out", Source: "aws", Type: "x", Actor: "c", Timestamp: base.Add(61 * time.Minute)}, // outside 1h window
	}
	// The subject "event" id (finding's underlying event id) is "subject" —
	// use that ID on the finding so the self-exclusion path is exercised via
	// underlyingEventID-shaped matching. assembleNeighbors excludes by
	// f.ID == e.ID, so give the finding the same literal ID as the seeded
	// "subject" event for this test.
	f := finding.Finding{ID: "subject", Timestamp: base}

	out := assembleNeighbors(all, f, time.Hour, 50)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	// far-before, far-after, edge-out excluded; subject excluded by ID match.
	// Remaining: near-1, near-2, edge-in = 3.
	if out.Total != 3 {
		t.Fatalf("Total = %d, want 3", out.Total)
	}
	if len(out.Events) != 3 {
		t.Fatalf("len(Events) = %d, want 3", len(out.Events))
	}
	// Nearest-first by |offset|: near-2 (60s) < near-1 (300s) < edge-in (3540s).
	gotOrder := []string{out.Events[0].ID, out.Events[1].ID, out.Events[2].ID}
	wantOrder := []string{"near-2", "near-1", "edge-in"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Errorf("Events[%d].ID = %q, want %q (full order: %v)", i, gotOrder[i], wantOrder[i], gotOrder)
		}
	}
	if out.Events[0].OffsetSeconds != -60 {
		t.Errorf("nearest neighbor OffsetSeconds = %v, want -60", out.Events[0].OffsetSeconds)
	}
}

// TestAssembleNeighbors_CapTruncatesButTotalStaysFull proves maxNeighbors
// bounds the returned Events slice while Total still reports every candidate
// within the window.
func TestAssembleNeighbors_CapTruncatesButTotalStaysFull(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := finding.Finding{ID: "subject", Timestamp: base}

	var all []event.Event
	for i := 0; i < 10; i++ {
		all = append(all, event.Event{
			ID: "n" + string(rune('a'+i)), Source: "aws", Type: "x", Actor: "a",
			Timestamp: base.Add(time.Duration(i+1) * time.Minute),
		})
	}

	out := assembleNeighbors(all, f, time.Hour, 3)
	if out.Total != 10 {
		t.Errorf("Total = %d, want 10 (pre-cap)", out.Total)
	}
	if len(out.Events) != 3 {
		t.Fatalf("len(Events) = %d, want 3 (post-cap)", len(out.Events))
	}
}

// TestAssembleNeighbors_NoPayloadFields proves the neighbor projection never
// carries payload data — only the fixed envelope fields.
func TestAssembleNeighbors_NoPayloadFields(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := finding.Finding{ID: "subject", Timestamp: base}
	all := []event.Event{
		{ID: "n1", Source: "aws", Type: "x", Actor: "a", Timestamp: base.Add(time.Minute),
			Payload: rawEventPayload(t, map[string]any{"secret": "leaked-if-projected"})},
	}
	out := assembleNeighbors(all, f, time.Hour, 50)
	if len(out.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(out.Events))
	}
	// NeighborEvent has no Payload/Metadata field at all — this compiles as
	// proof by construction, but also assert nothing payload-shaped leaked
	// into any of the string fields.
	n := out.Events[0]
	for _, s := range []string{n.ID, n.Source, n.Type, n.Actor, n.Target, n.Timestamp} {
		if s == "leaked-if-projected" {
			t.Fatalf("payload content leaked into neighbor projection: %+v", n)
		}
	}
}
