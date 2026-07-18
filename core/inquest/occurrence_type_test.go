package inquest

import (
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestOccurrenceEventType_ResolvesSourceEventType is the mallcoppro-f4c
// regression: findings carry detector-family types ("new-external-access")
// while events carry raw source types ("trust_added"), so collecting the
// occurrence set by f.Type matched zero events for essentially every
// detector — recurrence and scan-correlation were structurally zero, and the
// narrate model (starved of the cadence signal) mislabeled the operator's own
// hourly relay a threat on the first live v0.16.0 records. The occurrence
// type must come from the finding's linked SOURCE event.
func TestOccurrenceEventType_ResolvesSourceEventType(t *testing.T) {
	evs := []event.Event{
		{ID: "evt_1", Type: "trust_added", Actor: "forge-proxy", Timestamp: time.Unix(1000, 0)},
		{ID: "evt_2", Type: "trust_added", Actor: "forge-proxy", Timestamp: time.Unix(2000, 0)},
		{ID: "evt_3", Type: "trust_added", Actor: "forge-proxy", Timestamp: time.Unix(3000, 0)},
	}
	f := finding.Finding{
		ID:       "finding-abc",
		Type:     "new-external-access",
		Actor:    "forge-proxy",
		EventIDs: []string{"evt_2"},
	}

	typ := occurrenceEventType(evs, f)
	if typ != "trust_added" {
		t.Fatalf("occurrenceEventType = %q, want the linked source event's type %q", typ, "trust_added")
	}
	if got := len(actorTypeTimestamps(evs, f.Actor, typ)); got != 3 {
		t.Fatalf("occurrence set size = %d, want 3 (all trust_added events by the actor)", got)
	}
	// The old behavior this replaces: keying by the finding's own type finds
	// nothing — the exact structural zero mallcoppro-f4c documents.
	if got := len(actorTypeTimestamps(evs, f.Actor, f.Type)); got != 0 {
		t.Fatalf("sanity: f.Type keying found %d events, expected the historical 0", got)
	}
}

// TestOccurrenceEventType_FallsBackToFindingType pins the legacy path: a
// finding with no resolvable event linkage keeps the old f.Type keying rather
// than failing.
func TestOccurrenceEventType_FallsBackToFindingType(t *testing.T) {
	evs := []event.Event{{ID: "evt_1", Type: "trust_added", Actor: "a", Timestamp: time.Unix(1000, 0)}}
	for _, f := range []finding.Finding{
		{Type: "new-external-access", Actor: "a"},                                  // no linkage at all
		{Type: "new-external-access", Actor: "a", EventIDs: []string{"evt_gone"}}, // linkage not in allEvents
	} {
		if typ := occurrenceEventType(evs, f); typ != f.Type {
			t.Fatalf("occurrenceEventType = %q, want fallback to f.Type %q", typ, f.Type)
		}
	}
}
