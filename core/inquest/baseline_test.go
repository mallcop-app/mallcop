package inquest

import (
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestAssembleBaselineEvidence_KnownnessCallsThroughToBaseline proves the
// section calls DIRECTLY on the same *baseline.Baseline the scan gated
// detection on, and derives actor_first_seen/actor_event_count from the
// event history (not baseline.UserProfile, which has no FirstSeen field).
func TestAssembleBaselineEvidence_KnownnessCallsThroughToBaseline(t *testing.T) {
	ts := time.Date(2026, 3, 1, 14, 0, 0, 0, time.UTC) // hour 14
	bl := &baseline.Baseline{
		KnownActors: []string{"forge-proxy"},
		KnownUsers: map[string]baseline.UserProfile{
			"forge-proxy": {KnownIPs: []string{"203.0.113.7"}},
		},
		ActorHours: map[string][]int{"forge-proxy": {14, 15}},
		ActorRoles: map[string][]string{"forge-proxy": {"mallcop-bedrock-relay"}},
	}
	f := finding.Finding{ID: "finding-x", Actor: "forge-proxy", Type: "assume_role", Timestamp: ts}
	identity := IdentityEvidence{Target: "mallcop-bedrock-relay"}

	allEvents := []event.Event{
		{ID: "e1", Actor: "forge-proxy", Timestamp: ts.Add(-2 * time.Hour)},
		{ID: "e2", Actor: "forge-proxy", Timestamp: ts.Add(-1 * time.Hour)},
		{ID: "e3", Actor: "someone-else", Timestamp: ts},
	}

	out := assembleBaselineEvidence(bl, allEvents, f, identity)
	if !out.KnownActor {
		t.Error("KnownActor = false, want true")
	}
	if !out.HasLoginProfile {
		t.Error("HasLoginProfile = false, want true")
	}
	if !out.KnownHour {
		t.Error("KnownHour = false, want true (hour 14 is in ActorHours)")
	}
	if !out.KnownRole {
		t.Error("KnownRole = false, want true (identity.Target matches ActorRoles)")
	}
	if out.ActorEventCount != 2 {
		t.Errorf("ActorEventCount = %d, want 2 (e1, e2 — e3 belongs to a different actor)", out.ActorEventCount)
	}
	wantFirst := ts.Add(-2 * time.Hour).Format(time.RFC3339)
	if out.ActorFirstSeen != wantFirst {
		t.Errorf("ActorFirstSeen = %q, want %q", out.ActorFirstSeen, wantFirst)
	}
}

// TestAssembleBaselineEvidence_UnknownActor proves a genuinely new actor
// (absent from baseline) reports every known-ness bit false, with no error —
// this is honest evidence for the narrative, not a degraded section.
func TestAssembleBaselineEvidence_UnknownActor(t *testing.T) {
	bl := &baseline.Baseline{}
	f := finding.Finding{ID: "finding-x", Actor: "brand-new-actor", Type: "login", Timestamp: time.Now()}
	out := assembleBaselineEvidence(bl, nil, f, IdentityEvidence{})
	if out.KnownActor || out.HasLoginProfile || out.KnownHour || out.KnownRole {
		t.Errorf("expected all known-ness bits false for an unbaselined actor, got %+v", out)
	}
	if out.ActorEventCount != 0 || out.ActorFirstSeen != "" {
		t.Errorf("expected zero-value actor stats with no matching events, got %+v", out)
	}
}

// TestAssembleBaselineEvidence_NilBaseline proves a nil *baseline.Baseline
// (a scan that ran with no baseline at all) is treated as empty, never
// panics.
func TestAssembleBaselineEvidence_NilBaseline(t *testing.T) {
	f := finding.Finding{ID: "finding-x", Actor: "a", Timestamp: time.Now()}
	out := assembleBaselineEvidence(nil, nil, f, IdentityEvidence{})
	if out.KnownActor {
		t.Error("nil baseline should report KnownActor=false")
	}
}
