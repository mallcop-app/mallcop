package eval

import (
	"testing"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// TestBaselineFromScenario_ExplicitActorHoursHonored is the baseline-key format
// fix (mallcoppro-ebe5). A scenario can express an actor's known active hours the
// EXPLICIT canonical way — known_entities.actor_hours: {actor: [hours]} — the same
// shape production builds. baselineFromScenario used to reconstruct hours ONLY
// from the fragile 5-segment "source:event_type:actor:N:partofday" frequency keys
// and DROP the explicit map, so a scenario using the canonical format had no timing
// profile and unusual-timing could never fire. This proves the explicit format is
// now projected into the typed baseline.
func TestBaselineFromScenario_ExplicitActorHoursHonored(t *testing.T) {
	s := &exam.Scenario{
		Baseline: &exam.Baseline{
			KnownEntities: exam.KnownEntities{
				Actors:     []string{"alice"},
				ActorHours: map[string][]int{"alice": {9, 10, 11, 12, 13, 14, 15, 16, 17}},
			},
		},
	}

	bl := baselineFromScenario(s)
	if bl == nil {
		t.Fatal("baselineFromScenario returned nil for a scenario with a baseline block")
	}
	got := bl.ActorHours["alice"]
	if len(got) != 9 {
		t.Fatalf("ActorHours[alice] = %v, want the 9 explicit hours 9-17 (the explicit format was dropped)", got)
	}
	if !bl.KnownHour("alice", 10) || bl.KnownHour("alice", 3) {
		t.Fatalf("KnownHour wrong: hour 10 should be known, hour 3 should not (got known(10)=%v known(3)=%v)",
			bl.KnownHour("alice", 10), bl.KnownHour("alice", 3))
	}
}

// TestBaselineFromScenario_ExplicitActorHoursMakesTimingFire proves the fix
// end-to-end through the REAL unusual-timing detector: with the explicit
// actor_hours profile in place, an event at an hour OUTSIDE that profile fires
// unusual-timing (and one inside it stays silent) — the general mechanism, not a
// per-scenario rule.
func TestBaselineFromScenario_ExplicitActorHoursMakesTimingFire(t *testing.T) {
	base := func() *exam.Scenario {
		return &exam.Scenario{
			Baseline: &exam.Baseline{
				KnownEntities: exam.KnownEntities{
					Actors:     []string{"alice"},
					ActorHours: map[string][]int{"alice": {9, 10, 11, 12, 13, 14, 15, 16, 17}},
				},
			},
		}
	}

	unusual := base()
	unusual.Events = []exam.Event{{ID: "e1", Source: "github", EventType: "push", Actor: "alice", Timestamp: "2026-04-10T03:00:00Z"}}
	if got := detect.Detect(scenarioEvents(unusual), baselineFromScenario(unusual)); len(got) == 0 {
		t.Fatalf("expected unusual-timing to fire on a 03:00 event outside alice's 09-17 explicit profile, got none")
	}

	normal := base()
	normal.Events = []exam.Event{{ID: "e1", Source: "github", EventType: "push", Actor: "alice", Timestamp: "2026-04-10T10:00:00Z"}}
	for _, f := range detect.Detect(scenarioEvents(normal), baselineFromScenario(normal)) {
		if f.Type == "unusual-timing" {
			t.Fatalf("unusual-timing must NOT fire on a 10:00 event inside alice's known hours: %+v", f)
		}
	}
}

// TestBaselineFromScenario_ExplicitAndDerivedHoursUnion proves the two formats
// UNION rather than one clobbering the other: an actor carrying an explicit
// morning profile AND a derived-afternoon 5-segment key is known during BOTH.
func TestBaselineFromScenario_ExplicitAndDerivedHoursUnion(t *testing.T) {
	s := &exam.Scenario{
		Baseline: &exam.Baseline{
			KnownEntities: exam.KnownEntities{
				Actors:     []string{"alice"},
				ActorHours: map[string][]int{"alice": {9}}, // explicit morning hour
			},
			FrequencyTables: map[string]int{"azure:login:alice:0:afternoon": 50}, // derived afternoon
		},
	}
	bl := baselineFromScenario(s)
	if !bl.KnownHour("alice", 9) {
		t.Errorf("explicit hour 9 was clobbered by the derived hours")
	}
	if !bl.KnownHour("alice", 14) {
		t.Errorf("derived afternoon hour 14 missing — the union dropped the 5-segment key")
	}
}
