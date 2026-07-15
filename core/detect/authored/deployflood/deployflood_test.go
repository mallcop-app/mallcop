package deployflood

import (
	"strconv"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// makeDeployEvents returns n synthetic github.deployment events for actor,
// each carrying a distinct ID/timestamp within a short window.
func makeDeployEvents(actor string, n int) []event.Event {
	base := time.Date(2026, 3, 10, 11, 22, 0, 0, time.UTC)
	out := make([]event.Event, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, event.Event{
			ID:        "evt-" + actor + "-" + strconv.Itoa(i),
			Source:    "github",
			Type:      deployEventType,
			Actor:     actor,
			Timestamp: base.Add(time.Duration(i) * 30 * time.Second),
		})
	}
	return out
}

// oldNaiveDetect reproduces the ORIGINAL (buggy) detector logic this file
// replaces: it fired on every single github.deployment event, no counting, no
// baseline. It is reconstructed here ONLY to prove the regression the rewrite
// fixes (mallcoppro-8ac9) — it is not shipped.
func oldNaiveDetect(events []event.Event) int {
	fires := 0
	for _, ev := range events {
		if ev.Type == deployEventType {
			fires++
		}
	}
	return fires
}

// TestDetect_SingleDeployment_DoesNotFire is the core regression test: a lone
// legitimate deployment must never fire, regardless of baseline.
func TestDetect_SingleDeployment_DoesNotFire(t *testing.T) {
	events := makeDeployEvents("solo-actor", 1)
	bl := &baseline.Baseline{}
	got := detector{}.Detect(events, bl)
	if len(got) != 0 {
		t.Fatalf("single deployment fired: %+v", got)
	}
}

// TestDetect_SingleDeployment_ConsistentWithBaseline_DoesNotFire mirrors the
// benign-twin scenario: one deployment against an actor with an established
// deployment history.
func TestDetect_SingleDeployment_ConsistentWithBaseline_DoesNotFire(t *testing.T) {
	events := makeDeployEvents("routine-actor", 1)
	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{
			"github:github.deployment:routine-actor": 5,
		},
	}
	got := detector{}.Detect(events, bl)
	if len(got) != 0 {
		t.Fatalf("baseline-consistent single deployment fired: %+v", got)
	}
}

// TestDetect_Burst_FiresHigh mirrors the must-fire scenario: a burst well
// above a zero baseline fires exactly one high-severity finding for the actor.
func TestDetect_Burst_FiresHigh(t *testing.T) {
	events := makeDeployEvents("burst-actor", 10)
	bl := &baseline.Baseline{}
	got := detector{}.Detect(events, bl)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 finding for the burst, got %d: %+v", len(got), got)
	}
	if got[0].Severity != "high" {
		t.Fatalf("want severity high, got %q", got[0].Severity)
	}
	if got[0].Actor != "burst-actor" {
		t.Fatalf("want actor burst-actor, got %q", got[0].Actor)
	}
}

// TestDetect_ModerateVolumeConsistentWithBaseline_DoesNotFire proves the
// detector is not just "count >= 2": a handful of deployments that the
// baseline already explains must not fire either.
func TestDetect_ModerateVolumeConsistentWithBaseline_DoesNotFire(t *testing.T) {
	events := makeDeployEvents("steady-actor", 4)
	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{
			"github:github.deployment:steady-actor": 50,
		},
	}
	got := detector{}.Detect(events, bl)
	if len(got) != 0 {
		t.Fatalf("baseline-consistent moderate volume fired: %+v", got)
	}
}

// TestSabotage_SingleEventExtractedFromBurst_DoesNotFire is the required
// sabotage check (mallcoppro-8ac9): the must-fire scenario's verdict must
// genuinely depend on VOLUME, not merely on "a github.deployment event is
// present". Replaying just ONE event lifted out of the burst must NOT fire
// the new detector — if it did, the must-fire scenario would be passing for
// the same reason the old, buggy single-event detector always fired, and the
// fix would be cosmetic rather than real.
func TestSabotage_SingleEventExtractedFromBurst_DoesNotFire(t *testing.T) {
	burst := makeDeployEvents("burst-actor", 10)
	oneEvent := burst[:1]

	bl := &baseline.Baseline{}
	got := detector{}.Detect(oneEvent, bl)
	if len(got) != 0 {
		t.Fatalf("a single event lifted from the burst fired the NEW detector — the must-fire scenario does not genuinely require volume: %+v", got)
	}

	// Cross-check: the OLD (pre-fix) naive logic WOULD have fired on that same
	// single event — this is precisely the false-positive-cannon bug
	// mallcoppro-8ac9 reports. Confirms the sabotage check is meaningful: the
	// old logic and the new logic disagree on this exact input.
	if oldFires := oldNaiveDetect(oneEvent); oldFires != 1 {
		t.Fatalf("sabotage check invalid: expected the reconstructed OLD naive logic to fire once on a single github.deployment event, got %d", oldFires)
	}
}

// TestSabotage_OldNaiveLogic_WouldHaveFiredOnBenignTwin proves the OLD (buggy)
// logic is exactly what mallcoppro-8ac9 reports: it would have escalated the
// new benign-twin's single legitimate deployment, where the NEW detector
// correctly stays silent.
func TestSabotage_OldNaiveLogic_WouldHaveFiredOnBenignTwin(t *testing.T) {
	benign := makeDeployEvents("routine-actor", 1)

	if oldFires := oldNaiveDetect(benign); oldFires != 1 {
		t.Fatalf("sabotage check invalid: expected OLD naive logic to fire once on the benign-twin's single deployment, got %d", oldFires)
	}

	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{
			"github:github.deployment:routine-actor": 5,
		},
	}
	got := detector{}.Detect(benign, bl)
	if len(got) != 0 {
		t.Fatalf("NEW detector fired on the benign-twin single deployment, same as the old bug: %+v", got)
	}
}
