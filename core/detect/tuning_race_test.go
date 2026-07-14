package detect

// tuning_race_test.go — K7 REGRESSION for the priv-escalation tuning race.
//
// Before tuning isolation, priv-escalation read the live-mutable package knob
// maps (elevatedKeywords / elevationEventTypes / elevatedActionKeywords) inside
// Detect while ApplyTuning wrote them. A leaked or concurrent ApplyTuning
// goroutine racing a Detect was a concurrent-map read/write — a hard fatal crash
// ("fatal error: concurrent map read and map write") that -race also flags.
//
// The isolation fix makes the knob sets an IMMUTABLE snapshot: Detect loads it
// once and reads only frozen maps; ApplyTuning clones + widens + atomically
// swaps a NEW snapshot. This test hammers ApplyTuning and Detect concurrently;
// under `go test -race` it must stay clean and never crash. It is the standing
// proof that the write side of the race is closed even if fix #1's shape gate
// (which forbids authored code from reaching ApplyTuning at all) were bypassed.

import (
	"sync"
	"testing"
)

// TestPrivEscalationTuningNoRace runs ApplyTuning and the priv-escalation Detect
// path concurrently. On the pre-fix live-map code this deterministically tripped
// the Go runtime's concurrent-map detector (and -race); with the immutable
// snapshot it completes cleanly.
func TestPrivEscalationTuningNoRace(t *testing.T) {
	snap := saveKnobs()
	t.Cleanup(func() { restoreKnobs(snap) })

	events, bl := tuningFixture(t)

	const writers, readers, iters = 4, 8, 200

	var wg sync.WaitGroup
	start := make(chan struct{})

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < iters; i++ {
				// Each ApplyTuning clones + widens + atomically swaps a fresh
				// snapshot; it must never mutate a map a reader is iterating.
				// nonBuiltinTuningTestKeyword (tuning_test.go) is used rather than
				// "poweruser" — that keyword was promoted into
				// builtinElevatedKeywords (mallcoppro-a07), so it no longer
				// exercises a non-builtin add.
				ApplyTuning(Tuning{PrivEscalation: PrivEscalationTuning{
					ExtraElevatedKeywords:       []string{nonBuiltinTuningTestKeyword},
					ExtraElevatedActionKeywords: []string{"attachrolepolicy"},
					ExtraElevationEventTypes:    []string{"custom_grant"},
				}})
			}
		}(w)
	}

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iters; i++ {
				// The real Detect path reads the priv-escalation knob snapshot.
				_ = Detect(events, bl)
			}
		}()
	}

	close(start)
	wg.Wait()

	// Sanity: the detector still fires after all the concurrent widening, i.e. the
	// snapshot machinery did not corrupt the knob sets.
	if !privEscActors(events, bl)["a-owner"] {
		t.Fatal("priv-escalation stopped firing after concurrent tuning — snapshot corruption")
	}
}

// TestApplyTuningDoesNotMutatePublishedSnapshot proves the published snapshot is
// truly immutable: a snapshot loaded BEFORE a later ApplyTuning keeps its
// original contents (ApplyTuning swaps in a new pointer rather than mutating the
// one an in-flight Detect already loaded). This is the property that makes the
// concurrent read safe.
func TestApplyTuningDoesNotMutatePublishedSnapshot(t *testing.T) {
	snap := saveKnobs()
	t.Cleanup(func() { restoreKnobs(snap) })

	before := loadPrivEscalationTuning()
	kwLen, etLen, actLen := len(before.elevatedKeywords), len(before.elevationEventTypes), len(before.elevatedActionKeywords)

	ApplyTuning(Tuning{PrivEscalation: PrivEscalationTuning{
		ExtraElevatedKeywords:       []string{nonBuiltinTuningTestKeyword},
		ExtraElevatedActionKeywords: []string{"attachrolepolicy"},
		ExtraElevationEventTypes:    []string{"custom_grant"},
	}})

	if len(before.elevatedKeywords) != kwLen || len(before.elevationEventTypes) != etLen || len(before.elevatedActionKeywords) != actLen {
		t.Fatalf("ApplyTuning mutated a previously-loaded snapshot in place (keywords %d→%d, eventTypes %d→%d, actions %d→%d) — an in-flight Detect could see a torn map",
			kwLen, len(before.elevatedKeywords), etLen, len(before.elevationEventTypes), actLen, len(before.elevatedActionKeywords))
	}
	// And the NEW published snapshot did pick up the widening.
	after := loadPrivEscalationTuning()
	if !after.elevatedKeywords[nonBuiltinTuningTestKeyword] {
		t.Fatal("ApplyTuning did not publish the widened snapshot")
	}
}
