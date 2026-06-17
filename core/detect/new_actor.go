package detect

import (
	"encoding/json"
	"fmt"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(newActorDetector{}) }

type newActorDetector struct{}

func (newActorDetector) Name() string { return "new-actor" }

// Detect emits one finding per actor not present in the baseline. The emitted
// dedup map is local to this call (one finding per new actor across the
// corpus), mirroring the standalone binary's per-process dedup.
func (newActorDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	emitted := make(map[string]bool)
	var out []finding.Finding
	for _, ev := range events {
		if f := newActorEvaluate(ev, bl, emitted); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// newActorEvaluate returns a Finding if the actor has not been seen in the
// baseline, or nil if the actor is known. emitted tracks actors already
// reported so only the first event per new actor produces a finding.
// This is a pure function with respect to state mutation (emitted is caller-owned).
func newActorEvaluate(ev event.Event, bl *baseline.Baseline, emitted map[string]bool) *finding.Finding {
	if ev.Actor == "" {
		return nil
	}

	if bl.IsKnownActor(ev.Actor) {
		return nil
	}

	if emitted[ev.Actor] {
		return nil
	}
	emitted[ev.Actor] = true

	evidence, _ := json.Marshal(map[string]string{
		"actor":      ev.Actor,
		"source":     ev.Source,
		"event_type": ev.Type,
		"event_id":   ev.ID,
	})

	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:new-actor",
		Severity:  "medium",
		Type:      "new-actor",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    fmt.Sprintf("actor %q not seen in baseline period (source: %s)", ev.Actor, ev.Source),
		Evidence:  evidence,
	}
}
