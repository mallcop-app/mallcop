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

// entityCreationEventTypes are event types that CREATE a new principal whose
// identity lives in metadata (display_name / principal_id) while the performing
// actor is an existing admin. new-actor scans these for the CREATED entity so a
// freshly-provisioned principal is surfaced under its OWN name (ID-01's
// deploy-svc-new), not the admin who created it.
var entityCreationEventTypes = map[string]bool{
	"service_principal_created": true,
	"user_created":              true,
	"member_added":              true,
	"user_provisioned":          true,
}

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
		// Entity-creation events name a NEW principal in metadata while the
		// performing actor is a known admin. Surface the CREATED entity too.
		if f := createdEntityEvaluate(ev, bl, emitted); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// createdEntityEvaluate emits a new-actor finding for the principal NAMED in an
// entity-creation event's metadata (display_name / principal_id) when that
// principal is not in the baseline — fired with Actor = the created entity. Gated
// to entity-creation event types so it never fires on ordinary activity.
func createdEntityEvaluate(ev event.Event, bl *baseline.Baseline, emitted map[string]bool) *finding.Finding {
	if !entityCreationEventTypes[ev.Type] {
		return nil
	}
	meta := payloadMeta(ev.Payload)
	created := metaStr(meta, "display_name", "principal_id", "member", "new_principal")
	if created == "" || bl.IsKnownActor(created) || emitted[created] {
		return nil
	}
	emitted[created] = true
	evidence, _ := json.Marshal(map[string]string{
		"actor":      created,
		"created_by": ev.Actor,
		"source":     ev.Source,
		"event_type": ev.Type,
		"event_id":   ev.ID,
	})
	return &finding.Finding{
		ID:        "finding-" + ev.ID + "-" + created,
		Source:    "detector:new-actor",
		Severity:  "medium",
		Type:      "new-actor",
		Actor:     created,
		Timestamp: ev.Timestamp,
		Reason:    fmt.Sprintf("new principal %q created by %q (not seen in baseline period)", created, ev.Actor),
		Evidence:  evidence,
	}
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
