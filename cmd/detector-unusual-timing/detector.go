package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// timingKey identifies one (actor, UTC hour) behavior group.
type timingKey struct {
	actor string
	hour  int
}

// collapse groups the events whose (actor, UTC hour) is outside the actor's
// known active hours in bl, then returns ONE finding per distinct group
// instead of one per event — mirroring core/detect's unusualTimingCollapse
// (see core/detect/unusual_timing.go for the full rationale, mallcoppro-d73)
// so this WASM/stdin sidecar and the in-tree detector stay behaviorally
// identical.
//
// Returns nil when:
//   - no actor-hours baseline data exists at all (bl.HasActorHours() false)
//   - the actor has no hour profile (unknown actor; new-actor handles unknowns)
//   - every one of the actor's event hours is within its known hours
//
// Group order is FIRST-SEEN order over the input events slice, so output is
// deterministic for a fixed input.
//
// This is a pure function: no I/O, no globals mutated.
func collapse(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	if !bl.HasActorHours() {
		return nil
	}

	var order []timingKey
	groups := make(map[timingKey][]event.Event)

	for _, ev := range events {
		// If this actor has no timing profile, skip — new-actor handles unknowns.
		if _, ok := bl.ActorHours[ev.Actor]; !ok {
			continue
		}

		hour := ev.Timestamp.UTC().Hour()
		if bl.KnownHour(ev.Actor, hour) {
			continue
		}

		k := timingKey{actor: ev.Actor, hour: hour}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], ev)
	}

	if len(order) == 0 {
		return nil
	}

	out := make([]finding.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, findingForGroup(k, groups[k]))
	}
	return out
}

// eventIDCap bounds how many event IDs ride along in the finding's evidence —
// enough to sample the group without inflating the payload for a group of
// hundreds of events.
const eventIDCap = 10

// findingForGroup builds the single finding representing one (actor, hour)
// group. The finding ID and Timestamp are keyed on the FIRST event in the
// group (first-seen order), keeping IDs stable and unique per scan. Evidence
// keeps the original "actor"/"hour_utc"/"event_id" keys (backward compat) and
// adds event_count, event_ids (capped), sources, and event_types (both
// distinct + sorted).
func findingForGroup(k timingKey, evs []event.Event) finding.Finding {
	first := evs[0]

	sourceSet := map[string]struct{}{}
	typeSet := map[string]struct{}{}
	eventIDs := make([]string, 0, eventIDCap)
	for i, ev := range evs {
		if ev.Source != "" {
			sourceSet[ev.Source] = struct{}{}
		}
		if ev.Type != "" {
			typeSet[ev.Type] = struct{}{}
		}
		if i < eventIDCap {
			eventIDs = append(eventIDs, ev.ID)
		}
	}

	evidence, _ := json.Marshal(map[string]interface{}{
		"actor":       k.actor,
		"hour_utc":    k.hour,
		"event_id":    first.ID,
		"event_count": len(evs),
		"event_ids":   eventIDs,
		"sources":     sortedSet(sourceSet),
		"event_types": sortedSet(typeSet),
	})

	return finding.Finding{
		ID:        "finding-" + first.ID,
		Source:    "detector:unusual-timing",
		Severity:  "low",
		Type:      "unusual-timing",
		Actor:     k.actor,
		Timestamp: first.Timestamp,
		Reason: fmt.Sprintf("actor %q active at unusual hour %02d:xx UTC (%d event(s), not in baseline pattern)",
			k.actor, k.hour, len(evs)),
		Evidence: evidence,
	}
}

// sortedSet returns the set's members as a sorted slice (never nil, so the
// evidence JSON always carries an array — even a single-member group).
func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
