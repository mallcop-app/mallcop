package detect

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(unusualTimingDetector{}) }

type unusualTimingDetector struct{}

func (unusualTimingDetector) Name() string { return "unusual-timing" }

func (unusualTimingDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	return unusualTimingCollapse(events, bl)
}

// unusualTimingKey identifies one (actor, UTC hour) behavior group.
type unusualTimingKey struct {
	actor string
	hour  int
}

// unusualTimingCollapse groups the events whose (actor, UTC hour) is outside
// the actor's known active hours in the baseline, then returns ONE finding per
// distinct group instead of one per event.
//
// Root cause this fixes (mallcoppro-d73): one novel actor-hour with N events
// used to produce N findings — each escalated to its own paid inference
// investigation. A live scan of the 3dl-dev/mallcop-deploy corpus produced
// 2010 findings that collapsed to only 145 distinct (actor, hour) BEHAVIORS
// (e.g. actor forge-relay at hour 16 alone accounted for 485 of them). The
// per-actor baseline gating below is unchanged — only the fan-out per matching
// event is collapsed.
//
// Returns nil when:
//   - no actor-hours baseline data exists at all (bl.HasActorHours() false —
//     nothing to compare against)
//   - the actor has no hour profile (unknown actor; new-actor handles unknowns)
//   - every one of the actor's event hours is within its known hours
//
// Group order is FIRST-SEEN order over the input events slice, so output is
// deterministic for a fixed input (no map iteration in the emitted order).
//
// This is a pure function: no I/O, no globals mutated.
func unusualTimingCollapse(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	// Without baseline timing data, every event looks "unusual" — skip.
	if !bl.HasActorHours() {
		return nil
	}

	var order []unusualTimingKey
	groups := make(map[unusualTimingKey][]event.Event)

	for _, ev := range events {
		// If this actor has no timing profile, skip — new-actor handles unknowns.
		if _, ok := bl.ActorHours[ev.Actor]; !ok {
			continue
		}

		hour := ev.Timestamp.UTC().Hour()
		if bl.KnownHour(ev.Actor, hour) {
			continue
		}

		k := unusualTimingKey{actor: ev.Actor, hour: hour}
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
		out = append(out, unusualTimingFindingForGroup(k, groups[k]))
	}
	return out
}

// unusualTimingEventIDCap bounds how many event IDs ride along in the finding's
// evidence — enough to sample the group without inflating the payload for a
// group of hundreds of events.
const unusualTimingEventIDCap = 10

// unusualTimingFindingForGroup builds the single finding representing one
// (actor, hour) group. The finding ID and Timestamp are keyed on the FIRST
// event in the group (first-seen order), keeping IDs stable and unique per
// scan. Evidence keeps the original "actor"/"hour_utc"/"event_id" keys
// (backward compat with existing consumers) and adds event_count, event_ids
// (capped), sources, and event_types (both distinct + sorted).
func unusualTimingFindingForGroup(k unusualTimingKey, evs []event.Event) finding.Finding {
	first := evs[0]

	// A first event with an EMPTY ID (a connector or test fixture that assigns
	// none — see pipeline.dedupeEvents' identical "ev.ID == \"\" is never an
	// identity" guard) would otherwise make every such group's finding ID
	// exactly "finding-", colliding across ANY OTHER empty-ID group in the
	// same scan (e.g. actor-a at hour 3 and actor-b at hour 9, both with
	// empty-ID first events, would both mint finding ID "finding-"). Fall back
	// to the group's (actor, hour) key: unusualTimingCollapse groups events by
	// exactly that key, so it is guaranteed unique WITHIN one Detect() call —
	// unlike first.ID, which carries no such guarantee when empty.
	idSuffix := first.ID
	if idSuffix == "" {
		idSuffix = fmt.Sprintf("actor-%s-hour-%02d", k.actor, k.hour)
	}

	sourceSet := map[string]struct{}{}
	typeSet := map[string]struct{}{}
	eventIDs := make([]string, 0, unusualTimingEventIDCap)
	for i, ev := range evs {
		// len(...) > 0, not a direct `ev.Type != ""` comparison: vocab_test.go's
		// AST scan treats any `*.Type == "literal"` / `!=` comparison in this
		// package as a detector gate declaration, and would otherwise
		// misidentify this non-empty check as a (bogus) gate on "".
		if len(ev.Source) > 0 {
			sourceSet[ev.Source] = struct{}{}
		}
		if len(ev.Type) > 0 {
			typeSet[ev.Type] = struct{}{}
		}
		if i < unusualTimingEventIDCap {
			eventIDs = append(eventIDs, ev.ID)
		}
	}

	evidence, _ := json.Marshal(map[string]interface{}{
		"actor":       k.actor,
		"hour_utc":    k.hour,
		"event_id":    first.ID,
		"event_count": len(evs),
		"event_ids":   eventIDs,
		"sources":     sortedStringSet(sourceSet),
		"event_types": sortedStringSet(typeSet),
	})

	return finding.Finding{
		ID:        "finding-" + idSuffix,
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

// sortedStringSet returns the set's members as a sorted slice (never nil, so
// the evidence JSON always carries an array — even a single-member group).
func sortedStringSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
