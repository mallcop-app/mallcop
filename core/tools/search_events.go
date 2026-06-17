// search_events.go — the search-events pure read tool, reusing pkg/event and
// reading the events stream from core/store.
//
// SearchEvents replays the events stream from a *store.Store and returns the
// typed event.Event records that pass the actor/source/type/time filters. It is
// a PURE read: it opens no channel, runs no inference, and never writes. Its
// only effect is to read committed records from the git-backed store.
package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// SearchEventsInput is the filter for SearchEvents. Every field is optional; an
// empty filter returns every event in the stream.
//
// Actor / Source / Type are case-insensitive equality filters on the matching
// event field. Since / Until bound the event timestamp (inclusive). A zero time
// means "unbounded on that side".
type SearchEventsInput struct {
	Actor  string    `json:"actor,omitempty"`
	Source string    `json:"source,omitempty"`
	Type   string    `json:"type,omitempty"`
	Since  time.Time `json:"since,omitempty"`
	Until  time.Time `json:"until,omitempty"`
}

// SearchEvents reads the events stream from the store and returns the events
// matching the filter, oldest first.
//
// Time-filter fallback: if a Since/Until window excludes EVERY event but the
// non-time filters matched some, SearchEvents returns the non-time-filtered set
// instead. A caller-supplied window is frequently anchored to a different
// "now" than the stored fixtures (an LLM hallucinating a date range a year off
// from the data); treating an all-excluding window as a no-op keeps the read
// useful rather than silently empty. The boolean second return reports whether
// this fallback fired, so the caller can annotate the result if it cares.
//
// SearchEvents returns an error only when the store cannot be read or a record
// is not valid event JSON.
func SearchEvents(s *store.Store, in SearchEventsInput) (events []event.Event, timeFilterFellBack bool, err error) {
	if s == nil {
		return nil, false, fmt.Errorf("search-events: nil store")
	}
	raws, err := s.Load(store.KindEvents)
	if err != nil {
		return nil, false, fmt.Errorf("search-events: load events: %w", err)
	}

	all := make([]event.Event, 0, len(raws))
	for i, raw := range raws {
		var ev event.Event
		// §3.7: normalize key casing at the boundary so PascalCase / camelCase /
		// kebab-case fixtures parse into the snake_case struct tags instead of
		// silently decoding to an all-zero-value struct.
		if err := json.Unmarshal(normalizeRecordKeys(raw), &ev); err != nil {
			return nil, false, fmt.Errorf("search-events: decode event %d: %w", i, err)
		}
		all = append(all, ev)
	}

	// Pass 1: non-time filters (always applied).
	preTime := make([]event.Event, 0, len(all))
	for _, ev := range all {
		if in.Actor != "" && !strings.EqualFold(ev.Actor, in.Actor) {
			continue
		}
		if in.Source != "" && !strings.EqualFold(ev.Source, in.Source) {
			continue
		}
		if in.Type != "" && !strings.EqualFold(ev.Type, in.Type) {
			continue
		}
		preTime = append(preTime, ev)
	}

	// Pass 2: time filter (only when a bound is set).
	if in.Since.IsZero() && in.Until.IsZero() {
		return preTime, false, nil
	}
	filtered := make([]event.Event, 0, len(preTime))
	for _, ev := range preTime {
		if ev.Timestamp.IsZero() {
			continue
		}
		if !in.Since.IsZero() && ev.Timestamp.Before(in.Since) {
			continue
		}
		if !in.Until.IsZero() && ev.Timestamp.After(in.Until) {
			continue
		}
		filtered = append(filtered, ev)
	}
	// Fallback: window excluded every event but non-time filters had hits.
	if len(filtered) == 0 && len(preTime) > 0 {
		return preTime, true, nil
	}
	return filtered, false, nil
}

// SearchEventsWrapped is the agent-facing search-events tool. It returns the
// canonical SearchEventsEnvelope on EVERY call — same shape, every key present
// — and folds the operator-decisions rule lookup INTO the response (§3.8): the
// matched_rules field carries the rules whose applies_to predicate matches the
// returned events' finding family + metadata. The model reliably calls
// search-events and reliably ignores a standalone lookup-rules, so the rule data
// rides along on the tool the model already drives. (LookupRules remains
// callable for callers that want it directly; search-events is the path that
// reaches the model.)
//
// Contract guarantees:
//
//   - §3.3 one shape always: every field is populated on every call (empty
//     slices, empty strings) — never an omitted key, never a conditional shape.
//   - §3.4 empty-is-data: no matches returns the wrapped envelope with empty
//     Events / MatchedRules and a Notes explanation. An ERROR is returned ONLY
//     for a genuine schema violation (nil store, unreadable store, malformed
//     record JSON) — never for "the world is empty".
//   - §3.5 self-resolving config: the rule corpus is located by walking up from
//     the binary, not from CWD or a required env var.
//   - §3.6 date-hallucination fallback: a time window that excludes every
//     candidate is DROPPED (the unfiltered set is returned) with a Notes line
//     and FilterApplied.Effective = "dropped".
//
// findingFamily selects which operator rules can match (matches finding.detector
// case-insensitively); pass "" to skip rule matching (matched_rules stays
// empty, the envelope shape is unchanged). findingMetadata is the flat predicate
// the rules' metadata_match is evaluated against (event metadata the agent
// observed: maintenance_window, scheduled, location_change, etc.).
func SearchEventsWrapped(s *store.Store, in SearchEventsInput, findingFamily string, findingMetadata map[string]string) (SearchEventsEnvelope, error) {
	events, fellBack, err := SearchEvents(s, in)
	if err != nil {
		// Genuine schema violation (nil/unreadable store, malformed record).
		// Reserve the error channel for these — never for an empty world.
		return SearchEventsEnvelope{}, err
	}

	env := SearchEventsEnvelope{
		Events:       eventViews(events),
		MatchedRules: []OperatorRule{},
		FilterApplied: FilterApplied{
			Actor:     in.Actor,
			Source:    in.Source,
			Type:      in.Type,
			Since:     formatTime(in.Since),
			Until:     formatTime(in.Until),
			Effective: timeEffective(in, fellBack),
		},
	}

	var notes []string
	if fellBack {
		// §3.6: the supplied window excluded every candidate; we returned the
		// unfiltered set instead. Tell the model so it corrects course rather
		// than concluding "no activity → resolve benign".
		notes = append(notes, "Supplied time filter excluded all events; returning unfiltered. Check that since/until reflect actual event timestamps.")
	}

	// §3.8: fold the operator-decisions rule lookup into this response.
	if findingFamily != "" {
		root, rootErr := findConfigRoot()
		if rootErr != nil {
			// §3.4: config-root resolution failure is surfaced in Notes, not as
			// an error — the events are still useful and the model can proceed.
			notes = append(notes, "rule corpus not consulted: "+rootErr.Error())
		} else {
			matched, lookupErr := matchRulesForEvents(root, findingFamily, findingMetadata)
			if lookupErr != nil {
				notes = append(notes, "rule matching skipped: "+lookupErr.Error())
			} else {
				env.MatchedRules = matched
			}
		}
	}

	if len(env.Events) == 0 {
		notes = append(notes, "no events matched the filter")
	}

	env.Notes = strings.Join(notes, " ")
	return env, nil
}

// matchRulesForEvents loads the operator-decisions corpus from root and returns
// the rules whose applies_to predicate matches the given finding family +
// metadata. Returns an empty slice (never nil) on no match. This is the same
// matcher LookupRules uses, exposed so search-events can fold the rule data in.
func matchRulesForEvents(root, findingFamily string, findingMetadata map[string]string) ([]OperatorRule, error) {
	rules, err := LoadOperatorRules(root)
	if err != nil {
		return nil, err
	}
	if findingMetadata == nil {
		findingMetadata = map[string]string{}
	}
	matches := []OperatorRule{}
	for _, r := range rules {
		if matchesRule(r, findingFamily, findingMetadata) {
			matches = append(matches, r)
		}
	}
	return matches, nil
}

// eventViews projects typed events into the flat EventView the envelope carries.
// Always returns a non-nil slice (empty when there are no events).
func eventViews(events []event.Event) []EventView {
	out := make([]EventView, 0, len(events))
	for _, ev := range events {
		out = append(out, EventView{
			ID:        ev.ID,
			Source:    ev.Source,
			Type:      ev.Type,
			Actor:     ev.Actor,
			Timestamp: formatTime(ev.Timestamp),
		})
	}
	return out
}

// formatTime renders a time as RFC3339, or "" when zero.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// timeEffective reports how the time window was applied for FilterApplied:
// "none" when no bound was supplied, "dropped" when the date-hallucination
// fallback fired (window excluded everything → discarded), "applied" otherwise.
func timeEffective(in SearchEventsInput, fellBack bool) string {
	if in.Since.IsZero() && in.Until.IsZero() {
		return "none"
	}
	if fellBack {
		return "dropped"
	}
	return "applied"
}
