package finding

import (
	"encoding/json"
	"sort"
	"time"
)

// Finding is a security finding emitted by a detector.
type Finding struct {
	ID        string          `json:"id"`
	Source    string          `json:"source"`   // "detector:unusual-login"
	Severity  string          `json:"severity"` // "critical", "high", "medium", "low"
	Type      string          `json:"type"`     // "unusual-login"
	Actor     string          `json:"actor"`    // GitHub username
	Timestamp time.Time       `json:"timestamp"`
	Reason    string          `json:"reason"`   // human-readable explanation
	Evidence  json.RawMessage `json:"evidence"` // supporting data

	// EventIDs are the pkg/event.Event id(s) this finding was derived from —
	// the first-class event linkage that identity resolution (core/inquest's
	// assembleIdentity), the id-lenience event lookup, and any consumer that
	// wants to "chain a finding to its underlying event(s)" reads directly,
	// rather than reverse-engineering it out of the detector-defined Evidence
	// blob (mallcoppro-323). Every detector in core/detect that mints a
	// Finding from one or more events populates this: a single-event detector
	// sets it to []string{ev.ID}; an aggregate detector that collapses many
	// events into one finding (e.g. auth-failure-burst's per-actor burst,
	// unusual-timing's per-(actor,hour) group, volume-anomaly's per-group
	// spike) sets it to the FULL contributing event-id set, not just one
	// representative id. omitempty: a finding built before this field existed
	// (an old store record, or a detector that genuinely fired on zero
	// events) marshals with no event_ids key at all, never an empty array
	// pretending to be meaningful.
	EventIDs []string `json:"event_ids,omitempty"`
}

// ExtractEvidenceEventIDs pulls event_id / event_ids values out of a raw
// Evidence blob. The evidence shape is detector-defined, but by convention
// the keys are "event_id" (string) and "event_ids" (array of strings) — see
// e.g. core/detect/new_external_access.go. Returns a sorted, deduplicated,
// non-empty slice, or nil when nothing is present.
//
// This is the BACKSTOP extraction path: it exists for two consumers that
// need to recover event linkage from Evidence when Finding.EventIDs (the
// primary, first-class path added by mallcoppro-323) is unavailable —
// core/pipeline populates a stored finding's EventIDs from it when a
// detector left EventIDs empty, and cmd/mallcop-finding-context uses it to
// scope which raw events to surface for a finding read from an older store
// record. New code should prefer Finding.EventIDs directly; this helper is
// for filling that field in, not a replacement for it.
func ExtractEvidenceEventIDs(evidence json.RawMessage) []string {
	if len(evidence) == 0 {
		return nil
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(evidence, &parsed); err != nil {
		return nil
	}

	seen := map[string]struct{}{}
	if raw, ok := parsed["event_id"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && s != "" {
			seen[s] = struct{}{}
		}
	}
	if raw, ok := parsed["event_ids"]; ok {
		var xs []string
		if err := json.Unmarshal(raw, &xs); err == nil {
			for _, s := range xs {
				if s != "" {
					seen[s] = struct{}{}
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
