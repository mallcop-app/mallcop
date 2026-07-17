// get_raw_event.go — the get-raw-event pure read tool (mallcoppro-37d).
//
// search_events projects an event down to a flat id/source/type/actor/target/
// action + a fixed discriminatingMetaKeys allowlist (envelope.go) — payload.raw,
// the full record a connector collected (e.g. the complete CloudTrail record for
// an AssumeRole event: userIdentity.arn, sourceIPAddress, requestParameters), is
// never serialized to the model. When the operator asks a provenance question
// ("who did this") that the projected view doesn't answer, the chat agent had no
// way to reach the underlying record and punted to "check CloudTrail" — even
// though the answer was sitting in the store the whole time.
//
// GetRawEvent closes that gap: given an event id, it returns that ONE event's
// full Payload, decoded and re-marshaled as real JSON (never a doubly-escaped
// string blob), with two defensive passes applied at READ time:
//
//   - credential scrub: any key matching (case-insensitively) "sessionToken" or
//     "secretAccessKey" at any depth is replaced with "[REDACTED]". This is a
//     belt-and-suspenders read-time scrub — historical stores may already
//     contain this material from before connector-side redaction
//     (mallcoppro-132) existed, and this tool must never re-surface it to the
//     model regardless of what mallcoppro-132 does at write time.
//   - size cap: a payload whose serialized form exceeds ~64KB has its largest
//     leaf string values progressively truncated until it fits (or the
//     truncation floor is hit) — NEVER an error. A big payload is still useful
//     evidence; dropping it entirely is worse than trimming it.
//
// Id lookup is lenient exactly like search_events (mallcoppro-45c):
// eventIDCandidates tries the id as given and, if it carries a "finding-"
// prefix, the id with that prefix stripped — so a finding id echoed from
// earlier in the conversation still resolves to its underlying event.
package tools

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// getRawEventPayloadCap bounds the serialized size of the payload this tool
// returns. ~64KB keeps a single tool_result well inside a reasonable context
// budget even for a verbose CloudTrail-style record.
const getRawEventPayloadCap = 64 * 1024

// getRawEventInitialLeafCap / getRawEventMinLeafCap bound the leaf-string
// truncation pass capPayloadSize runs when the whole payload is over cap: it
// starts truncating every leaf string longer than getRawEventInitialLeafCap,
// and if that still doesn't fit, halves the leaf cap (down to
// getRawEventMinLeafCap) and tries again. The largest values shrink first and
// most; short discriminating fields (an actor name, an event type) are the
// last thing to lose bytes.
const (
	getRawEventInitialLeafCap = 4096
	getRawEventMinLeafCap     = 64
)

// credentialKeyNames are the exact (case-insensitive) key names redacted at
// any depth in a raw event payload. Kept as literal names (not normalized
// snake/camel forms) per the mallcoppro-37d spec — connector payloads store
// these under their native CloudTrail-style camelCase names.
var credentialKeyNames = []string{"sessionToken", "secretAccessKey"}

// GetRawEventInput is the input for GetRawEvent: the event id to fetch.
type GetRawEventInput struct {
	ID string `json:"id"`
}

// GetRawEventOutput is the output contract for get-raw-event. Every field is
// always populated (one-shape-always, portable-agent-architecture.md §3.3):
// Found reports whether the id resolved to a stored event; Payload is "null"
// (never omitted, never an empty string) when there is nothing to show;
// Redacted/Truncated report whether either defensive pass actually fired;
// Notes explains anything non-obvious (redaction happened, truncation
// happened, the id didn't resolve) — never the channel for an error.
type GetRawEventOutput struct {
	ID        string          `json:"id"`
	Found     bool            `json:"found"`
	Payload   json.RawMessage `json:"payload"`
	Redacted  bool            `json:"redacted"`
	Truncated bool            `json:"truncated"`
	Notes     string          `json:"notes"`
}

// GetRawEvent reads the events stream from the store and returns the full,
// scrubbed, size-capped payload of the ONE event whose id matches (leniently,
// per eventIDCandidates). GetRawEvent returns an error only for a genuine
// schema violation (nil store, unreadable store, malformed record JSON, empty
// input id) — an id that resolves to no event is NOT an error, it is Found:
// false with an explanatory Notes, so the model can self-recover (broaden,
// try search_events/search_findings) instead of the call itself failing.
func GetRawEvent(s *store.Store, in GetRawEventInput) (GetRawEventOutput, error) {
	if s == nil {
		return GetRawEventOutput{}, fmt.Errorf("get-raw-event: nil store")
	}
	if in.ID == "" {
		return GetRawEventOutput{}, fmt.Errorf("get-raw-event: id is required")
	}

	raws, err := s.Load(store.KindEvents)
	if err != nil {
		return GetRawEventOutput{}, fmt.Errorf("get-raw-event: load events: %w", err)
	}

	candidates := map[string]struct{}{}
	for _, c := range eventIDCandidates(in.ID) {
		candidates[c] = struct{}{}
	}

	for i, raw := range raws {
		var ev event.Event
		if err := json.Unmarshal(normalizeRecordKeys(raw), &ev); err != nil {
			return GetRawEventOutput{}, fmt.Errorf("get-raw-event: decode event %d: %w", i, err)
		}
		if _, ok := candidates[strings.ToLower(ev.ID)]; !ok {
			continue
		}
		return buildRawEventOutput(ev.ID, ev.Payload), nil
	}

	return GetRawEventOutput{
		ID:      in.ID,
		Found:   false,
		Payload: json.RawMessage("null"),
		Notes: fmt.Sprintf("no event found for id %q — this may be a finding id rather than an "+
			"event id; use search_findings or search_events to confirm the exact event id first", in.ID),
	}, nil
}

// buildRawEventOutput applies the credential scrub and size cap to a matched
// event's payload and assembles the output. Never returns an error — a
// payload that fails to parse as JSON (should not happen: it was already
// validated as part of decoding the enclosing event record) is handed back
// verbatim with a Notes explanation rather than blocking the tool call.
func buildRawEventOutput(id string, payload json.RawMessage) GetRawEventOutput {
	out := GetRawEventOutput{ID: id, Found: true}

	if len(strings.TrimSpace(string(payload))) == 0 {
		out.Payload = json.RawMessage("null")
		out.Notes = "event has no payload"
		return out
	}

	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		out.Payload = payload
		out.Notes = "payload is not valid JSON; returned verbatim, unscrubbed"
		return out
	}

	redactedVal, redacted := redactCredentialFields(decoded)
	out.Redacted = redacted

	capped, truncated := capPayloadSize(redactedVal)
	out.Payload = capped
	out.Truncated = truncated

	var notes []string
	if redacted {
		notes = append(notes, "credential fields (sessionToken/secretAccessKey) were redacted")
	}
	if truncated {
		notes = append(notes, fmt.Sprintf("payload exceeded %d bytes; largest leaf values were truncated", getRawEventPayloadCap))
	}
	out.Notes = strings.Join(notes, "; ")
	return out
}

// redactCredentialFields recursively walks a decoded JSON value (the output
// of json.Unmarshal into `any`: map[string]any / []any / string / float64 /
// bool / nil) and replaces the value of any object key matching
// credentialKeyNames (case-insensitive) at ANY depth with "[REDACTED]".
// Returns a new value (the input is never mutated in place) and whether any
// redaction fired.
func redactCredentialFields(v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		redacted := false
		for k, val := range t {
			if isCredentialKey(k) {
				out[k] = "[REDACTED]"
				redacted = true
				continue
			}
			nv, r := redactCredentialFields(val)
			out[k] = nv
			redacted = redacted || r
		}
		return out, redacted
	case []any:
		out := make([]any, len(t))
		redacted := false
		for i, val := range t {
			nv, r := redactCredentialFields(val)
			out[i] = nv
			redacted = redacted || r
		}
		return out, redacted
	default:
		return v, false
	}
}

// isCredentialKey reports whether k case-insensitively matches one of
// credentialKeyNames.
func isCredentialKey(k string) bool {
	for _, name := range credentialKeyNames {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// capPayloadSize serializes v and, if the result exceeds
// getRawEventPayloadCap, progressively truncates the largest leaf string
// values (starting at getRawEventInitialLeafCap, halving down to
// getRawEventMinLeafCap) until the serialized form fits under the cap. This
// NEVER errors: an oversized payload always comes back as usable data,
// truncated rather than dropped. If even the smallest leaf cap doesn't get
// under the byte cap (a payload with an enormous number of small leaves
// rather than a few huge ones), the smallest-leaf-cap attempt is returned
// regardless of its final size — still valid, still useful, just larger than
// the target.
func capPayloadSize(v any) (json.RawMessage, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		// v was decoded from valid JSON by json.Unmarshal, so re-marshaling it
		// should never fail — but this tool never errors on a payload problem,
		// so degrade to an explicit placeholder instead of propagating err.
		return json.RawMessage(`"[unserializable payload]"`), true
	}
	if len(b) <= getRawEventPayloadCap {
		return b, false
	}

	last := b
	for leafCap := getRawEventInitialLeafCap; leafCap >= getRawEventMinLeafCap; leafCap /= 2 {
		tb, terr := json.Marshal(truncateLeaves(v, leafCap))
		if terr != nil {
			continue
		}
		last = tb
		if len(tb) <= getRawEventPayloadCap {
			return tb, true
		}
	}
	return last, true
}

// truncateLeaves returns a copy of v with every leaf string longer than
// leafCap shortened to leafCap runes-worth of bytes plus a "...[truncated]"
// marker. Maps and slices are walked recursively; non-string scalars and nil
// pass through unchanged.
func truncateLeaves(v any, leafCap int) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = truncateLeaves(val, leafCap)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = truncateLeaves(val, leafCap)
		}
		return out
	case string:
		if len(t) > leafCap {
			return t[:leafCap] + "...[truncated]"
		}
		return t
	default:
		return t
	}
}
