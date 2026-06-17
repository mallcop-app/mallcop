// casefold.go — case-insensitive structured-record parsing at the boundary
// (portable-agent-architecture.md §3.7).
//
// Humans write fixtures on different days as EventType, event_type, eventType,
// or event-type. Go's encoding/json matches a JSON key to a struct tag
// case-insensitively, but it does NOT translate between casing CONVENTIONS:
// "EventType" matches struct tag `json:"EventType"` but does NOT match struct
// tag `json:"event_type"`. The failure is the worst kind — the tool runs
// without error, returns shape-correct data, but every field is the zero value
// because no key matched. No error log to grep. This is bug #5 in the brief.
//
// The fix: normalize every JSON object key to a canonical snake_case form at the
// parse boundary BEFORE unmarshalling into the typed struct. Then snake_case,
// camelCase, PascalCase, and kebab-case fixtures all parse identically.
//
// normalizeRecordKeys rewrites the top level of a JSON object so each key is
// snake_case. It is applied to each record's raw JSON before json.Unmarshal in
// the event/finding decode paths.
package tools

import (
	"encoding/json"
	"strings"
	"unicode"
)

// normalizeKey converts a key in any common casing convention to snake_case:
//
//	EventType  → event_type   (PascalCase)
//	eventType  → event_type   (camelCase)
//	event-type → event_type   (kebab-case)
//	event_type → event_type   (already snake_case, unchanged)
//	EVENT_TYPE → event_type    (screaming snake → lowercased)
//
// The transform is idempotent: normalizeKey(normalizeKey(k)) == normalizeKey(k).
func normalizeKey(k string) string {
	if k == "" {
		return k
	}
	var b strings.Builder
	b.Grow(len(k) + 4)
	prevLower := false // previous emitted rune was a lowercase letter or digit
	for i, r := range k {
		switch {
		case r == '-' || r == ' ' || r == '_':
			// Separator → single underscore (collapse runs, skip leading).
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
				b.WriteByte('_')
			}
			prevLower = false
		case unicode.IsUpper(r):
			// Insert a boundary underscore when transitioning out of a
			// lowercase/digit run (camelCase / PascalCase word boundary), but
			// not at the very start and not right after an existing underscore.
			if i > 0 && prevLower && b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			prevLower = false
		default:
			b.WriteRune(unicode.ToLower(r))
			prevLower = unicode.IsLetter(r) || unicode.IsDigit(r)
		}
	}
	return b.String()
}

// normalizeRecordKeys rewrites the keys of a single top-level JSON object so
// each is snake_case, then re-marshals. Non-object JSON (arrays, scalars) is
// returned unchanged. A normalized key that collides with an existing
// snake_case key does NOT overwrite it — an explicit snake_case key in the
// fixture wins over a re-cased duplicate, so a fixture that carries both
// `event_type` and `EventType` keeps the canonical one.
//
// This is applied per record at the decode boundary; it does not recurse into
// nested objects (the event/finding records this package reads are flat at the
// fields it filters on — id/source/type/actor/timestamp).
func normalizeRecordKeys(raw json.RawMessage) json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return raw // not a JSON object — leave untouched
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw // malformed — let the typed unmarshal surface the error
	}
	out := make(map[string]json.RawMessage, len(obj))
	// First pass: copy keys that are already canonical snake_case verbatim so
	// they take precedence over any re-cased duplicate.
	for k, v := range obj {
		if normalizeKey(k) == k {
			out[k] = v
		}
	}
	// Second pass: add normalized forms of non-canonical keys, never clobbering
	// a canonical key already present.
	for k, v := range obj {
		nk := normalizeKey(k)
		if nk == k {
			continue // already copied
		}
		if _, exists := out[nk]; exists {
			continue // canonical key wins
		}
		out[nk] = v
	}
	reencoded, err := json.Marshal(out)
	if err != nil {
		return raw
	}
	return reencoded
}
