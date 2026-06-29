package detect

import "encoding/json"

// payloadMeta returns the discriminating metadata block a detector reads from an
// event payload, handling BOTH on-disk layouts the canonical schema defines:
//
//  1. CORPUS / eval-seeder shape (scenario_tools.go eventRecord): the payload is
//     {action, target, severity, metadata:{role, ip, collaborator, ...}} — the
//     discriminators live NESTED under payload.metadata.
//  2. PRODUCTION connector shape (normalizeEntry): the payload IS the raw audit
//     entry FLAT — {action, actor, collaborator, permission, role, ...} at the
//     top level.
//
// payloadMeta unmarshals the payload to a map and returns m["metadata"] when it is
// an object, else the top-level map itself. This mirrors core/tools'
// payloadDiscriminatingMeta metadata-first fallback so every detector stays
// aligned to BOTH contracts from ONE read pattern. A nil/empty/malformed payload
// yields an empty (never nil) map.
func payloadMeta(payload json.RawMessage) map[string]any {
	out := map[string]any{}
	if len(payload) == 0 {
		return out
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return out
	}
	if meta, ok := m["metadata"].(map[string]any); ok {
		return meta
	}
	return m
}

// metaStr reads key k from a meta map as a string, accepting the first present
// alias. Non-string scalars are not coerced (the corpus carries these fields as
// strings); a missing key yields "". Returns the value for the first alias found.
func metaStr(meta map[string]any, aliases ...string) string {
	for _, k := range aliases {
		if v, ok := meta[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// metaFloat reads key k from a meta map as a float64, accepting the first present
// alias. JSON numbers decode to float64; a string number is parsed. Returns
// (value, true) on the first numeric alias found, else (0, false).
func metaFloat(meta map[string]any, aliases ...string) (float64, bool) {
	for _, k := range aliases {
		v, ok := meta[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case float64:
			return t, true
		case int:
			return float64(t), true
		case json.Number:
			if f, err := t.Float64(); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}
