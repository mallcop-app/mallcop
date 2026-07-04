//go:build docdemo

package docdemo

import (
	"encoding/json"
	"strings"
	"testing"
)

// assertJSONLLineMatchesElidedExample checks a real JSONL line against a doc's
// ABBREVIATED example of it. The doc example is a strict SUBSET of the real
// line's keys (extra real fields not mentioned in the doc — confidence,
// severity, timestamp — are allowed and NOT compared), and any string value in
// the doc containing "..." is treated as an ellipsis: only the text before the
// first "..." and after the last "..." must match as a prefix/suffix of the
// real value (with the real value's embedded newlines collapsed to single
// spaces first, matching the doc's single-line rendering). This is documented,
// narrow normalization for hand-abbreviated example blocks — never a skip:
// every key the doc shows, and every literal character it shows around an
// elision, is asserted against the real captured output.
func assertJSONLLineMatchesElidedExample(t *testing.T, realLine, docExample string) {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal([]byte(docExample), &doc); err != nil {
		t.Fatalf("doc example is not valid JSON: %v\n%s", err, docExample)
	}
	var real map[string]any
	if err := json.Unmarshal([]byte(realLine), &real); err != nil {
		t.Fatalf("real resolutions.jsonl line is not valid JSON: %v\n%s", err, realLine)
	}

	for key, docVal := range doc {
		realVal, ok := real[key]
		if !ok {
			t.Fatalf("doc shows key %q but the real resolutions.jsonl line has no such key.\nreal: %s\ndoc:  %s", key, realLine, docExample)
		}
		docStr, docIsStr := docVal.(string)
		realStr, realIsStr := realVal.(string)
		if !docIsStr || !realIsStr {
			if docVal != realVal {
				t.Fatalf("key %q: doc shows %v, real is %v", key, docVal, realVal)
			}
			continue
		}
		realFlat := strings.Join(strings.Fields(strings.ReplaceAll(realStr, "\n", " ")), " ")
		if !strings.Contains(docStr, "...") {
			if docStr != realFlat {
				t.Fatalf("key %q drifted.\ndoc:  %q\nreal: %q", key, docStr, realFlat)
			}
			continue
		}
		parts := strings.SplitN(docStr, "...", 2)
		prefix, suffix := parts[0], parts[1]
		if prefix != "" && !strings.HasPrefix(realFlat, prefix) {
			t.Fatalf("key %q: doc's elided example prefix %q not found at the start of the real value:\n%q", key, prefix, realFlat)
		}
		if suffix != "" && !strings.HasSuffix(realFlat, suffix) {
			t.Fatalf("key %q: doc's elided example suffix %q not found at the end of the real value:\n%q", key, suffix, realFlat)
		}
	}
}
