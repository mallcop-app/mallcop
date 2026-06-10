// tools_f1g_llm_compat.go — forgiving input parsing for F1G action tools
// (mallcoppro-e32).
//
// Different models emit tool arguments in subtly different shapes. glm-5 and
// mistral were strict; llama-3.3-70b on Bedrock Converse produces three
// recurring deviations that the strict parsers reject as exit-1 crashes,
// blowing up the entire chain:
//
//   1. Markdown-wrapped JSON — the argument string arrives as
//      ```json
//      {"finding_id":"...", "action":"resolved"}
//      ```
//      instead of bare JSON.
//
//   2. Verb-form actions — "resolve", "escalate", "remediate" instead of
//      the past-tense forms the enum expects.
//
//   3. Numbers quoted as strings — "confidence":"0.9" instead of 0.9.
//
// These are llm-side formatting variances, not semantic errors — the model's
// intent is unambiguous. This file normalizes the input upstream of strict
// schema validation so the model gets to drive the chain end-to-end.
//
// Validation that DOES catch real errors (unknown action values, missing
// required fields, malformed JSON after cleanup) is left in place.
//
// bk-20260610-002356-allied-llama and the original us_only run both
// produced ~40 resolve-finding exit-1 errors per lane against llama;
// without this fix both lanes are capped at the HC-only ceiling (~30%).

package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// stripMarkdownFences removes triple-backtick or tilde code fences (with
// optional language tag) from the start and end of s, plus any wrapping
// whitespace. Bare JSON is passed through unchanged.
//
// Idempotent. Safe to call on any input.
func stripMarkdownFences(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	// Strip a leading fence: ``` or ~~~, optionally followed by a language tag
	// like "json" or "JSON".
	for _, fence := range []string{"```", "~~~"} {
		if strings.HasPrefix(s, fence) {
			s = strings.TrimPrefix(s, fence)
			// Drop the language tag on the same line as the opening fence.
			if nl := strings.IndexByte(s, '\n'); nl >= 0 {
				// If everything before the newline is just a word (e.g. "json"),
				// strip the whole opening line. Otherwise the newline is
				// already content — leave it.
				head := strings.TrimSpace(s[:nl])
				if head == "" || isLanguageTag(head) {
					s = s[nl+1:]
				}
			}
			break
		}
	}

	// Strip trailing fence.
	for _, fence := range []string{"```", "~~~"} {
		s = strings.TrimRight(s, " \t\n\r")
		if strings.HasSuffix(s, fence) {
			s = strings.TrimSuffix(s, fence)
			break
		}
	}

	return strings.TrimSpace(s)
}

// isLanguageTag reports whether s looks like a markdown code-fence language
// tag (e.g. "json", "JSON", "yaml"). Used to decide whether to strip the
// first line of a fenced block.
func isLanguageTag(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// normalizeAction maps verb-form action names to the past-tense forms that
// the F1G action enum accepts. Llama in particular emits "resolve" when the
// schema requires "resolved".
//
// Anything else (already-correct values, unknown values, empty) passes
// through unchanged so strict validation downstream still catches genuine
// errors with a clear message.
func normalizeAction(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "resolve":
		return "resolved"
	case "escalate":
		return "escalated"
	case "remediate":
		return "remediated"
	}
	return s
}

// flexibleFloat is a float64 that accepts either JSON numbers or
// string-quoted numbers in the input. Used for confidence fields that
// llama-3.3-70b sometimes emits as "0.9" instead of 0.9.
//
// A zero value is "absent" — UnmarshalJSON returns nil for null/missing,
// matching the legacy `confidence,omitempty` behaviour.
type flexibleFloat float64

// UnmarshalJSON tries number form first (the schema-correct form), then
// string form. Returns a parse error only when neither shape is decodable.
func (f *flexibleFloat) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return nil
	}
	// Schema-correct form: a JSON number.
	var n json.Number
	if err := json.Unmarshal(data, &n); err == nil {
		v, perr := n.Float64()
		if perr == nil {
			*f = flexibleFloat(v)
			return nil
		}
	}
	// Llama deviation: a JSON-quoted string containing a number.
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		v, perr := strconv.ParseFloat(strings.TrimSpace(str), 64)
		if perr == nil {
			*f = flexibleFloat(v)
			return nil
		}
	}
	return fmt.Errorf("flexibleFloat: cannot parse %s as number", data)
}
