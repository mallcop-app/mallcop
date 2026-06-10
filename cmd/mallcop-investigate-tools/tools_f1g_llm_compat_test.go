package main

import (
	"encoding/json"
	"testing"
)

func TestStripMarkdownFences(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare JSON unchanged", `{"a":1}`, `{"a":1}`},
		{"triple-backtick with json tag", "```json\n{\"a\":1}\n```", `{"a":1}`},
		{"triple-backtick no tag", "```\n{\"a\":1}\n```", `{"a":1}`},
		{"tilde fences", "~~~json\n{\"a\":1}\n~~~", `{"a":1}`},
		{"backtick with surrounding whitespace", "  ```json\n  {\"a\":1}\n  ```  ", `{"a":1}`},
		{"only opening fence (no closer)", "```json\n{\"a\":1}", `{"a":1}`},
		{"only closing fence", "{\"a\":1}\n```", `{"a":1}`},
		{"empty input", "", ""},
		{"non-language tag preserved", "```\nthis is the first line\n{\"a\":1}\n```", "this is the first line\n{\"a\":1}"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripMarkdownFences(c.in)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestNormalizeAction(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"resolve", "resolved"},
		{"escalate", "escalated"},
		{"remediate", "remediated"},
		{"resolved", "resolved"},  // pass-through
		{"escalated", "escalated"}, // pass-through
		{"RESOLVE", "resolved"},   // case insensitive
		{"  Resolve  ", "resolved"},
		{"unknown", "unknown"}, // unknown values pass through for downstream validator
		{"", ""},
	}
	for _, c := range cases {
		got := normalizeAction(c.in)
		if got != c.want {
			t.Errorf("normalizeAction(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFlexibleFloat_NumberForm(t *testing.T) {
	var f flexibleFloat
	if err := json.Unmarshal([]byte(`0.9`), &f); err != nil {
		t.Fatalf("unmarshal number: %v", err)
	}
	if float64(f) != 0.9 {
		t.Errorf("got %v, want 0.9", float64(f))
	}
}

func TestFlexibleFloat_StringForm(t *testing.T) {
	var f flexibleFloat
	if err := json.Unmarshal([]byte(`"0.9"`), &f); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	if float64(f) != 0.9 {
		t.Errorf("got %v, want 0.9", float64(f))
	}
}

func TestFlexibleFloat_StringWithSpaces(t *testing.T) {
	var f flexibleFloat
	if err := json.Unmarshal([]byte(`"  0.75  "`), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if float64(f) != 0.75 {
		t.Errorf("got %v, want 0.75", float64(f))
	}
}

func TestFlexibleFloat_NullOrAbsent(t *testing.T) {
	var f flexibleFloat
	if err := json.Unmarshal([]byte(`null`), &f); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if float64(f) != 0 {
		t.Errorf("got %v, want 0", float64(f))
	}
}

func TestFlexibleFloat_InvalidString_ReturnsError(t *testing.T) {
	var f flexibleFloat
	if err := json.Unmarshal([]byte(`"not-a-number"`), &f); err == nil {
		t.Error("expected error for non-numeric string")
	}
}

// End-to-end: resolveInput parses llama-style inputs that previously crashed.
func TestResolveInput_LlamaCompat(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"verb action + string confidence",
			`{"finding_id":"fnd_test","action":"resolve","reason":"benign","confidence":"0.9"}`},
		{"verb action only",
			`{"finding_id":"fnd_test","action":"resolve","reason":"benign","confidence":0.9}`},
		{"string confidence only",
			`{"finding_id":"fnd_test","action":"resolved","reason":"benign","confidence":"0.9"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var in resolveInput
			if err := json.Unmarshal([]byte(c.in), &in); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			in.Action = normalizeAction(in.Action)
			if in.Action != "resolved" {
				t.Errorf("Action = %q, want %q", in.Action, "resolved")
			}
			if float64(in.Confidence) != 0.9 {
				t.Errorf("Confidence = %v, want 0.9", float64(in.Confidence))
			}
		})
	}
}

func TestResolveInput_MarkdownWrapped(t *testing.T) {
	wrapped := "```json\n" +
		`{"finding_id":"fnd_test","action":"resolved","reason":"benign","confidence":0.9}` +
		"\n```"
	stripped := stripMarkdownFences(wrapped)
	var in resolveInput
	if err := json.Unmarshal([]byte(stripped), &in); err != nil {
		t.Fatalf("unmarshal stripped: %v\nstripped=%q", err, stripped)
	}
	if in.FindingID != "fnd_test" {
		t.Errorf("FindingID = %q, want %q", in.FindingID, "fnd_test")
	}
}
