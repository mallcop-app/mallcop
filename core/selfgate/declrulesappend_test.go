package selfgate

import (
	"strings"
	"testing"
)

// declrulesappend_test.go — the K6 guard checker: detectors/rules.yaml is
// APPEND-ONLY widen data. These prove the checker directly (base/head blobs) and
// end-to-end through Guard's filename dispatch.

// checkDeclRulesAppendOnly table: base→head diffs and whether they widen.
func TestCheckDeclRulesAppendOnly(t *testing.T) {
	const ruleA = `rules:
  - name: audit-tamper
    event_types: ["audit_log_disabled"]
    match: {kind: event_type_present}
    severity: critical
    reason_template: "{rule} by {actor}"
    dedup_key: actor
`
	const ruleAB = `rules:
  - name: audit-tamper
    event_types: ["audit_log_disabled"]
    match: {kind: event_type_present}
    severity: critical
    reason_template: "{rule} by {actor}"
    dedup_key: actor
  - name: sqli-probe
    match: {kind: regex, patterns: ["(?i)' or 1=1"]}
    severity: high
    reason_template: "{match}"
    dedup_key: event
`
	// ruleA with a MUTATED existing rule (severity high->critical differs? here
	// change the template of the frozen rule).
	const ruleAMutated = `rules:
  - name: audit-tamper
    event_types: ["audit_log_disabled"]
    match: {kind: event_type_present}
    severity: critical
    reason_template: "TAMPERED {rule} by {actor}"
    dedup_key: actor
`
	const empty = "rules: []\n"

	cases := []struct {
		name       string
		base, head string
		wantReject bool
		fragment   string
	}{
		{"append new rule", ruleA, ruleAB, false, ""},
		{"seed to first rule", empty, ruleA, false, ""},
		{"no change", ruleAB, ruleAB, false, ""},
		{"remove a rule", ruleAB, ruleA, true, "removed"},
		{"mutate existing rule", ruleA, ruleAMutated, true, "mutated"},
		{"drop to empty", ruleA, empty, true, "removed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := checkDeclRulesAppendOnly("detectors/rules.yaml", []byte(c.base), []byte(c.head))
			if c.wantReject {
				if len(findings) == 0 {
					t.Fatalf("expected a rejection, got none")
				}
				if c.fragment != "" && !strings.Contains(findings[0].Detail, c.fragment) {
					t.Fatalf("detail %q missing fragment %q", findings[0].Detail, c.fragment)
				}
				for _, f := range findings {
					if f.Rule != RuleDetectorDataWidenOnly {
						t.Fatalf("finding rule = %q, want %q", f.Rule, RuleDetectorDataWidenOnly)
					}
				}
			} else if len(findings) != 0 {
				t.Fatalf("expected a clean pass, got %+v", findings)
			}
		})
	}
}

// TestCheckDeclRulesAppendOnly_FailsClosed proves malformed/unrecognized shapes
// are rejected (never silently passed).
func TestCheckDeclRulesAppendOnly_FailsClosed(t *testing.T) {
	cases := map[string][2]string{
		"unparseable head":   {"rules: []\n", "rules: [oops\n"},
		"unknown section":    {"rules: []\n", "sneaky: {}\nrules: []\n"},
		"rules not sequence": {"rules: []\n", "rules: {a: b}\n"},
		"entry not mapping":  {"rules: []\n", "rules:\n  - just-a-string\n"},
		"missing name":       {"rules: []\n", "rules:\n  - {severity: low}\n"},
		"duplicate name":     {"rules: []\n", "rules:\n  - {name: x}\n  - {name: x}\n"},
	}
	for name, bh := range cases {
		t.Run(name, func(t *testing.T) {
			findings := checkDeclRulesAppendOnly("detectors/rules.yaml", []byte(bh[0]), []byte(bh[1]))
			if len(findings) == 0 {
				t.Fatalf("expected a fail-closed rejection for %q", name)
			}
		})
	}
}

// TestGuard_RulesYamlDispatch proves Guard routes an 'M' of detectors/rules.yaml
// through the append-only checker: appending a rule PASSES, mutating an existing
// rule is REJECTED, and a NEW rules.yaml ('A') passes (additive by definition).
func TestGuard_RulesYamlDispatch(t *testing.T) {
	const base = `rules:
  - name: audit-tamper
    match: {kind: event_type_present}
    severity: critical
    reason_template: "{rule}"
    dedup_key: actor
`
	const appended = base + `  - name: new-probe
    match: {kind: keyword, patterns: ["needle"]}
    severity: high
    reason_template: "{match}"
    dedup_key: event
`
	const mutated = `rules:
  - name: audit-tamper
    match: {kind: event_type_present}
    severity: low
    reason_template: "{rule}"
    dedup_key: actor
`

	t.Run("append passes", func(t *testing.T) {
		f := newFixture(t)
		f.write("detectors/rules.yaml", base)
		b := f.commit("base rules")
		f.write("detectors/rules.yaml", appended)
		h := f.commit("append a rule")
		requireClean(t, f.guard(b, h))
	})

	t.Run("mutation rejected", func(t *testing.T) {
		f := newFixture(t)
		f.write("detectors/rules.yaml", base)
		b := f.commit("base rules")
		f.write("detectors/rules.yaml", mutated)
		h := f.commit("mutate a frozen rule")
		requireRejected(t, f.guard(b, h), RuleDetectorDataWidenOnly, "detectors/rules.yaml")
	})

	t.Run("new file passes", func(t *testing.T) {
		f := newFixture(t)
		f.write("detectors/other.txt", "x")
		b := f.commit("base without rules.yaml")
		f.write("detectors/rules.yaml", base)
		h := f.commit("add rules.yaml")
		requireClean(t, f.guard(b, h))
	})

	t.Run("deletion rejected", func(t *testing.T) {
		f := newFixture(t)
		f.write("detectors/rules.yaml", base)
		b := f.commit("base rules")
		f.remove("detectors/rules.yaml")
		h := f.commit("delete rules.yaml")
		requireRejected(t, f.guard(b, h), RuleDetectorDataWidenOnly, "detectors/rules.yaml")
	})
}
