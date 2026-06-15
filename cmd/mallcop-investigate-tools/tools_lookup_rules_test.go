// tools_lookup_rules_test.go — tests for the lookup-rules tool and the
// rule_id citation path in resolve-finding's confidence gate.
//
// Tests (mallcoppro-00c, Wave 3 / Phase 2):
//
//  1. TestLookupRules_LoadsYaml             — loadOperatorRules returns the rule set.
//  2. TestLookupRules_MatchesFamily         — finding_family filters returned rules.
//  3. TestLookupRules_NoMatch               — unmatched family/metadata returns empty.
//  4. TestResolveFinding_RuleIDCitation     — valid rule_id passes the gate's citation check.
//  5. TestResolveFinding_InvalidRuleID      — invalid rule_id does NOT bypass the gate.
//  6. TestGate_RuleIDCountsAsCitation       — gate's citation_count increments correctly.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeRulesFixture seeds an operator-decisions.yaml under repoRoot/agents/rules/
// with the supplied YAML content. Sets MALLCOP_REPO_ROOT to repoRoot for the
// duration of the test so loadOperatorRules picks the fixture.
//
// Returns repoRoot. The caller is responsible for using t.Setenv before any
// test that calls loadOperatorRules / runLookupRules / runResolveFinding.
func writeRulesFixture(t *testing.T, content string) string {
	t.Helper()
	repoRoot := t.TempDir()
	rulesDir := filepath.Join(repoRoot, "agents", "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir rules dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "operator-decisions.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write operator-decisions.yaml: %v", err)
	}
	t.Setenv("MALLCOP_REPO_ROOT", repoRoot)
	return repoRoot
}

// fixtureRulesYAML is the canonical 3-rule corpus used by these tests. Mirrors
// the schema in mallcoppro-2fc's seed file.
const fixtureRulesYAML = `
rules:
  - id: "R-001"
    applies_to:
      family: "unusual-timing"
      metadata_match:
        scenario_pattern: "maintenance-window"
        actor_role: "automation"
    operator_directive: |
      Off-hours automation activity inside a declared maintenance window
      is non-investigatory; resolve with reference to the window id.

  - id: "R-002"
    applies_to:
      family: "volume-anomaly"
      metadata_match:
        scenario_pattern: "scheduled-batch"
        actor_role: "automation"
    operator_directive: |
      A volume spike on a declared schedule is consistent with batch reporting;
      resolve with reference to the job_id and schedule cadence.

  - id: "R-003"
    applies_to:
      family: "auth-failure-burst"
      metadata_match:
        scenario_pattern: "fat-finger"
        resolution_event: "login_success"
    operator_directive: |
      An auth-failure burst followed within minutes by a login_success from
      the same IP is the canonical credential-typo pattern.
`

// ---- TestLookupRules_LoadsYaml ----------------------------------------------

func TestLookupRules_LoadsYaml(t *testing.T) {
	repoRoot := writeRulesFixture(t, fixtureRulesYAML)

	rules, err := loadOperatorRules(repoRoot)
	if err != nil {
		t.Fatalf("loadOperatorRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}

	// Verify the well-known IDs round-tripped.
	wantIDs := map[string]bool{"R-001": true, "R-002": true, "R-003": true}
	for _, r := range rules {
		if !wantIDs[r.ID] {
			t.Errorf("unexpected rule id %q", r.ID)
		}
	}

	// Spot-check R-001's parsed shape.
	r1, ok := findRuleByID(rules, "R-001")
	if !ok {
		t.Fatalf("R-001 not found in loaded rules")
	}
	if r1.AppliesTo.Family != "unusual-timing" {
		t.Errorf("R-001 family = %q, want unusual-timing", r1.AppliesTo.Family)
	}
	if r1.AppliesTo.MetadataMatch["actor_role"] != "automation" {
		t.Errorf("R-001 actor_role = %q, want automation", r1.AppliesTo.MetadataMatch["actor_role"])
	}
	if !strings.Contains(r1.OperatorDirective, "maintenance window") {
		t.Errorf("R-001 operator_directive missing expected phrase; got: %q", r1.OperatorDirective)
	}
}

// ---- TestLookupRules_MatchesFamily ------------------------------------------

func TestLookupRules_MatchesFamily(t *testing.T) {
	_ = writeRulesFixture(t, fixtureRulesYAML)

	out := captureStdout(t, func() {
		input := `{"finding_id":"fnd-001","finding_family":"unusual-timing","finding_metadata":{"scenario_pattern":"maintenance-window","actor_role":"automation"}}`
		if err := runLookupRules(input); err != nil {
			t.Errorf("runLookupRules: unexpected error: %v", err)
		}
	})

	var result lookupRulesOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	if result.FindingID != "fnd-001" {
		t.Errorf("finding_id = %q, want fnd-001", result.FindingID)
	}
	if len(result.Rules) != 1 {
		t.Fatalf("expected 1 matching rule, got %d", len(result.Rules))
	}
	if result.Rules[0].ID != "R-001" {
		t.Errorf("matched rule id = %q, want R-001", result.Rules[0].ID)
	}
}

// ---- TestLookupRules_NoMatch -------------------------------------------------

func TestLookupRules_NoMatch(t *testing.T) {
	_ = writeRulesFixture(t, fixtureRulesYAML)

	// (a) Unmatched family.
	out := captureStdout(t, func() {
		input := `{"finding_id":"fnd-002","finding_family":"privilege-escalation","finding_metadata":{}}`
		if err := runLookupRules(input); err != nil {
			t.Errorf("runLookupRules: unexpected error: %v", err)
		}
	})
	var result lookupRulesOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	if len(result.Rules) != 0 {
		t.Errorf("expected 0 rules for unmatched family, got %d", len(result.Rules))
	}

	// (b) Family matches but metadata mismatches — conjunctive predicate fails.
	out2 := captureStdout(t, func() {
		input := `{"finding_id":"fnd-003","finding_family":"unusual-timing","finding_metadata":{"scenario_pattern":"different-pattern"}}`
		if err := runLookupRules(input); err != nil {
			t.Errorf("runLookupRules: unexpected error: %v", err)
		}
	})
	var result2 lookupRulesOutput
	if err := json.Unmarshal([]byte(out2), &result2); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out2)
	}
	if len(result2.Rules) != 0 {
		t.Errorf("expected 0 rules when metadata mismatches, got %d", len(result2.Rules))
	}

	// (c) Sanity: schema round-trips for a separate yaml.Marshal of the rules
	// (defensive against silently-dropped fields when the loader struct loses
	// fields — caught at PR review time, not at run time).
	rules, err := loadOperatorRules(os.Getenv("MALLCOP_REPO_ROOT"))
	if err != nil {
		t.Fatalf("loadOperatorRules: %v", err)
	}
	roundtrip, err := yaml.Marshal(operatorRulesFile{Rules: rules})
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if !strings.Contains(string(roundtrip), "operator_directive") {
		t.Errorf("yaml roundtrip lost operator_directive field; got:\n%s", roundtrip)
	}
}

// ---- TestResolveFinding_RuleIDCitation --------------------------------------
//
// Verifies a valid rule_id satisfies the F2A citation requirement: the gate
// MUST NOT fire for an otherwise-citation-free resolve-finding when the agent
// cites a real rule_id.
func TestResolveFinding_RuleIDCitation(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)
	_ = writeRulesFixture(t, fixtureRulesYAML)

	// Seed enough tool calls so the score (with the rule_id citation bump)
	// clears the investigate floor of 0.40:
	//   tool_calls = 8 → 0.04*8 = 0.32
	//   distinct   = 4 → 0.08*4 = 0.32
	//   citations  = 1 (from rule_id only) → 0.04
	//   iter penalty: 8 iters - 3 threshold = 5 → -0.10
	//   total = 0.32 + 0.32 + 0.04 - 0.10 = 0.58 ≥ 0.40 ✓
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "read-config",
		"check-baseline", "search-events", "search-findings", "read-config",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)

	// Reason has NO event-ID-style citations — the only citation source is rule_id.
	reason := "Automation actor inside declared maintenance window; non-investigatory."

	envPairs := append(gateEnvPairs(true, 0.40),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-rule-cite-001",
			"action":     "resolved",
			"reason":     reason,
			"rule_id":    "R-001",
		})
		if err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...); err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Gate MUST NOT fire — rule_id satisfies the citation check.
	if gf, fired := result["gate_fired"]; fired && gf == true {
		t.Errorf("expected gate to NOT fire with valid rule_id; got gate_fired=true. result=%v", result)
	}
	if result["finding_id"] != "fnd-rule-cite-001" {
		t.Errorf("finding_id = %v, want fnd-rule-cite-001", result["finding_id"])
	}
	if result["rule_id"] != "R-001" {
		t.Errorf("rule_id = %v, want R-001 (must be echoed in work:output)", result["rule_id"])
	}

	// work:output must be present (gate did not fire → normal close).
	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(msgs, "work:output") {
		t.Errorf("expected work:output in engagement campfire for valid rule_id resolve; got %d messages", len(msgs))
	}
}

// ---- TestResolveFinding_InvalidRuleID ---------------------------------------
//
// Security test: an invented rule_id does NOT bypass the gate. The gate must
// load the rule_id from the YAML and reject anything that does not match.
//
// We test with the universal zero-citation hard floor pathway: 8 tool calls
// (high score on tool volume) + 0 retrieved-ID citations + a forged rule_id.
// The gate MUST still fire because the forged rule_id does not load from the
// YAML and the reason has no other citations.
func TestResolveFinding_InvalidRuleID(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)
	_ = writeRulesFixture(t, fixtureRulesYAML)

	// 8 tool calls (would clear 0.40 score floor on tool volume + breadth alone).
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "read-config",
		"check-baseline", "search-events", "search-findings", "read-config",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)

	// No retrieved-ID citations in the reason. Forged rule_id.
	reason := "Pattern matches operator decision rule (forged citation attempt)."

	envPairs := append(gateEnvPairs(true, 0.40),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-rule-forge-001",
			"action":     "resolved",
			"reason":     reason,
			"rule_id":    "R-999-does-not-exist",
		})
		if err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...); err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Gate MUST fire — forged rule_id does not load from YAML, no real citations.
	if result["gate_fired"] != true {
		t.Errorf("expected gate_fired=true for forged rule_id (no real citations); got result=%v", result)
	}
	if cc, ok := result["citations"]; ok {
		if n, _ := cc.(float64); n != 0 {
			t.Errorf("expected citations=0 for forged rule_id (rule did not load), got %v", cc)
		}
	}

	// Fan-out work:create must be present (gate fired).
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected work:create in work campfire (fan-out should fire on forged rule_id)")
	}
}

// ---- TestGate_RuleIDCountsAsCitation -----------------------------------------
//
// White-box test of checkConfidenceGate's citation-count behaviour. Verifies
// that a valid rule_id contributes +1 to gateResult.CitationCount even when no
// other citations are present in the reason field. This is the core invariant
// the gate-side feature exposes.
func TestGate_RuleIDCountsAsCitation(t *testing.T) {
	cfBin, cfHome, campfireID, _ := newTestCampfirePair(t)
	_ = writeRulesFixture(t, fixtureRulesYAML)

	// Seed 2 tool calls so we are not in the zero-tool-call edge case.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline", "search-events"})

	// Reason has no retrieved-ID citations. The only citation source is rule_id.
	reason := "Resolved per operator decision corpus."

	// Use task:investigate skill with default investigate floor.
	t.Setenv("MALLCOP_SKILL", "task:investigate")
	// Ensure cfg is at defaults so this test doesn't depend on env overrides.
	for _, k := range []string{
		"MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR",
	} {
		t.Setenv(k, "") // resolveBlank → default
	}

	// (a) Valid rule_id → citationCount=1.
	gr, err := checkConfidenceGate(campfireID, "resolved", reason, "R-001")
	if err != nil {
		t.Fatalf("checkConfidenceGate (valid rule_id): %v", err)
	}
	if gr.CitationCount != 1 {
		t.Errorf("valid rule_id: citation_count = %d, want 1", gr.CitationCount)
	}

	// (b) Invalid rule_id → citationCount=0 (forgery defence).
	gr2, err := checkConfidenceGate(campfireID, "resolved", reason, "R-forged-999")
	if err != nil {
		t.Fatalf("checkConfidenceGate (forged rule_id): %v", err)
	}
	if gr2.CitationCount != 0 {
		t.Errorf("forged rule_id: citation_count = %d, want 0", gr2.CitationCount)
	}
	if !gr2.Fired {
		// With 0 citations and the universal hard floor, this MUST fire.
		t.Errorf("forged rule_id: expected gate to fire (zero-citation hard floor), got gr=%+v", gr2)
	}

	// (c) No rule_id → citationCount=0 (regression: no rule_id means no rule_id bump).
	gr3, err := checkConfidenceGate(campfireID, "resolved", reason, "")
	if err != nil {
		t.Fatalf("checkConfidenceGate (empty rule_id): %v", err)
	}
	if gr3.CitationCount != 0 {
		t.Errorf("empty rule_id: citation_count = %d, want 0", gr3.CitationCount)
	}
}

// ---- TestLoadOperatorRules_ChecksumMismatch_Errors --------------------------
//
// Security test (mallcoppro-b92): when sha256 enforcement is on, a corpus
// whose hash does not match the expected value MUST fail to load. This is the
// belt+suspenders defence against a tampered operator-decisions.yaml that
// would otherwise grant gate-bypassing rule_id citations.
func TestLoadOperatorRules_ChecksumMismatch_Errors(t *testing.T) {
	resetRulesCache := func() {
		rulesCacheMu.Lock()
		rulesCacheData = nil
		rulesCacheErr = nil
		rulesCacheKey = ""
		rulesCacheOnce = sync.Once{}
		rulesCacheMu.Unlock()
	}

	// (a) Wrong hash via MALLCOP_RULES_SHA256 override → expect error.
	resetRulesCache()
	repoRoot := writeRulesFixture(t, fixtureRulesYAML)
	t.Setenv("MALLCOP_RULES_SHA256", "0000000000000000000000000000000000000000000000000000000000000000")
	t.Setenv("MALLCOP_RULES_SHA256_ENFORCE", "")
	if _, err := loadOperatorRules(repoRoot); err == nil {
		t.Errorf("expected load error on sha256 mismatch (override), got nil")
	} else if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("expected 'sha256 mismatch' in error, got: %v", err)
	}

	// (b) Correct hash via override → expect success.
	resetRulesCache()
	repoRoot2 := writeRulesFixture(t, fixtureRulesYAML)
	sum := sha256.Sum256([]byte(fixtureRulesYAML))
	t.Setenv("MALLCOP_RULES_SHA256", hex.EncodeToString(sum[:]))
	if rules, err := loadOperatorRules(repoRoot2); err != nil {
		t.Errorf("expected load success with matching override hash, got: %v", err)
	} else if len(rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rules))
	}

	// (c) MALLCOP_RULES_SHA256_ENFORCE=1 with no override → expected hash is the
	// pinned constant; the test fixture's content differs from the shipped
	// corpus so the load must fail.
	resetRulesCache()
	repoRoot3 := writeRulesFixture(t, fixtureRulesYAML)
	t.Setenv("MALLCOP_RULES_SHA256", "")
	t.Setenv("MALLCOP_RULES_SHA256_ENFORCE", "1")
	if _, err := loadOperatorRules(repoRoot3); err == nil {
		t.Errorf("expected load error: fixture YAML hash != pinned constant; got nil")
	} else if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("expected 'sha256 mismatch' in error, got: %v", err)
	}

	// (d) No enforcement (both env vars empty) → load succeeds regardless.
	resetRulesCache()
	repoRoot4 := writeRulesFixture(t, fixtureRulesYAML)
	t.Setenv("MALLCOP_RULES_SHA256", "")
	t.Setenv("MALLCOP_RULES_SHA256_ENFORCE", "")
	if _, err := loadOperatorRules(repoRoot4); err != nil {
		t.Errorf("expected load success with enforcement off, got: %v", err)
	}
}

// ---- TestExpectedOperatorRulesSHA256_MatchesShippedCorpus -------------------
//
// Regression guard (mallcoppro-b92): expectedOperatorRulesSHA256 must equal
// the sha256 of the repo's agents/rules/operator-decisions.yaml. If they
// diverge, the build/release process forgot to regenerate the constant after
// editing the corpus — production deploys with MALLCOP_RULES_SHA256_ENFORCE=1
// would then refuse to load rules.
func TestExpectedOperatorRulesSHA256_MatchesShippedCorpus(t *testing.T) {
	// Walk up from CWD until we find go.mod, which is robust against package
	// restructures. go test's CWD is the package directory.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(repoRoot)
		if parent == repoRoot {
			t.Fatalf("could not locate repo root (go.mod) from %s", cwd)
		}
		repoRoot = parent
	}
	corpus := filepath.Join(repoRoot, "agents", "rules", "operator-decisions.yaml")
	data, err := os.ReadFile(corpus)
	if err != nil {
		t.Fatalf("read shipped corpus: %v", err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != expectedOperatorRulesSHA256 {
		t.Errorf("expectedOperatorRulesSHA256 is stale.\n  shipped corpus: %s\n  constant:       %s\n  fix: update expectedOperatorRulesSHA256 in tools_lookup_rules.go to the shipped hash and commit.", got, expectedOperatorRulesSHA256)
	}
}
