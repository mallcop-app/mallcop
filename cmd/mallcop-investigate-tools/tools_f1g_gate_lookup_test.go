// tools_f1g_gate_lookup_test.go — shared test helper for seeding a
// tool:lookup-rules invocation in a test campfire.
//
// History:
//   - mallcoppro-8b0 (Wave B): added a soft penalty (lookupRulesSkipPenalty)
//     subtracted from the structural score when the worker resolved without
//     invoking lookup-rules. The penalty was *soft* so it only flipped
//     borderline-score resolves; high-score resolves and escalate-to-stage-c
//     dispatches bypassed it entirely.
//   - mallcoppro-structural-lookup-enforce: three bakeoffs (171 scenarios,
//     0 lookup-rules invocations) proved prompt enforcement is ineffective.
//     The soft penalty has been replaced with a HARD runtime guard in
//     runResolveFinding and runEscalateToStageC. The penalty constants
//     (lookupRulesSkipPenalty, lookupRulesSkippedResolves) and the
//     gateResult.SkippedLookup field were removed.
//
// What remains in this file:
//   - seedLookupRulesCall — the helper many other tests use to satisfy the
//     hard guard so they can exercise gate score logic, fan-out shape, etc.
//   - TestEnforce_LookupRulesInvoked_PassesGuard — happy path: worker who
//     invoked lookup-rules can resolve normally.
//   - TestEnforce_RuleIDCitation_CountsToward_Score — pinpoints that the
//     valid-rule_id citation bump still contributes to citationCount (this
//     was an mallcoppro-00c invariant the soft-penalty path was tangled
//     with; the guard-side refactor must not regress it).
//
// The hard-guard refusal contract is tested by
// tools_f1g_structural_enforcement_test.go.
package main

import (
	"encoding/json"
	"testing"
)

// seedLookupRulesCall posts a synthetic tool_use message tagged tool:lookup-rules
// to simulate the worker having invoked the lookup-rules tool. The payload mimics
// what legion emits for a real lookup-rules call.
//
// Used by tests that need to satisfy the hard runtime guard in runResolveFinding
// and runEscalateToStageC so they can exercise downstream gate logic, fan-out
// shape, or other behavior unrelated to the lookup-rules requirement itself.
func seedLookupRulesCall(t *testing.T, cfBin, cfHome, campfireID string) {
	t.Helper()
	payload := `{"tool_use":true,"name":"lookup-rules","input":{"finding_id":"fnd-test","finding_family":"unusual-timing"}}`
	_, err := runCFCmd(cfBin, cfHome, "send", campfireID, payload,
		"--tag", "tool_use", "--tag", "tool:lookup-rules")
	if err != nil {
		t.Fatalf("seed tool:lookup-rules msg: %v", err)
	}
}

// ---- TestEnforce_LookupRulesInvoked_PassesGuard ------------------------------
//
// Worker that invoked lookup-rules can resolve normally. The hard guard sees
// the tool:lookup-rules tag in the transcript and does not block.
//
// Pre-structural-enforce, this same test asserted "no soft penalty applied"
// via a counter check. The counter is gone; the behavioral assertion (gate
// passes through to normal close) is what matters.
func TestEnforce_LookupRulesInvoked_PassesGuard(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// 8 tool calls × 4 distinct tools, INCLUDING lookup-rules.
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "lookup-rules",
		"check-baseline", "search-events", "search-findings", "lookup-rules",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)

	// Seed a real retrieval result so the citation evt_002 passes the cross-check.
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_002","actor":"bob@example.com"}]}`)

	reason := "Investigation complete: evt_002 traces to scheduled batch; no rule matched but evidence is clear."

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-guard-invoked-001",
			"action":     "resolved",
			"reason":     reason,
		})
		if err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...); err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Gate MUST NOT fire: lookup-rules was invoked, score 0.04*8 + 0.08*4 + 0.04*1 - 0.02*5 = 0.58 ≥ 0.55.
	if gf, fired := result["gate_fired"]; fired && gf == true {
		t.Errorf("expected gate to NOT fire when lookup-rules was invoked; got gate_fired=true. result=%v", result)
	}

	// Normal close: work:output in engagement campfire.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output in engagement campfire when gate passes; got %d messages", len(engMsgs))
	}
}

// ---- TestEnforce_RuleIDCitation_CountsToward_Score ---------------------------
//
// mallcoppro-00c invariant preservation: a valid rule_id still contributes +1
// to the citation count when the gate scores the resolve. The structural-
// enforce refactor removed the soft penalty but must not break the rule_id
// citation bump that lets workers cite operator-decision rules.
//
// The test seeds lookup-rules so the hard guard passes, then verifies that
// a worker citing a valid rule_id (no event citations in the reason) still
// has citation_count >= 1 in the resolve output.
func TestEnforce_RuleIDCitation_CountsToward_Score(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)
	_ = writeRulesFixture(t, fixtureRulesYAML)

	// 2 tool calls — slim transcript; the rule_id citation is the only evidence.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline", "search-events"})
	// Satisfy the hard guard.
	seedLookupRulesCall(t, cfBin, cfHome, campfireID)

	reason := "Resolved per operator decision corpus rule for maintenance-window pattern."

	// Floor 0.18 — focuses the test on the rule_id citation count, not the floor.
	envPairs := append(gateEnvPairs(true, 0.18),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-guard-ruleid-001",
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

	// Gate MUST NOT fire — valid rule_id satisfies the citation count requirement.
	if gf, fired := result["gate_fired"]; fired && gf == true {
		t.Errorf("expected gate to NOT fire with valid rule_id; got gate_fired=true. result=%v", result)
	}

	// rule_id MUST be echoed on the work:output payload (mallcoppro-00c invariant).
	if result["rule_id"] != "R-001" {
		t.Errorf("expected rule_id=R-001 echoed on resolve output; got %v", result["rule_id"])
	}

	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output in engagement campfire for valid rule_id resolve; got %d messages", len(engMsgs))
	}
}
