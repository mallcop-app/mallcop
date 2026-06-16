// tools_f1g_structural_enforcement_test.go — hard runtime guard contract for
// the lookup-rules requirement (mallcoppro-structural-lookup-enforce).
//
// Three bakeoffs (baseline 87.3%, two prompt-strength attempts) confirmed the
// model never calls lookup-rules regardless of how strongly the prompt insists:
// 0 invocations across 171 scenarios. Prompt enforcement is dead.
//
// The fix is mechanical: runResolveFinding and runEscalateToStageC refuse to
// dispatch unless a prior tool_use tagged tool:lookup-rules appears in the
// worker's engagement campfire transcript. The model gets an actionable error
// back, retries with lookup-rules, then retries the terminal-decision tool.
//
// runEscalateToInvestigator is INTENTIONALLY not gated — it is a chain
// handoff, not a terminal decision. The downstream investigator will then be
// gated when it tries to run resolve-finding or escalate-to-stage-c itself.
//
// This file pins five contract invariants:
//
//   1. TestResolveFinding_NoLookupRules_Refuses — no tool:lookup-rules in
//      transcript → runResolveFinding returns the guard error, no message
//      posted to the engagement campfire.
//   2. TestResolveFinding_WithLookupRules_Proceeds — tool:lookup-rules
//      present → runResolveFinding proceeds normally (work:output posted).
//   3. TestEscalateToStageC_NoLookupRules_Refuses — same shape, stage-c side.
//   4. TestEscalateToStageC_WithLookupRules_Proceeds — happy path for stage-c.
//   5. TestEscalateToInvestigator_NoLookupRules_Proceeds — pinpoints that the
//      investigator handoff is NOT gated (downstream investigator inherits
//      the requirement).
//
// All tests use real campfires (no mocks). Each test is self-contained: the
// guard contract is independent of the F2A confidence gate, the per-skill
// registry, and the rule_id citation path.
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---- TestResolveFinding_NoLookupRules_Refuses --------------------------------
//
// Engagement campfire has no tool:lookup-rules tool_use. runResolveFinding
// MUST return an error referencing lookup-rules and MUST NOT post any
// work:output to the campfire. The error message must be actionable: tell
// the model what to call and that calling lookup-rules is required even
// when the worker expects no rule match.
func TestResolveFinding_NoLookupRules_Refuses(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Seed a normal-looking investigation transcript — everything EXCEPT
	// lookup-rules. The guard must still refuse.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{
		"check-baseline", "search-events", "search-findings",
	})
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_001"}]}`)

	envPairs := []string{
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	}

	input, _ := json.Marshal(map[string]interface{}{
		"finding_id": "fnd-guard-refuse-001",
		"action":     "resolved",
		"reason":     "evt_001 confirms benign pattern.",
	})

	var gotErr error
	captureStdout(t, func() {
		gotErr = runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
	})

	if gotErr == nil {
		t.Fatalf("expected guard error from runResolveFinding when no tool:lookup-rules is seeded; got nil")
	}
	msg := gotErr.Error()
	if !strings.Contains(msg, "lookup-rules") {
		t.Errorf("guard error must mention lookup-rules; got %q", msg)
	}
	if !strings.Contains(msg, "resolve-finding") {
		t.Errorf("guard error must reference the calling tool name (resolve-finding); got %q", msg)
	}
	if !strings.Contains(msg, "no rule match") {
		t.Errorf("guard error must be actionable about the no-rule-match case; got %q", msg)
	}

	// No work:output may have been posted to the engagement campfire — the
	// guard fires before any side effect.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected NO work:output in engagement campfire when guard refuses; got %d messages", len(engMsgs))
	}
	// No work:create may have been posted either (the guard is pre-gate, so
	// no fan-out either).
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected NO work:create in work campfire when guard refuses; got %d messages", len(workMsgs))
	}
}

// ---- TestResolveFinding_WithLookupRules_Proceeds -----------------------------
//
// Engagement campfire contains tool:lookup-rules → runResolveFinding proceeds
// past the guard. The downstream F2A gate may still fire on score/citation
// independently; this test pins only that the GUARD does not block when its
// precondition is satisfied. We arrange the transcript so the gate also
// passes (sufficient evidence + a real retrieved citation).
func TestResolveFinding_WithLookupRules_Proceeds(t *testing.T) {
	cfBin, cfHome, campfireID, _ := newTestCampfirePair(t)

	// 8 tool calls including lookup-rules so both the guard and the gate
	// pass. Score: 0.04*8 + 0.08*4 + 0.04*1 - 0.02*5 = 0.32+0.32+0.04-0.10 = 0.58.
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "lookup-rules",
		"check-baseline", "search-events", "search-findings", "lookup-rules",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_777","actor":"alice@example.com"}]}`)

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"CF_HOME", cfHome,
	)

	input, _ := json.Marshal(map[string]interface{}{
		"finding_id": "fnd-guard-proceed-001",
		"action":     "resolved",
		"reason":     "Investigation complete: evt_777 confirms benign maintenance window activity.",
	})

	out := captureStdout(t, func() {
		if err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...); err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Gate must NOT fire (score 0.58 ≥ 0.55), AND the guard must not have
	// refused — combined result is a normal close.
	if gf, fired := result["gate_fired"]; fired && gf == true {
		t.Errorf("expected gate to NOT fire when lookup-rules invoked and score sufficient; got %v", result)
	}
	if result["finding_id"] != "fnd-guard-proceed-001" {
		t.Errorf("finding_id = %v, want fnd-guard-proceed-001 (normal close path)", result["finding_id"])
	}

	// work:output must be in the engagement campfire (normal close).
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output in engagement campfire when guard passes and gate clears; got %d messages", len(engMsgs))
	}
}

// ---- TestEscalateToStageC_NoLookupRules_Refuses ------------------------------
//
// Stage-c is a TERMINAL decision (worker commits to a remediation class).
// Without tool:lookup-rules in the engagement transcript, runEscalateToStageC
// must refuse. The error message must reference escalate-to-stage-c
// specifically so the model knows which retry path to take.
func TestEscalateToStageC_NoLookupRules_Refuses(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Seed enough tool activity that this looks like a real escalation, but
	// without lookup-rules — the guard must still block.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{
		"check-baseline", "search-events", "search-findings",
	})

	envPairs := []string{
		"MALLCOP_CAMPFIRE_ID", campfireID, // engagement campfire — the guard reads this
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"MALLCOP_ITEM_ID", "item-stage-c-refuse-test",
		"CF_HOME", cfHome,
	}

	input, _ := json.Marshal(map[string]interface{}{
		"finding_id":   "fnd-guard-stage-c-refuse-001",
		"reason":       "Confirmed lateral movement — needs approval.",
		"action_class": "needs-approval",
		"flags":        []string{"high-risk"},
	})

	var gotErr error
	captureStdout(t, func() {
		gotErr = runToolWithEnv(t, "escalate-to-stage-c", string(input), envPairs...)
	})

	if gotErr == nil {
		t.Fatalf("expected guard error from runEscalateToStageC when no tool:lookup-rules is seeded; got nil")
	}
	msg := gotErr.Error()
	if !strings.Contains(msg, "lookup-rules") {
		t.Errorf("guard error must mention lookup-rules; got %q", msg)
	}
	if !strings.Contains(msg, "escalate-to-stage-c") {
		t.Errorf("guard error must reference the calling tool name (escalate-to-stage-c); got %q", msg)
	}

	// No work:create may have been posted to the work campfire.
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected NO work:create when stage-c guard refuses; got %d messages", len(workMsgs))
	}
}

// ---- TestEscalateToStageC_WithLookupRules_Proceeds ---------------------------
//
// With tool:lookup-rules present, runEscalateToStageC proceeds and posts the
// normal work:create + terminal work:output to the work campfire. This pins
// that the guard does not over-fire on stage-c when its precondition is met.
func TestEscalateToStageC_WithLookupRules_Proceeds(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{
		"check-baseline", "search-events",
	})
	seedLookupRulesCall(t, cfBin, cfHome, campfireID)

	envPairs := []string{
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"MALLCOP_ITEM_ID", "item-stage-c-proceed-test",
		"CF_HOME", cfHome,
	}

	input, _ := json.Marshal(map[string]interface{}{
		"finding_id":   "fnd-guard-stage-c-proceed-001",
		"reason":       "Confirmed malicious — needs approval.",
		"action_class": "needs-approval",
	})

	out := captureStdout(t, func() {
		if err := runToolWithEnv(t, "escalate-to-stage-c", string(input), envPairs...); err != nil {
			t.Errorf("escalate-to-stage-c: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result["action_class"] != "needs-approval" {
		t.Errorf("action_class = %v, want needs-approval", result["action_class"])
	}
	if result["skill"] != "task:escalate" {
		t.Errorf("skill = %v, want task:escalate", result["skill"])
	}
	if id, _ := result["item_id"].(string); id == "" {
		t.Errorf("item_id must be non-empty when stage-c proceeds; got %v", result["item_id"])
	}

	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected work:create in work campfire when stage-c proceeds; got %d messages", len(workMsgs))
	}
}

// ---- TestEscalateToInvestigator_NoLookupRules_Proceeds -----------------------
//
// escalate-to-investigator is a chain HANDOFF, not a terminal decision. It
// MUST NOT be gated by the lookup-rules guard — the downstream investigator
// will inherit the requirement when it tries to run resolve-finding or
// escalate-to-stage-c itself.
//
// This test exercises the unhappy precondition case (no tool:lookup-rules in
// the transcript) and asserts the handoff still succeeds: an item_id is
// returned and a work:create is posted to the work campfire.
//
// If this test fails, an over-broad guard has been applied to a non-terminal
// tool, and the chain progression is broken (workers escalate to investigator
// expecting that investigator to do the lookup-rules call, but the handoff
// itself was blocked).
func TestEscalateToInvestigator_NoLookupRules_Proceeds(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Engagement transcript has NO tool:lookup-rules — the test condition.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline"})

	envPairs := []string{
		"MALLCOP_CAMPFIRE_ID", campfireID, // engagement campfire is set but lacks lookup-rules
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"MALLCOP_ITEM_ID", "item-handoff-test",
		"CF_HOME", cfHome,
	}

	input, _ := json.Marshal(map[string]interface{}{
		"finding_id": "fnd-guard-handoff-001",
		"reason":     "Unusual login pattern from new IP — handing off to investigator for deeper look.",
	})

	out := captureStdout(t, func() {
		if err := runToolWithEnv(t, "escalate-to-investigator", string(input), envPairs...); err != nil {
			t.Errorf("escalate-to-investigator: unexpected error (handoff must NOT be gated): %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// The handoff item_id must be returned — the chain progression depends on it.
	if id, _ := result["item_id"].(string); id == "" {
		t.Errorf("item_id must be non-empty when escalate-to-investigator proceeds; got %v", result["item_id"])
	}
	if result["skill"] != "task:investigate" {
		t.Errorf("skill = %v, want task:investigate", result["skill"])
	}

	// work:create must be in the work campfire — the investigator dispatch.
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected work:create in work campfire from handoff (must NOT be gated by lookup-rules); got %d messages", len(workMsgs))
	}
}
