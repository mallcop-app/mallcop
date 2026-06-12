// tools_f1g_gate_test.go — integration tests for F2A confidence-score gate.
//
// Tests create real isolated campfires (via newTestCampfire) and seed them with
// synthetic tool_use messages to simulate investigate worker sessions.
// No mocks — the gate reads real cf campfire data.
//
// Test plan:
//
//  1. TestConfidenceGate_Disabled_PassesThrough — enabled=false → normal work:output.
//  2. TestConfidenceGate_OtherSkill_PassesThrough — MALLCOP_SKILL not in {investigate, triage} → normal close.
//  3. TestConfidenceGate_HighScore_PassesThrough — 8 tool calls, 4 distinct, citation → score ≥ 0.55.
//  4. TestConfidenceGate_LowScore_FiresFanOut — 1 tool call, no citations, 5 iterations → gate fires.
//  5. TestConfidenceGate_VerifyFanOutShape — all 3 hypotheses present, merge has 3 deep ids.
//  6. TestConfidenceGate_IterationPenalty — high tool count + many iterations → gate fires.
//  7. TestConfidenceGate_EscalatedAction_PassesThrough — action=escalated + low evidence → no fan-out (rung-3 semantic).
//  8. TestConfidenceGate_RemediatedAction_PassesThrough — action=remediated + low evidence → no fan-out (rung-3 semantic).
//  9. TestConfidenceGate_TriageSkill_Fires — MALLCOP_SKILL=task:triage + 1 tool + 0 citations → fires, triage fan-out.
// 10. TestConfidenceGate_TriageSkill_NormalResolveDoesNotFire — 2 tools + 1 citation → score above triage floor, no fire.
// 11. TestConfidenceGate_TriageScoreFloor_EnvOverride — env var overrides TriageScoreFloor.
// 12. TestForceEscalateToInvestigator — gate-fired triage emits exactly one task:investigate work:create.
// 13. TestPhase1Defaults_ZeroCitationStillFires_Triage — zero-citation hard floor applies to triage skill too.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// newTestCampfirePair creates two campfires in the SAME cf home:
// one for engagement (engagement) and one for work (work:create emissions).
// CF_HOME is set to the shared cfHome for the test duration.
// Returns (cfBin, cfHome, engagementCampfireID, workCampfireID).
func newTestCampfirePair(t *testing.T) (cfBin, cfHome, engCampfireID, workCampfireID string) {
	t.Helper()
	cfBin = requireCFF(t)
	cfHome = t.TempDir()
	t.Setenv("CF_HOME", cfHome)

	// Init the cf home once.
	initOut, err := runCFCmd(cfBin, cfHome, "init")
	if err != nil {
		t.Fatalf("cf init: %v\nout: %s", err, initOut)
	}

	// Create engagement campfire.
	createOut, err := runCFCmd(cfBin, cfHome, "create", "--description", "test-gate-eng-"+t.Name())
	if err != nil {
		t.Fatalf("cf create (eng): %v\nout: %s", err, createOut)
	}
	for _, line := range strings.Split(strings.TrimSpace(createOut), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isHexStr(line) {
			engCampfireID = line
			break
		}
	}
	if engCampfireID == "" {
		t.Fatalf("could not parse eng campfire ID from: %s", createOut)
	}

	// Create work campfire (same cf home).
	createOut2, err := runCFCmd(cfBin, cfHome, "create", "--description", "test-gate-work-"+t.Name())
	if err != nil {
		t.Fatalf("cf create (work): %v\nout: %s", err, createOut2)
	}
	for _, line := range strings.Split(strings.TrimSpace(createOut2), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isHexStr(line) {
			workCampfireID = line
			break
		}
	}
	if workCampfireID == "" {
		t.Fatalf("could not parse work campfire ID from: %s", createOut2)
	}

	return cfBin, cfHome, engCampfireID, workCampfireID
}

// seedToolUseMsgs posts N tool_use messages to campfireID with the given tool names.
// Each message has a "tool_use" tag and a payload containing the tool name.
// Returns an error if any post fails.
func seedToolUseMsgs(t *testing.T, cfBin, cfHome, campfireID string, toolNames []string) {
	t.Helper()
	for i, name := range toolNames {
		payload := fmt.Sprintf(`{"tool_use":true,"name":%q,"turn":%d}`, name, i+1)
		_, err := runCFCmd(cfBin, cfHome, "send", campfireID, payload, "--tag", "tool_use", "--tag", "tool:"+name)
		if err != nil {
			t.Fatalf("seed tool_use msg %d (%s): %v", i+1, name, err)
		}
	}
}

// seedToolResultMsg posts a tool result message to campfireID containing the
// given payload (arbitrary JSON). The message is tagged "tool:result" so that
// extractRetrievedIDs picks up any IDs embedded in the payload.
func seedToolResultMsg(t *testing.T, cfBin, cfHome, campfireID, resultPayload string) {
	t.Helper()
	_, err := runCFCmd(cfBin, cfHome, "send", campfireID, resultPayload, "--tag", "tool:result")
	if err != nil {
		t.Fatalf("seed tool result msg: %v", err)
	}
}

// gateEnvPairs returns the env key=value pairs for the confidence gate config.
//
// Uses the default TriageScoreFloor (0.18) — triage-specific tests that need a
// custom floor should use gateEnvPairsTriage.
func gateEnvPairs(enabled bool, scoreFloor float64) []string {
	return gateEnvPairsTriage(enabled, scoreFloor, 0.18)
}

// gateEnvPairsTriage is gateEnvPairs with an explicit TriageScoreFloor.
// Used by mallcoppro-499 triage tests that need to exercise the triage-specific
// floor independently of the investigate floor.
func gateEnvPairsTriage(enabled bool, scoreFloor, triageScoreFloor float64) []string {
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	return []string{
		"MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED", enabledStr,
		"MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR", fmt.Sprintf("%.4f", scoreFloor),
		"MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR", fmt.Sprintf("%.4f", triageScoreFloor),
		"MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_WEIGHT", "0.04",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_CAP", "8",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_WEIGHT", "0.08",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_CAP", "4",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_WEIGHT", "0.04",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_CAP", "5",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_PENALTY", "-0.02",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_THRESHOLD", "3",
	}
}

// ---- TestConfidenceGate_Disabled_PassesThrough --------------------------------

func TestConfidenceGate_Disabled_PassesThrough(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Seed a low-score transcript (1 tool call, no citations, 5 iters).
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"search-events"})

	// Call resolve-finding with MALLCOP_SKILL=task:investigate but enabled=false.
	envPairs := append(gateEnvPairs(false, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-gate-dis-001","action":"resolved","reason":"Normal activity."}`,
			envPairs...,
		)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Must NOT have gate_fired: enabled=false → pass through to normal close.
	if _, fired := result["gate_fired"]; fired {
		t.Errorf("expected normal close output, but got gate_fired field: %v", result)
	}
	if result["finding_id"] != "fnd-gate-dis-001" {
		t.Errorf("finding_id = %v, want fnd-gate-dis-001", result["finding_id"])
	}
	if result["action"] != "resolved" {
		t.Errorf("action = %v, want resolved", result["action"])
	}

	// Verify work:output is present in campfire (normal close).
	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(msgs, "work:output") {
		t.Errorf("expected work:output in campfire for disabled gate; got %d messages", len(msgs))
	}
}

// ---- TestConfidenceGate_OtherSkill_PassesThrough ------------------------------
//
// mallcoppro-499 update: task:triage is now a gated skill. This test uses
// task:escalate (a non-gated skill) to preserve "non-gated skill" coverage.
// Gated-skill behavior (investigate, triage) is covered by their own tests.
func TestConfidenceGate_OtherSkill_PassesThrough(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Seed a low-score transcript.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"search-events"})

	// Gate is enabled but skill is NOT in {task:investigate, task:triage}.
	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:escalate", // non-gated skill → pass through
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-gate-skill-001","action":"resolved","reason":"Escalate-stage resolved."}`,
			envPairs...,
		)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Must NOT have gate_fired: skill is not in the gated set.
	if _, fired := result["gate_fired"]; fired {
		t.Errorf("expected normal close output for non-gated skill, but got gate_fired: %v", result)
	}
	if result["finding_id"] != "fnd-gate-skill-001" {
		t.Errorf("finding_id = %v, want fnd-gate-skill-001", result["finding_id"])
	}

	// work:output must be present in campfire.
	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(msgs, "work:output") {
		t.Errorf("expected work:output in campfire for non-gated skill; got %d messages", len(msgs))
	}
}

// ---- TestConfidenceGate_HighScore_PassesThrough --------------------------------

func TestConfidenceGate_HighScore_PassesThrough(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// High score: 8 tool calls (cap=8), 4 distinct tools, 1 valid citation.
	// evt_001 must be seeded in a tool result payload so the cross-check passes.
	// Score: 0.04*8 + 0.08*4 + 0.04*1 - 0.02*max(8-3,0)
	//      = 0.32  + 0.32  + 0.04  - 0.10 = 0.58 ≥ 0.55 ✓
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "read-config",
		"check-baseline", "search-events", "search-findings", "read-config",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)

	// Seed a tool result payload containing evt_001 so the cross-check passes.
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_001","actor":"alice@example.com"}]}`)

	// Reason cites evt_001 — which IS in the tool result payload (valid citation).
	reason := "Investigation complete: found event evt_001 confirms normal activity. No anomaly."

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-hi-001",
			"action":     "resolved",
			"reason":     reason,
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// High score → gate should NOT fire.
	if gf, ok := result["gate_fired"]; ok && gf == true {
		t.Errorf("expected gate to NOT fire for high-score session; got gate_fired=true. result=%v", result)
	}
	if result["finding_id"] != "fnd-gate-hi-001" {
		t.Errorf("finding_id = %v, want fnd-gate-hi-001", result["finding_id"])
	}

	// work:output must be in campfire.
	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(msgs, "work:output") {
		t.Errorf("expected work:output in campfire for high-score session; got %d messages", len(msgs))
	}
}

// ---- TestConfidenceGate_LowScore_FiresFanOut -----------------------------------

func TestConfidenceGate_LowScore_FiresFanOut(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Low score: 1 tool call, no citations, 5 iterations.
	// Score: 0.04*1 + 0.08*1 + 0.04*0 + (-0.02 * max(5-3,0))
	//      = 0.04 + 0.08 + 0 - 0.04 = 0.08 < 0.55
	// BUT with only 1 tool, distinct_tool_count = 1, so:
	// 0.04*1 + 0.08*1 + 0.04*0 = 0.04 + 0.08 = 0.12, minus 0.04 penalty = 0.08 < 0.55 ✓
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"search-events"})
	// Seed 4 extra non-tool messages to simulate iterations without tool calls.
	// These are just plain messages (no tool_use tag) so they count as iterations.
	for i := 0; i < 4; i++ {
		_, _ = runCFCmd(cfBin, cfHome, "send", campfireID,
			fmt.Sprintf(`{"assistant_turn":true,"turn":%d}`, i+2), "--tag", "assistant:turn")
	}

	// No citations in the reason.
	reason := "Activity looks suspicious but I did not find conclusive evidence."

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-lo-001",
			"action":     "resolved",
			"reason":     reason,
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Gate must fire.
	gf, ok := result["gate_fired"]
	if !ok || gf != true {
		t.Errorf("expected gate_fired=true for low-score session; got result=%v", result)
	}
	if result["finding_id"] != "fnd-gate-lo-001" {
		t.Errorf("finding_id = %v, want fnd-gate-lo-001", result["finding_id"])
	}

	// Score should be below floor.
	score, _ := result["score"].(float64)
	if score >= 0.55 {
		t.Errorf("score = %.4f, want < 0.55 (gate should have fired)", score)
	}

	// work:create messages must be present in work campfire (not work:output in engagement campfire).
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected work:create in work campfire after gate fires; got %d messages", len(workMsgs))
	}

	// work:output must NOT be in engagement campfire (gate intercepts the close).
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected NO work:output in engagement campfire when gate fires (fan-out replaces close)")
	}
}

// ---- TestConfidenceGate_VerifyFanOutShape -------------------------------------

func TestConfidenceGate_VerifyFanOutShape(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Low score: 1 tool call, no citations.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline"})

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-shape-001",
			"action":     "resolved",
			"reason":     "Insufficient evidence to conclude.",
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result["gate_fired"] != true {
		t.Fatalf("expected gate_fired=true; got result=%v", result)
	}

	// deep_item_ids must have exactly 3 entries.
	deepIDsRaw, ok := result["deep_item_ids"]
	if !ok {
		t.Fatal("expected deep_item_ids in gate output")
	}
	deepIDs, ok := deepIDsRaw.([]interface{})
	if !ok {
		t.Fatalf("deep_item_ids must be an array; got %T", deepIDsRaw)
	}
	if len(deepIDs) != 3 {
		t.Errorf("deep_item_ids length = %d, want 3", len(deepIDs))
	}

	// All 3 deep IDs must be non-empty.
	for i, idRaw := range deepIDs {
		id, _ := idRaw.(string)
		if id == "" {
			t.Errorf("deep_item_ids[%d] is empty", i)
		}
	}

	// merge_item_id must be set.
	mergeID, _ := result["merge_item_id"].(string)
	if mergeID == "" {
		t.Errorf("merge_item_id must be non-empty in gate output")
	}

	// Verify work:create messages: must have skill tags for the 3 deep workers
	// and the merge worker.
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)

	// Count work:create messages.
	workCreateCount := 0
	for _, msg := range workMsgs {
		if hasTagInMessages([]map[string]interface{}{msg}, "work:create") {
			workCreateCount++
		}
	}
	// Expect 4 work:create messages: 3 deep-investigate + 1 investigate-merge.
	if workCreateCount < 4 {
		t.Errorf("expected at least 4 work:create messages (3 deep + 1 merge); got %d", workCreateCount)
	}

	// Verify the 3 hypotheses appear in work:create skill tags.
	deepInvestigateCount := 0
	mergeSeen := false
	for _, msg := range workMsgs {
		if !hasTagInMessages([]map[string]interface{}{msg}, "work:create") {
			continue
		}
		for _, tagRaw := range msg["tags"].([]interface{}) {
			tag, _ := tagRaw.(string)
			if tag == "skill:task:deep-investigate" {
				deepInvestigateCount++
			}
			if tag == "skill:task:investigate-merge" {
				mergeSeen = true
			}
		}
	}
	if deepInvestigateCount != 3 {
		t.Errorf("expected 3 work:create messages with skill:task:deep-investigate; got %d", deepInvestigateCount)
	}
	if !mergeSeen {
		t.Errorf("expected 1 work:create message with skill:task:investigate-merge")
	}

	// Verify hypotheses in the work:create payloads.
	hypothesesFound := make(map[string]bool)
	for _, msg := range workMsgs {
		payloadRaw, _ := msg["payload"].(string)
		if payloadRaw == "" {
			continue
		}
		for _, hyp := range []string{"benign", "malicious", "incomplete"} {
			if strings.Contains(payloadRaw, hyp) {
				hypothesesFound[hyp] = true
			}
		}
	}
	for _, hyp := range []string{"benign", "malicious", "incomplete"} {
		if !hypothesesFound[hyp] {
			t.Errorf("hypothesis %q not found in any work:create payload", hyp)
		}
	}
}

// ---- TestConfidenceGate_IterationPenalty --------------------------------------

func TestConfidenceGate_IterationPenalty(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Moderate tool count (6 calls, 3 distinct tools) + many iterations (13).
	// Score without penalty:
	//   0.04*6 + 0.08*3 + 0.04*0 = 0.24 + 0.24 = 0.48
	// Penalty: -0.02 * max(13-3, 0) = -0.02 * 10 = -0.20
	// Final score: 0.48 - 0.20 = 0.28 < 0.55 → gate fires.
	toolNamesFor6Calls := []string{
		"check-baseline", "search-events", "read-config",
		"check-baseline", "search-events", "read-config",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNamesFor6Calls)

	// Seed 7 more non-tool-use messages to bring total messages to 13
	// (6 tool_use + 7 plain assistant turns = 13 iterations).
	for i := 0; i < 7; i++ {
		_, _ = runCFCmd(cfBin, cfHome, "send", campfireID,
			fmt.Sprintf(`{"assistant_thinking":true,"turn":%d}`, i+10), "--tag", "assistant:turn")
	}

	reason := "I spent many iterations but could not conclude."

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		// Use action=resolved so the gate evaluates the iteration penalty path.
		// Per the rung-3 semantic restored in mallcoppro-09d, the gate only fires
		// on "resolved" — escalations are an early-return no-op.
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-iter-001",
			"action":     "resolved",
			"reason":     reason,
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Gate must fire due to iteration penalty pushing score below floor.
	if result["gate_fired"] != true {
		score, _ := result["score"].(float64)
		t.Errorf("expected gate_fired=true (iteration penalty should push score below 0.55); got gate_fired=%v, score=%.4f", result["gate_fired"], score)
	}

	score, _ := result["score"].(float64)
	if score >= 0.55 {
		t.Errorf("score = %.4f, want < 0.55 (iteration penalty test)", score)
	}

	// Fan-out messages must be present in work campfire.
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected work:create in work campfire after iteration penalty gate fires; got %d messages", len(workMsgs))
	}
}

// ---- TestConfidenceGate_EscalatedAction_PassesThrough --------------------------
//
// Rung-3 semantic (mallcoppro-09d): the confidence gate exists to second-guess
// "resolved" decisions only. An "escalated" action is already a system PASS and
// must not trigger fan-out, even with low structural evidence. The gate must
// early-return before reading the engagement transcript or counting citations.
//
// Without this gate, ~78% of investigate workers (the ones that escalate) would
// pay the consensus surcharge unnecessarily, causing the cost ladder to collapse.
// This test pins the early-return: the same low-evidence transcript that fires
// the gate when action=resolved (TestConfidenceGate_LowScore_FiresFanOut) MUST
// pass through when action=escalated.
func TestConfidenceGate_EscalatedAction_PassesThrough(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Same low-evidence transcript as LowScore_FiresFanOut: 1 tool call, no citations.
	// If the gate were not action-gated, this would fire fan-out.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"search-events"})
	for i := 0; i < 4; i++ {
		_, _ = runCFCmd(cfBin, cfHome, "send", campfireID,
			fmt.Sprintf(`{"assistant_turn":true,"turn":%d}`, i+2), "--tag", "assistant:turn")
	}

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-esc-001",
			"action":     "escalated",
			"reason":     "Insufficient evidence; escalating to a human reviewer.",
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Gate MUST NOT fire on escalated action, regardless of evidence quality.
	if gf, ok := result["gate_fired"]; ok && gf == true {
		t.Errorf("expected gate to NOT fire for action=escalated (rung-3 early-return); got gate_fired=true. result=%v", result)
	}
	if result["finding_id"] != "fnd-gate-esc-001" {
		t.Errorf("finding_id = %v, want fnd-gate-esc-001", result["finding_id"])
	}
	if result["action"] != "escalated" {
		t.Errorf("action = %v, want escalated", result["action"])
	}

	// Normal close (work:output) must be in engagement campfire.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output in engagement campfire for action=escalated; got %d messages", len(engMsgs))
	}

	// Critical: NO work:create messages in work campfire — fan-out must be skipped.
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected NO work:create in work campfire for action=escalated; deep-investigate fan-out must be skipped. got %d messages", len(workMsgs))
	}

	// Specifically, no skill:task:deep-investigate messages.
	deepCount := 0
	for _, msg := range workMsgs {
		for _, tagRaw := range msg["tags"].([]interface{}) {
			if tag, _ := tagRaw.(string); tag == "skill:task:deep-investigate" {
				deepCount++
			}
		}
	}
	if deepCount != 0 {
		t.Errorf("expected 0 deep-investigate workers for action=escalated; got %d (rung-3 escalate-PASS contract violated)", deepCount)
	}
}

// ---- TestConfidenceGate_RemediatedAction_PassesThrough -------------------------
//
// Sibling of EscalatedAction: any non-"resolved" action skips the gate. Pinning
// "remediated" (the third valid action per resolveInput.Action) ensures we don't
// regress to special-casing only "escalated".
func TestConfidenceGate_RemediatedAction_PassesThrough(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Low-evidence transcript — same shape as the fan-out tests.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline"})

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-rem-001",
			"action":     "remediated",
			"reason":     "Issue auto-remediated via runbook step 3.",
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	// Gate MUST NOT fire on remediated action.
	if gf, ok := result["gate_fired"]; ok && gf == true {
		t.Errorf("expected gate to NOT fire for action=remediated; got gate_fired=true. result=%v", result)
	}

	// No fan-out work:create messages.
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected NO work:create for action=remediated; got %d messages", len(workMsgs))
	}
}

// ---- mallcoppro-276: Phase 1 asymmetric gate defaults ------------------------

// TestPhase1Defaults_EnabledAndFloor locks in the binary defaults for the
// Phase 1 asymmetric gate (mallcoppro-276). Without env-var overrides — which
// legion's apiToolEnv does NOT pass through to tool subprocesses — these are
// what runs in production bakeoffs.
//
// If this test fails, the chain redesign Phase 1 OUTCOME is broken: fan-out
// will not fire on B1 scenarios because the gate defaults to disabled.
func TestPhase1Defaults_EnabledAndFloor(t *testing.T) {
	cfg := defaultGateConfig()

	if !cfg.Enabled {
		t.Errorf("default Enabled = false, want true (mallcoppro-276 Phase 1 asymmetric gate). "+
			"Without env-var passthrough in legion, this default is what runs in the bakeoff.")
	}
	if cfg.ScoreFloor != 0.40 {
		t.Errorf("default ScoreFloor = %.4f, want 0.40 (mallcoppro-276 Phase 1)", cfg.ScoreFloor)
	}
	// mallcoppro-499 Phase 2: TriageScoreFloor default for triage's 2-tool flow.
	if cfg.TriageScoreFloor != 0.18 {
		t.Errorf("default TriageScoreFloor = %.4f, want 0.18 (mallcoppro-499 RPT-structural)", cfg.TriageScoreFloor)
	}
}

// TestPhase1Defaults_LoadGateConfig_NoEnv verifies loadGateConfig returns the
// new defaults when no env vars are set. This is the worker-spawned case
// because legion's apiToolEnv strips MALLCOP_CONFIDENCE_GATED_CLOSE_* env vars.
func TestPhase1Defaults_LoadGateConfig_NoEnv(t *testing.T) {
	// Clear all MALLCOP_CONFIDENCE_GATED_CLOSE_* env vars in the test process.
	for _, k := range []string{
		"MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_WEIGHT",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_CAP",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_WEIGHT",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_CAP",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_WEIGHT",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_CAP",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_PENALTY",
		"MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_THRESHOLD",
	} {
		t.Setenv(k, "")
	}

	cfg := loadGateConfig()

	if !cfg.Enabled {
		t.Errorf("loadGateConfig() Enabled = false, want true (mallcoppro-276 Phase 1)")
	}
	if cfg.ScoreFloor != 0.40 {
		t.Errorf("loadGateConfig() ScoreFloor = %.4f, want 0.40 (mallcoppro-276 Phase 1)", cfg.ScoreFloor)
	}
	if cfg.TriageScoreFloor != 0.18 {
		t.Errorf("loadGateConfig() TriageScoreFloor = %.4f, want 0.18 (mallcoppro-499)", cfg.TriageScoreFloor)
	}
}

// TestPhase1Defaults_ZeroCitationStillFires verifies the zero-citation hard
// floor at gate.go:444 still fires regardless of the new defaults. The score
// floor change does NOT relax the zero-citation requirement: even if score
// would clear the floor on tool volume + breadth alone, zero citations
// unconditionally fire the gate.
//
// mallcoppro-499: this invariant applies to BOTH task:investigate and
// task:triage. The "no evidence = no resolve" rule is universal — neither
// skill gets to short-circuit citations.
//
// This is the integration test the spec's done condition (4) calls for.
func TestPhase1Defaults_ZeroCitationStillFires(t *testing.T) {
	for _, skill := range []string{"task:investigate", "task:triage"} {
		skill := skill
		t.Run(skill, func(t *testing.T) {
			cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

			// Seed 8 tool calls across 4 distinct tools — would clear BOTH the 0.40
			// investigate floor (8*0.04 + 4*0.08 = 0.64) and the 0.18 triage floor on
			// score alone. Zero citations must still fire the gate unconditionally.
			toolNames := []string{
				"check-baseline", "search-events", "search-findings", "read-config",
				"check-baseline", "search-events", "search-findings", "read-config",
			}
			seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)

			// Reason has NO citations (no evt_*, fnd-*, etc. that match retrieved IDs).
			reason := "Investigation complete. No anomaly. Standard activity pattern."

			// Use the NEW defaults — pass empty env for gate vars so loadGateConfig
			// returns the binary defaults (Enabled=true, ScoreFloor=0.40, TriageScoreFloor=0.18).
			envPairs := []string{
				"MALLCOP_SKILL", skill,
				"MALLCOP_CAMPFIRE_ID", campfireID,
				"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
				"CF_HOME", cfHome,
			}

			out := captureStdout(t, func() {
				input, _ := json.Marshal(map[string]interface{}{
					"finding_id": "fnd-phase1-zero-cite",
					"action":     "resolved",
					"reason":     reason,
				})
				err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
				if err != nil {
					t.Errorf("resolve-finding: unexpected error: %v", err)
				}
			})

			var result map[string]interface{}
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatalf("parse output JSON: %v\nout=%q", err, out)
			}

			// Gate MUST fire — zero citation hard floor at gate.go:444.
			if result["gate_fired"] != true {
				t.Errorf("expected gate_fired=true on zero-citation resolve for skill=%s (gate.go:444 hard floor); got %v",
					skill, result)
			}
			if cc, ok := result["citation_count"]; ok {
				if n, _ := cc.(float64); n != 0 {
					t.Errorf("expected citation_count=0, got %v", cc)
				}
			}

			// Fan-out work:create must be posted.
			workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
			if !hasTagInMessages(workMsgs, "work:create") {
				t.Errorf("expected work:create in work campfire for skill=%s (fan-out fired); got %d messages",
					skill, len(workMsgs))
			}
		})
	}
}

// ---- mallcoppro-499: Phase 2 triage-tier gate tests --------------------------
//
// These tests pin the new MALLCOP_SKILL=task:triage gate behavior:
//   - The gate fires on triage workers with low evidence.
//   - The gate does NOT fire on legitimate triage resolves (2-tool flow + citation).
//   - The TriageScoreFloor is independently configurable via env var.
//   - The triage fan-out emits exactly one task:investigate handoff (force escalate).
//
// These complement the investigate-skill tests above and prove that the gate
// fires on the CLAIM-OF-RESOLUTION regardless of which worker tier emits it
// (the RPT-structural insight that produced mallcoppro-499).

// TestConfidenceGate_TriageSkill_Fires verifies the gate fires on a low-evidence
// triage resolve. Mirrors TestConfidenceGate_LowScore_FiresFanOut but with
// MALLCOP_SKILL=task:triage. The fan-out must be the triage-specific
// force-escalate-to-investigator (NOT deep×3 + merge).
func TestConfidenceGate_TriageSkill_Fires(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Low evidence: 1 tool call, no citations. Score = 0.04 + 0.08 + 0 = 0.12,
	// well below the triage floor of 0.18. AND zero citations triggers the
	// universal hard floor regardless of score — either path fires the gate.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"search-events"})

	envPairs := append(gateEnvPairsTriage(true, 0.40, 0.18),
		"MALLCOP_SKILL", "task:triage",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-triage-fire-001",
			"action":     "resolved",
			"reason":     "Looks normal, no anomaly observed.",
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result["gate_fired"] != true {
		t.Errorf("expected gate_fired=true on triage short-circuit; got result=%v", result)
	}
	// Triage fan-out emits fanout_action=escalate-to-investigator, not the
	// investigate fan-out's deep-investigate-panel.
	if action, _ := result["fanout_action"].(string); action != "escalate-to-investigator" {
		t.Errorf("expected fanout_action=escalate-to-investigator on triage gate fire; got %q", action)
	}
	// Triage fan-out must NOT emit deep_item_ids or merge_item_id (those are
	// investigate-fan-out keys).
	if _, has := result["deep_item_ids"]; has {
		t.Errorf("triage fan-out must not emit deep_item_ids; got %v", result["deep_item_ids"])
	}
	if _, has := result["merge_item_id"]; has {
		t.Errorf("triage fan-out must not emit merge_item_id; got %v", result["merge_item_id"])
	}
	// The handoff item ID must be present and non-empty.
	itemID, _ := result["item_id"].(string)
	if itemID == "" {
		t.Errorf("expected non-empty item_id from triage fan-out (force escalate-to-investigator); got %v", result["item_id"])
	}

	// Exactly one work:create in the work campfire, tagged skill:task:investigate.
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	investigateCreates := 0
	deepCreates := 0
	for _, msg := range workMsgs {
		tagsRaw, _ := msg["tags"].([]interface{})
		isWorkCreate := false
		isInvestigate := false
		isDeep := false
		for _, tagRaw := range tagsRaw {
			tag, _ := tagRaw.(string)
			switch tag {
			case "work:create":
				isWorkCreate = true
			case "skill:task:investigate":
				isInvestigate = true
			case "skill:task:deep-investigate":
				isDeep = true
			}
		}
		if isWorkCreate && isInvestigate {
			investigateCreates++
		}
		if isWorkCreate && isDeep {
			deepCreates++
		}
	}
	if investigateCreates != 1 {
		t.Errorf("expected exactly 1 work:create with skill:task:investigate (triage fan-out); got %d", investigateCreates)
	}
	if deepCreates != 0 {
		t.Errorf("expected 0 work:create with skill:task:deep-investigate (deep panel is investigate-only); got %d", deepCreates)
	}
}

// TestConfidenceGate_TriageSkill_NormalResolveDoesNotFire verifies that a
// legitimate triage resolve (2 tools + 1 valid citation) does NOT fire the gate.
//
// Score: 0.04*2 + 0.08*2 + 0.04*1 = 0.08 + 0.16 + 0.04 = 0.28, comfortably
// above the 0.18 triage floor. The gate must pass through to normal close.
//
// This discriminates "I executed the rubric" from "I short-circuited" —
// the false-fire test that proves the triage floor is calibrated correctly.
func TestConfidenceGate_TriageSkill_NormalResolveDoesNotFire(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// 2 tools (check-baseline + search-events) — the classic triage rubric.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline", "search-events"})
	// Seed a tool result payload containing evt_001 so the citation cross-check
	// recognizes it as a real retrieved ID (not a hallucinated citation).
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_001","actor":"alice@example.com"}]}`)

	reason := "Triage complete: baseline matched, event evt_001 confirms benign pattern."

	envPairs := append(gateEnvPairsTriage(true, 0.40, 0.18),
		"MALLCOP_SKILL", "task:triage",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-triage-normal-001",
			"action":     "resolved",
			"reason":     reason,
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if gf, ok := result["gate_fired"]; ok && gf == true {
		t.Errorf("expected gate to NOT fire for legitimate triage resolve (2 tools + 1 citation); got gate_fired=true. result=%v", result)
	}
	if result["finding_id"] != "fnd-gate-triage-normal-001" {
		t.Errorf("finding_id = %v, want fnd-gate-triage-normal-001", result["finding_id"])
	}
	if result["action"] != "resolved" {
		t.Errorf("action = %v, want resolved", result["action"])
	}

	// Normal close: work:output in engagement campfire, no work:create in work.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output in engagement campfire for legitimate triage resolve; got %d messages", len(engMsgs))
	}
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected NO work:create when triage gate passes; got %d messages", len(workMsgs))
	}
}

// TestConfidenceGate_TriageScoreFloor_EnvOverride verifies that
// MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR is honored independently
// of the investigate-tier MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR.
//
// The same transcript (1 tool + 1 valid citation, score = 0.04 + 0.08 + 0.04 = 0.16)
// fires the gate at floor=0.40 (default investigate floor we set here too) AND
// at the default triage floor of 0.18 — to prove the env var actually takes
// effect, we lower the triage floor to 0.05 and confirm the gate does NOT fire.
func TestConfidenceGate_TriageScoreFloor_EnvOverride(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// 1 tool + 1 valid citation. Score = 0.04*1 + 0.08*1 + 0.04*1 = 0.16.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"search-events"})
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_042","actor":"bob@example.com"}]}`)

	reason := "Triage: event evt_042 explains the anomaly."

	// Override TriageScoreFloor to 0.05 — well below the 0.16 score, so the
	// gate must pass through. This proves the env var is plumbed through
	// loadGateConfig() into checkConfidenceGate's effective-floor selection.
	envPairs := append(gateEnvPairsTriage(true, 0.40, 0.05),
		"MALLCOP_SKILL", "task:triage",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-triage-envoverride-001",
			"action":     "resolved",
			"reason":     reason,
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if gf, ok := result["gate_fired"]; ok && gf == true {
		t.Errorf("expected gate to NOT fire with TRIAGE_SCORE_FLOOR=0.05 (score=0.16); got gate_fired=true. result=%v", result)
	}

	// Now rerun with a HIGHER triage floor (0.30) on the same transcript shape —
	// gate must fire. This proves the env var actively controls the decision in
	// both directions, not just the permissive direction above. Use a fresh
	// campfire pair (with its own cfHome) so the second resolve-finding call
	// doesn't see the first call's persisted state.
	cfBin2, cfHome2, campfireID2, workCampfireID2 := newTestCampfirePair(t)
	seedToolUseMsgs(t, cfBin2, cfHome2, campfireID2, []string{"search-events"})
	seedToolResultMsg(t, cfBin2, cfHome2, campfireID2,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_042","actor":"bob@example.com"}]}`)

	envPairs2 := append(gateEnvPairsTriage(true, 0.40, 0.30),
		"MALLCOP_SKILL", "task:triage",
		"MALLCOP_CAMPFIRE_ID", campfireID2,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID2,
		"CF_HOME", cfHome2,
	)

	out2 := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-triage-envoverride-002",
			"action":     "resolved",
			"reason":     reason,
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs2...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result2 map[string]interface{}
	if err := json.Unmarshal([]byte(out2), &result2); err != nil {
		t.Fatalf("parse output JSON (rerun): %v\nout=%q", err, out2)
	}

	if result2["gate_fired"] != true {
		t.Errorf("expected gate to fire with TRIAGE_SCORE_FLOOR=0.30 (score=0.16 < 0.30); got result=%v", result2)
	}
}

// TestForceEscalateToInvestigator verifies the triage fan-out helper directly:
// it emits a work:create message tagged skill:task:investigate (the canonical
// handoff to the investigator tier), carries the finding tag, and reports an
// item_id back to the caller.
//
// This is the integration test for the new fan-out helper. The helper is
// exercised indirectly by TestConfidenceGate_TriageSkill_Fires, but this test
// pins the call surface so a refactor can't silently break the handoff
// without a test failure.
func TestForceEscalateToInvestigator(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Drive the helper through the normal resolve-finding entry point so we
	// exercise the runConfidenceGateFanOut → forceEscalateToInvestigator path
	// the production code uses. Low-evidence transcript → gate fires.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline"})

	envPairs := append(gateEnvPairsTriage(true, 0.40, 0.18),
		"MALLCOP_SKILL", "task:triage",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"MALLCOP_ITEM_ID", "parent-item-499-test",
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-force-escalate-001",
			"action":     "resolved",
			"reason":     "Triage short-circuit.",
		})
		err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result["gate_fired"] != true {
		t.Fatalf("expected gate_fired=true; got %v", result)
	}
	if action, _ := result["fanout_action"].(string); action != "escalate-to-investigator" {
		t.Errorf("expected fanout_action=escalate-to-investigator; got %q", action)
	}
	itemID, _ := result["item_id"].(string)
	if itemID == "" {
		t.Fatalf("expected non-empty item_id in fan-out output; got %v", result)
	}

	// Verify the work:create message carries the right tags.
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	var found bool
	for _, msg := range workMsgs {
		tagsRaw, _ := msg["tags"].([]interface{})
		hasWorkCreate := false
		hasInvestigateSkill := false
		hasFindingTag := false
		for _, tagRaw := range tagsRaw {
			tag, _ := tagRaw.(string)
			switch tag {
			case "work:create":
				hasWorkCreate = true
			case "skill:task:investigate":
				hasInvestigateSkill = true
			case "finding:fnd-force-escalate-001":
				hasFindingTag = true
			}
		}
		if hasWorkCreate && hasInvestigateSkill && hasFindingTag {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a work:create message with tags [work:create, skill:task:investigate, finding:fnd-force-escalate-001]; got %d messages", len(workMsgs))
	}

	// No deep-investigate or investigate-merge messages allowed (triage fan-out
	// must NOT spawn the panel).
	for _, msg := range workMsgs {
		tagsRaw, _ := msg["tags"].([]interface{})
		for _, tagRaw := range tagsRaw {
			tag, _ := tagRaw.(string)
			if tag == "skill:task:deep-investigate" || tag == "skill:task:investigate-merge" {
				t.Errorf("triage fan-out must not spawn %s; got message tags=%v", tag, tagsRaw)
			}
		}
	}
}

// ---- mallcoppro-a5d defenses: extractRetrievedIDs tag-prefix allowlist -------

// TestExtractRetrievedIDs_AllowlistedTagsOnly verifies the Defense 1 invariant
// (mallcoppro-a5d): payloads tagged with allowlisted retrieval tools contribute
// IDs, payloads tagged with model-controlled tools (annotate-finding,
// write-partial-transcript) do NOT, even when the worker writes a citation-
// shape token into the payload body.
//
// Companion to TestVeracity_Bypass6_CitationFabricationViaAnnotate (in PR #101)
// which exercises the end-to-end resolve-finding path.
func TestExtractRetrievedIDs_AllowlistedTagsOnly(t *testing.T) {
	msgs := []cfMessage{
		// Allowlisted retrieval tool — contributes.
		{
			ID:      "msg-search-events",
			Tags:    []string{"tool_use", "tool:search-events", "tool:result"},
			Payload: `{"events":[{"id":"evt-001"}]}`,
		},
		// Allowlisted retrieval tool — contributes.
		{
			ID:      "msg-check-baseline",
			Tags:    []string{"tool_use", "tool:check-baseline"},
			Payload: `{"baseline":"evt-002"}`,
		},
		// Allowlisted lookup-rules — contributes.
		{
			ID:      "msg-lookup-rules",
			Tags:    []string{"tool:lookup-rules"},
			Payload: `{"rule":"rule-abc"}`,
		},
		// Model-controlled annotate-finding — MUST NOT contribute.
		{
			ID:      "msg-annotate",
			Tags:    []string{"finding:annotation", "finding:fnd-x"},
			Payload: `{"note":"see evt-fake999 for evidence"}`,
		},
		// Model-controlled partial transcript — MUST NOT contribute.
		{
			ID:      "msg-partial",
			Tags:    []string{"transcript:partial"},
			Payload: `{"content":"evt-fake888 looks bad"}`,
		},
	}

	got := extractRetrievedIDs(msgs)

	// Allowlisted IDs must be present.
	for _, want := range []string{"evt-001", "evt-002", "rule-abc"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected retrieved IDs to include %q (from allowlisted payload); got %v", want, got)
		}
	}

	// Model-controlled tokens must be absent.
	for _, denied := range []string{"evt-fake999", "evt-fake888"} {
		if _, ok := got[denied]; ok {
			t.Errorf("model-controlled token %q leaked into retrieved IDs — allowlist bypass. got=%v", denied, got)
		}
	}
}

// TestExtractRetrievedIDs_UntaggedSkipped verifies the conservative invariant
// for messages with no tags: no provenance = no trust (mallcoppro-a5d).
// A message with a citation-shape token but zero tags must not contribute
// anything to the retrieved set, even if it would have under the old
// scan-everything implementation.
func TestExtractRetrievedIDs_UntaggedSkipped(t *testing.T) {
	msgs := []cfMessage{
		// Untagged — no provenance, must skip.
		{
			ID:      "msg-untagged-ambient",
			Tags:    nil,
			Payload: `evt-untagged-1 looks suspicious`,
		},
		// Empty tag slice — also no provenance.
		{
			ID:      "msg-empty-tags",
			Tags:    []string{},
			Payload: `evt-untagged-2 trash`,
		},
		// Tagged with a NON-allowlisted, non-denylisted tag (e.g. a
		// hypothetical future tool that wasn't added to either list) —
		// also skipped: positive allowlist match is required.
		{
			ID:      "msg-unknown-tool",
			Tags:    []string{"tool:future-experimental"},
			Payload: `evt-untagged-3 lurks`,
		},
	}

	got := extractRetrievedIDs(msgs)
	if len(got) != 0 {
		t.Errorf("untagged / non-allowlisted payloads contributed retrieved IDs — provenance check broken. got=%v", got)
	}
}
