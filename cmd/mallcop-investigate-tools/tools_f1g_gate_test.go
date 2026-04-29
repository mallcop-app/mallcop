// tools_f1g_gate_test.go — integration tests for F2A confidence-score gate.
//
// Tests create real isolated campfires (via newTestCampfire) and seed them with
// synthetic tool_use messages to simulate investigate worker sessions.
// No mocks — the gate reads real cf campfire data.
//
// Test plan (6 tests):
//
//  1. TestConfidenceGate_Disabled_PassesThrough — enabled=false → normal work:output.
//  2. TestConfidenceGate_OtherSkill_PassesThrough — MALLCOP_SKILL != task:investigate → normal close.
//  3. TestConfidenceGate_HighScore_PassesThrough — 8 tool calls, 4 distinct, citation → score ≥ 0.55.
//  4. TestConfidenceGate_LowScore_FiresFanOut — 1 tool call, no citations, 5 iterations → gate fires.
//  5. TestConfidenceGate_VerifyFanOutShape — all 3 hypotheses present, merge has 3 deep ids.
//  6. TestConfidenceGate_IterationPenalty — high tool count + many iterations → gate fires.
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

// gateEnvPairs returns the env key=value pairs for the confidence gate config.
func gateEnvPairs(enabled bool, scoreFloor float64) []string {
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	return []string{
		"MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED", enabledStr,
		"MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR", fmt.Sprintf("%.4f", scoreFloor),
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

func TestConfidenceGate_OtherSkill_PassesThrough(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// Seed a low-score transcript.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"search-events"})

	// Gate is enabled but skill is NOT task:investigate.
	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:triage",  // not investigate → pass through
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-gate-skill-001","action":"resolved","reason":"Triage resolved."}`,
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

	// Must NOT have gate_fired: skill is not task:investigate.
	if _, fired := result["gate_fired"]; fired {
		t.Errorf("expected normal close output for non-investigate skill, but got gate_fired: %v", result)
	}
	if result["finding_id"] != "fnd-gate-skill-001" {
		t.Errorf("finding_id = %v, want fnd-gate-skill-001", result["finding_id"])
	}

	// work:output must be present in campfire.
	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(msgs, "work:output") {
		t.Errorf("expected work:output in campfire for non-investigate skill; got %d messages", len(msgs))
	}
}

// ---- TestConfidenceGate_HighScore_PassesThrough --------------------------------

func TestConfidenceGate_HighScore_PassesThrough(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// High score: 8 tool calls (cap=8), 4 distinct tools, citation in reason.
	// Expected score: 0.04*8 + 0.08*4 + 0.04*1 = 0.32 + 0.32 + 0.04 = 0.68 ≥ 0.55
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "read-config",
		"check-baseline", "search-events", "search-findings", "read-config",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)

	// Reason with event ID citation.
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
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-gate-iter-001",
			"action":     "escalated",
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
