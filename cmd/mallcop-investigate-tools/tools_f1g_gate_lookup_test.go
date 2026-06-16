// tools_f1g_gate_lookup_test.go — tests for the lookup-rules-skip soft penalty
// (mallcoppro-8b0).
//
// Wave 4 (mallcoppro-df1) bakeoff revealed investigate workers explicitly
// writing prose like "events carry maintenance_window=true ... suitable for
// lookup-rules" and then escalating WITHOUT actually invoking the tool.
// Across all B1 scenarios, 0/3 had rule_id citations. The infrastructure
// shipped in Waves 2-3 (rules.yaml + lookup-rules tool + rule_id citation +
// forgery defense) was dead code in production because nothing enforced tool
// usage.
//
// This file pins the enforcement contract:
//
//   - When MALLCOP_SKILL=task:investigate AND the worker resolved WITHOUT
//     invoking lookup-rules AND did NOT cite a valid rule_id, the gate subtracts
//     lookupRulesSkipPenalty (0.10) from the score.
//   - High scores (≥ floor+0.10) remain above floor → no fire.
//   - Borderline scores ([floor, floor+0.10)) flip from pass to fire.
//   - Workers that DID call lookup-rules (even if no rule matched) get no
//     penalty — they did the right process.
//   - Workers that cited a valid rule_id get no penalty — the rule_id is itself
//     proof of lookup-rules invocation, and the existing Wave 3 bypass for
//     rule_id citations is preserved.
//
// All tests use task:investigate; the penalty is investigate-only by design.
// Triage's Step 2b is correctly advisory (skip when no benign-pattern flag is
// present), so the gate-side penalty does not apply to task:triage.
package main

import (
	"encoding/json"
	"sync/atomic"
	"testing"
)

// seedLookupRulesCall posts a synthetic tool_use message tagged tool:lookup-rules
// to simulate the worker having invoked the lookup-rules tool. The payload mimics
// what legion emits for a real lookup-rules call.
func seedLookupRulesCall(t *testing.T, cfBin, cfHome, campfireID string) {
	t.Helper()
	payload := `{"tool_use":true,"name":"lookup-rules","input":{"finding_id":"fnd-test","finding_family":"unusual-timing"}}`
	_, err := runCFCmd(cfBin, cfHome, "send", campfireID, payload,
		"--tag", "tool_use", "--tag", "tool:lookup-rules")
	if err != nil {
		t.Fatalf("seed tool:lookup-rules msg: %v", err)
	}
}

// ---- TestEnforce_LookupRulesNotInvoked_Penalizes -----------------------------
//
// Borderline-score worker that skipped lookup-rules MUST fire the gate after
// the soft penalty pushes the score below the floor.
//
// Pre-penalty score: 8 tool calls × 0.04 (cap=8) + 4 distinct × 0.08 (cap=4)
//                  + 1 citation × 0.04 - 0.02 × max(8-3,0)
//                  = 0.32 + 0.32 + 0.04 - 0.10 = 0.58
// Floor: 0.55. Pre-penalty: 0.58 ≥ 0.55 → would pass.
// After lookup-rules-skip penalty (-0.10): 0.48 < 0.55 → fires.
//
// This is the borderline-tip case in the spec — the exact scenario where the
// penalty changes the gate outcome, not just reinforces a foregone conclusion.
func TestEnforce_LookupRulesNotInvoked_Penalizes(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// 8 tool calls × 4 distinct tools, NO lookup-rules in chain.
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "read-config",
		"check-baseline", "search-events", "search-findings", "read-config",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)

	// Seed a real retrieval result so the citation evt_001 passes the cross-check.
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_001","actor":"alice@example.com"}]}`)

	reason := "Investigation complete: evt_001 confirms benign maintenance window activity."

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	before := atomic.LoadInt64(&lookupRulesSkippedResolves)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-8b0-skipped-001",
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

	// Gate MUST fire: penalty pushes 0.58 → 0.48 < 0.55.
	if gf, _ := result["gate_fired"].(bool); !gf {
		t.Errorf("expected gate_fired=true after lookup-rules-skip penalty; got result=%v", result)
	}
	score, _ := result["score"].(float64)
	if score >= 0.55 {
		t.Errorf("expected score < 0.55 after penalty; got %.4f (penalty not applied?)", score)
	}
	if score > 0.50 {
		// Sanity: post-penalty score should be ~0.48 (pre 0.58 - 0.10).
		t.Logf("post-penalty score = %.4f (expected ~0.48 from 0.58 - 0.10)", score)
	}

	// Counter MUST have incremented for the bakeoff-level adoption metric.
	after := atomic.LoadInt64(&lookupRulesSkippedResolves)
	if after-before != 1 {
		t.Errorf("expected lookupRulesSkippedResolves to increment by 1; before=%d after=%d", before, after)
	}

	// Fan-out work:create must be present (gate fired → deep-investigate panel).
	workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(workMsgs, "work:create") {
		t.Errorf("expected work:create in work campfire after gate fires; got %d messages", len(workMsgs))
	}
}

// ---- TestEnforce_LookupRulesInvoked_NoPenalty --------------------------------
//
// Worker that invoked lookup-rules — even without a matching rule — must NOT
// be penalized. Calling the tool IS the process step the gate looks for; a
// "no match" result is a legitimate outcome (some findings genuinely have no
// pre-seeded rule).
//
// Pre-penalty score: 0.58 (same shape as Penalizes test).
// Floor: 0.55. With lookup-rules in chain, no penalty applied → 0.58 ≥ 0.55 → pass.
func TestEnforce_LookupRulesInvoked_NoPenalty(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// 8 tool calls × 4 distinct tools, INCLUDING lookup-rules.
	// One of the distinct tools is lookup-rules — the gate looks for the tag, not
	// for a specific call count.
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

	before := atomic.LoadInt64(&lookupRulesSkippedResolves)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-8b0-invoked-001",
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

	// Gate MUST NOT fire: lookup-rules was invoked, no penalty applied, score 0.58 ≥ 0.55.
	if gf, fired := result["gate_fired"]; fired && gf == true {
		t.Errorf("expected gate to NOT fire when lookup-rules was invoked; got gate_fired=true. result=%v", result)
	}

	// Counter MUST NOT have incremented.
	after := atomic.LoadInt64(&lookupRulesSkippedResolves)
	if after != before {
		t.Errorf("expected lookupRulesSkippedResolves to be unchanged when lookup-rules invoked; before=%d after=%d", before, after)
	}

	// Normal close: work:output in engagement campfire.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output in engagement campfire when gate passes; got %d messages", len(engMsgs))
	}
}

// ---- TestEnforce_RuleIDCited_BypassesPenaltyAndFloor -------------------------
//
// A valid rule_id citation is itself proof the worker queried the operator-
// decisions corpus (the rule_id had to come from somewhere). The existing
// Wave 3 rule_id citation path (mallcoppro-00c) must be preserved unchanged:
//
//   - +1 to citation_count from a valid rule_id.
//   - Zero-citation hard floor bypassed.
//   - No lookup-rules-skip penalty applied (rule_id IS the proof of lookup).
//
// This test exercises the "worker did the right thing" path with a slim
// transcript: 2 tool calls (not 8), a valid rule_id, and no retrieval-tool
// citations. Score = 0.04*2 + 0.08*2 + 0.04*1 = 0.28 (from the +1 rule_id
// bump). With floor 0.18 (we lower it here to focus the test on the rule_id
// path, not the floor calculation), gate must pass.
//
// We pin this test at floor=0.18 deliberately: the goal is to verify that the
// rule_id citation path is unaffected by the new penalty, not to re-test the
// score floor itself. With floor=0.55, this thin transcript would fire on
// score, which would mask whether the lookup-rules skip detection correctly
// honored the rule_id exemption.
func TestEnforce_RuleIDCited_BypassesPenaltyAndFloor(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)
	_ = writeRulesFixture(t, fixtureRulesYAML)

	// 2 tool calls, NO lookup-rules in chain. Only the rule_id citation counts.
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline", "search-events"})

	reason := "Resolved per operator decision corpus rule for maintenance-window pattern."

	// Floor 0.18 — focuses the test on the rule_id exemption, not the floor.
	envPairs := append(gateEnvPairs(true, 0.18),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	before := atomic.LoadInt64(&lookupRulesSkippedResolves)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-8b0-ruleid-001",
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

	// Gate MUST NOT fire — valid rule_id satisfies both citation requirement
	// AND exempts from lookup-rules-skip penalty.
	if gf, fired := result["gate_fired"]; fired && gf == true {
		t.Errorf("expected gate to NOT fire with valid rule_id; got gate_fired=true. result=%v", result)
	}

	// Counter MUST NOT have incremented (valid rule_id exempts the penalty).
	after := atomic.LoadInt64(&lookupRulesSkippedResolves)
	if after != before {
		t.Errorf("expected lookupRulesSkippedResolves unchanged when valid rule_id cited; before=%d after=%d", before, after)
	}

	// Normal close: work:output in engagement campfire, rule_id echoed.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output in engagement campfire for valid rule_id resolve; got %d messages", len(engMsgs))
	}
	if result["rule_id"] != "R-001" {
		t.Errorf("expected rule_id=R-001 echoed in work:output; got %v", result["rule_id"])
	}
}

// ---- TestEnforce_HighScoreUnaffected -----------------------------------------
//
// A worker with a score well above the floor (pre-penalty ≥ floor+0.10) must
// still pass after the penalty is applied. The penalty is a soft signal, not
// a hard verdict — workers with strong direct evidence (many tools, many
// citations) can resolve without lookup-rules when no rule applies.
//
// Pre-penalty score: 8 tool calls × 0.04 + 4 distinct × 0.08 + 5 citations × 0.04
//                  - 0.02 × max(8-3,0)
//                  = 0.32 + 0.32 + 0.20 - 0.10 = 0.74
// Floor: 0.55. Pre-penalty: 0.74 ≥ 0.55 → would pass.
// After penalty: 0.64 ≥ 0.55 → still passes (high score absorbs the penalty).
//
// This is the "don't false-fire legitimate resolves" case: the penalty must
// not punish workers who genuinely investigated thoroughly even when they
// didn't query the corpus.
func TestEnforce_HighScoreUnaffected(t *testing.T) {
	cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

	// 8 tool calls × 4 distinct tools, NO lookup-rules in chain.
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "read-config",
		"check-baseline", "search-events", "search-findings", "read-config",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)

	// Seed 5 distinct retrieved IDs so the worker can legitimately cite all of them.
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[`+
			`{"id":"evt_001"},{"id":"evt_002"},{"id":"evt_003"},{"id":"evt_004"},{"id":"evt_005"}]}`)

	reason := "Investigation complete with 5 corroborating events: " +
		"evt_001 (baseline match), evt_002 (auth context), evt_003 (provenance), " +
		"evt_004 (correlation), evt_005 (resolution). Activity is benign."

	envPairs := append(gateEnvPairs(true, 0.55),
		"MALLCOP_SKILL", "task:investigate",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
		"CF_HOME", cfHome,
	)

	before := atomic.LoadInt64(&lookupRulesSkippedResolves)

	out := captureStdout(t, func() {
		input, _ := json.Marshal(map[string]interface{}{
			"finding_id": "fnd-8b0-highscore-001",
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

	// Gate MUST NOT fire — high score absorbs the penalty.
	if gf, fired := result["gate_fired"]; fired && gf == true {
		t.Errorf("expected high-score worker to pass through despite lookup-rules skip; got gate_fired=true. score=%v result=%v",
			result["score"], result)
	}

	// Counter MUST have incremented — the penalty WAS applied (the score is
	// reduced; the worker just had enough margin to absorb it). The counter
	// tracks "the soft penalty path was taken," not "the gate fired because of it."
	after := atomic.LoadInt64(&lookupRulesSkippedResolves)
	if after-before != 1 {
		t.Errorf("expected lookupRulesSkippedResolves to increment by 1 (penalty path taken even though gate passed); before=%d after=%d",
			before, after)
	}

	// Normal close: work:output in engagement campfire.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output for high-score resolve; got %d messages", len(engMsgs))
	}
}

// ---- TestEnforce_BorderlineFlipsToFire ---------------------------------------
//
// White-box check on the borderline window: a worker whose pre-penalty score
// sits in [floor, floor+0.10) — passing without the penalty — must fire after
// the penalty. Confirms the soft-penalty mechanism actively changes outcomes
// in the borderline band, not just reinforces already-failing scores.
//
// Pre-penalty score: 8 tool calls × 0.04 + 4 distinct × 0.08 + 1 citation × 0.04
//                  - 0.02 × max(8-3,0)
//                  = 0.32 + 0.32 + 0.04 - 0.10 = 0.58
// Floor: 0.55. Window: [0.55, 0.65).
// Pre-penalty 0.58 is squarely in the window → must flip from pass to fire.
//
// Companion to Penalizes test but with explicit white-box assertions on the
// computed score values via checkConfidenceGate, so a refactor of the penalty
// implementation that breaks the borderline math fails this test.
func TestEnforce_BorderlineFlipsToFire(t *testing.T) {
	cfBin, cfHome, campfireID, _ := newTestCampfirePair(t)

	// 8 tool calls × 4 distinct tools, NO lookup-rules.
	toolNames := []string{
		"check-baseline", "search-events", "search-findings", "read-config",
		"check-baseline", "search-events", "search-findings", "read-config",
	}
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, toolNames)
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_007"}]}`)

	reason := "Worker cites evt_007 as the borderline-evidence anchor."

	// Floor 0.55: window is [0.55, 0.65). Pre-penalty score 0.58 is in the window.
	t.Setenv("MALLCOP_SKILL", "task:investigate")
	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED", "true")
	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR", "0.55")
	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR", "0.18")

	before := atomic.LoadInt64(&lookupRulesSkippedResolves)

	// White-box: call checkConfidenceGate directly to see Score / SkippedLookup.
	gr, err := checkConfidenceGate(campfireID, "resolved", reason, "")
	if err != nil {
		t.Fatalf("checkConfidenceGate: %v", err)
	}

	if !gr.Fired {
		t.Errorf("expected gate.Fired=true at borderline (pre-penalty 0.58, floor 0.55, penalty -0.10); got gr=%+v", gr)
	}
	if !gr.SkippedLookup {
		t.Errorf("expected gr.SkippedLookup=true (no tool:lookup-rules in chain, no rule_id); got gr=%+v", gr)
	}
	// Post-penalty score: 0.58 - 0.10 = 0.48. Allow small float tolerance.
	if gr.Score > 0.50 || gr.Score < 0.45 {
		t.Errorf("expected post-penalty score ≈ 0.48; got %.4f (gr=%+v)", gr.Score, gr)
	}
	if gr.CitationCount != 1 {
		t.Errorf("expected citation_count=1 (evt_007 from real retrieval); got %d", gr.CitationCount)
	}
	if gr.EffectiveFloor != 0.55 {
		t.Errorf("expected effective floor=0.55 (investigate skill); got %.4f", gr.EffectiveFloor)
	}

	after := atomic.LoadInt64(&lookupRulesSkippedResolves)
	if after-before != 1 {
		t.Errorf("expected lookupRulesSkippedResolves +1; before=%d after=%d", before, after)
	}
}
