// tools_f1g_gate_registry_test.go — mallcoppro-801d white-box tests for the
// per-skill gate registry.
//
// Wave 2 (PR #97 mallcoppro-499) added a hardcoded skill switch in
// checkConfidenceGate. Wave 5 veracity flagged this as not-extensible. Wave B
// (PR #105 mallcoppro-8b0) then added a `lookupRulesSkipPenalty` mechanism that
// applied ONLY when skill=task:investigate via a literal `skill ==
// "task:investigate"` check in the gate.
//
// mallcoppro-801d replaces both checks with a per-skill registry:
//
//	type skillGateConfig struct {
//	    floor              float64
//	    fanoutMode         string // fanoutModeDeepX3Merge | fanoutModeEscalateToInvestigator | ...
//	    applyLookupPenalty bool   // gates the mallcoppro-8b0 soft penalty
//	}
//
//	func (cfg confidenceGateConfig) skillRegistry() map[string]skillGateConfig { ... }
//
// These tests pin the registry shape, the dispatch behavior, and the per-skill
// penalty applicability that was preserved across the refactor.
//
// All five tests run real campfires (via newTestCampfirePair) — no mocks. The
// registry-shape tests do not need a campfire and run direct on the config
// struct.

package main

import (
	"encoding/json"
	"testing"
)

// ---- TestSkillRegistry_ContainsInvestigateAndTriage ---------------------------
//
// Pins the registry shape: cfg.skillRegistry() returns entries for
// task:investigate (deep×3 merge) and task:triage (escalate-to-investigator).
// Adding a 3rd entry is a change to skillRegistry, not a change to
// checkConfidenceGate's dispatch logic — and this test will alert if the
// existing two entries are ever silently removed.
//
// mallcoppro-structural-lookup-enforce: the applyLookupPenalty field is gone
// (hard runtime guards in runResolveFinding and runEscalateToStageC supersede
// the soft per-resolve penalty). The shape assertions for that field have
// been removed; the floor + fanoutMode invariants are unchanged.
func TestSkillRegistry_ContainsInvestigateAndTriage(t *testing.T) {
	cfg := defaultGateConfig()
	reg := cfg.skillRegistry()

	inv, ok := reg["task:investigate"]
	if !ok {
		t.Fatalf("expected registry to contain task:investigate entry; got keys: %v", keysOf(reg))
	}
	if inv.floor != cfg.ScoreFloor {
		t.Errorf("task:investigate floor = %.4f, want %.4f (cfg.ScoreFloor)", inv.floor, cfg.ScoreFloor)
	}
	if inv.fanoutMode != fanoutModeDeepX3Merge {
		t.Errorf("task:investigate fanoutMode = %q, want %q", inv.fanoutMode, fanoutModeDeepX3Merge)
	}

	tri, ok := reg["task:triage"]
	if !ok {
		t.Fatalf("expected registry to contain task:triage entry; got keys: %v", keysOf(reg))
	}
	if tri.floor != cfg.TriageScoreFloor {
		t.Errorf("task:triage floor = %.4f, want %.4f (cfg.TriageScoreFloor)", tri.floor, cfg.TriageScoreFloor)
	}
	if tri.fanoutMode != fanoutModeEscalateToInvestigator {
		t.Errorf("task:triage fanoutMode = %q, want %q", tri.fanoutMode, fanoutModeEscalateToInvestigator)
	}
}

// ---- TestSkillRegistry_UnknownSkill_SkipsGate --------------------------------
//
// MALLCOP_SKILL=task:heal (an unregistered skill) → checkConfidenceGate must
// return Fired=false with no campfire I/O. This is the "registry miss = skip"
// branch — equivalent to the original `default: return ... skipped` arm of the
// hardcoded switch. The skip MUST happen before any cf read, otherwise unknown
// skills would pay the transcript-read cost.
//
// We do not seed any campfire messages and verify gr.Fired=false to prove the
// early-return path took precedence over the transcript read (which would have
// failed-closed if reached).
func TestSkillRegistry_UnknownSkill_SkipsGate(t *testing.T) {
	cfBin, cfHome, campfireID, _ := newTestCampfirePair(t)
	_ = cfBin
	_ = cfHome

	t.Setenv("MALLCOP_SKILL", "task:heal")
	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED", "true")
	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR", "0.40")
	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR", "0.18")

	gr, err := checkConfidenceGate(campfireID, "resolved", "Healed via runbook.", "")
	if err != nil {
		t.Fatalf("checkConfidenceGate (unknown skill): unexpected error: %v", err)
	}
	if gr.Fired {
		t.Errorf("expected gr.Fired=false for unknown skill (registry miss); got gr=%+v", gr)
	}
	// The skip path produces a zero-value gateResult — no floor, no fan-out mode.
	if gr.EffectiveFloor != 0 {
		t.Errorf("expected EffectiveFloor=0 on skip; got %.4f", gr.EffectiveFloor)
	}
	if gr.FanoutMode != "" {
		t.Errorf("expected empty FanoutMode on skip; got %q", gr.FanoutMode)
	}
}

// ---- TestSkillRegistry_ConfigOverrideTakesEffect -----------------------------
//
// Setting MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR=0.05 must flow
// through loadGateConfig() into cfg.skillRegistry()["task:triage"].floor.
// This guards against a regression where the registry copies field values at
// init time (which would break env-var overrides) instead of reading them on
// every call.
//
// We verify both the direct registry value AND that checkConfidenceGate
// reports it as EffectiveFloor on a triage call.
func TestSkillRegistry_ConfigOverrideTakesEffect(t *testing.T) {
	cfBin, cfHome, campfireID, _ := newTestCampfirePair(t)
	_ = cfBin
	_ = cfHome

	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED", "true")
	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR", "0.40")
	t.Setenv("MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR", "0.05")

	cfg := loadGateConfig()
	reg := cfg.skillRegistry()
	tri := reg["task:triage"]
	if tri.floor != 0.05 {
		t.Errorf("expected registry triage floor = 0.05 from env override; got %.4f", tri.floor)
	}

	// And the same value must surface as EffectiveFloor on a real triage call.
	t.Setenv("MALLCOP_SKILL", "task:triage")
	// Seed an evidence-bearing transcript so the zero-citation hard floor does
	// not fire (which would mask the floor-comparison path we want to exercise).
	seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"check-baseline", "search-events"})
	seedToolResultMsg(t, cfBin, cfHome, campfireID,
		`{"tool_result":true,"tool":"search-events","events":[{"id":"evt_801d","actor":"alice@example.com"}]}`)

	gr, err := checkConfidenceGate(campfireID, "resolved",
		"Triage: event evt_801d confirms benign pattern.", "")
	if err != nil {
		t.Fatalf("checkConfidenceGate (override): %v", err)
	}
	if gr.EffectiveFloor != 0.05 {
		t.Errorf("expected gr.EffectiveFloor = 0.05; got %.4f", gr.EffectiveFloor)
	}
}

// ---- TestFanoutMode_DispatchesCorrectly --------------------------------------
//
// Pins the dispatch contract: gr.FanoutMode == fanoutModeDeepX3Merge routes
// runConfidenceGateFanOut through the investigate path (write-partial-
// transcript + escalate-to-deep ×3 + create-investigate-merge), while
// fanoutModeEscalateToInvestigator routes to forceEscalateToInvestigator (one
// task:investigate work:create handoff).
//
// We drive the dispatch end-to-end via resolve-finding so the FanoutMode is
// populated by checkConfidenceGate exactly as production does. The contract
// surface is the `fanout_action` field in the emitted JSON plus the count and
// tag of messages on the work campfire.
func TestFanoutMode_DispatchesCorrectly(t *testing.T) {
	type dispatchCase struct {
		name              string
		skill             string
		wantFanoutAction  string
		wantDeepCreates   int
		wantInvCreates    int
		wantMergeKey      bool
	}

	cases := []dispatchCase{
		{
			name:             "investigate skill → deep_x3_merge",
			skill:            "task:investigate",
			wantFanoutAction: "deep-investigate-panel",
			wantDeepCreates:  3,
			wantInvCreates:   0,
			wantMergeKey:     true,
		},
		{
			name:             "triage skill → escalate_to_investigator",
			skill:            "task:triage",
			wantFanoutAction: "escalate-to-investigator",
			wantDeepCreates:  0,
			wantInvCreates:   1,
			wantMergeKey:     false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfBin, cfHome, campfireID, workCampfireID := newTestCampfirePair(t)

			// Low evidence: 1 tool call, no citations → fires either skill.
			seedToolUseMsgs(t, cfBin, cfHome, campfireID, []string{"search-events"})
			// Satisfy the structural lookup-rules guard (mallcoppro-structural-lookup-enforce).
			seedLookupRulesCall(t, cfBin, cfHome, campfireID)

			envPairs := append(gateEnvPairsTriage(true, 0.40, 0.18),
				"MALLCOP_SKILL", tc.skill,
				"MALLCOP_CAMPFIRE_ID", campfireID,
				"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
				"CF_HOME", cfHome,
			)

			out := captureStdout(t, func() {
				input, _ := json.Marshal(map[string]interface{}{
					"finding_id": "fnd-gate-801d-dispatch-001",
					"action":     "resolved",
					"reason":     "Low-evidence resolve to exercise dispatch.",
				})
				if err := runToolWithEnv(t, "resolve-finding", string(input), envPairs...); err != nil {
					t.Errorf("resolve-finding: unexpected error: %v", err)
				}
			})

			var result map[string]interface{}
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatalf("parse output JSON: %v\nout=%q", err, out)
			}

			if result["gate_fired"] != true {
				t.Fatalf("expected gate_fired=true on low-evidence resolve; got %v", result)
			}
			if got, _ := result["fanout_action"].(string); got != tc.wantFanoutAction {
				t.Errorf("fanout_action = %q, want %q", got, tc.wantFanoutAction)
			}
			_, hasMerge := result["merge_item_id"]
			if hasMerge != tc.wantMergeKey {
				t.Errorf("merge_item_id present = %v, want %v (result=%v)", hasMerge, tc.wantMergeKey, result)
			}

			// Count work:create messages by skill tag.
			workMsgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
			invCreates, deepCreates := 0, 0
			for _, msg := range workMsgs {
				tagsRaw, _ := msg["tags"].([]interface{})
				isWorkCreate, isInv, isDeep := false, false, false
				for _, tagRaw := range tagsRaw {
					switch tagRaw {
					case "work:create":
						isWorkCreate = true
					case "skill:task:investigate":
						isInv = true
					case "skill:task:deep-investigate":
						isDeep = true
					}
				}
				if isWorkCreate && isInv {
					invCreates++
				}
				if isWorkCreate && isDeep {
					deepCreates++
				}
			}
			if invCreates != tc.wantInvCreates {
				t.Errorf("work:create skill:task:investigate count = %d, want %d", invCreates, tc.wantInvCreates)
			}
			if deepCreates != tc.wantDeepCreates {
				t.Errorf("work:create skill:task:deep-investigate count = %d, want %d", deepCreates, tc.wantDeepCreates)
			}
		})
	}
}

// TestLookupRulesPenalty_InvestigateOnly was removed in mallcoppro-structural-
// lookup-enforce: the soft per-resolve penalty it pinned has been replaced
// with a hard runtime guard. The hard-guard refusal contract is tested by
// tools_f1g_structural_enforcement_test.go.

// keysOf returns the keys of a string-keyed map in arbitrary order. Used only
// by the test for human-readable failure messages when an expected registry
// key is missing.
func keysOf(m map[string]skillGateConfig) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
