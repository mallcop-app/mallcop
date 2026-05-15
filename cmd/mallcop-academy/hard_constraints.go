// Hard-constraint short-circuit (rung 0 of the March cost ladder).
//
// Findings whose detector matches the always-escalate set go straight to
// "escalated" without spawning any LLM worker. Ports the March pipeline's
// check_hard_constraints (mallcop/src/mallcop/resolution_rules.py:48-70)
//
// Scenario authoring contract: scenarios whose finding.detector matches a key
// in alwaysEscalateDetectors MUST set expected.chain_action: escalated.
// Setting chain_action: resolved is unreachable for these detectors and will
// deterministically fail evaluation. See docs/exams/scenario-authoring.md.
// into the Go academy seed step so eval runs avoid spending donuts on
// scenarios that the system would always escalate by policy anyway.
//
// See docs/diagnosis/2026-05-05-ladder-gap.md (rung 0) in mallcop-pro for
// the full rationale and the cost projection.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mallcop-app/mallcop/internal/exam"
)

// alwaysEscalateDetectors is the literal port of ALWAYS_ESCALATE_DETECTORS
// from mallcop/resolution_rules.py:48-53. These four detector classes are
// hard security constraints — the system always escalates to a human. The
// model is not consulted because models fail to enforce these reliably and
// the donut cost is wasted.
//
// DO NOT widen this set. The whole point of the rung-0 ladder is that it
// is a small, deterministic, security-critical allowlist. New detectors
// must go through the LLM triage path until they earn promotion via a
// design decision.
var alwaysEscalateDetectors = map[string]bool{
	"priv-escalation":    true, // privilege changes always need audit
	"log-format-drift":   true, // structural drift = security blind spot
	"injection-probe":    true, // prompt-injection attempts
	"boundary-violation": true, // access-boundary violations
}

// checkHardConstraints reports whether a finding's detector class triggers
// deterministic escalation. Returns a human-readable reason if matched.
// Mirrors check_hard_constraints in mallcop/resolution_rules.py:56-70.
func checkHardConstraints(detector string) (string, bool) {
	if alwaysEscalateDetectors[detector] {
		return fmt.Sprintf(
			"Hard constraint: %s findings always require human review "+
				"(deterministic escalation, no LLM involved)",
			detector,
		), true
	}
	return "", false
}

// hardConstraintTerminalPayload is the synthetic work:close payload posted
// to the work campfire so the audit trail records the deterministic
// escalation alongside real LLM-driven closes.
type hardConstraintTerminalPayload struct {
	ItemID    string `json:"item_id"`
	Action    string `json:"action"`
	Skill     string `json:"skill"`
	Reason    string `json:"reason"`
	FindingID string `json:"finding_id"`
}

// seedHardConstraintEscalate handles a scenario whose finding matches a
// hard-constraint detector. It does NOT post a work:create (no triage skill,
// no LLM worker spawned), so the worker spawn count contributed by this
// scenario is exactly zero. Instead it:
//
//  1. Posts a single synthetic work:close to the work campfire so observers
//     (and downstream audit) see a terminal-escalate event for the scenario.
//  2. Populates the trackedScenario as terminal with action="escalated" and
//     a one-entry chain identifying the hard-constraint resolver.
//
// Returns the synthetic close message ID so the caller can register it in
// workItemToScenario for the watch loop's lookup table (it will not match a
// real close because we mark terminal directly, but registration keeps the
// bookkeeping symmetric with the LLM path).
func seedHardConstraintEscalate(
	sender Sender,
	s *exam.Scenario,
	runID, campfireID, reason string,
	ts *trackedScenario,
) (string, error) {
	syntheticItemID := "hard-constraint-" + findingTrackingID(runID, s.ID)

	// Use ts.findingID (already suffixed with the run ID) so the finding: tag
	// and payload finding_id are per-run-unique — consistent with the LLM path.
	payload := hardConstraintTerminalPayload{
		ItemID:    syntheticItemID,
		Action:    "escalated",
		Skill:     "task:hard-constraint",
		Reason:    reason,
		FindingID: ts.findingID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal hard-constraint payload: %w", err)
	}

	tags := []string{
		"work:close",
		"action:escalated",
		"academy:hard-constraint",
		"detector:" + s.Finding.Detector,
		"scenario:" + s.ID,
		"run:" + runID,
		"finding:" + ts.findingID,
	}
	msgID, err := sender.send(campfireID, string(body), tags)
	if err != nil {
		return "", fmt.Errorf("post synthetic terminal-escalate: %w", err)
	}

	now := time.Now()

	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.workItemID = syntheticItemID
	ts.postedAt = now
	ts.chain = []ChainEntry{{
		ItemID: syntheticItemID,
		Skill:  "task:hard-constraint",
		Action: "escalated",
	}}
	ts.terminal = true
	ts.terminalAt = now
	ts.terminalAction = "escalated"
	ts.terminalItemID = syntheticItemID
	ts.terminalReason = reason
	// Triage close action mirrors the terminal action so grading code that
	// inspects triageCloseAction sees the deterministic escalate, not "".
	ts.triageCloseAction = "escalated"

	return msgID, nil
}
