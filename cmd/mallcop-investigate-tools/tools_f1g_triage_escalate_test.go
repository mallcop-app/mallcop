// tools_f1g_triage_escalate_test.go — Force-escalate routing tests.
//
// Post-merge bakeoff bakeoff-20260615-163359-postmerge-full (87.3% pass, 5/6
// failures = over-escalations) showed every failing chain shaped like:
//   [task:triage worker, academy-item, triage close action=done, finding-item close action=escalated]
// Triage was using resolve-finding(action="escalated") as a terminal close,
// which bypassed lookup-rules, the asymmetric gate, and dispatch of a
// task:investigate handoff. The Wave 1-5 / A+B+C escalation infrastructure
// never engaged on these scenarios because no investigator ever ran.
//
// The fix forces triage to use escalate-to-investigator for escalation. The
// runtime in runResolveFinding rejects action="escalated" when
// MALLCOP_SKILL=task:triage; other skills (task:investigate,
// task:investigate-merge, task:deep-investigate, task:heal, task:escalate)
// retain action="escalated" as a legitimate terminal close.
//
// These tests pin both halves of the contract:
//   - Triage REJECTS resolve-finding(action="escalated") with no campfire write.
//   - Triage ACCEPTS resolve-finding(action="resolved") (existing path preserved).
//   - Investigate ACCEPTS resolve-finding(action="escalated") (legitimate caller).
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestResolveFinding_TriageRejectsEscalatedAction verifies that triage workers
// cannot use resolve-finding to escalate. The runtime guard returns an error
// before any campfire I/O so no terminal close message is posted — the
// agent's turn ends without closing the finding, and the model must retry
// with escalate-to-investigator.
func TestResolveFinding_TriageRejectsEscalatedAction(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	err := runToolWithEnv(t, "resolve-finding",
		`{"finding_id":"fnd-triage-esc-001","action":"escalated","reason":"Suspicious pattern; needs deeper look.","confidence":2}`,
		"MALLCOP_SKILL", "task:triage",
		"MALLCOP_CAMPFIRE_ID", campfireID,
		"CF_HOME", cfHome,
	)
	if err == nil {
		t.Fatal("expected error rejecting triage action=escalated; got nil")
	}
	if !strings.Contains(err.Error(), "escalate-to-investigator") {
		t.Errorf("expected error to mention escalate-to-investigator; got: %v", err)
	}
	if !strings.Contains(err.Error(), "triage") {
		t.Errorf("expected error to mention triage skill; got: %v", err)
	}

	// Critical: no campfire write happened. The finding is NOT closed.
	// The reject guard runs before checkConfidenceGate and before cfSend, so
	// the engagement campfire must be empty of any terminal-close artifacts.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected NO work:output written; the reject guard must run before campfire I/O. got %d messages", len(engMsgs))
	}
	if hasTagInMessages(engMsgs, "action:escalated") {
		t.Errorf("expected NO action:escalated tag; the reject guard must prevent terminal-close emission. got %d messages", len(engMsgs))
	}
}

// TestResolveFinding_TriageAcceptsResolvedAction verifies the existing benign
// resolution path is preserved. Triage's primary close action — high-confidence
// benign — must still flow through resolve-finding unchanged.
//
// The confidence gate is disabled (MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED=false)
// because gate fan-out behavior is exercised by the existing tools_f1g_gate
// tests; this test isolates the action-acceptance contract.
func TestResolveFinding_TriageAcceptsResolvedAction(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-triage-res-001","action":"resolved","reason":"Routine login from established IP; baseline shows actor performs this action daily.","confidence":4}`,
			"MALLCOP_SKILL", "task:triage",
			"MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED", "false",
			"MALLCOP_CAMPFIRE_ID", campfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error on action=resolved: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result["finding_id"] != "fnd-triage-res-001" {
		t.Errorf("finding_id = %v, want fnd-triage-res-001", result["finding_id"])
	}
	if result["action"] != "resolved" {
		t.Errorf("action = %v, want resolved", result["action"])
	}

	// Campfire must have received the terminal close.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output written for action=resolved; got %d messages", len(engMsgs))
	}
	if !hasTagInMessages(engMsgs, "action:resolved") {
		t.Errorf("expected action:resolved tag; got %d messages", len(engMsgs))
	}
}

// TestResolveFinding_InvestigateAcceptsEscalatedAction is the companion test
// that pins the non-triage path. task:investigate (and the other non-triage
// skills — investigate-merge, deep-investigate, heal, escalate) MUST still
// be able to close a finding with action="escalated"; the guard is
// triage-specific. Without this test, a future change could over-broaden the
// guard and break investigate-merge's "system genuinely uncertain" close
// path (agents/investigate-merge/POST.md:136).
//
// The confidence gate is disabled for the same reason as the resolved test:
// the gate's escalated-passes-through behavior is already covered by
// TestConfidenceGate_EscalatedAction_PassesThrough in tools_f1g_gate_test.go.
func TestResolveFinding_InvestigateAcceptsEscalatedAction(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-inv-esc-001","action":"escalated","reason":"Investigation exhausted; cannot distinguish stolen-credential pattern from legitimate use.","confidence":2}`,
			"MALLCOP_SKILL", "task:investigate",
			"MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED", "false",
			"MALLCOP_CAMPFIRE_ID", campfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error on investigate+escalated: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result["finding_id"] != "fnd-inv-esc-001" {
		t.Errorf("finding_id = %v, want fnd-inv-esc-001", result["finding_id"])
	}
	if result["action"] != "escalated" {
		t.Errorf("action = %v, want escalated", result["action"])
	}

	// Investigate's escalated terminal close MUST land on the engagement campfire.
	engMsgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(engMsgs, "work:output") {
		t.Errorf("expected work:output for investigate action=escalated; got %d messages", len(engMsgs))
	}
	if !hasTagInMessages(engMsgs, "action:escalated") {
		t.Errorf("expected action:escalated tag for investigate; got %d messages", len(engMsgs))
	}
}
