// grading_test.go — F4B structural grading unit and integration tests.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/internal/exam"
)

// ---- Unit tests: per-axis pass/fail/n/a -----------------------------------------

func TestGrading_NilExpected_AllNA(t *testing.T) {
	g := computeStructuralGrade(nil, "resolved", "some reason", "resolved", false, 0, 0, false)
	if g.ChainAction != AxisNA {
		t.Errorf("chain_action: want n/a, got %q", g.ChainAction)
	}
	if g.TriageAction != AxisNA {
		t.Errorf("triage_action: want n/a, got %q", g.TriageAction)
	}
	if g.Mentions != AxisNA {
		t.Errorf("mentions: want n/a, got %q", g.Mentions)
	}
	if g.NoMentions != AxisNA {
		t.Errorf("no_mentions: want n/a, got %q", g.NoMentions)
	}
	if g.ToolsUsed != AxisNA {
		t.Errorf("tools_used: want n/a, got %q", g.ToolsUsed)
	}
	if g.Iterations != AxisNA {
		t.Errorf("iterations: want n/a, got %q", g.Iterations)
	}
	if g.QualityFloor != AxisNA {
		t.Errorf("quality_floor: want n/a, got %q", g.QualityFloor)
	}
}

// --- chain_action axis ---

func TestGrading_ChainAction_Pass(t *testing.T) {
	exp := &exam.ExpectedResolution{ChainAction: "escalated"}
	g := computeStructuralGrade(exp, "escalated", "", "", false, 0, 0, false)
	if g.ChainAction != AxisPass {
		t.Errorf("chain_action: want pass, got %q", g.ChainAction)
	}
}

func TestGrading_ChainAction_PassCaseInsensitive(t *testing.T) {
	exp := &exam.ExpectedResolution{ChainAction: "Resolved"}
	g := computeStructuralGrade(exp, "resolved", "", "", false, 0, 0, false)
	if g.ChainAction != AxisPass {
		t.Errorf("chain_action: want pass (case-insensitive), got %q", g.ChainAction)
	}
}

func TestGrading_ChainAction_Fail(t *testing.T) {
	exp := &exam.ExpectedResolution{ChainAction: "escalated"}
	g := computeStructuralGrade(exp, "resolved", "", "", false, 0, 0, false)
	if g.ChainAction != AxisFail {
		t.Errorf("chain_action: want fail, got %q", g.ChainAction)
	}
}

func TestGrading_ChainAction_NA_WhenEmpty(t *testing.T) {
	exp := &exam.ExpectedResolution{}
	g := computeStructuralGrade(exp, "resolved", "", "", false, 0, 0, false)
	if g.ChainAction != AxisNA {
		t.Errorf("chain_action: want n/a when expected empty, got %q", g.ChainAction)
	}
}

// --- chain_action: "escalate-or-stronger" semantics (mallcoppro-a42) ---

// expected="escalate-or-stronger" + actual terminal "escalated" → PASS.
// A safe escalate satisfies the "escalate-or-stronger" expectation.
func TestGrading_ChainAction_EscalateOrStronger_AcceptsEscalated(t *testing.T) {
	exp := &exam.ExpectedResolution{ChainAction: "escalate-or-stronger"}
	g := computeStructuralGrade(exp, "escalated", "", "", false, 0, 0, false)
	if g.ChainAction != AxisPass {
		t.Errorf("chain_action: want pass for escalate-or-stronger + escalated, got %q", g.ChainAction)
	}
}

// expected="escalate-or-stronger" + actual "resolved" → FAIL.
// "resolved" does not satisfy "escalate-or-stronger" — it is weaker.
func TestGrading_ChainAction_EscalateOrStronger_RejectsResolved(t *testing.T) {
	exp := &exam.ExpectedResolution{ChainAction: "escalate-or-stronger"}
	g := computeStructuralGrade(exp, "resolved", "", "", false, 0, 0, false)
	if g.ChainAction != AxisFail {
		t.Errorf("chain_action: want fail for escalate-or-stronger + resolved, got %q", g.ChainAction)
	}
}

// Strict expected="resolved" + actual "escalated" → FAIL. No semantic change
// for the strict-resolve case; only the explicit "escalate-or-stronger" token
// loosens grading.
func TestGrading_ChainAction_StrictResolved_RejectsEscalated(t *testing.T) {
	exp := &exam.ExpectedResolution{ChainAction: "resolved"}
	g := computeStructuralGrade(exp, "escalated", "", "", false, 0, 0, false)
	if g.ChainAction != AxisFail {
		t.Errorf("chain_action: want fail for strict resolved + escalated, got %q", g.ChainAction)
	}
}

// --- triage_action axis ---

func TestGrading_TriageAction_Pass(t *testing.T) {
	exp := &exam.ExpectedResolution{TriageAction: "escalated"}
	g := computeStructuralGrade(exp, "", "", "escalated", false, 0, 0, false)
	if g.TriageAction != AxisPass {
		t.Errorf("triage_action: want pass, got %q", g.TriageAction)
	}
}

func TestGrading_TriageAction_Fail(t *testing.T) {
	exp := &exam.ExpectedResolution{TriageAction: "escalated"}
	g := computeStructuralGrade(exp, "", "", "resolved", false, 0, 0, false)
	if g.TriageAction != AxisFail {
		t.Errorf("triage_action: want fail, got %q", g.TriageAction)
	}
}

func TestGrading_TriageAction_NA_WhenNoClose(t *testing.T) {
	exp := &exam.ExpectedResolution{TriageAction: "escalated"}
	// triageCloseAction empty → no triage close observed
	g := computeStructuralGrade(exp, "", "", "", false, 0, 0, false)
	if g.TriageAction != AxisNA {
		t.Errorf("triage_action: want n/a when no triage close, got %q", g.TriageAction)
	}
}

func TestGrading_TriageAction_NA_WhenExpectedEmpty(t *testing.T) {
	exp := &exam.ExpectedResolution{}
	g := computeStructuralGrade(exp, "", "", "escalated", false, 0, 0, false)
	if g.TriageAction != AxisNA {
		t.Errorf("triage_action: want n/a when expected empty, got %q", g.TriageAction)
	}
}

// --- mentions axis ---

func TestGrading_Mentions_Pass(t *testing.T) {
	exp := &exam.ExpectedResolution{
		ReasoningMustMention: []string{"external", "python-requests"},
	}
	reason := "The action involved an external collaborator via python-requests tool."
	g := computeStructuralGrade(exp, "", reason, "", false, 0, 0, false)
	if g.Mentions != AxisPass {
		t.Errorf("mentions: want pass, got %q", g.Mentions)
	}
}

func TestGrading_Mentions_PassCaseInsensitive(t *testing.T) {
	exp := &exam.ExpectedResolution{
		ReasoningMustMention: []string{"EXTERNAL"},
	}
	reason := "external collaborator was added"
	g := computeStructuralGrade(exp, "", reason, "", false, 0, 0, false)
	if g.Mentions != AxisPass {
		t.Errorf("mentions: want pass (case-insensitive), got %q", g.Mentions)
	}
}

func TestGrading_Mentions_Fail_MissingSubstring(t *testing.T) {
	exp := &exam.ExpectedResolution{
		ReasoningMustMention: []string{"external", "anomaly"},
	}
	reason := "The action involved an external collaborator."
	g := computeStructuralGrade(exp, "", reason, "", false, 0, 0, false)
	if g.Mentions != AxisFail {
		t.Errorf("mentions: want fail when substring missing, got %q", g.Mentions)
	}
}

func TestGrading_Mentions_NA_WhenEmpty(t *testing.T) {
	exp := &exam.ExpectedResolution{}
	g := computeStructuralGrade(exp, "", "any reason", "", false, 0, 0, false)
	if g.Mentions != AxisNA {
		t.Errorf("mentions: want n/a when no must-mention list, got %q", g.Mentions)
	}
}

// --- no_mentions axis ---

func TestGrading_NoMentions_Pass(t *testing.T) {
	exp := &exam.ExpectedResolution{
		ReasoningMustNotMention: []string{"known actor", "false positive"},
	}
	reason := "The external collaborator event is anomalous and requires escalation."
	g := computeStructuralGrade(exp, "", reason, "", false, 0, 0, false)
	if g.NoMentions != AxisPass {
		t.Errorf("no_mentions: want pass, got %q", g.NoMentions)
	}
}

func TestGrading_NoMentions_Fail_ForbiddenPresent(t *testing.T) {
	exp := &exam.ExpectedResolution{
		ReasoningMustNotMention: []string{"known actor"},
	}
	reason := "Dismissed because the known actor has a long history."
	g := computeStructuralGrade(exp, "", reason, "", false, 0, 0, false)
	if g.NoMentions != AxisFail {
		t.Errorf("no_mentions: want fail when forbidden substring present, got %q", g.NoMentions)
	}
}

func TestGrading_NoMentions_Pass_EmptyList(t *testing.T) {
	exp := &exam.ExpectedResolution{
		ReasoningMustNotMention: []string{},
	}
	g := computeStructuralGrade(exp, "", "any reason", "", false, 0, 0, false)
	if g.NoMentions != AxisPass {
		t.Errorf("no_mentions: want pass for empty forbidden list, got %q", g.NoMentions)
	}
}

// --- tools_used axis ---

func TestGrading_ToolsUsed_Pass_WhenRequired(t *testing.T) {
	exp := &exam.ExpectedResolution{InvestigateMustUseTools: true}
	g := computeStructuralGrade(exp, "", "", "", true, 0, 0, false)
	if g.ToolsUsed != AxisPass {
		t.Errorf("tools_used: want pass when required and used, got %q", g.ToolsUsed)
	}
}

func TestGrading_ToolsUsed_Fail_WhenRequiredButNotUsed(t *testing.T) {
	exp := &exam.ExpectedResolution{InvestigateMustUseTools: true}
	g := computeStructuralGrade(exp, "", "", "", false, 0, 0, false)
	if g.ToolsUsed != AxisFail {
		t.Errorf("tools_used: want fail when required but not used, got %q", g.ToolsUsed)
	}
}

func TestGrading_ToolsUsed_Pass_WhenNotRequired(t *testing.T) {
	exp := &exam.ExpectedResolution{InvestigateMustUseTools: false}
	// expected=false → always pass regardless of actual tool use
	g := computeStructuralGrade(exp, "", "", "", false, 0, 0, false)
	if g.ToolsUsed != AxisPass {
		t.Errorf("tools_used: want pass when not required, got %q", g.ToolsUsed)
	}
}

// --- iterations axis ---

func TestGrading_Iterations_Pass(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigateIterations: 2}
	g := computeStructuralGrade(exp, "", "", "", false, 3, 0, false)
	if g.Iterations != AxisPass {
		t.Errorf("iterations: want pass when actual >= required, got %q", g.Iterations)
	}
}

func TestGrading_Iterations_PassExact(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigateIterations: 2}
	g := computeStructuralGrade(exp, "", "", "", false, 2, 0, false)
	if g.Iterations != AxisPass {
		t.Errorf("iterations: want pass when actual == required, got %q", g.Iterations)
	}
}

func TestGrading_Iterations_Fail(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigateIterations: 5}
	g := computeStructuralGrade(exp, "", "", "", false, 2, 0, false)
	if g.Iterations != AxisFail {
		t.Errorf("iterations: want fail when actual < required, got %q", g.Iterations)
	}
}

func TestGrading_Iterations_NA_WhenZero(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigateIterations: 0}
	g := computeStructuralGrade(exp, "", "", "", false, 0, 0, false)
	if g.Iterations != AxisNA {
		t.Errorf("iterations: want n/a when min=0, got %q", g.Iterations)
	}
}

// --- quality_floor axis ---

func TestGrading_QualityFloor_Pass(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigationQuality: 4}
	g := computeStructuralGrade(exp, "", "", "", false, 0, 5, true)
	if g.QualityFloor != AxisPass {
		t.Errorf("quality_floor: want pass when rubric >= min, got %q", g.QualityFloor)
	}
}

func TestGrading_QualityFloor_PassExact(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigationQuality: 4}
	g := computeStructuralGrade(exp, "", "", "", false, 0, 4, true)
	if g.QualityFloor != AxisPass {
		t.Errorf("quality_floor: want pass when rubric == min, got %q", g.QualityFloor)
	}
}

func TestGrading_QualityFloor_Fail(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigationQuality: 4}
	g := computeStructuralGrade(exp, "", "", "", false, 0, 3, true)
	if g.QualityFloor != AxisFail {
		t.Errorf("quality_floor: want fail when rubric < min, got %q", g.QualityFloor)
	}
}

func TestGrading_QualityFloor_Pending_WhenNoRubric(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigationQuality: 4}
	// judgeRan=false: judge not yet dispatched → pending
	g := computeStructuralGrade(exp, "", "", "", false, 0, 0, false) // rubricScore=0
	if g.QualityFloor != AxisPending {
		t.Errorf("quality_floor: want pending when rubric not yet run (score=0), got %q", g.QualityFloor)
	}
}

func TestGrading_QualityFloor_Unavailable_WhenJudgeRanButScoreZero(t *testing.T) {
	// Judge was dispatched (judgeRan=true) but returned 0 (unavailable/fail-safe).
	// quality_floor should be "unavailable", not "pending".
	exp := &exam.ExpectedResolution{MinInvestigationQuality: 4}
	g := computeStructuralGrade(exp, "", "", "", false, 0, 0, true) // rubricScore=0, judgeRan=true
	if g.QualityFloor != AxisUnavailable {
		t.Errorf("quality_floor: want unavailable when judge ran but score=0, got %q", g.QualityFloor)
	}
}

func TestGrading_QualityFloor_NA_WhenZeroMin(t *testing.T) {
	exp := &exam.ExpectedResolution{MinInvestigationQuality: 0}
	g := computeStructuralGrade(exp, "", "", "", false, 0, 3, true)
	if g.QualityFloor != AxisNA {
		t.Errorf("quality_floor: want n/a when min=0, got %q", g.QualityFloor)
	}
}

// --- cross-feed test: F4B + F4C quality_floor wiring ---

func TestGrading_CrossFeed_QualityFloor_Pass(t *testing.T) {
	// Scenario has min_investigation_quality: 4 + judge returns thoroughness=5 → pass
	exp := &exam.ExpectedResolution{
		ChainAction:             "escalated",
		MinInvestigationQuality: 4,
	}
	g := computeStructuralGrade(exp, "escalated", "", "", false, 0, 5, true)
	if g.QualityFloor != AxisPass {
		t.Errorf("cross-feed pass: want pass, got %q", g.QualityFloor)
	}
	if g.ChainAction != AxisPass {
		t.Errorf("cross-feed pass: chain_action should be pass, got %q", g.ChainAction)
	}
}

func TestGrading_CrossFeed_QualityFloor_Fail(t *testing.T) {
	// Same yaml + judge returns thoroughness=3 → fail
	exp := &exam.ExpectedResolution{
		ChainAction:             "escalated",
		MinInvestigationQuality: 4,
	}
	g := computeStructuralGrade(exp, "escalated", "", "", false, 0, 3, true)
	if g.QualityFloor != AxisFail {
		t.Errorf("cross-feed fail: want fail when rubric < min, got %q", g.QualityFloor)
	}
}

// --- extractTerminalReason ---

func TestExtractTerminalReason_Valid(t *testing.T) {
	payload := `{"item_id":"abc","action":"escalated","skill":"task:triage","reason":"external collaborator detected"}`
	got := extractTerminalReason(payload)
	want := "external collaborator detected"
	if got != want {
		t.Errorf("extractTerminalReason: got %q, want %q", got, want)
	}
}

func TestExtractTerminalReason_Empty(t *testing.T) {
	got := extractTerminalReason("")
	if got != "" {
		t.Errorf("extractTerminalReason empty input: got %q, want empty", got)
	}
}

func TestExtractTerminalReason_InvalidJSON(t *testing.T) {
	got := extractTerminalReason("not json at all")
	if got != "" {
		t.Errorf("extractTerminalReason invalid JSON: got %q, want empty", got)
	}
}

// --- extractToolsUsed / extractIterationCount ---

func TestExtractToolsUsed_WithTools(t *testing.T) {
	transcript := []toolCallEntry{
		{Turn: 1, ToolUse: &toolUseEntry{Name: "check-baseline"}},
		{Turn: 2, ToolUse: &toolUseEntry{Name: "search-events"}},
	}
	if !extractToolsUsed(transcript) {
		t.Error("extractToolsUsed: expected true")
	}
}

func TestExtractToolsUsed_NoTools(t *testing.T) {
	transcript := []toolCallEntry{
		{Turn: 1},
		{Turn: 2},
	}
	if extractToolsUsed(transcript) {
		t.Error("extractToolsUsed: expected false for no tool calls")
	}
}

func TestExtractToolsUsed_Empty(t *testing.T) {
	if extractToolsUsed(nil) {
		t.Error("extractToolsUsed: expected false for nil")
	}
}

func TestExtractIterationCount(t *testing.T) {
	transcript := []toolCallEntry{
		{Turn: 1, ToolUse: &toolUseEntry{Name: "check-baseline"}},
		{Turn: 2},
		{Turn: 3, ToolUse: &toolUseEntry{Name: "search-events"}},
		{Turn: 4, ToolUse: &toolUseEntry{Name: "search-findings"}},
	}
	got := extractIterationCount(transcript)
	if got != 3 {
		t.Errorf("extractIterationCount: got %d, want 3", got)
	}
}

func TestExtractIterationCount_Empty(t *testing.T) {
	got := extractIterationCount(nil)
	if got != 0 {
		t.Errorf("extractIterationCount nil: got %d, want 0", got)
	}
}

// --- parseToolCallTranscript ---

func TestParseToolCallTranscript_Valid(t *testing.T) {
	data := `[{"turn":1,"tool_use":{"name":"check-baseline","input":{}}},{"turn":2}]`
	entries := parseToolCallTranscript([]byte(data))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ToolUse == nil || entries[0].ToolUse.Name != "check-baseline" {
		t.Errorf("first entry tool name: got %v", entries[0].ToolUse)
	}
	if entries[1].ToolUse != nil {
		t.Errorf("second entry should have no tool_use")
	}
}

func TestParseToolCallTranscript_InvalidJSON(t *testing.T) {
	entries := parseToolCallTranscript([]byte("not json"))
	if entries != nil {
		t.Error("invalid JSON should return nil")
	}
}

// --- Integration test: grading wired into scenario record write ---------------

// TestGrading_Integration_RecordHasStructuralBlock verifies that writeScenarioRecord
// emits a structural block when the scenario has an expected: block.
func TestGrading_Integration_RecordHasStructuralBlock(t *testing.T) {
	outDir := t.TempDir()

	s := &exam.Scenario{
		ID:          "AC-01",
		FailureMode: "KA",
		Category:    "access",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_001",
			Detector: "new-external-access",
			Title:    "External access granted",
			Severity: "critical",
		},
		Baseline: &exam.Baseline{
			KnownEntities: exam.KnownEntities{Actors: []string{"admin-user"}},
		},
		ExpectedResolution: &exam.ExpectedResolution{
			ChainAction:             "escalated",
			TriageAction:            "escalated",
			ReasoningMustMention:    []string{"external"},
			ReasoningMustNotMention: []string{},
			InvestigateMustUseTools: true,
			MinInvestigateIterations: 2,
			MinInvestigationQuality: 4,
		},
	}

	ts := &trackedScenario{
		scenarioID:          s.ID,
		findingID:           "academy-run-001-AC-01",
		workItemID:          "msg-001",
		terminal:            true,
		terminalAction:      "escalated",
		terminalItemID:      "item-001",
		terminalReason:      "external collaborator detected",
		triageCloseAction:   "escalated",
		toolsUsedInInvest:   true,
		maxInvestIterations: 3,
		scenario:            s,
		judgeResult: &JudgeResult{
			FindingID: "fnd_001",
			Verdict:   "pass",
			Rubric: JudgeRubric{
				ReasoningQuality:          4,
				InvestigationThoroughness: 5,
				ResolveQuality:            1,
				EscalationActionability:   4,
			},
			Rationale:      "strong evidence from tool calls",
			JudgeFixTarget: "none",
		},
	}
	now := timeNow()
	ts.postedAt = now
	ts.terminalAt = now.Add(5)

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "AC-01.json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}

	// Structural block must be present.
	if rec.Structural == nil {
		t.Fatal("structural block must not be nil when expected: block is present")
	}

	// chain_action: "escalated" matches expected "escalated" → pass
	if rec.Structural.ChainAction != AxisPass {
		t.Errorf("chain_action: want pass, got %q", rec.Structural.ChainAction)
	}

	// triage_action: "escalated" matches expected "escalated" → pass
	if rec.Structural.TriageAction != AxisPass {
		t.Errorf("triage_action: want pass, got %q", rec.Structural.TriageAction)
	}

	// mentions: "external" is in reason → pass
	if rec.Structural.Mentions != AxisPass {
		t.Errorf("mentions: want pass, got %q", rec.Structural.Mentions)
	}

	// no_mentions: empty list → pass
	if rec.Structural.NoMentions != AxisPass {
		t.Errorf("no_mentions: want pass, got %q", rec.Structural.NoMentions)
	}

	// tools_used: required and used → pass
	if rec.Structural.ToolsUsed != AxisPass {
		t.Errorf("tools_used: want pass, got %q", rec.Structural.ToolsUsed)
	}

	// iterations: 3 >= 2 → pass
	if rec.Structural.Iterations != AxisPass {
		t.Errorf("iterations: want pass, got %q", rec.Structural.Iterations)
	}

	// quality_floor: rubric=5 >= min=4 → pass
	if rec.Structural.QualityFloor != AxisPass {
		t.Errorf("quality_floor: want pass, got %q", rec.Structural.QualityFloor)
	}

	// Rubric block must be present.
	if rec.Rubric == nil {
		t.Fatal("rubric block must not be nil when judge result is set")
	}
	if rec.Rubric.Rubric.InvestigationThoroughness != 5 {
		t.Errorf("rubric.investigation_thoroughness: want 5, got %d",
			rec.Rubric.Rubric.InvestigationThoroughness)
	}
	if rec.Rubric.JudgeFixTarget != "none" {
		t.Errorf("rubric.judge_fix_target: want none, got %q", rec.Rubric.JudgeFixTarget)
	}
}

// TestGrading_Integration_StructuralFail verifies that a mismatched chain_action
// produces chain_action=fail in the record.
func TestGrading_Integration_StructuralFail(t *testing.T) {
	outDir := t.TempDir()

	s := &exam.Scenario{
		ID:          "AC-02",
		FailureMode: "KA",
		Category:    "access",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_002",
			Detector: "new-external-access",
			Title:    "External access granted",
			Severity: "high",
		},
		Baseline: &exam.Baseline{
			KnownEntities: exam.KnownEntities{Actors: []string{"user-a"}},
		},
		ExpectedResolution: &exam.ExpectedResolution{
			ChainAction: "escalated",
		},
	}

	ts := &trackedScenario{
		scenarioID:     s.ID,
		findingID:      "academy-run-001-AC-02",
		workItemID:     "msg-002",
		terminal:       true,
		terminalAction: "resolved", // WRONG — expected escalated
		terminalItemID: "item-002",
		scenario:       s,
	}
	now := timeNow()
	ts.postedAt = now
	ts.terminalAt = now.Add(5)

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "AC-02.json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}

	if rec.Structural == nil {
		t.Fatal("structural block must not be nil")
	}
	if rec.Structural.ChainAction != AxisFail {
		t.Errorf("chain_action: want fail (resolved != escalated), got %q", rec.Structural.ChainAction)
	}
}

// TestGrading_Integration_QualityFloor_Pending verifies that quality_floor is
// "pending" when no judge result is available but min_investigation_quality is set.
func TestGrading_Integration_QualityFloor_Pending(t *testing.T) {
	outDir := t.TempDir()

	s := &exam.Scenario{
		ID:          "AC-03",
		FailureMode: "KA",
		Category:    "access",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_003",
			Detector: "new-external-access",
			Title:    "Access event",
			Severity: "medium",
		},
		Baseline: &exam.Baseline{
			KnownEntities: exam.KnownEntities{Actors: []string{"user-a"}},
		},
		ExpectedResolution: &exam.ExpectedResolution{
			ChainAction:             "escalated",
			MinInvestigationQuality: 4,
		},
	}

	ts := &trackedScenario{
		scenarioID:     s.ID,
		findingID:      "academy-run-001-AC-03",
		workItemID:     "msg-003",
		terminal:       true,
		terminalAction: "escalated",
		terminalItemID: "item-003",
		scenario:       s,
		judgeResult:    nil, // no judge result
	}
	now := timeNow()
	ts.postedAt = now
	ts.terminalAt = now.Add(5)

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "AC-03.json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}

	if rec.Structural == nil {
		t.Fatal("structural block must not be nil")
	}
	if rec.Structural.QualityFloor != AxisPending {
		t.Errorf("quality_floor: want pending when no judge result, got %q", rec.Structural.QualityFloor)
	}
}

// TestGrading_Integration_QualityFloor_WiredAndPopulated verifies that
// quality_floor is NOT "pending" when ts.judgeResult is set (judge wired).
// This is the F4C done condition: quality_floor must be resolved after judge dispatch.
func TestGrading_Integration_QualityFloor_WiredAndPopulated(t *testing.T) {
	outDir := t.TempDir()

	s := &exam.Scenario{
		ID:          "AC-04",
		FailureMode: "KA",
		Category:    "access",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_004",
			Detector: "new-external-access",
			Title:    "Access event",
			Severity: "medium",
		},
		Baseline: &exam.Baseline{
			KnownEntities: exam.KnownEntities{Actors: []string{"user-b"}},
		},
		ExpectedResolution: &exam.ExpectedResolution{
			ChainAction:             "escalated",
			MinInvestigationQuality: 3,
		},
	}

	// judgeResult set with investigation_thoroughness=5 → quality_floor should be "pass"
	ts := &trackedScenario{
		scenarioID:     s.ID,
		findingID:      "academy-run-001-AC-04",
		workItemID:     "msg-004",
		terminal:       true,
		terminalAction: "escalated",
		terminalItemID: "item-004",
		scenario:       s,
		judgeResult: &JudgeResult{
			FindingID: "fnd_004",
			Verdict:   "pass",
			Rubric: JudgeRubric{
				ReasoningQuality:          4,
				InvestigationThoroughness: 5,
				ResolveQuality:            3,
				EscalationActionability:   4,
			},
			Rationale:      "judge dispatched and scored",
			JudgeFixTarget: "none",
		},
	}
	now := timeNow()
	ts.postedAt = now
	ts.terminalAt = now.Add(5)

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "AC-04.json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}

	if rec.Structural == nil {
		t.Fatal("structural block must not be nil")
	}
	// The key assertion: quality_floor must NOT be "pending" — judge was wired and ran.
	if rec.Structural.QualityFloor == AxisPending {
		t.Errorf("quality_floor: must not be pending when judge result is set; got %q", rec.Structural.QualityFloor)
	}
	// rubric=5 >= min=3 → pass
	if rec.Structural.QualityFloor != AxisPass {
		t.Errorf("quality_floor: want pass (rubric=5 >= min=3), got %q", rec.Structural.QualityFloor)
	}
	// Rubric block must be present.
	if rec.Rubric == nil {
		t.Fatal("rubric block must not be nil when judge result is set")
	}
	if rec.Rubric.Rubric.InvestigationThoroughness != 5 {
		t.Errorf("rubric.investigation_thoroughness: want 5, got %d", rec.Rubric.Rubric.InvestigationThoroughness)
	}
}

// TestGrading_Integration_QualityFloor_UnavailableWhenJudgeRanButFailed verifies
// that quality_floor is "unavailable" (not "pending") when judge was dispatched
// but returned a zero rubric score (unavailable/fail-safe path).
func TestGrading_Integration_QualityFloor_UnavailableWhenJudgeRanButFailed(t *testing.T) {
	outDir := t.TempDir()

	s := &exam.Scenario{
		ID:          "AC-05",
		FailureMode: "KA",
		Category:    "access",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_005",
			Detector: "new-external-access",
			Title:    "Access event",
			Severity: "medium",
		},
		Baseline: &exam.Baseline{
			KnownEntities: exam.KnownEntities{Actors: []string{"user-c"}},
		},
		ExpectedResolution: &exam.ExpectedResolution{
			ChainAction:             "escalated",
			MinInvestigationQuality: 3,
		},
	}

	// judgeResult set to the "unavailable" sentinel (rubric all zeros).
	ts := &trackedScenario{
		scenarioID:     s.ID,
		findingID:      "academy-run-001-AC-05",
		workItemID:     "msg-005",
		terminal:       true,
		terminalAction: "escalated",
		terminalItemID: "item-005",
		scenario:       s,
		judgeResult:    judgeUnavailable("we binary failed to spawn in test"),
	}
	now := timeNow()
	ts.postedAt = now
	ts.terminalAt = now.Add(5)

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "AC-05.json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}

	if rec.Structural == nil {
		t.Fatal("structural block must not be nil")
	}
	// Judge ran but returned 0 → "unavailable", not "pending".
	if rec.Structural.QualityFloor == AxisPending {
		t.Errorf("quality_floor: must not be pending when judge was dispatched (even if it failed); got %q", rec.Structural.QualityFloor)
	}
	if rec.Structural.QualityFloor != AxisUnavailable {
		t.Errorf("quality_floor: want unavailable when judge ran but score=0, got %q", rec.Structural.QualityFloor)
	}
	// The rubric block should still be present (the unavailable sentinel).
	if rec.Rubric == nil {
		t.Fatal("rubric block must not be nil when judge result is set (even unavailable)")
	}
	if rec.Rubric.Verdict != "unavailable" {
		t.Errorf("rubric.verdict: want unavailable, got %q", rec.Rubric.Verdict)
	}
}

// --- isTriageSkill / isInvestigateSkill ---

func TestIsTriageSkill(t *testing.T) {
	if !isTriageSkill("task:triage") {
		t.Error("task:triage should be triage skill")
	}
	if !isTriageSkill("exam:scenario") {
		t.Error("exam:scenario should be triage skill")
	}
	if isTriageSkill("task:investigate") {
		t.Error("task:investigate should not be triage skill")
	}
}

func TestIsInvestigateSkill(t *testing.T) {
	if !isInvestigateSkill("task:investigate") {
		t.Error("task:investigate should be investigate skill")
	}
	if !isInvestigateSkill("task:deep-investigate") {
		t.Error("task:deep-investigate should be investigate skill")
	}
	if !isInvestigateSkill("task:investigate-merge") {
		t.Error("task:investigate-merge should be investigate skill")
	}
	if isInvestigateSkill("task:triage") {
		t.Error("task:triage should not be investigate skill")
	}
}

// --- Aggregate report test ---

func TestWriteAggregateReport_Basic(t *testing.T) {
	outDir := t.TempDir()

	scenarios := []*exam.Scenario{
		{
			ID:          "AC-01",
			FailureMode: "KA",
			Category:    "access",
			Finding:     &exam.ScenarioFinding{ID: "fnd_001", Detector: "d", Title: "t", Severity: "high"},
			Baseline:    &exam.Baseline{KnownEntities: exam.KnownEntities{Actors: []string{"a"}}},
			ExpectedResolution: &exam.ExpectedResolution{
				ChainAction: "escalated",
			},
		},
		{
			ID:          "AC-02",
			FailureMode: "AE",
			Category:    "access",
			Finding:     &exam.ScenarioFinding{ID: "fnd_002", Detector: "d", Title: "t", Severity: "high"},
			Baseline:    &exam.Baseline{KnownEntities: exam.KnownEntities{Actors: []string{"a"}}},
			ExpectedResolution: &exam.ExpectedResolution{
				ChainAction: "resolved",
			},
		},
	}

	tracked := map[string]*trackedScenario{
		"AC-01": {
			scenarioID:     "AC-01",
			terminalAction: "escalated", // pass
			scenario:       scenarios[0],
		},
		"AC-02": {
			scenarioID:     "AC-02",
			terminalAction: "dismissed", // fail (expected: resolved)
			scenario:       scenarios[1],
		},
	}

	if err := writeAggregateReport("test-run-001", outDir, scenarios, tracked); err != nil {
		t.Fatalf("writeAggregateReport: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "report.md"))
	if err != nil {
		t.Fatalf("read report.md: %v", err)
	}

	content := string(data)

	// Must contain run ID.
	if !containsString(content, "test-run-001") {
		t.Error("report.md must contain run ID")
	}
	// Must contain total count.
	if !containsString(content, "2") {
		t.Error("report.md must mention total scenario count")
	}
	// Must contain failure mode names.
	if !containsString(content, "KA") {
		t.Error("report.md must contain KA failure mode")
	}
	if !containsString(content, "AE") {
		t.Error("report.md must contain AE failure mode")
	}
	// Must contain category.
	if !containsString(content, "access") {
		t.Error("report.md must contain access category")
	}
}

// ---- helpers ------------------------------------------------------------------

// timeNow returns the current time — indirected to allow deterministic tests.
var timeNow = func() time.Time { return time.Now() }

func containsString(s, sub string) bool {
	return len(sub) > 0 && (s == sub || len(s) >= len(sub) &&
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// Dummy usage of fmt to prevent import errors if all tests compile cleanly.
var _ = fmt.Sprintf
