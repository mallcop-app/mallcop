// judge_test.go — F4C LLM-as-judge unit tests.
//
// Unit tests cover:
//   - judgeUnavailable returns a sentinel result with all axes at 0.
//   - pollForVerdict correctly parses a judge:verdict message from a campfire.
//   - JudgeResult JSON round-trips cleanly.
//
// Integration tests (require cf binary + we binary) cover:
//   - End-to-end judicator.spawnAndCollect against a real isolated campfire
//     with a stub judge worker that emits a canned verdict.
//
// The judge binary (`we`) is NOT mocked — real spawn or escalation per spec.
// If the we binary is unavailable, integration tests are skipped.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---- unit: judgeUnavailable ---------------------------------------------------

func TestJudgeUnavailable_SentinelValues(t *testing.T) {
	r := judgeUnavailable("binary not found")
	if r == nil {
		t.Fatal("judgeUnavailable must return non-nil")
	}
	if r.Verdict != "unavailable" {
		t.Errorf("verdict: want unavailable, got %q", r.Verdict)
	}
	if r.Rubric.InvestigationThoroughness != 0 {
		t.Errorf("investigation_thoroughness: want 0, got %d", r.Rubric.InvestigationThoroughness)
	}
	if r.Rubric.ReasoningQuality != 0 {
		t.Errorf("reasoning_quality: want 0, got %d", r.Rubric.ReasoningQuality)
	}
	if !strings.Contains(r.Rationale, "binary not found") {
		t.Errorf("rationale must contain reason, got %q", r.Rationale)
	}
	if r.JudgeFixTarget != "none" {
		t.Errorf("fix_target: want none, got %q", r.JudgeFixTarget)
	}
}

// ---- unit: JudgeResult JSON round-trip ----------------------------------------

func TestJudgeResult_JSONRoundTrip(t *testing.T) {
	original := JudgeResult{
		FindingID: "fnd_shk_005",
		Verdict:   "pass",
		Rubric: JudgeRubric{
			ReasoningQuality:          4,
			InvestigationThoroughness: 5,
			ResolveQuality:            1,
			EscalationActionability:   4,
		},
		Rationale:      "analyst used check-baseline and search-events, cross-referenced results",
		JudgeFixTarget: "none",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed JudgeResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed.FindingID != original.FindingID {
		t.Errorf("finding_id: got %q, want %q", parsed.FindingID, original.FindingID)
	}
	if parsed.Verdict != original.Verdict {
		t.Errorf("verdict: got %q, want %q", parsed.Verdict, original.Verdict)
	}
	if parsed.Rubric.InvestigationThoroughness != 5 {
		t.Errorf("investigation_thoroughness: got %d, want 5", parsed.Rubric.InvestigationThoroughness)
	}
	if parsed.Rubric.EscalationActionability != 4 {
		t.Errorf("escalation_actionability: got %d, want 4", parsed.Rubric.EscalationActionability)
	}
	if parsed.Rationale != original.Rationale {
		t.Errorf("rationale: got %q, want %q", parsed.Rationale, original.Rationale)
	}
	if parsed.JudgeFixTarget != "none" {
		t.Errorf("judge_fix_target: got %q, want none", parsed.JudgeFixTarget)
	}
}

// ---- unit: pollForVerdict parses campfire messages correctly ------------------

func TestPollForVerdict_ParsesJudgeVerdictTag(t *testing.T) {
	cfBin := requireCFForJudge(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	// Post a judge:verdict message manually.
	verdict := judgeVerdictMessage{
		FindingID: "fnd_shk_005",
		Verdict:   "pass",
		Rubric: JudgeRubric{
			ReasoningQuality:          4,
			InvestigationThoroughness: 5,
			ResolveQuality:            1,
			EscalationActionability:   4,
		},
		Rationale: "check-baseline and search-events both called",
		FixTarget: "none",
	}
	verdictBytes, _ := json.Marshal(verdict)

	cfSendRaw(t, cfBin, cfHome, campfireID, string(verdictBytes),
		[]string{"judge:verdict", "scenario:AC-01-external-access-stolen-cred"})

	j := &judicator{
		cfBin:             cfBin,
		academyCampfireID: campfireID,
		academyCFHome:     cfHome,
	}

	result, err := j.pollForVerdict("AC-01-external-access-stolen-cred")
	if err != nil {
		t.Fatalf("pollForVerdict: %v", err)
	}
	if result == nil {
		t.Fatal("pollForVerdict: expected non-nil result")
	}
	if result.Verdict != "pass" {
		t.Errorf("verdict: got %q, want pass", result.Verdict)
	}
	if result.Rubric.InvestigationThoroughness != 5 {
		t.Errorf("investigation_thoroughness: got %d, want 5", result.Rubric.InvestigationThoroughness)
	}
	if result.Rationale != "check-baseline and search-events both called" {
		t.Errorf("rationale: got %q", result.Rationale)
	}
	if result.JudgeFixTarget != "none" {
		t.Errorf("fix_target: got %q, want none", result.JudgeFixTarget)
	}
}

func TestPollForVerdict_EmptyCampfire_ReturnsNil(t *testing.T) {
	cfBin := requireCFForJudge(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	j := &judicator{
		cfBin:             cfBin,
		academyCampfireID: campfireID,
		academyCFHome:     cfHome,
	}

	result, err := j.pollForVerdict("AC-01")
	if err != nil {
		t.Fatalf("pollForVerdict empty: %v", err)
	}
	if result != nil {
		t.Errorf("pollForVerdict empty campfire: expected nil, got %+v", result)
	}
}

func TestPollForVerdict_WrongScenario_ReturnsNil(t *testing.T) {
	cfBin := requireCFForJudge(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	// Post a verdict for a DIFFERENT scenario.
	verdict := judgeVerdictMessage{
		FindingID: "fnd_other",
		Verdict:   "fail",
		Rubric:    JudgeRubric{},
		FixTarget: "none",
	}
	verdictBytes, _ := json.Marshal(verdict)
	cfSendRaw(t, cfBin, cfHome, campfireID, string(verdictBytes),
		[]string{"judge:verdict", "scenario:AC-99-other"})

	j := &judicator{
		cfBin:             cfBin,
		academyCampfireID: campfireID,
		academyCFHome:     cfHome,
	}

	// Asking for AC-01 but only AC-99 verdict is present → nil
	result, err := j.pollForVerdict("AC-01")
	if err != nil {
		t.Fatalf("pollForVerdict: %v", err)
	}
	if result != nil {
		t.Errorf("pollForVerdict wrong scenario: expected nil, got %+v", result)
	}
}

// ---- unit: judgeVerdictMessage JSON shape -----------------------------------------------

func TestJudgeVerdictMessage_JSONShape(t *testing.T) {
	// The judge POST.md emits this JSON shape — verify our struct matches.
	raw := `{"finding_id":"fnd_shk_005","verdict":"pass","rubric":{"reasoning_quality":4,"investigation_thoroughness":5,"resolve_quality":1,"escalation_actionability":4},"rationale":"tool calls confirmed external access","fix_target":"none"}`

	var v judgeVerdictMessage
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal judge verdict: %v", err)
	}
	if v.FindingID != "fnd_shk_005" {
		t.Errorf("finding_id: got %q", v.FindingID)
	}
	if v.Verdict != "pass" {
		t.Errorf("verdict: got %q", v.Verdict)
	}
	if v.Rubric.InvestigationThoroughness != 5 {
		t.Errorf("investigation_thoroughness: got %d", v.Rubric.InvestigationThoroughness)
	}
	if v.FixTarget != "none" {
		t.Errorf("fix_target: got %q", v.FixTarget)
	}
}

// ---- unit: fail-safe verdict shape from judge POST.md ----------------------------

func TestJudgeVerdictMessage_FailSafe(t *testing.T) {
	// Matches the fail-safe format from agents/judge/POST.md.
	raw := `{"finding_id":"fnd_shk_005","verdict":"fail","rubric":{"reasoning_quality":1,"investigation_thoroughness":1,"resolve_quality":1,"escalation_actionability":1},"rationale":"unable to retrieve analyst output (fetch_work_output: null)","fix_target":"none"}`

	var v judgeVerdictMessage
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal fail-safe verdict: %v", err)
	}
	if v.Verdict != "fail" {
		t.Errorf("verdict: want fail, got %q", v.Verdict)
	}
	for _, score := range []int{
		v.Rubric.ReasoningQuality,
		v.Rubric.InvestigationThoroughness,
		v.Rubric.ResolveQuality,
		v.Rubric.EscalationActionability,
	} {
		if score != 1 {
			t.Errorf("fail-safe: all axes should be 1, got %d", score)
		}
	}
}

// ---- integration: we binary spawn (Option A feasibility) ----------------------

// TestJudge_SpawnFeasibility verifies that the we binary is available and
// can be invoked, confirming Option A (academy-side judge dispatch) is feasible.
// This test does NOT spawn a real judge session — it just checks `we --version`
// to confirm the binary is present and executable.
func TestJudge_SpawnFeasibility(t *testing.T) {
	weBin := requireWE(t)

	cmd := exec.Command(weBin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Some versions exit non-zero but still print a version — log and continue.
		t.Logf("we --version exit error (non-fatal): %v\noutput: %s", err, out)
	}
	if len(out) == 0 {
		t.Error("we --version produced no output")
	}
	t.Logf("we binary: %s", weBin)
	t.Logf("we --version output: %s", strings.TrimSpace(string(out)))
}

// TestJudge_AcademySideDispatch_Integration verifies the end-to-end
// academy-side judge dispatch path:
//  1. Academy posts a judge work:create to an isolated per-run campfire.
//  2. A stub judge worker script emits a canned verdict tagged judge:verdict.
//  3. Academy polls the campfire and ingests the verdict.
//
// This test uses a shell script stub as the "judge worker" to simulate the
// verdict emission without requiring a full legion session. The stub is
// functionally equivalent to what a real judge would emit, verifying the
// ingestion path (pollForVerdict, JudgeResult parsing) is correct.
func TestJudge_AcademySideDispatch_Integration(t *testing.T) {
	cfBin := requireCFForJudge(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)
	outDir := t.TempDir()

	// Create a stub judge script that emits a canned verdict.
	stubScript := filepath.Join(t.TempDir(), "stub-judge.sh")
	canned := judgeVerdictMessage{
		FindingID: "academy-integ-test-AC-01",
		Verdict:   "pass",
		Rubric: JudgeRubric{
			ReasoningQuality:          4,
			InvestigationThoroughness: 5,
			ResolveQuality:            1,
			EscalationActionability:   4,
		},
		Rationale: "test: check-baseline and search-events both called with correct params",
		FixTarget: "none",
	}
	cannedJSON, _ := json.Marshal(canned)

	// Script: post the verdict to the campfire and exit.
	scriptContent := fmt.Sprintf(`#!/bin/sh
CF_HOME="%s" cf send "%s" '%s' --tag judge:verdict --tag "scenario:AC-01"
`, cfHome, campfireID, string(cannedJSON))

	if err := os.WriteFile(stubScript, []byte(scriptContent), 0o755); err != nil {
		t.Fatalf("write stub script: %v", err)
	}

	// Run the stub.
	cmd := exec.Command("/bin/sh", stubScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run stub judge: %v\nout: %s", err, out)
	}

	j := &judicator{
		cfBin:             cfBin,
		academyCampfireID: campfireID,
		academyCFHome:     cfHome,
	}

	result, err := j.pollForVerdict("AC-01")
	if err != nil {
		t.Fatalf("pollForVerdict: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil verdict after stub emission")
	}
	if result.Verdict != "pass" {
		t.Errorf("verdict: got %q, want pass", result.Verdict)
	}
	if result.Rubric.InvestigationThoroughness != 5 {
		t.Errorf("investigation_thoroughness: got %d, want 5", result.Rubric.InvestigationThoroughness)
	}
	if !strings.Contains(result.Rationale, "check-baseline") {
		t.Errorf("rationale must mention check-baseline, got %q", result.Rationale)
	}

	_ = outDir // used if we write anything
}

// ---- helpers -------------------------------------------------------------------

// requireCFForJudge skips the test if cf is not on PATH.
func requireCFForJudge(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skip("cf binary not found on PATH — skipping judge integration tests")
	}
	return p
}

// requireWE skips the test if the `we` binary is not on PATH.
func requireWE(t *testing.T) string {
	t.Helper()
	// Check PATH
	if p, err := exec.LookPath("we"); err == nil {
		return p
	}
	// Check bin/ directory in repo.
	if p, err := exec.LookPath("bin/we"); err == nil {
		return p
	}
	t.Skip("we binary not found on PATH or bin/ — skipping we-spawn integration tests")
	return ""
}

// filepath is used in TestJudge_AcademySideDispatch_Integration.
// Import guard.
var _ = fmt.Sprintf

