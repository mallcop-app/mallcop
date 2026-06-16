// tools_heal_e2e_test.go — E2E integration tests for the heal-broaden workflow.
//
// Design source: docs/design/heal-broaden.md §5, §8, item mallcoppro-7bb.
//
// # What this tests
//
// These tests exercise the complete heal-broaden end-to-end path from a synthetic
// log_format_drift finding through spawn-claude-code-fix to resolve/annotate.
// They simulate exactly what the heal POST.md agent does:
//
//  1. A synthetic finding is injected into an isolated engagement campfire.
//  2. spawn-claude-code-fix is called (via spawnClaudeCodeFix) with a stub-claude
//     binary that writes a deterministic file diff in the worktree.
//  3. The heal agent's post-spawn logic runs: annotate-finding + resolve-finding.
//  4. Assertions are made on (a) finding closed as resolved/escalated with the
//     correct annotation, (b) budget counter incremented, (c) transcript persisted,
//     (d) worktree cleaned up.
//
// Test 1 (TestHealE2E_Success): stub-claude exits 0, writes a file inside the
// mallcop-legion-prompts subtree, success_criterion is "true" (no-op pass),
// gh pr create stub returns a fake pr_url.
//
// Test 2 (TestHealE2E_Failure): stub-claude exits 1; finding closed as escalated,
// no PR, transcript captured, message-operator ping posted to operator campfire.
//
// # Campfire requirement
//
// Both tests require cf on PATH. They create isolated campfires (fresh CF_HOME)
// so they never touch production campfires. Tests skip gracefully if cf is absent.
//
// # Stub wiring
//
//   - CLAUDE_CLI_OVERRIDE_PATH  → stub-claude binary (happy or fail mode)
//   - MALLCOP_HEAL_SKIP_GH_PR=1 → skip real gh pr create; returns synthetic pr_url
//   - MALLCOP_HEAL_BUDGET_DIR   → isolated temp dir
//   - MALLCOP_TRANSCRIPT_DIR    → temp dir (transcript assertions)
//   - MALLCOP_CAMPFIRE_ID       → isolated engagement campfire
//   - MALLCOP_OPERATOR_CAMPFIRE_ID → isolated operator campfire (failure test)
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

// ---- campfire helpers (reuse pattern from tools_f1g_test.go) ------------------

// requireCFForE2E skips the test if cf is not on PATH.
func requireCFForE2E(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skip("cf binary not found on PATH — skipping heal E2E campfire tests")
	}
	return p
}

// newE2ECampfire creates an isolated campfire: fresh CF_HOME + cf init + cf create.
// Returns (cfHome, campfireID). Sets CF_HOME for the test via t.Setenv.
func newE2ECampfire(t *testing.T, cfBin, label string) (cfHome, campfireID string) {
	t.Helper()
	cfHome = t.TempDir()
	t.Setenv("CF_HOME", cfHome)

	initOut, err := runE2ECFCmd(cfBin, cfHome, "init")
	if err != nil {
		t.Fatalf("cf init: %v\nout: %s", err, initOut)
	}

	createOut, err := runE2ECFCmd(cfBin, cfHome, "create", "--description", "heal-e2e-"+label+"-"+t.Name())
	if err != nil {
		t.Fatalf("cf create: %v\nout: %s", err, createOut)
	}

	for _, line := range strings.Split(strings.TrimSpace(createOut), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isHexStrE2E(line) {
			campfireID = line
			break
		}
	}
	if campfireID == "" {
		t.Fatalf("could not parse campfire ID from cf create output: %s", createOut)
	}
	return cfHome, campfireID
}

// newE2ECampfireWithHome creates a campfire under an existing cfHome (for tests
// that need two campfires sharing a single CF_HOME identity).
func newE2ECampfireWithHome(t *testing.T, cfBin, cfHome, label string) string {
	t.Helper()
	createOut, err := runE2ECFCmd(cfBin, cfHome, "create", "--description", "heal-e2e-"+label+"-"+t.Name())
	if err != nil {
		t.Fatalf("cf create %s: %v\nout: %s", label, err, createOut)
	}
	for _, line := range strings.Split(strings.TrimSpace(createOut), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isHexStrE2E(line) {
			return line
		}
	}
	t.Fatalf("could not parse campfire ID from cf create output: %s", createOut)
	return ""
}

// runE2ECFCmd runs cf with the given cfHome and args, returns combined output.
func runE2ECFCmd(cfBin, cfHome string, args ...string) (string, error) {
	cmd := exec.Command(cfBin, args...) // #nosec G204
	cmd.Env = setEnvE2E(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// setEnvE2E replaces or adds key=val in the base env slice.
func setEnvE2E(base []string, key, val string) []string {
	prefix := key + "="
	result := make([]string, 0, len(base)+1)
	for _, e := range base {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			continue
		}
		result = append(result, e)
	}
	return append(result, key+"="+val)
}

// isHexStrE2E returns true if every character is a hex digit.
func isHexStrE2E(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// readE2ECampfireMessages reads all messages from campfireID via cf read --json --all.
func readE2ECampfireMessages(t *testing.T, cfBin, cfHome, campfireID string) []map[string]interface{} {
	t.Helper()
	cmd := exec.Command(cfBin, "read", campfireID, "--json", "--all") // #nosec G204
	cmd.Env = setEnvE2E(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.Output()
	if err != nil {
		t.Logf("cf read %s: %v; raw: %s", campfireID[:8], err, out)
		return nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var msgs []map[string]interface{}
	if jsonErr := json.Unmarshal(out, &msgs); jsonErr != nil {
		t.Logf("cf read parse error: %v; raw: %s", jsonErr, out)
		return nil
	}
	return msgs
}

// e2eHasTag returns true if any message in msgs has the given tag value.
func e2eHasTag(msgs []map[string]interface{}, wantTag string) bool {
	for _, msg := range msgs {
		tagsRaw, ok := msg["tags"]
		if !ok {
			continue
		}
		switch tags := tagsRaw.(type) {
		case []interface{}:
			for _, tag := range tags {
				if s, ok := tag.(string); ok && s == wantTag {
					return true
				}
			}
		case []string:
			for _, tag := range tags {
				if tag == wantTag {
					return true
				}
			}
		}
	}
	return false
}

// e2eMessageContaining returns the first message payload whose string representation
// contains all of the given substrings (case-sensitive). Returns nil if not found.
func e2eMessageContaining(msgs []map[string]interface{}, substrings ...string) map[string]interface{} {
	for _, msg := range msgs {
		payload, _ := json.Marshal(msg)
		s := string(payload)
		all := true
		for _, sub := range substrings {
			if !strings.Contains(s, sub) {
				all = false
				break
			}
		}
		if all {
			return msg
		}
	}
	return nil
}

// ---- inject synthetic finding -------------------------------------------------

// injectSyntheticFinding posts a synthetic log_format_drift finding to the
// engagement campfire to simulate what the detector emits before heal is called.
// Returns the message ID.
func injectSyntheticFinding(t *testing.T, cfBin, cfHome, campfireID, findingID string) string {
	t.Helper()
	payload := fmt.Sprintf(
		`{"finding_id":%q,"class":"log_format_drift","app_name":"nginx-prod","severity":"medium",`+
			`"reason":"nginx access log line no longer matches parser template: missing request_id field",`+
			`"evidence":{"unmatched_count":147,"sample_line":"[USER_DATA_BEGIN]192.0.2.1 GET /api/v2/check 200[USER_DATA_END]"},`+
			`"timestamp":"2026-04-29T08:00:00Z"}`,
		findingID,
	)
	cmd := exec.Command(cfBin, "send", campfireID, payload, // #nosec G204
		"--tag", "finding:"+findingID,
		"--tag", "class:log_format_drift",
		"--tag", "work:input",
	)
	cmd.Env = setEnvE2E(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("inject finding: cf send: %v\nout: %s", err, out)
	}
	// Extract message ID from cf send output.
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 16 && isHexStrE2E(line) {
			return line
		}
	}
	return ""
}

// ---- heal workflow simulator --------------------------------------------------

// runHealWorkflow simulates what the heal POST.md agent does after
// spawn-claude-code-fix returns. It posts annotate-finding and resolve-finding
// (on success) or annotate-finding + resolve-finding (escalated) + message-operator
// (on failure) to the campfire.
//
// This is NOT the Claude agent — it is a deterministic Go simulation of the
// documented heal procedure (heal-broaden.md §5, steps 8-9) so the test can verify
// the campfire side effects without spending real Forge tokens.
func runHealWorkflow(t *testing.T, findingID string, spawnResult *spawnClaudeFixResult) {
	t.Helper()
	if spawnResult.Outcome == "success" {
		// Step 8 (design §5): annotate-finding with pr_url.
		annotateJSON := fmt.Sprintf(
			`{"finding_id":%q,"note":"Fix proposed: %s","tags":["heal:proposed","binding:log_format_drift"]}`,
			findingID, spawnResult.PRUrl,
		)
		if err := dispatchActionTool("annotate-finding", annotateJSON); err != nil {
			t.Fatalf("annotate-finding (success path): %v", err)
		}

		// Step 8: resolve-finding action=resolved.
		resolveJSON := fmt.Sprintf(
			`{"finding_id":%q,"action":"resolved","reason":"Fix proposed at %s; awaiting human review per heal-pr-workflow","confidence":4}`,
			findingID, spawnResult.PRUrl,
		)
		if err := dispatchActionTool("resolve-finding", resolveJSON); err != nil {
			t.Fatalf("resolve-finding (success path): %v", err)
		}
	} else {
		// Step 9 (design §5): annotate-finding with failure reason.
		annotateJSON := fmt.Sprintf(
			`{"finding_id":%q,"note":"Heal attempt failed: %s","tags":["heal:failed","binding:log_format_drift"]}`,
			findingID, spawnResult.Reason,
		)
		if err := dispatchActionTool("annotate-finding", annotateJSON); err != nil {
			t.Fatalf("annotate-finding (failure path): %v", err)
		}

		// Step 9: resolve-finding action=escalated.
		resolveJSON := fmt.Sprintf(
			`{"finding_id":%q,"action":"escalated","reason":"Heal could not produce a working patch: %s; operator review needed","confidence":2}`,
			findingID, spawnResult.Reason,
		)
		if err := dispatchActionTool("resolve-finding", resolveJSON); err != nil {
			t.Fatalf("resolve-finding (failure path): %v", err)
		}

		// C6 / design §8: message-operator ping on failure (MALLCOP_OPERATOR_CAMPFIRE_ID).
		msgJSON := fmt.Sprintf(
			`{"finding_id":%q,"message":"Heal attempt failed for finding %s: %s","category":"open-question"}`,
			findingID, findingID, spawnResult.Reason,
		)
		if err := dispatchActionTool("message-operator", msgJSON); err != nil {
			t.Fatalf("message-operator (failure path): %v", err)
		}
	}
}

// ---- Test 1: happy path (stub exits 0, PR created) ----------------------------

// TestHealE2E_Success is the gate test proving the broadened heal E2E works.
//
// Scenario: synthetic log_format_drift finding → spawn-claude-code-fix (stub-claude
// writes agents/heal-test/POST.md inside the mallcop-legion-prompts subtree) →
// success_criterion="true" (no-op pass) → gh pr create stub returns a fake pr_url.
//
// Assertions (design item mallcoppro-7bb):
//   (a) finding closed as resolved with annotation pr_url=<stub_url> on campfire.
//   (b) budget counter incremented for log_format_drift class (AttemptsToday=1,
//       ConsecutiveFailures=0).
//   (c) transcript persisted at expected path.
//   (d) worktree cleaned up (no /tmp/heal-e2e-* directories remain).
func TestHealE2E_Success(t *testing.T) {
	cfBin := requireCFForE2E(t)
	setTempBudgetDir(t)

	// Isolated campfires.
	cfHome, engCampfire := newE2ECampfire(t, cfBin, "eng")

	transcriptDir := t.TempDir()
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", transcriptDir)
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1") // stub gh: returns https://github.com/stub/repo/pull/0
	t.Setenv("MALLCOP_CAMPFIRE_ID", engCampfire)
	t.Setenv("CF_HOME", cfHome)

	// Fake MALLCOP_RUN_ID so transcript path is deterministic.
	t.Setenv("MALLCOP_RUN_ID", "heal-run")

	// Build a stub-claude that commits inside the mallcop-legion-prompts subtree.
	stubDir := t.TempDir()
	stub := writeClaudeStub(t, stubDir, "claude", "happy")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	// Patch the allowlist so mallcop-legion-prompts → our temp test repo.
	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	// Inject a synthetic log_format_drift finding into the engagement campfire.
	findingID := "e2e-lfd-001"
	injectSyntheticFinding(t, cfBin, cfHome, engCampfire, findingID)

	// ── Core: call spawn-claude-code-fix ─────────────────────────────────────
	input := spawnClaudeFixInput{
		FindingID:        findingID,
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "Add parser template entry for missing request_id field in nginx access log parser (log_format_drift: 147 unmatched lines).",
		SuccessCriterion: "true", // no-op pass per item spec
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-" + findingID,
	}
	spawnResult, err := spawnClaudeCodeFix(input, "work/heal-"+findingID)
	if err != nil {
		t.Fatalf("spawnClaudeCodeFix: unexpected hard error: %v", err)
	}

	// ── Assert spawn outcome ──────────────────────────────────────────────────
	if spawnResult.Outcome != "success" {
		t.Fatalf("expected outcome=success, got %q (reason: %s)", spawnResult.Outcome, spawnResult.Reason)
	}

	stubPRURL := "https://github.com/stub/repo/pull/0" // MALLCOP_HEAL_SKIP_GH_PR stub value
	if spawnResult.PRUrl != stubPRURL {
		t.Errorf("expected pr_url=%q, got %q", stubPRURL, spawnResult.PRUrl)
	}

	// ── Assertion (c): transcript persisted ──────────────────────────────────
	if spawnResult.TranscriptPath == "" {
		t.Error("transcript_path is empty")
	} else if _, statErr := os.Stat(spawnResult.TranscriptPath); statErr != nil {
		t.Errorf("transcript file not found at %q: %v", spawnResult.TranscriptPath, statErr)
	}

	// ── Assertion (d): worktree cleaned up ────────────────────────────────────
	// spawnClaudeCodeFix calls cleanupWorktree via defer. The worktree path is
	// constructed as /tmp/heal-<findingID>-<ts> by createHealWorktree.
	// We verify that no heal worktree with our finding ID remains in /tmp.
	safeFID := sanitizePathComponent(findingID)
	tmpEntries, readErr := os.ReadDir(os.TempDir())
	if readErr == nil {
		for _, entry := range tmpEntries {
			if strings.HasPrefix(entry.Name(), "heal-"+safeFID+"-") {
				t.Errorf("worktree not cleaned up: found %q in %s", entry.Name(), os.TempDir())
			}
		}
	}

	// ── Simulate heal POST.md agent: annotate + resolve ───────────────────────
	captureStdout(t, func() {
		runHealWorkflow(t, findingID, spawnResult)
	})

	// ── Assertion (a): campfire shows resolved with pr_url annotation ─────────
	msgs := readE2ECampfireMessages(t, cfBin, cfHome, engCampfire)

	// (a-1): annotate-finding message with heal:proposed tag must appear.
	if !e2eHasTag(msgs, "heal:proposed") {
		t.Error("expected campfire message with tag 'heal:proposed' (annotate-finding success path)")
	}

	// (a-2): resolve-finding message with action:resolved must appear.
	if !e2eHasTag(msgs, "action:resolved") {
		t.Error("expected campfire message with tag 'action:resolved'")
	}

	// (a-3): the pr_url must appear in the annotation note on the campfire.
	if e2eMessageContaining(msgs, stubPRURL) == nil {
		t.Errorf("expected campfire message containing pr_url %q", stubPRURL)
	}

	// ── Assertion (b): budget counter incremented ─────────────────────────────
	bg, budgetErr := loadBudgetGate()
	if budgetErr != nil {
		t.Fatalf("loadBudgetGate: %v", budgetErr)
	}
	e := bg.Classes[findingID]
	if e == nil {
		t.Fatal("expected budget class entry after successful spawn")
	}
	if e.AttemptsToday != 1 {
		t.Errorf("expected AttemptsToday=1 for %q, got %d", findingID, e.AttemptsToday)
	}
	if e.ConsecutiveFailures != 0 {
		t.Errorf("expected ConsecutiveFailures=0 after success, got %d", e.ConsecutiveFailures)
	}

	t.Logf("TestHealE2E_Success: outcome=%q pr_url=%q transcript=%q budget_attempts=%d",
		spawnResult.Outcome, spawnResult.PRUrl, spawnResult.TranscriptPath, e.AttemptsToday)
}

// ---- Test 2: failure path (stub exits 1) --------------------------------------

// TestHealE2E_Failure verifies that when stub-claude exits 1 the heal workflow
// correctly closes the finding as escalated (not resolved), posts no PR,
// captures the transcript, and pings the operator via message-operator.
//
// Assertions (design item mallcoppro-7bb):
//   (a) finding closed as escalated (action:escalated on campfire), no PR URL.
//   (b) budget counter incremented with ConsecutiveFailures=1.
//   (c) transcript persisted at expected path (captured even on failure).
//   (d) message-operator ping posted to operator campfire.
func TestHealE2E_Failure(t *testing.T) {
	cfBin := requireCFForE2E(t)
	setTempBudgetDir(t)

	// Two isolated campfires under the same CF_HOME identity.
	cfHome, engCampfire := newE2ECampfire(t, cfBin, "eng")
	opCampfire := newE2ECampfireWithHome(t, cfBin, cfHome, "op")

	transcriptDir := t.TempDir()
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", transcriptDir)
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1")
	t.Setenv("MALLCOP_CAMPFIRE_ID", engCampfire)
	t.Setenv("MALLCOP_OPERATOR_CAMPFIRE_ID", opCampfire)
	t.Setenv("CF_HOME", cfHome)
	t.Setenv("MALLCOP_RUN_ID", "heal-run")

	// Stub-claude that exits 1.
	stubDir := t.TempDir()
	stub := writeClaudeStub(t, stubDir, "claude", "fail")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	// Patch the allowlist.
	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	// Inject a synthetic finding.
	findingID := "e2e-lfd-002"
	injectSyntheticFinding(t, cfBin, cfHome, engCampfire, findingID)

	// ── Core: call spawn-claude-code-fix ─────────────────────────────────────
	input := spawnClaudeFixInput{
		FindingID:        findingID,
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "Add parser template entry for missing request_id field in nginx access log parser.",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-" + findingID,
	}
	spawnResult, err := spawnClaudeCodeFix(input, "work/heal-"+findingID)
	if err != nil {
		t.Fatalf("spawnClaudeCodeFix: unexpected hard error: %v", err)
	}

	// ── Assert spawn outcome ──────────────────────────────────────────────────
	if spawnResult.Outcome != "failure" {
		t.Fatalf("expected outcome=failure (stub exits 1), got %q", spawnResult.Outcome)
	}
	if !strings.Contains(spawnResult.Reason, "exit_nonzero") {
		t.Errorf("expected 'exit_nonzero' in reason, got %q", spawnResult.Reason)
	}
	// (a): no PR URL on failure.
	if spawnResult.PRUrl != "" {
		t.Errorf("expected empty pr_url on failure, got %q", spawnResult.PRUrl)
	}

	// ── Assertion (c): transcript persisted even on failure ───────────────────
	if spawnResult.TranscriptPath == "" {
		t.Error("transcript_path is empty on failure path")
	} else if _, statErr := os.Stat(spawnResult.TranscriptPath); statErr != nil {
		t.Errorf("transcript file not found at %q: %v", spawnResult.TranscriptPath, statErr)
	}

	// ── Simulate heal POST.md agent: annotate + escalated resolve + message-operator
	captureStdout(t, func() {
		runHealWorkflow(t, findingID, spawnResult)
	})

	// ── Assertion (a): campfire shows escalated, NOT resolved ─────────────────
	engMsgs := readE2ECampfireMessages(t, cfBin, cfHome, engCampfire)

	if !e2eHasTag(engMsgs, "action:escalated") {
		t.Error("expected campfire message with tag 'action:escalated' (finding closed as escalated)")
	}
	if e2eHasTag(engMsgs, "action:resolved") {
		t.Error("finding must NOT be closed as resolved when spawn fails")
	}
	if !e2eHasTag(engMsgs, "heal:failed") {
		t.Error("expected campfire message with tag 'heal:failed' on annotate-finding failure path")
	}

	// ── Assertion (d): message-operator ping posted to operator campfire ──────
	opMsgs := readE2ECampfireMessages(t, cfBin, cfHome, opCampfire)
	if len(opMsgs) == 0 {
		t.Fatal("expected operator campfire message (message-operator ping), got none")
	}
	if e2eMessageContaining(opMsgs, findingID) == nil {
		t.Errorf("expected operator campfire message mentioning finding_id %q", findingID)
	}
	// The message-operator call uses category:open-question.
	if !e2eHasTag(opMsgs, "category:open-question") {
		t.Logf("operator campfire messages: %+v", opMsgs)
		t.Error("expected operator campfire message with tag 'category:open-question'")
	}

	// ── Assertion (b): budget counter incremented as failure ──────────────────
	bg, budgetErr := loadBudgetGate()
	if budgetErr != nil {
		t.Fatalf("loadBudgetGate: %v", budgetErr)
	}
	e := bg.Classes[findingID]
	if e == nil {
		t.Fatal("expected budget class entry after failed spawn")
	}
	if e.AttemptsToday < 1 {
		t.Errorf("expected AttemptsToday>=1 for %q, got %d", findingID, e.AttemptsToday)
	}
	if e.ConsecutiveFailures < 1 {
		t.Errorf("expected ConsecutiveFailures>=1 after spawn failure, got %d", e.ConsecutiveFailures)
	}

	t.Logf("TestHealE2E_Failure: outcome=%q reason=%q transcript=%q budget_failures=%d op_msgs=%d",
		spawnResult.Outcome, spawnResult.Reason, spawnResult.TranscriptPath,
		e.ConsecutiveFailures, len(opMsgs))
}

// ── Supplementary: worktree cleanup assertion without campfire dependency ──────

// TestHealE2E_WorktreeCleanup_NoCFRequired verifies worktree cleanup in isolation
// (no campfire dependency). Uses the happy stub + SKIP_GH_PR.
// This is a belt-and-suspenders check for assertion (d) that runs even when cf
// is unavailable.
func TestHealE2E_WorktreeCleanup_NoCFRequired(t *testing.T) {
	setTempBudgetDir(t)
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", t.TempDir())
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1")
	t.Setenv("MALLCOP_RUN_ID", "heal-run")

	stubDir := t.TempDir()
	stub := writeClaudeStub(t, stubDir, "claude", "happy")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	findingID := "e2e-cleanup-003"
	input := spawnClaudeFixInput{
		FindingID:        findingID,
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "Add parser template for log_format_drift finding.",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-" + findingID,
	}

	result, err := spawnClaudeCodeFix(input, "work/heal-"+findingID)
	if err != nil {
		t.Fatalf("spawnClaudeCodeFix: %v", err)
	}
	if result.Outcome != "success" {
		t.Fatalf("expected success, got %q (reason: %s)", result.Outcome, result.Reason)
	}

	// Worktree must be gone after spawnClaudeCodeFix returns.
	safeFID := sanitizePathComponent(findingID)
	tmpEntries, readErr := os.ReadDir(os.TempDir())
	if readErr != nil {
		t.Fatalf("ReadDir /tmp: %v", readErr)
	}
	for _, entry := range tmpEntries {
		name := entry.Name()
		if strings.HasPrefix(name, "heal-"+safeFID+"-") {
			t.Errorf("worktree not cleaned up: found %s in %s", name, os.TempDir())
		}
	}

	// Transcript must exist.
	if result.TranscriptPath == "" {
		t.Error("transcript_path is empty")
	} else if _, statErr := os.Stat(result.TranscriptPath); statErr != nil {
		t.Errorf("transcript not found at %q: %v", result.TranscriptPath, statErr)
	}

	// Branch name must match expected.
	wantBranch := "work/heal-" + findingID
	if result.Branch != wantBranch {
		t.Errorf("branch = %q, want %q", result.Branch, wantBranch)
	}

	// Budget recorded as success.
	bg, budgetErr := loadBudgetGate()
	if budgetErr != nil {
		t.Fatalf("loadBudgetGate: %v", budgetErr)
	}
	e := bg.Classes[findingID]
	if e == nil || e.AttemptsToday != 1 || e.ConsecutiveFailures != 0 {
		t.Errorf("budget: expected AttemptsToday=1, ConsecutiveFailures=0; got %+v", e)
	}

	t.Logf("TestHealE2E_WorktreeCleanup: outcome=%q transcript=%q", result.Outcome, result.TranscriptPath)
}

// ── Supplementary: transcript naming convention ────────────────────────────────

// TestHealE2E_TranscriptPath_Convention verifies the transcript path follows the
// expected naming convention: <MALLCOP_TRANSCRIPT_DIR>/<MALLCOP_RUN_ID>/heal-<findingID>.jsonl
// This is part of assertion (c) from the item spec.
func TestHealE2E_TranscriptPath_Convention(t *testing.T) {
	transcriptBase := t.TempDir()
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", transcriptBase)
	t.Setenv("MALLCOP_RUN_ID", "e2e-run-test")

	findingID := "lfd-convention-check"
	filePath, dir, err := healTranscriptPath(findingID)
	if err != nil {
		t.Fatalf("healTranscriptPath: %v", err)
	}

	expectedDir := filepath.Join(transcriptBase, "e2e-run-test")
	if dir != expectedDir {
		t.Errorf("transcript dir = %q, want %q", dir, expectedDir)
	}

	expectedFile := filepath.Join(expectedDir, "heal-lfd-convention-check.jsonl")
	if filePath != expectedFile {
		t.Errorf("transcript path = %q, want %q", filePath, expectedFile)
	}
}
