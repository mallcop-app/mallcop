// tools_heal_spawn_test.go — Unit tests for spawn-claude-code-fix tool.
//
// Design source: docs/design/heal-broaden.md §4, §10 constraints C1-C9.
//
// # Test strategy
//
// Unit/integration tests — no real Claude Code spend. The claude CLI invocation
// is replaced by a stub bash script via CLAUDE_CLI_OVERRIDE_PATH. The gh CLI is
// bypassed via MALLCOP_HEAL_SKIP_GH_PR=1. All tests use real on-disk git repos
// (t.TempDir) so worktree, diff, and success criterion are exercised for real.
// Budget gate uses MALLCOP_HEAL_BUDGET_DIR override.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- stub helpers -----------------------------------------------------------

// writeClaudeStub writes a stub claude binary to dir/<name> and returns its path.
// mode controls the stub's behavior:
//
//	"happy"  — commits a file inside the allowed subtree; emits stream-json result.
//	"outsub" — commits a file OUTSIDE the subtree.
//	"sleep"  — sleeps indefinitely (timeout test).
//	"fail"   — exits 1.
//	"tokens" — emits 170k tokens result envelope, exits 0, no commits.
func writeClaudeStub(t *testing.T, dir, name, mode string) string {
	t.Helper()
	stub := filepath.Join(dir, name)
	var script string
	switch mode {
	case "happy":
		script = `#!/usr/bin/env bash
set -e
ADD_DIR=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--add-dir" ]]; then ADD_DIR="$2"; shift 2; else shift; fi
done
if [[ -n "$ADD_DIR" ]]; then
  mkdir -p "$ADD_DIR/agents/heal-test"
  echo "# stub patch" > "$ADD_DIR/agents/heal-test/POST.md"
  cd "$ADD_DIR"
  git config user.email "stub@test.example"
  git config user.name "Stub"
  git add agents/heal-test/POST.md
  git commit -m "heal: stub patch"
fi
echo '{"type":"result","subtype":"success","usage":{"input_tokens":1000,"output_tokens":500}}'
`
	case "outsub":
		script = `#!/usr/bin/env bash
set -e
ADD_DIR=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--add-dir" ]]; then ADD_DIR="$2"; shift 2; else shift; fi
done
if [[ -n "$ADD_DIR" ]]; then
  mkdir -p "$ADD_DIR/internal/secret"
  echo "oops" > "$ADD_DIR/internal/secret/file.go"
  cd "$ADD_DIR"
  git config user.email "stub@test.example"
  git config user.name "Stub"
  git add internal/secret/file.go
  git commit -m "oops: outside subtree"
fi
echo '{"type":"result","subtype":"success","usage":{"input_tokens":200,"output_tokens":100}}'
`
	case "sleep":
		// Use exec to replace the bash process with sleep directly, so that
		// killing the process group kills sleep immediately without orphan children.
		script = "#!/usr/bin/env bash\nexec sleep 9999\n"
	case "fail":
		script = `#!/usr/bin/env bash
echo '{"type":"result","subtype":"error","usage":{"input_tokens":100,"output_tokens":50}}'
exit 1
`
	case "tokens":
		// Emits 170k total tokens (>150k cap) without committing anything.
		script = `#!/usr/bin/env bash
echo '{"type":"result","subtype":"success","usage":{"input_tokens":120000,"output_tokens":50000}}'
`
	default:
		t.Fatalf("unknown stub mode %q", mode)
	}
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub %s: %v", stub, err)
	}
	return stub
}

// newTestRepo creates a minimal git repo with a remote (bare clone) so that
// git worktree add ... origin/main succeeds. Returns the working repo path.
func newTestRepo(t *testing.T) string {
	t.Helper()
	remoteDir := t.TempDir()
	runGitT(t, remoteDir, "init", "--bare")

	repoDir := t.TempDir()
	runGitT(t, repoDir, "init", "-b", "main")
	runGitT(t, repoDir, "config", "user.email", "test@example.com")
	runGitT(t, repoDir, "config", "user.name", "Test")

	readme := filepath.Join(repoDir, "README.md")
	if err := os.WriteFile(readme, []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runGitT(t, repoDir, "add", "README.md")
	runGitT(t, repoDir, "commit", "-m", "init")
	runGitT(t, repoDir, "remote", "add", "origin", remoteDir)
	runGitT(t, repoDir, "push", "-u", "origin", "main")
	return repoDir
}

// runGitT runs a git command in dir, failing the test on error.
func runGitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) // #nosec G204
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\noutput: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// patchAllowlist temporarily replaces the allowlist entry for alias with repoDir.
func patchAllowlist(t *testing.T, alias, repoDir string) {
	t.Helper()
	old, exists := healRepoAllowlist[alias]
	healRepoAllowlist[alias] = repoDir
	t.Cleanup(func() {
		if exists {
			healRepoAllowlist[alias] = old
		} else {
			delete(healRepoAllowlist, alias)
		}
	})
}

// ---- tests ------------------------------------------------------------------

// TestSpawnClaudeCodeFix_RejectsNonAllowlistedRepo verifies that an unknown
// alias returns outcome=failure with repo_not_allowed, no worktree created,
// and the budget gate is NOT charged.
func TestSpawnClaudeCodeFix_RejectsNonAllowlistedRepo(t *testing.T) {
	setTempBudgetDir(t)
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", t.TempDir())

	input := spawnClaudeFixInput{
		FindingID:        "test-001",
		RepoAlias:        "not-in-allowlist-xyz",
		TaskDescription:  "test task",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-test-001",
	}
	result, err := spawnClaudeCodeFix(input, "work/heal-test-001")
	if err != nil {
		t.Fatalf("expected no hard error, got: %v", err)
	}
	if result.Outcome != "failure" {
		t.Errorf("expected outcome=failure, got %q", result.Outcome)
	}
	if !strings.Contains(result.Reason, "repo_not_allowed") {
		t.Errorf("expected 'repo_not_allowed' in reason, got %q", result.Reason)
	}

	// Budget gate must NOT have been charged (no RecordAttempt for allowlist miss).
	bg, err := loadBudgetGate()
	if err != nil {
		t.Fatalf("loadBudgetGate: %v", err)
	}
	if e, ok := bg.Classes["test-001"]; ok && e.AttemptsToday > 0 {
		t.Errorf("expected 0 budget attempts for rejected repo, got %d", e.AttemptsToday)
	}
}

// TestSpawnClaudeCodeFix_RejectsBudgetExhausted verifies that a pre-exhausted
// budget gate returns outcome=failure with a budget-related reason.
func TestSpawnClaudeCodeFix_RejectsBudgetExhausted(t *testing.T) {
	setTempBudgetDir(t)
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", t.TempDir())

	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	now := time.Now().UTC()
	bg, err := loadBudgetGateAt(now)
	if err != nil {
		t.Fatalf("loadBudgetGate: %v", err)
	}
	for i := 0; i < healBudgetDailyCapPerClass; i++ {
		if err := bg.RecordAttempt("log_format_drift", true, 100); err != nil {
			t.Fatalf("RecordAttempt[%d]: %v", i, err)
		}
	}

	input := spawnClaudeFixInput{
		FindingID:        "log_format_drift",
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "test task",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-log-drift",
	}
	result, err := spawnClaudeCodeFix(input, "work/heal-log-drift")
	if err != nil {
		t.Fatalf("expected no hard error, got: %v", err)
	}
	if result.Outcome != "failure" {
		t.Errorf("expected outcome=failure, got %q", result.Outcome)
	}
	if !strings.Contains(result.Reason, "daily_cap_reached") &&
		!strings.Contains(result.Reason, "frozen_until") &&
		!strings.Contains(result.Reason, "daily_freeze") {
		t.Errorf("expected budget reason, got %q", result.Reason)
	}
}

// TestSpawnClaudeCodeFix_HappyPath_StubClaudeBinary exercises the full tool
// path with a stub that commits inside the allowed subtree.
func TestSpawnClaudeCodeFix_HappyPath_StubClaudeBinary(t *testing.T) {
	setTempBudgetDir(t)
	transcriptDir := t.TempDir()
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", transcriptDir)
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1")

	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	stubDir := t.TempDir()
	stub := writeClaudeStub(t, stubDir, "claude", "happy")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	input := spawnClaudeFixInput{
		FindingID:        "happy-abc",
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "Add a new POST.md for the heal-test agent",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-happy-abc",
	}
	result, err := spawnClaudeCodeFix(input, "work/heal-happy-abc")
	if err != nil {
		t.Fatalf("expected no hard error, got: %v", err)
	}
	if result.Outcome != "success" {
		t.Errorf("expected outcome=success, got %q (reason: %s)", result.Outcome, result.Reason)
	}
	if result.Branch != "work/heal-happy-abc" {
		t.Errorf("expected branch=work/heal-happy-abc, got %q", result.Branch)
	}
	if result.PRUrl == "" {
		t.Error("expected non-empty pr_url")
	}
	if result.TranscriptPath == "" {
		t.Error("expected non-empty transcript_path")
	}

	// C8: transcript file must exist.
	runDir := filepath.Join(transcriptDir, "heal-run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		t.Fatalf("read transcript dir %q: %v", runDir, err)
	}
	if len(entries) == 0 {
		t.Error("expected transcript file written, dir is empty")
	}

	// Budget charged as success.
	bg, err := loadBudgetGate()
	if err != nil {
		t.Fatalf("loadBudgetGate: %v", err)
	}
	e := bg.Classes["happy-abc"]
	if e == nil || e.AttemptsToday != 1 {
		t.Errorf("expected AttemptsToday=1, got %v", e)
	}
	if e != nil && e.ConsecutiveFailures != 0 {
		t.Errorf("expected ConsecutiveFailures=0 after success, got %d", e.ConsecutiveFailures)
	}
}

// TestSpawnClaudeCodeFix_DiffOutsideSubtree_Rejected verifies that files
// committed outside the subtree cause outcome=failure via validateHealDiff.
func TestSpawnClaudeCodeFix_DiffOutsideSubtree_Rejected(t *testing.T) {
	setTempBudgetDir(t)
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", t.TempDir())
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1")

	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	stubDir := t.TempDir()
	stub := writeClaudeStub(t, stubDir, "claude", "outsub")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	input := spawnClaudeFixInput{
		FindingID:        "outsub-def",
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "test outside subtree",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-outsub-def",
	}
	result, err := spawnClaudeCodeFix(input, "work/heal-outsub-def")
	if err != nil {
		t.Fatalf("expected no hard error, got: %v", err)
	}
	if result.Outcome != "failure" {
		t.Errorf("expected outcome=failure, got %q", result.Outcome)
	}
	if !strings.Contains(result.Reason, "diff_validation") {
		t.Errorf("expected 'diff_validation' in reason, got %q", result.Reason)
	}

	// Budget charged as failure.
	bg, err := loadBudgetGate()
	if err != nil {
		t.Fatalf("loadBudgetGate: %v", err)
	}
	e := bg.Classes["outsub-def"]
	if e == nil || e.AttemptsToday < 1 {
		t.Error("expected budget attempt recorded after diff failure")
	}
	if e != nil && e.ConsecutiveFailures < 1 {
		t.Error("expected ConsecutiveFailures >= 1 after diff failure")
	}
}

// TestSpawnClaudeCodeFix_TimeoutKillsClaude verifies that a sleeping stub is
// killed by context timeout and the tool returns outcome=failure.
// Uses MALLCOP_HEAL_TIMEOUT_OVERRIDE_SECS=2 for a 2-second timeout.
func TestSpawnClaudeCodeFix_TimeoutKillsClaude(t *testing.T) {
	setTempBudgetDir(t)
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", t.TempDir())
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1")
	t.Setenv("MALLCOP_HEAL_TIMEOUT_OVERRIDE_SECS", "2")

	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	stubDir := t.TempDir()
	stub := writeClaudeStub(t, stubDir, "claude", "sleep")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	input := spawnClaudeFixInput{
		FindingID:        "timeout-ghi",
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "test timeout",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-timeout-ghi",
	}
	result, err := spawnClaudeCodeFix(input, "work/heal-timeout-ghi")
	if err != nil {
		t.Fatalf("expected no hard error, got: %v", err)
	}
	if result.Outcome != "failure" {
		t.Errorf("expected outcome=failure, got %q (reason: %s)", result.Outcome, result.Reason)
	}
	// Context kill → non-zero exit → exit_nonzero reason.
	if !strings.Contains(result.Reason, "exit_nonzero") &&
		!strings.Contains(result.Reason, "spawn_error") &&
		!strings.Contains(result.Reason, "timeout") {
		t.Errorf("expected timeout/exit reason, got %q", result.Reason)
	}

	// Budget charged as failure.
	bg, err := loadBudgetGate()
	if err != nil {
		t.Fatalf("loadBudgetGate: %v", err)
	}
	e := bg.Classes["timeout-ghi"]
	if e == nil || e.AttemptsToday < 1 {
		t.Error("expected budget attempt recorded for timeout")
	}
	if e != nil && e.ConsecutiveFailures < 1 {
		t.Error("expected ConsecutiveFailures >= 1 after timeout")
	}
}

// TestSpawnClaudeCodeFix_TokenCapWarning verifies that tokens > 150k cap
// increments tokenCapWarningCounter (belt-and-suspenders C5 check).
func TestSpawnClaudeCodeFix_TokenCapWarning(t *testing.T) {
	setTempBudgetDir(t)
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", t.TempDir())
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1")

	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	stubDir := t.TempDir()
	// "tokens" stub: emits 170k tokens, exits 0, no commits (empty diff passes).
	stub := writeClaudeStub(t, stubDir, "claude", "tokens")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	before := tokenCapWarningCounter

	input := spawnClaudeFixInput{
		FindingID:        "tokencap-jkl",
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "test token cap",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-tokencap-jkl",
	}
	result, err := spawnClaudeCodeFix(input, "work/heal-tokencap-jkl")
	if err != nil {
		t.Fatalf("spawnClaudeCodeFix: %v", err)
	}

	// Regardless of outcome, warning counter must have incremented.
	if tokenCapWarningCounter <= before {
		t.Errorf("expected tokenCapWarningCounter to increment: before=%d after=%d tokens_used=%d",
			before, tokenCapWarningCounter, result.TokensUsed)
	}
}

// TestSpawnClaudeCodeFix_FailureRecordsToBudget verifies that a failed spawn
// increments ConsecutiveFailures in the persisted budget gate.
func TestSpawnClaudeCodeFix_FailureRecordsToBudget(t *testing.T) {
	setTempBudgetDir(t)
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", t.TempDir())
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1")

	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	stubDir := t.TempDir()
	stub := writeClaudeStub(t, stubDir, "claude", "fail")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	input := spawnClaudeFixInput{
		FindingID:        "fail-mno",
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "test failure budget",
		SuccessCriterion: "true",
		ModelTier:        "sonnet",
		BranchHint:       "work/heal-fail-mno",
	}
	result, err := spawnClaudeCodeFix(input, "work/heal-fail-mno")
	if err != nil {
		t.Fatalf("expected no hard error, got: %v", err)
	}
	if result.Outcome != "failure" {
		t.Errorf("expected outcome=failure, got %q", result.Outcome)
	}

	// Re-read budget from disk.
	bg, err := loadBudgetGate()
	if err != nil {
		t.Fatalf("loadBudgetGate: %v", err)
	}
	e := bg.Classes["fail-mno"]
	if e == nil {
		t.Fatal("expected budget class entry after failure")
	}
	if e.AttemptsToday != 1 {
		t.Errorf("expected AttemptsToday=1, got %d", e.AttemptsToday)
	}
	if e.ConsecutiveFailures != 1 {
		t.Errorf("expected ConsecutiveFailures=1, got %d", e.ConsecutiveFailures)
	}
}

// TestSpawnClaudeCodeFix_InputValidation checks required-field and enum validation.
func TestSpawnClaudeCodeFix_InputValidation(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"empty_input", "", "input JSON required"},
		{"missing_finding_id", `{"repo_alias":"mallcop","task_description":"x","success_criterion":"y"}`, "finding_id is required"},
		{"missing_repo_alias", `{"finding_id":"f1","task_description":"x","success_criterion":"y"}`, "repo_alias is required"},
		{"missing_task", `{"finding_id":"f1","repo_alias":"mallcop","success_criterion":"y"}`, "task_description is required"},
		{"missing_criterion", `{"finding_id":"f1","repo_alias":"mallcop","task_description":"x"}`, "success_criterion is required"},
		{"invalid_tier", `{"finding_id":"f1","repo_alias":"mallcop","task_description":"x","success_criterion":"y","model_tier":"invalid"}`, "model_tier must be haiku|sonnet|opus"},
		{"bad_branch", `{"finding_id":"f1","repo_alias":"mallcop","task_description":"x","success_criterion":"y","branch_hint":"main"}`, "does not match required pattern"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runSpawnClaudeCodeFix(tc.input)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error to contain %q, got %q", tc.want, err.Error())
			}
		})
	}
}

// TestHealTierToModel verifies the tier→model mapping (design §4.6).
func TestHealTierToModel(t *testing.T) {
	cases := []struct{ tier, model string }{
		{"haiku", "claude-haiku-4-5"},
		{"sonnet", "claude-sonnet-4-5"},
		{"opus", "claude-opus-4-6"},
		{"unknown", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := healTierToModel(tc.tier)
		if got != tc.model {
			t.Errorf("healTierToModel(%q) = %q, want %q", tc.tier, got, tc.model)
		}
	}
}

// TestHealStripEnvKeys verifies CLAUDECODE/CLAUDE_CODE_ENTRYPOINT are stripped.
func TestHealStripEnvKeys(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"CLAUDECODE=1",
		"CLAUDE_CODE_ENTRYPOINT=/path",
		"CLAUDE_SESSION_ID=abc",
		"FORGE_API_KEY=sk-test",
	}
	got := healStripEnvKeys(env, "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_SESSION_ID")
	for _, kv := range got {
		if strings.HasPrefix(kv, "CLAUDECODE=") ||
			strings.HasPrefix(kv, "CLAUDE_CODE_ENTRYPOINT=") ||
			strings.HasPrefix(kv, "CLAUDE_SESSION_ID=") {
			t.Errorf("key not stripped: %q (env=%v)", kv, got)
		}
	}
	found := false
	for _, kv := range got {
		if kv == "FORGE_API_KEY=sk-test" {
			found = true
		}
	}
	if !found {
		t.Error("FORGE_API_KEY should not have been stripped")
	}
}

// TestHealBranchRegex verifies ^work/heal- enforcement.
func TestHealBranchRegex(t *testing.T) {
	valid := []string{"work/heal-abc", "work/heal-finding-001", "work/heal-"}
	invalid := []string{"main", "feature/heal-abc", "work/fix-abc", "work/", ""}
	for _, b := range valid {
		if !healBranchRegex.MatchString(b) {
			t.Errorf("expected %q to match", b)
		}
	}
	for _, b := range invalid {
		if healBranchRegex.MatchString(b) {
			t.Errorf("expected %q NOT to match", b)
		}
	}
}

// TestSpawnClaudeCodeFix_DispatchRegistered verifies tool registration in
// actionTools map and dispatchActionTool switch.
func TestSpawnClaudeCodeFix_DispatchRegistered(t *testing.T) {
	if !actionTools["spawn-claude-code-fix"] {
		t.Error("spawn-claude-code-fix must be in actionTools map")
	}
	err := dispatchActionTool("spawn-claude-code-fix", "")
	if err == nil {
		t.Fatal("expected error for empty JSON")
	}
	if strings.Contains(err.Error(), "unknown action tool") {
		t.Errorf("expected handler to be reached, got: %v", err)
	}
}

// TestHealParseResultEnvelope verifies the stream-json parser handles valid,
// non-result-type, and invalid JSON gracefully.
func TestHealParseResultEnvelope(t *testing.T) {
	cases := []struct {
		name        string
		data        string
		wantInput   int64
		wantOutput  int64
		wantNonNil  bool
	}{
		{
			name:       "valid_result",
			data:       `{"type":"result","subtype":"success","usage":{"input_tokens":1234,"output_tokens":567}}`,
			wantInput:  1234,
			wantOutput: 567,
			wantNonNil: true,
		},
		{
			name:       "non_result_type",
			data:       `{"type":"assistant","usage":{"input_tokens":100}}`,
			wantNonNil: true,
		},
		{
			name:       "invalid_json",
			data:       `not-json`,
			wantNonNil: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := healParseResultEnvelope([]byte(tc.data))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNonNil && result == nil {
				t.Fatal("expected non-nil result")
			}
			if result != nil && result.InputTokens != tc.wantInput {
				t.Errorf("InputTokens = %d, want %d", result.InputTokens, tc.wantInput)
			}
			if result != nil && result.OutputTokens != tc.wantOutput {
				t.Errorf("OutputTokens = %d, want %d", result.OutputTokens, tc.wantOutput)
			}
		})
	}
}

// TestSpawnClaudeCodeFix_OutputSchema verifies JSON output contains required
// schema fields and that timestamps are RFC3339.
func TestSpawnClaudeCodeFix_OutputSchema(t *testing.T) {
	setTempBudgetDir(t)
	t.Setenv("MALLCOP_TRANSCRIPT_DIR", t.TempDir())
	t.Setenv("MALLCOP_HEAL_SKIP_GH_PR", "1")

	repoDir := newTestRepo(t)
	patchAllowlist(t, "mallcop-legion-prompts", repoDir)

	stubDir := t.TempDir()
	stub := writeClaudeStub(t, stubDir, "claude", "happy")
	t.Setenv("CLAUDE_CLI_OVERRIDE_PATH", stub)

	input := spawnClaudeFixInput{
		FindingID:        "schema-pqr",
		RepoAlias:        "mallcop-legion-prompts",
		TaskDescription:  "test schema validation",
		SuccessCriterion: "true",
		ModelTier:        "haiku",
		BranchHint:       "work/heal-schema-pqr",
	}
	result, err := spawnClaudeCodeFix(input, "work/heal-schema-pqr")
	if err != nil {
		t.Fatalf("spawnClaudeCodeFix: %v", err)
	}

	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Required fields in all outcomes.
	for _, k := range []string{"finding_id", "outcome", "timestamp"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing required field %q in output", k)
		}
	}

	// Success-specific fields.
	if result.Outcome == "success" {
		for _, k := range []string{"pr_url", "branch", "tokens_used", "wall_seconds", "transcript_path"} {
			if _, ok := m[k]; !ok {
				t.Errorf("missing success field %q", k)
			}
		}
	}

	if m["finding_id"] != "schema-pqr" {
		t.Errorf("finding_id = %v, want schema-pqr", m["finding_id"])
	}
	if ts, ok := m["timestamp"].(string); ok {
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("timestamp %q not RFC3339: %v", ts, err)
		}
	} else {
		t.Error("timestamp missing or not string")
	}
}

// Consume fmt import used in test output formatting.
var _ = fmt.Sprintf
