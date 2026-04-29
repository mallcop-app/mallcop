// tools_heal_spawn.go — spawn-claude-code-fix tool for the heal-broaden epic.
//
// Design source: docs/design/heal-broaden.md §4, §10 constraints C1-C9.
//
// # Constraint enforcement
//
//   - C1: Repo allowlist enforced via resolveHealRepo before any spawn.
//   - C2: Legion + mallcop-pro hard-excluded by absolute path (in allowlist code).
//   - C3: Subtree pathspec enforced post-dispatch via validateHealDiff.
//   - C4: No gh pr merge — only gh pr create --draft.
//   - C5: PerAttemptTimeout (20m), PerAttemptTokenCap (150k), daily cap (20),
//         consecutive-failure freeze enforced via BudgetGate.
//   - C6: Single dispatch per finding; no retry loop.
//   - C7: FORGE_API_KEY / FORGE_BASE_URL inherited by spawned Claude.
//   - C8: Transcript captured and persisted for every dispatch.
//   - C9: (Heal POST.md — outside this file's scope; documented there.)
//
// # Testing hooks
//
//   - CLAUDE_CLI_OVERRIDE_PATH: replaces the claude binary for unit tests.
//   - GH_CLI_OVERRIDE_PATH: replaces the gh binary for unit tests.
//   - MALLCOP_HEAL_BUDGET_DIR: overrides budget cache dir (inherited from budget lib).
//   - MALLCOP_HEAL_SKIP_GH_PR: when set to "1", skips gh pr create and returns a
//     synthetic pr_url (used in tests that don't want to exercise gh).
//   - MALLCOP_HEAL_TIMEOUT_OVERRIDE_SECS: overrides the 20m wall cap (tests only).
//
// This file lives in the same package as tools_f1g.go and is registered via
// dispatchActionTool in that file.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// healBranchRegex enforces the work/heal-* branch naming requirement.
var healBranchRegex = regexp.MustCompile(`^work/heal-`)

// spawnClaudeFixInput is the input_schema for spawn-claude-code-fix (§4.1).
type spawnClaudeFixInput struct {
	FindingID        string `json:"finding_id"`
	RepoAlias        string `json:"repo_alias"`
	TaskDescription  string `json:"task_description"`
	SuccessCriterion string `json:"success_criterion"`
	ModelTier        string `json:"model_tier,omitempty"`
	BranchHint       string `json:"branch_hint,omitempty"`
}

// spawnClaudeFixResult is the output schema for spawn-claude-code-fix (§4.2/4.3).
type spawnClaudeFixResult struct {
	FindingID      string `json:"finding_id"`
	Outcome        string `json:"outcome"` // "success" or "failure"
	PRUrl          string `json:"pr_url,omitempty"`
	Branch         string `json:"branch,omitempty"`
	TokensUsed     int64  `json:"tokens_used"`
	WallSeconds    int    `json:"wall_seconds"`
	TranscriptPath string `json:"transcript_path,omitempty"`
	Timestamp      string `json:"timestamp"`
	Reason         string `json:"reason,omitempty"` // failure only
}

// tokenCapWarningCounter tracks cases where token usage exceeded the cap.
// In-process counter; belt-and-suspenders for C5.
var tokenCapWarningCounter int

// runSpawnClaudeCodeFix is the entry point for --tool spawn-claude-code-fix.
func runSpawnClaudeCodeFix(inputJSON string) error {
	if inputJSON == "" {
		return errors.New("spawn-claude-code-fix: input JSON required (missing positional argument)")
	}
	var input spawnClaudeFixInput
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("spawn-claude-code-fix: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("spawn-claude-code-fix: finding_id is required")
	}
	if input.RepoAlias == "" {
		return errors.New("spawn-claude-code-fix: repo_alias is required")
	}
	if input.TaskDescription == "" {
		return errors.New("spawn-claude-code-fix: task_description is required")
	}
	if len(input.TaskDescription) > 4096 {
		return fmt.Errorf("spawn-claude-code-fix: task_description exceeds max length 4096 (got %d)", len(input.TaskDescription))
	}
	if input.SuccessCriterion == "" {
		return errors.New("spawn-claude-code-fix: success_criterion is required")
	}
	if len(input.SuccessCriterion) > 1024 {
		return fmt.Errorf("spawn-claude-code-fix: success_criterion exceeds max length 1024 (got %d)", len(input.SuccessCriterion))
	}
	if input.ModelTier == "" {
		input.ModelTier = "sonnet"
	}
	validTiers := map[string]bool{"haiku": true, "sonnet": true, "opus": true}
	if !validTiers[input.ModelTier] {
		return fmt.Errorf("spawn-claude-code-fix: model_tier must be haiku|sonnet|opus, got %q", input.ModelTier)
	}

	// Derive branch name (C4, design §7).
	branch := input.BranchHint
	if branch == "" {
		branch = "work/heal-" + input.FindingID
	}
	if !healBranchRegex.MatchString(branch) {
		return fmt.Errorf("spawn-claude-code-fix: branch %q does not match required pattern ^work/heal-", branch)
	}

	result, err := spawnClaudeCodeFix(input, branch)
	if err != nil {
		return err
	}
	return emitJSON(result)
}

// spawnClaudeCodeFix is the core implementation, separated for testability.
func spawnClaudeCodeFix(input spawnClaudeFixInput, branch string) (*spawnClaudeFixResult, error) {
	startTime := time.Now()
	ts := startTime.UTC().Format(time.RFC3339)

	// ── C1/C2: Allowlist check ────────────────────────────────────────────────
	repoPath, subtree, err := resolveHealRepo(input.RepoAlias)
	if err != nil {
		return &spawnClaudeFixResult{
			FindingID: input.FindingID,
			Outcome:   "failure",
			Reason:    err.Error(),
			Timestamp: ts,
		}, nil
	}

	// ── C5: Budget gate — CanAttempt ─────────────────────────────────────────
	bg, err := loadBudgetGate()
	if err != nil {
		return nil, fmt.Errorf("spawn-claude-code-fix: load budget gate: %w", err)
	}
	if err := bg.CanAttempt(input.FindingID); err != nil {
		return &spawnClaudeFixResult{
			FindingID: input.FindingID,
			Outcome:   "failure",
			Reason:    err.Error(),
			Timestamp: ts,
		}, nil
	}

	// ── Transcript path (C8) ──────────────────────────────────────────────────
	transcriptPath, transcriptDir, err := healTranscriptPath(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("spawn-claude-code-fix: transcript path: %w", err)
	}
	if err := os.MkdirAll(transcriptDir, 0o755); err != nil {
		return nil, fmt.Errorf("spawn-claude-code-fix: create transcript dir: %w", err)
	}

	// ── Worktree setup ────────────────────────────────────────────────────────
	worktreePath, cleanupWorktree, err := createHealWorktree(repoPath, input.FindingID, branch)
	if err != nil {
		return &spawnClaudeFixResult{
			FindingID:      input.FindingID,
			Outcome:        "failure",
			Reason:         "worktree_create: " + err.Error(),
			Timestamp:      ts,
			TranscriptPath: transcriptPath,
		}, nil
	}

	var tokensUsed int64
	success := false

	defer func() {
		// C5: RecordAttempt on all exit paths.
		if recordErr := bg.RecordAttempt(input.FindingID, success, int(tokensUsed)); recordErr != nil {
			log.Printf("spawn-claude-code-fix: record budget attempt: %v", recordErr)
		}
	}()

	defer cleanupWorktree()

	// ── C5: Timeout context ───────────────────────────────────────────────────
	timeout := bg.PerAttemptTimeout()
	if override := os.Getenv("MALLCOP_HEAL_TIMEOUT_OVERRIDE_SECS"); override != "" {
		if secs, parseErr := parseIntEnv(override); parseErr == nil && secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// ── Build system prompt ───────────────────────────────────────────────────
	systemPrompt := buildHealSystemPrompt(input.TaskDescription, input.SuccessCriterion, branch, subtree)
	extraEnv := healChildEnv(input.FindingID)

	// ── C8: Transcript file ───────────────────────────────────────────────────
	transcriptFile, err := os.Create(transcriptPath) // #nosec G304
	if err != nil {
		return &spawnClaudeFixResult{
			FindingID: input.FindingID,
			Outcome:   "failure",
			Reason:    "transcript_open: " + err.Error(),
			Timestamp: ts,
		}, nil
	}
	defer transcriptFile.Close()

	// ── Spawn Claude Code ─────────────────────────────────────────────────────
	inferResult, exitCode, spawnErr := spawnClaude(ctx, worktreePath, "heal-fixer", systemPrompt, extraEnv, transcriptFile, input.ModelTier)

	wallSeconds := int(time.Since(startTime).Seconds())
	if inferResult != nil {
		tokensUsed = inferResult.InputTokens + inferResult.OutputTokens
	}

	// C5: Token cap warning (belt-and-suspenders; already happened, log only).
	if tokensUsed > int64(bg.PerAttemptTokenCap()) {
		tokenCapWarningCounter++
		log.Printf("spawn-claude-code-fix: WARNING token cap exceeded: used=%d cap=%d finding=%s (counter=%d)",
			tokensUsed, bg.PerAttemptTokenCap(), input.FindingID, tokenCapWarningCounter)
	}

	if spawnErr != nil {
		return &spawnClaudeFixResult{
			FindingID:      input.FindingID,
			Outcome:        "failure",
			Reason:         "spawn_error: " + spawnErr.Error(),
			TokensUsed:     tokensUsed,
			WallSeconds:    wallSeconds,
			TranscriptPath: transcriptPath,
			Timestamp:      ts,
		}, nil
	}
	if exitCode != 0 {
		return &spawnClaudeFixResult{
			FindingID:      input.FindingID,
			Outcome:        "failure",
			Reason:         fmt.Sprintf("exit_nonzero: claude exited %d", exitCode),
			TokensUsed:     tokensUsed,
			WallSeconds:    wallSeconds,
			TranscriptPath: transcriptPath,
			Timestamp:      ts,
		}, nil
	}

	// ── C3: Subtree pathspec validation ───────────────────────────────────────
	if err := runDiffValidation(worktreePath, input.RepoAlias, subtree); err != nil {
		return &spawnClaudeFixResult{
			FindingID:      input.FindingID,
			Outcome:        "failure",
			Reason:         "diff_validation: " + err.Error(),
			TokensUsed:     tokensUsed,
			WallSeconds:    wallSeconds,
			TranscriptPath: transcriptPath,
			Timestamp:      ts,
		}, nil
	}

	// ── Success criterion ─────────────────────────────────────────────────────
	if err := runSuccessCriterion(ctx, worktreePath, input.SuccessCriterion); err != nil {
		return &spawnClaudeFixResult{
			FindingID:      input.FindingID,
			Outcome:        "failure",
			Reason:         "success_criterion_not_met: " + err.Error(),
			TokensUsed:     tokensUsed,
			WallSeconds:    wallSeconds,
			TranscriptPath: transcriptPath,
			Timestamp:      ts,
		}, nil
	}

	// ── C4: Create draft PR (no merge) ────────────────────────────────────────
	prURL, err := createDraftPR(ctx, worktreePath, input.FindingID, branch, input.TaskDescription)
	if err != nil {
		return &spawnClaudeFixResult{
			FindingID:      input.FindingID,
			Outcome:        "failure",
			Reason:         "pr_create_failed: " + err.Error(),
			TokensUsed:     tokensUsed,
			WallSeconds:    wallSeconds,
			TranscriptPath: transcriptPath,
			Timestamp:      ts,
		}, nil
	}

	success = true
	return &spawnClaudeFixResult{
		FindingID:      input.FindingID,
		Outcome:        "success",
		PRUrl:          prURL,
		Branch:         branch,
		TokensUsed:     tokensUsed,
		WallSeconds:    wallSeconds,
		TranscriptPath: transcriptPath,
		Timestamp:      ts,
	}, nil
}

// ---- spawn glue (inlined from legion/internal/inference) -----------------
//
// legion's inference package is github.com/3dl-dev/legion/internal/inference,
// which is not a dependency of github.com/thirdiv/mallcop-legion. Rather than
// introduce a cross-module dependency (with all the version-pinning overhead),
// we inline the ~50 lines of spawn glue here. The interface is identical.

// healInferResult holds token counts extracted from claude's stream-json output.
type healInferResult struct {
	InputTokens  int64
	OutputTokens int64
	ExitCode     int
}

// spawnClaude invokes the claude CLI for a heal session. CLAUDE_CLI_OVERRIDE_PATH
// replaces the binary path for tests (stub injection).
func spawnClaude(
	ctx context.Context,
	workDir, agentType, systemPrompt string,
	extraEnv []string,
	transcriptSink *os.File,
	modelTier string,
) (*healInferResult, int, error) {
	claudeBin := "claude"
	if override := os.Getenv("CLAUDE_CLI_OVERRIDE_PATH"); override != "" {
		claudeBin = override
	}

	args := []string{claudeBin, "--print", "--agent", agentType, "--dangerously-skip-permissions"}
	if workDir != "" {
		args = append(args, "--add-dir", workDir)
	}
	args = append(args, "--verbose", "--output-format", "stream-json")
	if modelTier != "" {
		if modelName := healTierToModel(modelTier); modelName != "" {
			args = append(args, "--model", modelName)
		}
	}
	args = append(args,
		"--append-system-prompt", systemPrompt,
		"Work this item per the system prompt above.",
	)

	cmd := exec.CommandContext(ctx, args[0], args[1:]...) // #nosec G204
	cmd.Dir = workDir
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	childEnv := append(os.Environ(), extraEnv...)
	childEnv = healStripEnvKeys(childEnv, "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_SESSION_ID")
	cmd.Env = childEnv

	pr, pw, err := os.Pipe()
	if err != nil {
		cmd.Stdout = os.Stderr
		if startErr := cmd.Start(); startErr != nil {
			return nil, 0, fmt.Errorf("claude start: %w", startErr)
		}
		waitErr := cmd.Wait()
		exitCode := exitCodeFrom(waitErr)
		return nil, exitCode, nil
	}
	cmd.Stdout = pw

	if startErr := cmd.Start(); startErr != nil {
		_ = pw.Close()
		_ = pr.Close()
		return nil, 0, fmt.Errorf("claude start: %w", startErr)
	}
	_ = pw.Close()

	resultCh := make(chan *healInferResult, 1)
	go func() {
		defer close(resultCh)
		result, scanErr := healScanStreamJSON(pr, transcriptSink)
		_ = pr.Close()
		if scanErr != nil {
			resultCh <- nil
			return
		}
		resultCh <- result
	}()

	waitErr := cmd.Wait()
	exitCode := exitCodeFrom(waitErr)

	// Force-close the read end of the pipe after cmd.Wait() returns.
	// When the child process is killed (context cancel), bash may keep child
	// processes (e.g., `sleep 9999`) alive briefly, holding the write end open
	// and blocking the scanner goroutine. Closing pr here unblocks the scanner
	// immediately. The goroutine handles the double-close gracefully (os.File
	// Close is a no-op on a closed fd).
	_ = pr.Close()

	var inferResult *healInferResult
	select {
	case res, ok := <-resultCh:
		if ok && res != nil {
			inferResult = res
		}
	case <-time.After(2 * time.Second):
		// Scanner still blocked after pipe close — proceed with zero tokens.
	}
	if inferResult == nil {
		inferResult = &healInferResult{ExitCode: exitCode}
	}
	inferResult.ExitCode = exitCode
	return inferResult, exitCode, nil
}

// exitCodeFrom extracts the exit code from a Wait() error.
func exitCodeFrom(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

// healScanStreamJSON reads claude's stream-json stdout, writes lines to sink,
// and parses the final "result" envelope for token counts.
func healScanStreamJSON(r *os.File, sink *os.File) (*healInferResult, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lastLine []byte
	for scanner.Scan() {
		line := scanner.Bytes()
		if sink != nil {
			_, _ = sink.Write(append(line, '\n'))
		}
		lastLine = append(lastLine[:0], line...)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("stream-json scan: %w", err)
	}
	if len(lastLine) == 0 {
		return &healInferResult{}, nil
	}
	return healParseResultEnvelope(lastLine)
}

// healParseResultEnvelope parses the last stream-json event for token counts.
func healParseResultEnvelope(data []byte) (*healInferResult, error) {
	var envelope struct {
		Type  string `json:"type"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return &healInferResult{}, nil
	}
	if envelope.Type != "result" {
		return &healInferResult{}, nil
	}
	return &healInferResult{
		InputTokens:  envelope.Usage.InputTokens,
		OutputTokens: envelope.Usage.OutputTokens,
	}, nil
}

// healTierToModel maps tier name to model identifier (mirrors legion's tierToModel).
func healTierToModel(tier string) string {
	switch tier {
	case "haiku":
		return "claude-haiku-4-5"
	case "sonnet":
		return "claude-sonnet-4-5"
	case "opus":
		return "claude-opus-4-6"
	default:
		return ""
	}
}

// healStripEnvKeys removes env entries whose key matches any given key prefix.
func healStripEnvKeys(env []string, keys ...string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		skip := false
		for _, k := range keys {
			if strings.HasPrefix(e, k+"=") {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, e)
		}
	}
	return out
}

// ---- helpers ----------------------------------------------------------------

// createHealWorktree creates a fresh git worktree for the heal session.
func createHealWorktree(repoPath, findingID, branch string) (string, func(), error) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	safeFindingID := sanitizePathComponent(findingID)
	worktreePath := filepath.Join(os.TempDir(), "heal-"+safeFindingID+"-"+ts)

	cmd := exec.Command("git", "worktree", "add", "-b", branch, worktreePath, "origin/main") // #nosec G204
	cmd.Dir = repoPath
	cmd.Stderr = os.Stderr
	if out, err := cmd.Output(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", nil, fmt.Errorf("git worktree add: %w; stderr: %s; stdout: %s", err, exitErr.Stderr, out)
		}
		return "", nil, fmt.Errorf("git worktree add: %w", err)
	}

	cleanup := func() {
		rmCmd := exec.Command("git", "worktree", "remove", "--force", worktreePath) // #nosec G204
		rmCmd.Dir = repoPath
		rmCmd.Stderr = os.Stderr
		if err := rmCmd.Run(); err != nil {
			log.Printf("spawn-claude-code-fix: cleanup worktree %q: %v", worktreePath, err)
		}
	}
	return worktreePath, cleanup, nil
}

// buildHealSystemPrompt composes the system prompt for the heal-fixer agent.
func buildHealSystemPrompt(taskDescription, successCriterion, branch string, subtree []string) string {
	var sb strings.Builder
	sb.WriteString("You are a heal-fixer agent. Your job is to make a precise, minimal code change to resolve a structural gap.\n\n")
	sb.WriteString("## Task\n\n")
	sb.WriteString(taskDescription)
	sb.WriteString("\n\n## Success criterion\n\n")
	sb.WriteString(successCriterion)
	sb.WriteString("\n\n## Branch\n\n")
	sb.WriteString("Your branch is: ")
	sb.WriteString(branch)
	sb.WriteString("\n\n## Hard constraints\n\n")
	sb.WriteString("- Do NOT merge any branch. Do NOT call 'gh pr merge'.\n")
	sb.WriteString("- Do NOT force-push (no 'git push -f').\n")
	sb.WriteString("- Commit only files in the allowed subtree.\n")
	if len(subtree) > 0 {
		sb.WriteString("- Allowed file paths (subtree restriction): ")
		sb.WriteString(strings.Join(subtree, ", "))
		sb.WriteString("\n")
	}
	sb.WriteString("- When done, commit your changes on the current branch.\n")
	sb.WriteString("- The harness will push and open the PR — you do not need to push or create the PR.\n")
	return sb.String()
}

// healChildEnv returns the extra env vars for the spawned claude process (C7).
func healChildEnv(findingID string) []string {
	var extra []string
	if v := os.Getenv("FORGE_API_KEY"); v != "" {
		extra = append(extra, "FORGE_API_KEY="+v)
	}
	if v := os.Getenv("FORGE_BASE_URL"); v != "" {
		extra = append(extra, "FORGE_BASE_URL="+v)
	}
	extra = append(extra, "MALLCOP_HEAL_FINDING_ID="+findingID)
	return extra
}

// runDiffValidation validates changed files against the subtree restriction (C3).
func runDiffValidation(worktreePath, repoAlias string, subtree []string) error {
	if len(subtree) == 0 {
		return nil
	}
	cmd := exec.Command("git", "diff", "--name-only", "origin/main...HEAD") // #nosec G204
	cmd.Dir = worktreePath
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("git diff: %w; stderr: %s", err, exitErr.Stderr)
		}
		return fmt.Errorf("git diff: %w", err)
	}
	return validateHealDiff(repoAlias, out)
}

// runSuccessCriterion runs the success criterion as a shell predicate.
func runSuccessCriterion(ctx context.Context, worktreePath, criterion string) error {
	if criterion == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", criterion) // #nosec G204
	cmd.Dir = worktreePath
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("exit %d", exitErr.ExitCode())
		}
		return err
	}
	return nil
}

// createDraftPR pushes the branch and creates a draft PR. C4: no merge.
// GH_CLI_OVERRIDE_PATH and MALLCOP_HEAL_SKIP_GH_PR are test hooks.
func createDraftPR(ctx context.Context, worktreePath, findingID, branch, taskDescription string) (string, error) {
	if os.Getenv("MALLCOP_HEAL_SKIP_GH_PR") == "1" {
		return "https://github.com/stub/repo/pull/0", nil
	}

	pushCmd := exec.CommandContext(ctx, "git", "push", "origin", branch) // #nosec G204
	pushCmd.Dir = worktreePath
	pushCmd.Stderr = os.Stderr
	if out, err := pushCmd.Output(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("git push: %w; stderr: %s; stdout: %s", err, exitErr.Stderr, out)
		}
		return "", fmt.Errorf("git push: %w", err)
	}

	ghBin := "gh"
	if override := os.Getenv("GH_CLI_OVERRIDE_PATH"); override != "" {
		ghBin = override
	}

	prTitle := fmt.Sprintf("heal: %s for finding %s", trimPRTitle(taskDescription), findingID)
	prBody := fmt.Sprintf("Automated heal PR for finding `%s`.\n\nTask: %s", findingID, taskDescription)

	prCmd := exec.CommandContext(ctx, ghBin, "pr", "create", // #nosec G204
		"--draft",
		"--title", prTitle,
		"--body", prBody,
	)
	prCmd.Dir = worktreePath
	prCmd.Stderr = os.Stderr
	out, err := prCmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("gh pr create: %w; stderr: %s; stdout: %s", err, exitErr.Stderr, out)
		}
		return "", fmt.Errorf("gh pr create: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// trimPRTitle truncates a task description to fit in a PR title.
func trimPRTitle(s string) string {
	const maxLen = 60
	s = strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// healTranscriptPath returns the transcript file path and its parent directory.
func healTranscriptPath(findingID string) (filePath, dir string, err error) {
	runID := os.Getenv("MALLCOP_RUN_ID")
	if runID == "" {
		runID = "heal-run"
	}
	transcriptDir := filepath.Join(".run", "transcripts", runID)
	if v := os.Getenv("MALLCOP_TRANSCRIPT_DIR"); v != "" {
		transcriptDir = filepath.Join(v, runID)
	}
	filePath = filepath.Join(transcriptDir, "heal-"+sanitizePathComponent(findingID)+".jsonl")
	return filePath, transcriptDir, nil
}

// sanitizePathComponent replaces non-alphanumeric/hyphen/underscore chars with '-'.
func sanitizePathComponent(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, s)
}

// parseIntEnv parses a decimal integer from a string.
func parseIntEnv(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}
