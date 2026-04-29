// judge.go — F4C LLM-as-judge dispatch and rubric ingestion for mallcop-academy.
//
// Architectural decision: Option A — academy-side judge dispatch.
//
// The judge runs in a per-run academy-side campfire (separate from the
// operational work campfire). This keeps the operational chart free of
// exam:* skill grants. The academy spawns the judge via `we start` pointing
// at an academy-side chart derived from charts/exam.toml.tmpl (with the judge
// seed only), then reads the judge:verdict message back from the per-run
// campfire.
//
// Cross-feed with F4B: judgeResult is returned to the caller so the structural
// grader can fill in quality_floor on the first (and only) scenario record
// write. Single-pass write: judge runs FIRST per scenario, then structural
// grade is computed with the rubric score already known.
//
// If the judge binary (we) is not found or Option A fails to spawn, the
// academy falls back gracefully: rubric fields are zero-valued, quality_floor
// is "pending", and a warning is logged. This is NOT a silent skip — the
// pending sentinel is explicit downstream signal.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// JudgeRubric holds the four-axis LLM-as-judge scores.
type JudgeRubric struct {
	ReasoningQuality          int `json:"reasoning_quality"`
	InvestigationThoroughness int `json:"investigation_thoroughness"`
	ResolveQuality            int `json:"resolve_quality"`
	EscalationActionability   int `json:"escalation_actionability"`
}

// JudgeResult is the full per-scenario judge output.
type JudgeResult struct {
	FindingID     string      `json:"finding_id"`
	Verdict       string      `json:"verdict"`
	Rubric        JudgeRubric `json:"rubric"`
	Rationale     string      `json:"judge_rationale"`
	JudgeFixTarget string     `json:"judge_fix_target"`
}

// judgeVerdictMessage is the JSON shape emitted by the judge worker and
// tagged judge:verdict on the campfire.
type judgeVerdictMessage struct {
	FindingID  string      `json:"finding_id"`
	Verdict    string      `json:"verdict"`
	Rubric     JudgeRubric `json:"rubric"`
	Rationale  string      `json:"rationale"`
	FixTarget  string      `json:"fix_target"`
}

// judicator dispatches a judge worker and collects the 4-axis verdict.
//
// Academy creates an isolated per-run campfire for the judge (separate from
// the operational work campfire). The judge worker reads the chain via
// get_session_transcript from the operational campfire (cross-engagement read
// supported in legion v0.6.1+), emits its verdict to the academy campfire,
// and the academy reads it back.
//
// If the judge binary is unavailable or spawn fails, returns a zero-valued
// JudgeResult with an error. Callers MUST NOT silently skip on error — they
// should log the error and set quality_floor to "pending".
type judicator struct {
	// weBin is the path to the `we` (legion) binary.
	weBin string
	// cfBin is the path to the `cf` binary.
	cfBin string
	// judgeChartPath is the rendered judge-only chart to pass to `we start`.
	judgeChartPath string
	// academyCampfireID is the per-run campfire where verdicts are posted.
	academyCampfireID string
	// academyCFHome is the CF_HOME for the academy campfire.
	academyCFHome string
	// repoRoot is the working directory for `we start`.
	repoRoot string
	// timeout is the per-judgment poll timeout.
	timeout time.Duration
}

// spawnAndCollect dispatches the judge for one scenario and returns the verdict.
// scenarioID is the scenario's canonical ID (e.g. "AC-01-external-access-stolen-cred").
// findingID is the finding tracking ID for this run.
// operationalCampfireID is the campfire holding the chain to grade.
func (j *judicator) spawnAndCollect(scenarioID, findingID, operationalCampfireID string) (*JudgeResult, error) {
	// Post a judge work:create item to the academy campfire.
	itemPayload := map[string]interface{}{
		"id":                      "judge-" + scenarioID,
		"title":                   "Judge verdict: " + scenarioID,
		"skill":                   "exam:judge",
		"scenario_id":             scenarioID,
		"finding_id":              findingID,
		"operational_campfire_id": operationalCampfireID,
	}
	payloadBytes, err := json.Marshal(itemPayload)
	if err != nil {
		return nil, fmt.Errorf("marshal judge item payload: %w", err)
	}

	// Send the judge work:create to the academy campfire.
	args := []string{"send", j.academyCampfireID, string(payloadBytes),
		"--tag", "work:create",
		"--tag", "exam:judge",
		"--tag", "scenario:" + scenarioID,
		"--json",
	}
	cmd := exec.Command(j.cfBin, args...)
	cmd.Env = setEnv(os.Environ(), "CF_HOME", j.academyCFHome)
	if out, err := cmd.Output(); err != nil {
		return nil, fmt.Errorf("cf send judge work:create: %w\nout: %s", err, out)
	}

	// Launch the judge worker.
	weCmd := exec.Command(j.weBin, "start", "--chart", j.judgeChartPath, "--exit-on-idle", "-v")
	weCmd.Env = setEnv(os.Environ(), "CF_HOME", j.academyCFHome)
	weCmd.Dir = j.repoRoot
	weOut, err := weCmd.CombinedOutput()
	if err != nil {
		// Non-fatal: we may still have a verdict if the worker posted before exiting.
		fmt.Fprintf(os.Stderr, "WARN: judge worker exited with error: %v\noutput: %s\n", err, weOut)
	}

	// Poll for the judge:verdict message.
	deadline := time.Now().Add(j.timeout)
	for time.Now().Before(deadline) {
		verdict, err := j.pollForVerdict(scenarioID)
		if err != nil {
			return nil, err
		}
		if verdict != nil {
			return verdict, nil
		}
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("judge verdict for %s not observed within %s", scenarioID, j.timeout)
}

// pollForVerdict reads the academy campfire for a judge:verdict message
// matching the given scenario ID. Returns nil if no verdict found yet.
func (j *judicator) pollForVerdict(scenarioID string) (*JudgeResult, error) {
	args := []string{"read", j.academyCampfireID, "--json", "--all"}
	cmd := exec.Command(j.cfBin, args...)
	cmd.Env = setEnv(os.Environ(), "CF_HOME", j.academyCFHome)
	out, err := cmd.Output()
	if err != nil {
		return nil, nil // treat as empty
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	var msgs []cfMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		return nil, nil
	}

	for _, msg := range msgs {
		if !hasTag(msg.Tags, "judge:verdict") {
			continue
		}
		// Check if this verdict is for our scenario.
		if !hasTag(msg.Tags, "scenario:"+scenarioID) {
			// Also try parsing the payload to match by finding_id.
			var v judgeVerdictMessage
			if err := json.Unmarshal([]byte(msg.Payload), &v); err != nil {
				continue
			}
			if !strings.Contains(v.FindingID, scenarioID) {
				continue
			}
		}
		var v judgeVerdictMessage
		if err := json.Unmarshal([]byte(msg.Payload), &v); err != nil {
			continue
		}
		return &JudgeResult{
			FindingID:      v.FindingID,
			Verdict:        v.Verdict,
			Rubric:         v.Rubric,
			Rationale:      v.Rationale,
			JudgeFixTarget: v.FixTarget,
		}, nil
	}
	return nil, nil
}

// buildJudicator constructs a judicator for the given run, or returns nil if
// the judge prerequisites (we binary, cf binary, chart template) are not met.
//
// Failure is non-fatal: the caller logs a warning and proceeds without a judge,
// leaving quality_floor as "n/a" (no min_investigation_quality in scenario) or
// "unavailable" (min set but judge couldn't run).
func buildJudicator(args runArgs) *judicator {
	// Require we binary.
	weBin, err := exec.LookPath("we")
	if err != nil {
		// Also check bin/ relative to cwd.
		if p, err2 := exec.LookPath("bin/we"); err2 == nil {
			weBin = p
		} else {
			fmt.Fprintf(os.Stderr, "INFO: judge skipped — we binary not found on PATH (F4C disabled)\n")
			return nil
		}
	}

	// Require cf binary.
	cfBin, err := exec.LookPath("cf")
	if err != nil {
		fmt.Fprintf(os.Stderr, "INFO: judge skipped — cf binary not found on PATH\n")
		return nil
	}

	// Resolve repo root for chart template.
	repoRoot, err := repoRootFromExec()
	if err != nil {
		fmt.Fprintf(os.Stderr, "INFO: judge skipped — cannot resolve repo root: %v\n", err)
		return nil
	}

	tmplPath := filepath.Join(repoRoot, "charts", "exam.toml.tmpl")
	if _, err := os.Stat(tmplPath); err != nil {
		fmt.Fprintf(os.Stderr, "INFO: judge skipped — chart template not found at %s\n", tmplPath)
		return nil
	}

	// Create per-run academy campfire in output dir.
	judgeCFHome := filepath.Join(args.outputDir, ".judge-cf-"+args.runID)
	if err := os.MkdirAll(judgeCFHome, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "INFO: judge skipped — cannot create judge CF_HOME: %v\n", err)
		return nil
	}

	// cf init
	initCmd := exec.Command(cfBin, "init")
	initCmd.Env = setEnv(os.Environ(), "CF_HOME", judgeCFHome)
	if out, err := initCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "INFO: judge skipped — cf init failed: %v\n%s\n", err, out)
		return nil
	}

	// cf create → get campfire ID
	createCmd := exec.Command(cfBin, "create", "--description", "academy-judge-"+args.runID)
	createCmd.Env = setEnv(os.Environ(), "CF_HOME", judgeCFHome)
	createOut, err := createCmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "INFO: judge skipped — cf create failed: %v\n%s\n", err, createOut)
		return nil
	}
	academyCampfireID := extractCampfireID(string(createOut))
	if academyCampfireID == "" {
		fmt.Fprintf(os.Stderr, "INFO: judge skipped — could not parse campfire ID from cf create output: %s\n", createOut)
		return nil
	}

	// Render judge chart.
	judgeChartPath := filepath.Join(args.outputDir, "judge-chart-"+args.runID+".toml")
	forgeAPIURL := os.Getenv("FORGE_API_URL")
	if forgeAPIURL == "" {
		forgeAPIURL = "http://localhost:8080"
	}
	forgeAPIKey := os.Getenv("FORGE_API_KEY")
	chartVars := map[string]string{
		"RUN_ID":        args.runID,
		"FORGE_API_URL": forgeAPIURL,
		"FORGE_API_KEY": forgeAPIKey,
	}
	if err := renderJudgeChart(tmplPath, judgeChartPath, chartVars); err != nil {
		fmt.Fprintf(os.Stderr, "INFO: judge skipped — render chart: %v\n", err)
		return nil
	}

	judgeTimeout := args.timeout
	if judgeTimeout <= 0 {
		judgeTimeout = 5 * time.Minute
	}

	fmt.Fprintf(os.Stderr, "INFO: judge enabled — academy campfire %s\n", academyCampfireID)
	return &judicator{
		weBin:             weBin,
		cfBin:             cfBin,
		judgeChartPath:    judgeChartPath,
		academyCampfireID: academyCampfireID,
		academyCFHome:     judgeCFHome,
		repoRoot:          repoRoot,
		timeout:           judgeTimeout,
	}
}

// extractCampfireID scans cf create output for a 64-char hex campfire ID.
func extractCampfireID(output string) string {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isAllHex(line) {
			return line
		}
	}
	return ""
}

// isAllHex returns true if all characters in s are hex digits.
func isAllHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// judgeUnavailable returns a zero JudgeResult with all axes at 0 (not scored).
// Used when the judge binary is not available or spawn fails.
func judgeUnavailable(reason string) *JudgeResult {
	return &JudgeResult{
		FindingID:      "",
		Verdict:        "unavailable",
		Rubric:         JudgeRubric{},
		Rationale:      "judge unavailable: " + reason,
		JudgeFixTarget: "none",
	}
}

// renderJudgeChart renders a minimal judge-only chart to outPath using the
// exam.toml.tmpl template. Only the exam:judge seed is needed.
// vars must include: RUN_ID, FORGE_API_URL, FORGE_API_KEY.
func renderJudgeChart(tmplPath, outPath string, vars map[string]string) error {
	b, err := os.ReadFile(tmplPath)
	if err != nil {
		return fmt.Errorf("read judge chart template: %w", err)
	}
	s := string(b)
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return os.WriteFile(outPath, []byte(s), 0o644)
}
