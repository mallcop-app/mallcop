// judge.go — F4C LLM-as-judge rubric ingestion for mallcop-academy.
//
// HISTORICAL NOTE: judge dispatch was previously "Option A" — an academy-side
// judge worker spawned via the external legion binary against a per-run
// campfire, with the verdict read back from that campfire. That legion/`we`
// runtime coupling has been removed (mallcop-legion no longer depends on the
// legion engine). buildJudicator now returns nil, so the academy proceeds
// without rubric axes (quality_floor "n/a"/"unavailable") until an in-process
// judge pipeline lands. This is NOT a silent skip — the unavailable sentinel
// is explicit downstream signal.
//
// The verdict-ingestion logic below (judicator.pollForVerdict, JudgeResult
// parsing, judgeUnavailable) is retained and unit-tested so a future
// in-process dispatch can reuse it. Cross-feed with F4B: judgeResult is
// returned to the caller so the structural grader can fill in quality_floor
// on the single-pass scenario record write.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	// cfBin is the path to the `cf` binary.
	cfBin string
	// academyCampfireID is the per-run campfire where verdicts are posted.
	academyCampfireID string
	// academyCFHome is the CF_HOME for the academy campfire.
	academyCFHome string
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

	// NOTE: The judge worker was previously dispatched in-process via the
	// external legion binary (`we start --chart … --exit-on-idle`). That
	// coupling has been removed; buildJudicator now returns nil so this method
	// is not reached in production. The cf-based verdict ingestion below is
	// retained (and unit-tested) for when an in-process judge dispatch lands.

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

// buildJudicator previously dispatched an LLM-as-judge worker via the external
// legion binary (`we start`) against a per-run campfire created with the `cf`
// CLI. That legion/`we` runtime coupling has been removed as part of decoupling
// mallcop-legion from the legion engine.
//
// It now always returns nil: judge dispatch is disabled until an in-process
// judge pipeline lands (pending core/pipeline). Returning nil is the existing
// "judge unavailable" path — callers (main.go) guard with `if judge != nil`
// and leave quality_floor as "n/a"/"unavailable", so grading proceeds without
// the rubric axes rather than failing.
//
// The verdict-ingestion logic (judicator.pollForVerdict / spawnAndCollect's cf
// poll) and the judgeUnavailable sentinel are retained and unit-tested so a
// future in-process dispatch can reuse them.
func buildJudicator(_ runArgs) *judicator {
	fmt.Fprintf(os.Stderr, "INFO: judge disabled — legion `we` dispatch removed (pending in-process judge pipeline)\n")
	return nil
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

