// tools_idempotency.go — Idempotency guard for terminal finding actions.
//
// Background (CO-02 race, mallcoppro-fix5)
//
// In bakeoff scenario CO-02 we observed a worker firing resolve-finding 7 times
// within 24 seconds for the same finding_id. The first call succeeded and posted
// a work:output to the engagement campfire; the remaining 6 also went through
// the F2A confidence gate and either re-emitted work:output or fanned out into
// deep-investigate panels. Academy grades on the FIRST closure tag it observes,
// so a stray duplicate close after a correct close inverts the verdict.
//
// The guard implemented here is a single-direction lock: the FIRST terminal
// action for a finding_id (resolve-finding action:resolved|escalated|remediated
// OR escalate-to-investigator work:create) wins. Any subsequent terminal call
// for the SAME finding_id from the SAME worker (same engagement campfire) is
// rejected with an error referencing the prior action and its timestamp.
//
// Scope
//
//   - Reads MALLCOP_CAMPFIRE_ID (engagement campfire) for prior closures.
//   - Detects:
//   - work:output messages with action:resolved|escalated|remediated and
//     finding:<id> tags (emitted by resolve-finding itself or the chain-
//     handoff helpers like emitScenarioTerminalWorkOutput).
//   - work:create messages with finding:<id> AND a skill: tag matching a
//     downstream chain skill (task:investigate, task:escalate,
//     task:deep-investigate, task:investigate-merge). These mark that the
//     worker already handed the finding off to a child worker.
//   - Fails OPEN when:
//   - MALLCOP_CAMPFIRE_ID is empty (no engagement campfire = no scope to
//     enforce against).
//   - cf binary is unavailable (test environments without cf installed).
//   - The campfire read itself fails (we cannot prove a duplicate; better
//     to allow than to block legitimate work).
//   - Fails CLOSED only when we have positive evidence of a prior terminal.
//
// Why fail-open on cf errors?
//
// The guard is a defence-in-depth check. Resolve-finding and escalate-to-
// investigator are themselves protected by the F2A confidence gate (resolve)
// and by academy-side de-duplication. Blocking the FIRST legitimate call
// because cf is briefly unreachable would be worse than allowing a duplicate.
//
// # Environment opt-out
//
// MALLCOP_SKIP_IDEMPOTENCY=1 bypasses the guard entirely. Reserved for unit
// tests and recovery scenarios where the operator deliberately re-fires a
// closure. Production worker jails MUST NOT set this.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// priorClosure describes a terminal action that already exists for a finding
// in the engagement campfire. Returned by findPriorClosure when a duplicate is
// detected.
type priorClosure struct {
	// Action is the action tag observed (resolved, escalated, remediated, or
	// the chain-skill name like "task:investigate" for a prior work:create).
	Action string
	// Timestamp is the RFC3339 string extracted from the prior payload, or
	// empty when the payload could not be parsed.
	Timestamp string
	// Kind distinguishes "terminal" (resolve-finding work:output) from
	// "handoff" (escalate-* work:create). Used only for the error message.
	Kind string
}

// chainSkillTags is the set of skill: tags that, when paired with finding:<id>
// on a work:create message, indicate the worker already handed the finding
// off to a downstream chain skill. A second terminal call from the same worker
// after such a handoff is a duplicate.
//
// Note: task:investigate-merge is intentionally NOT in this list — it is the
// LEGITIMATE downstream of the confidence-gate fan-out (3 escalate-to-deep
// items + 1 merge item are spawned together; the fan-out is one logical
// terminal). We treat the first escalate-to-deep work:create as the lock.
var chainSkillTags = map[string]struct{}{
	"skill:task:investigate":      {},
	"skill:task:escalate":         {},
	"skill:task:deep-investigate": {},
}

// terminalActionTags is the set of action:<verb> tags on a work:output message
// that constitute a finding terminal. resolve-finding writes one of these on
// EVERY successful close; emitScenarioTerminalWorkOutput mirrors them to the
// work campfire from the escalate-* helpers.
var terminalActionTags = map[string]string{
	"action:resolved":   "resolved",
	"action:escalated":  "escalated",
	"action:remediated": "remediated",
}

// findPriorClosure scans the engagement campfire (campfireID) for any prior
// terminal action targeting findingID. Returns (nil, nil) when none is found,
// (closure, nil) when one is, or (nil, err) when the campfire read failed.
//
// The caller decides fail-open vs fail-closed on err — see runResolveFinding
// and runEscalateToInvestigator for the actual policy.
func findPriorClosure(campfireID, findingID string) (*priorClosure, error) {
	if campfireID == "" || findingID == "" {
		return nil, nil
	}
	cfBin, err := exec.LookPath("cf")
	if err != nil {
		// cf unavailable: caller fails open. This branch is hit in unit tests
		// without cf on PATH.
		return nil, fmt.Errorf("cf binary not found on PATH: %w", err)
	}
	cmd := exec.Command(cfBin, "read", campfireID, "--json", "--all") // #nosec G204
	out, cmdErr := cmd.Output()
	if cmdErr != nil {
		var exitErr *exec.ExitError
		if errors.As(cmdErr, &exitErr) {
			return nil, fmt.Errorf("cf read: %w; stderr: %s", cmdErr, exitErr.Stderr)
		}
		return nil, fmt.Errorf("cf read: %w", cmdErr)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var msgs []cfMessage
	if jsonErr := json.Unmarshal(out, &msgs); jsonErr != nil {
		return nil, fmt.Errorf("cf read: parse JSON: %w", jsonErr)
	}

	findingTag := "finding:" + findingID
	for _, msg := range msgs {
		var (
			hasWorkOutput  bool
			hasWorkCreate  bool
			hasFinding     bool
			actionVerb     string
			chainSkillVerb string
		)
		for _, tag := range msg.Tags {
			switch {
			case tag == "work:output":
				hasWorkOutput = true
			case tag == "work:create":
				hasWorkCreate = true
			case tag == findingTag:
				hasFinding = true
			default:
				if verb, ok := terminalActionTags[tag]; ok {
					actionVerb = verb
				}
				if _, ok := chainSkillTags[tag]; ok {
					chainSkillVerb = strings.TrimPrefix(tag, "skill:")
				}
			}
		}
		if !hasFinding {
			continue
		}
		if hasWorkOutput && actionVerb != "" {
			return &priorClosure{
				Action:    actionVerb,
				Timestamp: extractTimestamp(msg.Payload),
				Kind:      "terminal",
			}, nil
		}
		if hasWorkCreate && chainSkillVerb != "" {
			return &priorClosure{
				Action:    chainSkillVerb,
				Timestamp: extractTimestamp(msg.Payload),
				Kind:      "handoff",
			}, nil
		}
	}
	return nil, nil
}

// extractTimestamp pulls a "timestamp" field out of a JSON payload, returning
// the empty string when parsing fails or the field is missing/non-string.
func extractTimestamp(payload string) string {
	if payload == "" {
		return ""
	}
	var p map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return ""
	}
	if ts, ok := p["timestamp"].(string); ok {
		return ts
	}
	return ""
}

// idempotencyGuard runs findPriorClosure with the standard fail-open policy and
// returns a non-nil error when a duplicate is positively detected. It is the
// canonical entry point shared by runResolveFinding and runEscalateToInvestigator.
//
// tool is the calling tool name (e.g. "resolve-finding") used only in the
// returned error message.
func idempotencyGuard(tool, findingID string) error {
	// Opt-out for unit tests and explicit operator overrides.
	if os.Getenv("MALLCOP_SKIP_IDEMPOTENCY") == "1" {
		return nil
	}
	campfireID := os.Getenv("MALLCOP_CAMPFIRE_ID")
	if campfireID == "" {
		// No engagement campfire scope — fail open. The plain F2B watcher and
		// academy de-dup are the other layers.
		return nil
	}
	prior, err := findPriorClosure(campfireID, findingID)
	if err != nil {
		// Fail open on infra errors; log to stderr so operators can see drift.
		fmt.Fprintf(os.Stderr, "%s: idempotency check failed (failing open): %v\n", tool, err)
		return nil
	}
	if prior == nil {
		return nil
	}
	ts := prior.Timestamp
	if ts == "" {
		ts = "unknown-timestamp"
	}
	return fmt.Errorf("%s: finding %s already closed with action %s at %s (idempotency guard)",
		tool, findingID, prior.Action, ts)
}
