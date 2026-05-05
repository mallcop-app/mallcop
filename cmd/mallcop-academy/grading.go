// grading.go — F4B structural ground-truth grading for mallcop-academy.
//
// Computes a StructuralGrade from a scenario's expected: block and the
// observed disposition chain captured by the watch loop.
//
// Each axis returns one of: "pass", "fail", "n/a", "pending".
//
//   - "pass"    — check ran and passed
//   - "fail"    — check ran and failed
//   - "n/a"     — expected key absent in scenario yaml (check skipped)
//   - "pending" — only for quality_floor when rubric hasn't run yet
package main

import (
	"encoding/json"
	"strings"

	"github.com/thirdiv/mallcop-legion/internal/exam"
)

// AxisResult is one of: "pass", "fail", "n/a", "pending".
type AxisResult = string

const (
	AxisPass        AxisResult = "pass"
	AxisFail        AxisResult = "fail"
	AxisNA          AxisResult = "n/a"
	AxisPending     AxisResult = "pending"
	AxisUnavailable AxisResult = "unavailable"
)

// StructuralGrade holds the per-axis grading results.
type StructuralGrade struct {
	// ChainAction: did the terminal action match expected.chain_action?
	ChainAction AxisResult `json:"chain_action"`

	// TriageAction: did the triage close action match expected.triage_action?
	TriageAction AxisResult `json:"triage_action"`

	// Mentions: did the terminal reason mention all required substrings?
	Mentions AxisResult `json:"mentions"`

	// NoMentions: did the terminal reason avoid all forbidden substrings?
	NoMentions AxisResult `json:"no_mentions"`

	// ToolsUsed: did at least one investigate step use tools (if required)?
	ToolsUsed AxisResult `json:"tools_used"`

	// Iterations: did an investigate/deep-investigate step reach min iterations?
	Iterations AxisResult `json:"iterations"`

	// QualityFloor: did judge's investigation_thoroughness meet the minimum?
	// "pending" until the rubric runs; then "pass" or "fail".
	QualityFloor AxisResult `json:"quality_floor"`
}

// closePayloadFull is a superset close payload used in grading — carries the
// reason field from resolve-finding outputs.
type closePayloadFull struct {
	ItemID    string `json:"item_id"`
	Action    string `json:"action"`
	Skill     string `json:"skill"`
	Reason    string `json:"reason"`
	FindingID string `json:"finding_id"`
}

// toolCallEntry mirrors a single entry from get_session_transcript output.
type toolCallEntry struct {
	Turn    int              `json:"turn"`
	ToolUse *toolUseEntry    `json:"tool_use,omitempty"`
}

type toolUseEntry struct {
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input,omitempty"`
}

// IterationInfo summarises investigate worker iteration data from a chain close.
type IterationInfo struct {
	Iterations int
}

// computeStructuralGrade evaluates F4B grading axes for one scenario.
//
// Parameters:
//   - expected: the scenario's ExpectedResolution block (may be nil → all n/a)
//   - chain: the full disposition chain (ChainEntry list with raw payloads)
//   - terminalAction: the observed terminal action (e.g. "resolved", "escalated")
//   - terminalReason: the reason text from the terminal close payload
//   - triageCloseAction: action from the first triage skill close in the chain
//   - toolsUsedInInvestigate: true if any investigate step had ≥1 tool call
//   - maxInvestigateIterations: the highest iteration count seen across investigate workers
//   - rubricScore: investigation_thoroughness score from F4C (0 = not yet available or unavailable)
//   - judgeRan: true if the judge was dispatched for this scenario (even if it returned 0)
func computeStructuralGrade(
	expected *exam.ExpectedResolution,
	terminalAction string,
	terminalReason string,
	triageCloseAction string,
	toolsUsedInInvestigate bool,
	maxInvestigateIterations int,
	rubricScore int,
	judgeRan bool,
) StructuralGrade {
	g := StructuralGrade{
		ChainAction:  AxisNA,
		TriageAction: AxisNA,
		Mentions:     AxisNA,
		NoMentions:   AxisNA,
		ToolsUsed:    AxisNA,
		Iterations:   AxisNA,
		QualityFloor: AxisNA,
	}

	if expected == nil {
		return g
	}

	// --- chain_action ---
	if expected.ChainAction != "" {
		// Special token "escalate-or-stronger": accept literal "escalated" as
		// PASS. A safe escalate satisfies the expectation; a weaker outcome
		// (e.g. "resolved") fails. See mallcoppro-a42.
		if strings.EqualFold(expected.ChainAction, "escalate-or-stronger") {
			if strings.EqualFold(terminalAction, "escalated") {
				g.ChainAction = AxisPass
			} else {
				g.ChainAction = AxisFail
			}
		} else if strings.EqualFold(terminalAction, expected.ChainAction) {
			g.ChainAction = AxisPass
		} else {
			g.ChainAction = AxisFail
		}
	}

	// --- triage_action ---
	if expected.TriageAction != "" {
		if triageCloseAction != "" {
			if strings.EqualFold(triageCloseAction, expected.TriageAction) {
				g.TriageAction = AxisPass
			} else {
				g.TriageAction = AxisFail
			}
		} else {
			// No triage close observed yet.
			g.TriageAction = AxisNA
		}
	}

	// --- reasoning_must_mention ---
	if len(expected.ReasoningMustMention) > 0 {
		reasonLower := strings.ToLower(terminalReason)
		allFound := true
		for _, substr := range expected.ReasoningMustMention {
			if !strings.Contains(reasonLower, strings.ToLower(substr)) {
				allFound = false
				break
			}
		}
		if allFound {
			g.Mentions = AxisPass
		} else {
			g.Mentions = AxisFail
		}
	}

	// --- reasoning_must_not_mention ---
	// Axis is always graded when the slice is present in the expected block.
	// An empty slice means "no forbidden substrings" → always pass.
	// We only enter this branch when the field was explicitly declared in YAML,
	// which we infer by checking if the pointer is non-nil. Since
	// ExpectedResolution is a struct (not pointer), we use the overall expected
	// non-nil check already done above.
	{
		reasonLower := strings.ToLower(terminalReason)
		forbidden := false
		for _, substr := range expected.ReasoningMustNotMention {
			if strings.Contains(reasonLower, strings.ToLower(substr)) {
				forbidden = true
				break
			}
		}
		// Only grade if the field is actually present in yaml (non-nil struct,
		// always the case here since expected != nil). With zero entries it's
		// a trivial pass.
		g.NoMentions = AxisPass
		if forbidden {
			g.NoMentions = AxisFail
		}
	}

	// --- investigate_must_use_tools ---
	if expected.InvestigateMustUseTools {
		if toolsUsedInInvestigate {
			g.ToolsUsed = AxisPass
		} else {
			g.ToolsUsed = AxisFail
		}
	} else {
		// expected=false → always pass (no requirement)
		g.ToolsUsed = AxisPass
	}

	// --- min_investigate_iterations ---
	if expected.MinInvestigateIterations > 0 {
		if maxInvestigateIterations >= expected.MinInvestigateIterations {
			g.Iterations = AxisPass
		} else {
			g.Iterations = AxisFail
		}
	}

	// --- min_investigation_quality (cross-axis on F4C) ---
	if expected.MinInvestigationQuality > 0 {
		if rubricScore == 0 {
			if judgeRan {
				// Judge ran but scored 0 (returned unavailable or failed to score).
				// Report as "unavailable" — not "pending" (judge did run).
				g.QualityFloor = AxisUnavailable
			} else {
				// Judge has not been dispatched yet.
				g.QualityFloor = AxisPending
			}
		} else if rubricScore >= expected.MinInvestigationQuality {
			g.QualityFloor = AxisPass
		} else {
			g.QualityFloor = AxisFail
		}
	}

	return g
}

// extractTerminalReason parses a work:close payload JSON string and returns
// the reason field if present, empty string otherwise.
func extractTerminalReason(payloadJSON string) string {
	if payloadJSON == "" {
		return ""
	}
	var cp closePayloadFull
	if err := json.Unmarshal([]byte(payloadJSON), &cp); err != nil {
		return ""
	}
	return cp.Reason
}

// extractIterationCount reads the iteration count from the transcript entries
// returned by get_session_transcript. It counts the number of tool_use turns
// as a proxy for iterations. Returns 0 if transcript is nil/empty.
func extractIterationCount(transcript []toolCallEntry) int {
	count := 0
	for _, e := range transcript {
		if e.ToolUse != nil && e.ToolUse.Name != "" {
			count++
		}
	}
	return count
}

// extractToolsUsed returns true if the transcript contains at least one tool
// call (i.e. the worker actually invoked a tool during investigation).
func extractToolsUsed(transcript []toolCallEntry) bool {
	for _, e := range transcript {
		if e.ToolUse != nil && e.ToolUse.Name != "" {
			return true
		}
	}
	return false
}

// parseToolCallTranscript parses the JSON array returned by
// get_session_transcript. Returns nil on parse error (caller treats as empty).
func parseToolCallTranscript(data []byte) []toolCallEntry {
	if len(data) == 0 {
		return nil
	}
	var entries []toolCallEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	return entries
}
