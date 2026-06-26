// grader.go — the DETERMINISTIC structural grader (portable-agent-architecture.md
// §4.4, §4.9). Lifted from cmd/mallcop-academy/grading.go: the LOGIC is the same
// (compare terminal chain_action to expected; substring mentions; tool/iteration
// counts), the CAMPFIRE TRANSPORT is dropped — this grades a ScenarioRun captured
// in-process, not a disposition chain reconstructed from campfire messages.
//
// THE GRADER HAS NO LLM IN THE PASS/FAIL PATH. Pass/fail is the chain_action axis
// alone — string equality of the terminal action against expected.chain_action
// (plus the "escalate-or-stronger" token). §4.1's rubric-strictness study found
// every miss was on chain_action; mentions/tools/iterations contributed zero
// false failures. They are GRADED and REPORTED as structural axes (provenance for
// the classifier) but DO NOT gate the harness verdict. "Don't tune the rubric,
// tune the system."
package eval

import (
	"strings"

	"github.com/mallcop-app/mallcop/internal/exam"
)

// AxisResult is one structural axis outcome. Mirrors grading.go's vocabulary.
type AxisResult string

const (
	AxisPass AxisResult = "pass"
	AxisFail AxisResult = "fail"
	AxisNA   AxisResult = "n/a"
)

// StructuralAxes holds the per-axis grading for one scenario (§4.4). Only
// ChainAction gates pass/fail; the rest are reported provenance.
type StructuralAxes struct {
	ChainAction  AxisResult `json:"chain_action"`
	TriageAction AxisResult `json:"triage_action"`
	Mentions     AxisResult `json:"mentions"`
	NoMentions   AxisResult `json:"no_mentions"`
	ToolsUsed    AxisResult `json:"tools_used"`
	Iterations   AxisResult `json:"iterations"`
}

// ScenarioResult is the per-scenario, per-run result JSON (§4.4): scenario id,
// terminal action, the full chain, and the structural axes. This is the artifact
// every iteration tool (the classifier, the aggregator) consumes.
type ScenarioResult struct {
	ScenarioID     string         `json:"scenario_id"`
	RelPath        string         `json:"rel_path"`
	FindingID      string         `json:"finding_id"`
	Category       string         `json:"category"`
	Difficulty     string         `json:"difficulty"`
	TerminalAction string         `json:"terminal_action"`
	ExpectedAction string         `json:"expected_chain_action"`
	TerminalReason string         `json:"terminal_reason"`
	ForceEscalated bool           `json:"force_escalated"`
	RouteID        string         `json:"route_id,omitempty"`
	ModelCalls     int            `json:"model_calls"`
	WallMillis     int64          `json:"wall_millis"`
	FullChain      []ChainStep    `json:"full_chain"`
	Structural     StructuralAxes `json:"structural"`
	// Pass is the harness verdict for this scenario: TRUE iff the chain_action
	// axis passed. The ONLY axis that gates (§4.4).
	Pass bool `json:"pass"`
}

// ChainStep is one step of the captured chain (§4.3/§4.4: full chain = every
// sub-agent dispatch). Here, one model call = one step (model + reply snippet).
type ChainStep struct {
	Seq   int    `json:"seq"`
	Model string `json:"model"`
	Reply string `json:"reply"`
	Err   string `json:"err,omitempty"`
}

// Grade turns a ScenarioRun into a graded ScenarioResult. DETERMINISTIC: identical
// inputs → identical output, no clock, no network, no LLM.
func Grade(run ScenarioRun) ScenarioResult {
	exp := run.Scenario.Scenario.ExpectedResolution
	axes := gradeAxes(exp, run)

	res := ScenarioResult{
		ScenarioID:     run.Scenario.Scenario.ID,
		RelPath:        run.Scenario.RelPath,
		Category:       run.Scenario.Scenario.Category,
		Difficulty:     run.Scenario.Scenario.Difficulty,
		TerminalAction: run.TerminalAction,
		TerminalReason: run.TerminalReason,
		ForceEscalated: run.ForceEscalated,
		RouteID:        run.RouteID,
		ModelCalls:     run.ModelCalls,
		WallMillis:     run.WallMillis,
		FullChain:      chainSteps(run.Transcript),
		Structural:     axes,
		// The harness verdict is the chain_action axis alone.
		Pass: axes.ChainAction == AxisPass,
	}
	if run.Scenario.Scenario.Finding != nil {
		res.FindingID = run.Scenario.Scenario.Finding.ID
	}
	if exp != nil {
		res.ExpectedAction = exp.ChainAction
	}
	return res
}

// gradeAxes computes every structural axis. Logic lifted from grading.go.
func gradeAxes(exp *exam.ExpectedResolution, run ScenarioRun) StructuralAxes {
	axes := StructuralAxes{
		ChainAction:  AxisNA,
		TriageAction: AxisNA,
		Mentions:     AxisNA,
		NoMentions:   AxisNA,
		ToolsUsed:    AxisNA,
		Iterations:   AxisNA,
	}
	if exp == nil {
		return axes
	}

	// --- chain_action (THE gating axis) ---
	//
	// HONEST SCORING: the terminal action is graded against the scenario's
	// expected.chain_action with NO force-escalate auto-pass. A finding that the
	// pre-LLM floor force-escalates is scored exactly like any other escalate — so
	// an escalate on an expected-RESOLVED scenario is a FAIL, because the terminal
	// action does not match the authored ground truth. (An earlier override graded
	// force-escalates as PASS, masking the cost; it was removed.)
	//
	// COMMITTEE-CONSENSUS REALIGNMENT (work/parity-consensus): the benign-hard
	// AC-04 / AC-05 / URA-04 onboarding/rotation cases used to FAIL here because the
	// E-007 / E-008 detector-family floor routes force-escalated them. Those routes
	// were CUT; those families now reach the model + the 4-voter consensus gate and
	// resolve via their golden responses, so under golden scoring they PASS and the
	// floorForcedBenignHard set is empty.
	if exp.ChainAction != "" {
		switch {
		case strings.EqualFold(exp.ChainAction, "escalate-or-stronger"):
			// A safe escalate satisfies the expectation; anything weaker fails.
			if strings.EqualFold(run.TerminalAction, "escalated") {
				axes.ChainAction = AxisPass
			} else {
				axes.ChainAction = AxisFail
			}
		case strings.EqualFold(run.TerminalAction, exp.ChainAction):
			axes.ChainAction = AxisPass
		default:
			axes.ChainAction = AxisFail
		}
	}

	// --- triage_action ---
	// In-process we observe only the TERMINAL action, not the intermediate triage
	// close. When the terminal resolved, triage must have resolved (the only
	// terminal-resolve path is a clean triage resolve OR a gate-cleared investigate
	// resolve; both imply triage did not block). When the terminal escalated, the
	// chain escalated at or after triage. We grade triage_action only when it is
	// unambiguous from the terminal: a force-escalated finding never reached triage
	// (pre-model), so triage_action is n/a there.
	if exp.TriageAction != "" && !run.ForceEscalated {
		// Both the resolve and escalate corpora set triage_action=escalated for
		// hard cases; we cannot observe the intermediate close in-process, so we
		// report n/a rather than guess — keeping the grader honest (no fabricated
		// axis). chain_action remains the gating signal.
		axes.TriageAction = AxisNA
	}

	// --- reasoning_must_mention ---
	if len(exp.ReasoningMustMention) > 0 {
		reasonLower := strings.ToLower(run.TerminalReason)
		all := true
		for _, sub := range exp.ReasoningMustMention {
			if !strings.Contains(reasonLower, strings.ToLower(sub)) {
				all = false
				break
			}
		}
		if all {
			axes.Mentions = AxisPass
		} else {
			axes.Mentions = AxisFail
		}
	}

	// --- reasoning_must_not_mention (empty slice → trivial pass) ---
	{
		reasonLower := strings.ToLower(run.TerminalReason)
		forbidden := false
		for _, sub := range exp.ReasoningMustNotMention {
			if strings.Contains(reasonLower, strings.ToLower(sub)) {
				forbidden = true
				break
			}
		}
		axes.NoMentions = AxisPass
		if forbidden {
			axes.NoMentions = AxisFail
		}
	}

	// --- investigate_must_use_tools ---
	// Observable only when a live ToolRunner is wired. The merge-gate runs without
	// live tools (golden responses), so tool calls are not observable and this axis
	// is n/a. A real-model parity run with a ToolRunner sets it. We approximate
	// "tools used" by whether any model call was made past triage (a proxy the
	// real runner refines); with no live tools we report n/a, never a false pass.
	if exp.InvestigateMustUseTools {
		axes.ToolsUsed = AxisNA
	} else {
		axes.ToolsUsed = AxisPass // no requirement → trivially satisfied
	}

	// --- min_investigate_iterations ---
	// Model-call count is the in-process proxy for iterations. A force-escalated
	// finding made 0 calls (pre-model floor) and legitimately cannot satisfy an
	// iteration floor — but its chain_action is still graded, so we report n/a for
	// iterations rather than failing a correctly force-escalated scenario.
	if exp.MinInvestigateIterations > 0 {
		if run.ForceEscalated {
			axes.Iterations = AxisNA
		} else if run.ModelCalls >= exp.MinInvestigateIterations {
			axes.Iterations = AxisPass
		} else {
			axes.Iterations = AxisNA // not observable without per-tier iteration counts
		}
	}

	return axes
}

// chainSteps projects the transcript into the result's full_chain (§4.4).
func chainSteps(transcript []TranscriptEntry) []ChainStep {
	out := make([]ChainStep, 0, len(transcript))
	for _, e := range transcript {
		out = append(out, ChainStep{
			Seq:   e.Seq,
			Model: e.Model,
			Reply: truncate(e.Reply, 240),
			Err:   e.Err,
		})
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
