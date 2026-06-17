// confidence.go — structural confidence scoring, ported from
// src/mallcop/actors/confidence.py.
//
// The model never self-reports confidence here — that's gameable (a model can
// emit "confidence: 5" to talk past a soft check). Instead confidence is
// computed from STRUCTURAL properties of the investigation the model cannot
// fake without actually doing the work:
//   - how many tool calls were made,
//   - how many DISTINCT tools were used,
//   - how many concrete evidence citations appear in the resolution reason,
//   - how many iterations were needed (excess iterations = thrashing penalty).
//
// This is the model-independent false-negative guard. A resolve whose structural
// confidence is below ConfidenceFanOutThreshold is BLOCKED by a runtime gate
// (see resolveguard.go) and fans out to a deep panel — the model cannot opt out
// by being more emphatic, because the score never reads the model's words for
// confidence, only its observable behaviour.
//
// Pure function: no side effects, no store access, no LLM calls. Unlike the
// Python original it is DETERMINISTIC — the ±0.05 Kerckhoffs noise floor is
// dropped so a runtime gate built on this score is reproducible and testable.
// (The noise floor mattered for an adversary predicting the exact score; the Go
// floor's threshold has margin built in and the gate decision must be stable.)
package agent

import "regexp"

// Transcript is the observable record of one investigation, the input to the
// structural confidence score. Every field is something the runtime measures
// from the agent loop — none is self-reported by the model.
type Transcript struct {
	// Resolved is false when the agent failed to conclude (no resolution
	// produced). A non-resolution scores near zero confidence.
	Resolved bool
	// ToolCalls is the total number of tool calls made during the investigation.
	ToolCalls int
	// DistinctTools is the number of DIFFERENT tools used (breadth of evidence
	// gathering, not just volume).
	DistinctTools int
	// Iterations is the loop count. Excess iterations (over 3) signal thrashing
	// and incur a mild penalty.
	Iterations int
	// Reason is the resolution reason text. Concrete evidence citations in it
	// (dates, times, baseline/frequency/IP references, event ids) raise the score.
	Reason string
}

// ConfidenceFanOutThreshold is the structural-confidence floor for a resolve. A
// resolve scoring strictly below this is blocked and fans out to a deep panel.
// 0.55 matches the investigate-tier threshold documented in
// portable-agent-architecture.md §2.4 / §1 (RESOLVE is conditional on
// confidence ≥ 0.55).
const ConfidenceFanOutThreshold = 0.55

// Score weights — ported verbatim from confidence.py so the Go gate calibrates
// identically to the validated Python scorer.
const (
	noResolutionBase = 0.10 // a non-resolution scores this (low confidence)

	toolCallWeight = 0.04 // per tool call (capped)
	toolCallCap    = 8    // cap at 8 tool calls for scoring

	distinctToolWeight = 0.08 // per distinct tool used (capped)
	distinctToolCap    = 4    // cap at 4 distinct tools

	evidenceWeight = 0.04 // per evidence pattern matched (capped)
	evidenceCap    = 5    // cap at 5 evidence signals

	iterationPenalty = 0.02 // per iteration above 3 (mild inefficiency penalty)
	iterationFree    = 3    // iterations up to this incur no penalty
)

// evidencePatterns are the concrete-evidence anchors counted in the reason text.
// Ported from confidence.py _EVIDENCE_PATTERNS — structural signals, not full
// NLP, just observable citation shapes. Each DISTINCT pattern that matches at
// least once counts as one evidence signal (matching the Python sum-of-bools).
var evidencePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}`),  // ISO date reference
	regexp.MustCompile(`\b\d{2}:\d{2}`),        // time reference
	regexp.MustCompile(`(?i)\bbaseline\b`),     //
	regexp.MustCompile(`(?i)\bfrequency\b`),    //
	regexp.MustCompile(`(?i)\brelationship\b`), //
	regexp.MustCompile(`(?i)\bactor:\w+`),      // actor:name reference
	regexp.MustCompile(`(?i)\bknown\b`),        //
	regexp.MustCompile(`(?i)\bpercentile\b`),   //
	regexp.MustCompile(`(?i)\bIP\s+\d+\.\d+`),  // IP address
	regexp.MustCompile(`(?i)\bfirst_seen\b|\blast_seen\b`),
	regexp.MustCompile(`(?i)\bcount\b`),   //
	regexp.MustCompile(`(?i)\bevents?\b`), //
}

// StructuralConfidence derives a confidence score in [0.0, 1.0] from an
// investigation transcript. It reads ONLY observable signals, never the model's
// self-asserted confidence. Deterministic.
//
// A transcript that did not resolve scores noResolutionBase (low). Otherwise the
// score is the sum of capped tool-call, distinct-tool, and evidence-citation
// contributions, minus the iteration thrashing penalty, clamped to [0, 1].
func StructuralConfidence(t Transcript) float64 {
	if !t.Resolved {
		return clamp01(noResolutionBase)
	}

	tc := min(t.ToolCalls, toolCallCap)
	tcContribution := float64(tc) * toolCallWeight

	dt := min(t.DistinctTools, distinctToolCap)
	dtContribution := float64(dt) * distinctToolWeight

	evidenceCount := 0
	for _, p := range evidencePatterns {
		if p.MatchString(t.Reason) {
			evidenceCount++
		}
	}
	ev := min(evidenceCount, evidenceCap)
	evContribution := float64(ev) * evidenceWeight

	excess := t.Iterations - iterationFree
	if excess < 0 {
		excess = 0
	}
	iterPenalty := float64(excess) * iterationPenalty

	score := tcContribution + dtContribution + evContribution - iterPenalty
	return clamp01(score)
}

// clamp01 clamps x to [0.0, 1.0].
func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
