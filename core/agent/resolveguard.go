// resolveguard.go — the two RUNTIME gates on the resolve (close-as-benign)
// action. The model cannot talk past either; both are code, not prompt text.
//
//  1. STRUCTURAL-CONFIDENCE GATE (portable-agent-architecture.md §2.4):
//     a resolve whose StructuralConfidence is below ConfidenceFanOutThreshold
//     (0.55) is BLOCKED and converted into a fan-out signal (3 deep-investigate
//     hypotheses + 1 merge). This is the false-negative guard — a model that is
//     "sure" because it didn't actually look (few tool calls, no distinct tools,
//     no evidence citations) scores low and cannot resolve.
//
//  2. FAIL-SAFE RESOLVE GATE (§2.5): ambiguous / tool-returned-empty /
//     unparseable / self-reported confidence 1-2 => ESCALATE. Resolution
//     requires POSITIVE evidence; absence of evidence is a reason to escalate,
//     never to silently dismiss. Asymmetric error cost is baked into the
//     default: a false escalate wastes analyst time; a false resolve misses an
//     incident.
//
// Pure functions over an explicit ResolveAttempt — no I/O, no model calls.
package agent

import "fmt"

// ResolveDecision is the outcome of running the resolve gates on a proposed
// resolve. Exactly one of the three dispositions is set.
type ResolveDecision string

const (
	// ResolveAllowed: both gates passed; the resolve (close-as-benign) stands.
	ResolveAllowed ResolveDecision = "resolve-allowed"
	// ResolveEscalated: the fail-safe gate fired; escalate to a human instead.
	ResolveEscalated ResolveDecision = "resolve-escalated"
	// ResolveFanOut: the structural-confidence gate fired; the resolve is blocked
	// and the run fans out to a deep panel (3 hypotheses + merge).
	ResolveFanOut ResolveDecision = "resolve-fanout"
)

// ResolveAttempt is the model's proposed resolve plus the observable signals the
// gates judge it by. The agent loop assembles this when the model tries to
// close a finding as benign.
type ResolveAttempt struct {
	// Transcript carries the observable investigation signals (tool calls,
	// distinct tools, iterations, reason text) scored by StructuralConfidence.
	Transcript Transcript

	// SelfConfidence is the model's self-reported 1-5 confidence (§2.4 scale),
	// or 0 when none was supplied. 1-2 force-escalates per the fail-safe rule.
	// It is advisory ONLY for the fail-safe floor; it never RAISES the verdict —
	// a model claiming 5 cannot bypass the structural gate.
	SelfConfidence int

	// ToolReturnedEmpty is true when a tool the investigation relied on returned
	// an empty result (no events, no matched rules). Per §2.5 + §3.4 an empty
	// tool result is a finding, not a dismissal — it force-escalates.
	ToolReturnedEmpty bool

	// Ambiguous is true when the agent itself flagged the evidence as ambiguous /
	// unparseable. Ambiguity always escalates.
	Ambiguous bool

	// HasPositiveEvidence must be true to RESOLVE. "Actor is known" alone is not
	// positive evidence; the bar is "actor has done this specific action on this
	// specific target before" (§2.2). When false, the resolve is escalated:
	// resolution requires positive evidence.
	HasPositiveEvidence bool
}

// GuardResolve runs both runtime gates on a proposed resolve and returns the
// disposition plus a human-readable reason. Gate order is load-bearing:
//
//  1. FAIL-SAFE FIRST. Ambiguity, empty tool results, unparseable evidence,
//     self-confidence 1-2, or absent positive evidence escalate immediately.
//     These are the cheap, certain "don't even think about resolving" cases.
//  2. STRUCTURAL CONFIDENCE SECOND. If the fail-safe lets the resolve through,
//     score the investigation structurally. Below threshold → fan-out (the run
//     wasn't thorough enough to trust a resolve, but nothing screams escalate).
//  3. Otherwise → resolve allowed.
//
// The model is never consulted in this function; it judges the model's output.
func GuardResolve(a ResolveAttempt) (ResolveDecision, string) {
	// (1) Fail-safe gate (§2.5) — ambiguity/empty/unparseable/low-confidence/
	// no-positive-evidence all escalate. Never silently dismiss.
	if a.Ambiguous {
		return ResolveEscalated, "fail-safe: evidence is ambiguous or unparseable; escalating (resolution requires positive evidence)"
	}
	if a.ToolReturnedEmpty {
		return ResolveEscalated, "fail-safe: a relied-on tool returned empty; an empty result is a finding, not a dismissal; escalating"
	}
	if a.SelfConfidence >= 1 && a.SelfConfidence <= 2 {
		return ResolveEscalated, fmt.Sprintf("fail-safe: self-reported confidence %d (1-2) is below the resolve floor; escalating", a.SelfConfidence)
	}
	if !a.HasPositiveEvidence {
		return ResolveEscalated, "fail-safe: no positive evidence of legitimacy; 'actor is known' alone is insufficient; escalating"
	}

	// (2) Structural-confidence gate (§2.4) — model-independent false-negative
	// guard. A resolve the model is "sure" of but did not actually work for
	// scores low and fans out to the deep panel.
	score := StructuralConfidence(a.Transcript)
	if score < ConfidenceFanOutThreshold {
		return ResolveFanOut, fmt.Sprintf(
			"structural-confidence gate: score %.3f < %.2f threshold; resolve blocked, fanning out to deep panel (3 hypotheses + merge)",
			score, ConfidenceFanOutThreshold)
	}

	// (3) Both gates passed.
	return ResolveAllowed, fmt.Sprintf("resolve allowed: structural confidence %.3f >= %.2f and positive evidence present", score, ConfidenceFanOutThreshold)
}
