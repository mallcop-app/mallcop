package agent

import "testing"

// --- StructuralConfidence: model-independent score from observable signals. ---

func TestStructuralConfidence_NoResolution_ScoresLow(t *testing.T) {
	// A transcript that did not resolve scores near the no-resolution base — well
	// below the fan-out threshold — regardless of how many tools were "claimed".
	got := StructuralConfidence(Transcript{Resolved: false, ToolCalls: 8, DistinctTools: 4})
	if got >= ConfidenceFanOutThreshold {
		t.Fatalf("a non-resolution must score below %.2f, got %.3f", ConfidenceFanOutThreshold, got)
	}
}

func TestStructuralConfidence_ShallowResolve_BelowThreshold(t *testing.T) {
	// The dangerous case: a model "sure" it's benign but that barely looked — one
	// tool call, one distinct tool, no evidence citations. Must score below the
	// fan-out threshold so the runtime gate blocks the resolve.
	got := StructuralConfidence(Transcript{
		Resolved:      true,
		ToolCalls:     1,
		DistinctTools: 1,
		Iterations:    1,
		Reason:        "looks fine",
	})
	if got >= ConfidenceFanOutThreshold {
		t.Fatalf("a shallow resolve must score below the %.2f threshold, got %.3f", ConfidenceFanOutThreshold, got)
	}
}

func TestStructuralConfidence_ThoroughResolve_MeetsThreshold(t *testing.T) {
	// A thorough resolve: many tool calls, several distinct tools, an evidence-
	// dense reason. Must clear the threshold.
	got := StructuralConfidence(Transcript{
		Resolved:      true,
		ToolCalls:     8,
		DistinctTools: 4,
		Iterations:    3,
		Reason: "Baseline shows actor login frequency count 412; events on 2026-03-10 at 09:02 from " +
			"IP 203.0.113.10 match first_seen relationship; known actor, no privilege change.",
	})
	if got < ConfidenceFanOutThreshold {
		t.Fatalf("a thorough resolve must clear the %.2f threshold, got %.3f", ConfidenceFanOutThreshold, got)
	}
}

func TestStructuralConfidence_Deterministic(t *testing.T) {
	// The Go scorer drops the Python noise floor so a runtime gate built on it is
	// reproducible. Same input must yield the same score every time.
	tr := Transcript{Resolved: true, ToolCalls: 5, DistinctTools: 3, Iterations: 4, Reason: "baseline count 10 events on 2026-03-10"}
	first := StructuralConfidence(tr)
	for i := 0; i < 100; i++ {
		if got := StructuralConfidence(tr); got != first {
			t.Fatalf("StructuralConfidence is not deterministic: %.6f vs %.6f", first, got)
		}
	}
}

func TestStructuralConfidence_IterationPenalty(t *testing.T) {
	// Excess iterations (thrashing) must lower the score relative to an otherwise
	// identical efficient run.
	efficient := Transcript{Resolved: true, ToolCalls: 6, DistinctTools: 3, Iterations: 3, Reason: "baseline frequency known"}
	thrashing := efficient
	thrashing.Iterations = 12
	if StructuralConfidence(thrashing) >= StructuralConfidence(efficient) {
		t.Fatalf("thrashing (12 iters) must score lower than efficient (3 iters)")
	}
}

// --- GuardResolve: the two runtime gates on the resolve action. ---

func TestGuardResolve_FailSafe_AmbiguousEscalates(t *testing.T) {
	d, _ := GuardResolve(ResolveAttempt{Ambiguous: true, HasPositiveEvidence: true,
		Transcript: thoroughTranscript()})
	if d != ResolveEscalated {
		t.Fatalf("ambiguous evidence must escalate, got %q", d)
	}
}

func TestGuardResolve_FailSafe_EmptyToolEscalates(t *testing.T) {
	d, _ := GuardResolve(ResolveAttempt{ToolReturnedEmpty: true, HasPositiveEvidence: true,
		Transcript: thoroughTranscript()})
	if d != ResolveEscalated {
		t.Fatalf("an empty tool result must escalate (a finding, not a dismissal), got %q", d)
	}
}

func TestGuardResolve_FailSafe_LowSelfConfidenceEscalates(t *testing.T) {
	for _, c := range []int{1, 2} {
		d, _ := GuardResolve(ResolveAttempt{SelfConfidence: c, HasPositiveEvidence: true,
			Transcript: thoroughTranscript()})
		if d != ResolveEscalated {
			t.Fatalf("self-confidence %d (1-2) must escalate, got %q", c, d)
		}
	}
}

func TestGuardResolve_FailSafe_NoPositiveEvidenceEscalates(t *testing.T) {
	// Even a structurally thorough run must escalate if it lacks POSITIVE evidence
	// of legitimacy — "actor is known" alone is not enough.
	d, _ := GuardResolve(ResolveAttempt{HasPositiveEvidence: false, Transcript: thoroughTranscript()})
	if d != ResolveEscalated {
		t.Fatalf("absent positive evidence must escalate, got %q", d)
	}
}

func TestGuardResolve_StructuralGate_LowConfidenceFansOut(t *testing.T) {
	// Fail-safe passes (positive evidence, no ambiguity, no empty tool, no low
	// self-confidence) but the investigation is structurally shallow → fan out.
	d, reason := GuardResolve(ResolveAttempt{
		HasPositiveEvidence: true,
		Transcript:          Transcript{Resolved: true, ToolCalls: 1, DistinctTools: 1, Iterations: 1, Reason: "fine"},
	})
	if d != ResolveFanOut {
		t.Fatalf("a shallow but fail-safe-passing resolve must fan out, got %q (%s)", d, reason)
	}
}

func TestGuardResolve_BothGatesPass_ResolveAllowed(t *testing.T) {
	d, reason := GuardResolve(ResolveAttempt{
		HasPositiveEvidence: true,
		SelfConfidence:      5,
		Transcript:          thoroughTranscript(),
	})
	if d != ResolveAllowed {
		t.Fatalf("a thorough, positive-evidence resolve must be allowed, got %q (%s)", d, reason)
	}
}

func TestGuardResolve_SelfConfidenceCannotBypassStructuralGate(t *testing.T) {
	// A model claiming confidence 5 over a shallow investigation must STILL be
	// blocked by the structural gate — self-report never raises the verdict.
	d, _ := GuardResolve(ResolveAttempt{
		HasPositiveEvidence: true,
		SelfConfidence:      5,
		Transcript:          Transcript{Resolved: true, ToolCalls: 1, DistinctTools: 1, Iterations: 1, Reason: "trust me"},
	})
	if d != ResolveFanOut {
		t.Fatalf("self-confidence 5 must not bypass the structural gate; expected fan-out, got %q", d)
	}
}

// thoroughTranscript is a structurally strong investigation used as the shared
// positive baseline for the fail-safe tests (so those tests isolate the
// fail-safe trigger, not the structural score).
func thoroughTranscript() Transcript {
	return Transcript{
		Resolved:      true,
		ToolCalls:     8,
		DistinctTools: 4,
		Iterations:    3,
		Reason: "Baseline frequency count 412 for known actor; events 2026-03-10 09:02 from IP 203.0.113.10; " +
			"first_seen relationship confirms; no privilege change.",
	}
}
