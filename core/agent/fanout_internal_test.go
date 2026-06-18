package agent

// fanout_internal_test.go — WHITE-BOX coverage for the two merge ESCALATE
// safety branches that are unreachable through the public cascade API:
//
//   (1) the NIL-CLIENT fail-safe at the head of runFanOut (fanout.go:116-119).
//       The public ResolveFindingWith guards a nil client BEFORE it ever reaches
//       the fan-out (cascade.go), so a black-box test can never drive a nil
//       client into runFanOut. This is defense-in-depth: runFanOut is also called
//       internally, and if a future refactor ever routed a nil client here the
//       3 deep goroutines would dereference it and PANIC (fail-open by crash).
//       The branch must fail SAFE (escalate), never panic, never resolve.
//
//   (2) the "a deep tier failed safe" reason-SUFFIX branch on the
//       majority-escalate terminal (fanout.go:257-259). mergeDeepResults appends
//       this suffix when any deep tier fail-safed (tool/model error, unparseable
//       reply). The black-box panel backend always returns a parseable reply, so
//       no deep tier fail-safes through it; the suffix branch is only reachable by
//       handing mergeDeepResults a result slice with failSafe:true directly.
//
// These are package-internal (`package agent`) because runFanOut and
// mergeDeepResults are unexported. The black-box scenarios live in fanout_test.go.

import (
	"context"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// internalFanOutFinding + opts mirror the black-box fixture: a finding that
// reaches investigate with shallow tools so a resolve is gate-blocked. The
// nil-client test never actually runs tools (it short-circuits), but the opts
// keep the call shape identical to the production caller.
func internalFanOutFinding() finding.Finding {
	return finding.Finding{
		ID: "FANOUT-INT-01", Type: "external-access", Severity: "high", Actor: "vendor-x",
		Source: "okta", Reason: "external access from new trust domain",
	}
}

// TestRunFanOut_NilClient_FailsSafeEscalates_NoPanic proves the nil-client
// fail-safe (fanout.go:116-119). runFanOut is invoked DIRECTLY with a nil Client.
// It must return a terminal ESCALATE and must NOT panic (which is what would
// happen if it fell through to spawn the 3 deep goroutines, each of which calls
// client.Messages on the nil client).
//
// MUTATION-PROOF: changing `if client == nil` to `if false` deletes the guard;
// runFanOut then builds the partial transcript and launches the deep goroutines,
// which call (nil).Messages and PANIC — the test fails with a panic instead of a
// clean escalate. Restored, it passes.
func TestRunFanOut_NilClient_FailsSafeEscalates_NoPanic(t *testing.T) {
	// A parent investigate result as the gate would hand it to the fan-out: a
	// proposed resolve the structural gate blocked. Its contents are irrelevant to
	// the nil-client branch (which short-circuits before reading it) but match the
	// production call shape.
	parent := tierResult{
		tier:       "investigate",
		verdict:    VerdictResolve,
		selfConf:   5,
		hasPosEvid: true,
		reason:     "seems fine to me",
	}

	// runFanOut must not panic on a nil client. A panic here = fail-OPEN by crash.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("runFanOut PANICKED on a nil client (fail-open by crash); it must fail SAFE (escalate): %v", r)
		}
	}()

	res := runFanOut(context.Background(), nil, internalFanOutFinding(), CascadeOptions{}.defaulted(),
		parent, "structural score 0.30 < 0.55")

	if res.Action != ActionEscalated {
		t.Fatalf("a nil-client fan-out must fail SAFE (ActionEscalated), never resolve; got action=%q reason=%q", res.Action, res.Reason)
	}
	if res.ForceEscalated {
		t.Fatalf("a fan-out fail-safe is a chain escalation, not a floor force-escalate; got %+v", res)
	}
	if !strings.Contains(res.Reason, "fail-safe") {
		t.Fatalf("the nil-client escalation must be attributed to the fail-safe; got %q", res.Reason)
	}
	// The gate reason must be carried forward in the audit trail.
	if !strings.Contains(res.Reason, "structural score 0.30 < 0.55") {
		t.Fatalf("the nil-client escalation must carry the upstream gate reason; got %q", res.Reason)
	}
}

// TestMergeDeepResults_FailSafeTier_AppendsSuffix proves the "a deep tier failed
// safe" reason-suffix branch on the majority-escalate terminal (fanout.go:
// 257-259). A deep tier that fail-safed (here: an unparseable/model-error tier
// the runtime defaulted to escalate, failSafe=true) contributes an escalate AND
// stamps the suffix so the audit trail records that ambiguity, not a positive
// malicious read, drove (part of) the escalation.
//
// Scenario: one resolve dissent + two SUSPICIOUS escalates, one of which is a
// fail-safe. nResolve=1, nSusp=2 ⇒ rule (5) majority-escalate; anyFailSafe=true
// ⇒ the suffix is appended. (A direct mergeDeepResults call with a nil client is
// fine here: the terminal escalate formatter tolerates a nil client — it keeps
// the upstream reason as the alert — so the reason text we assert is intact.)
//
// MUTATION-PROOF: deleting the `if anyFailSafe { reason += ... }` branch drops the
// suffix and this test fails on the missing substring. Restored, it passes.
func TestMergeDeepResults_FailSafeTier_AppendsSuffix(t *testing.T) {
	results := []deepResult{
		{
			hypothesis: "benign",
			verdict:    VerdictResolve,
			selfConf:   4,
			hasPosEvid: true,
			reason:     "documented onboarding; baseline match.",
		},
		{
			hypothesis:   "malicious",
			verdict:      VerdictEscalate,
			selfConf:     3,
			hasPosEvid:   false,
			insufficient: false,
			reason:       "unusual access pattern; no decisive vector but not benign.",
		},
		{
			// A FAIL-SAFED tier: the runtime could not get a trustworthy verdict
			// (model error / unparseable reply) and defaulted it to escalate.
			hypothesis: "incomplete",
			verdict:    VerdictEscalate,
			selfConf:   0,
			hasPosEvid: false,
			failSafe:   true,
			reason:     "deep-investigate:incomplete: model reply unparseable; escalating (fail-safe)",
		},
	}

	res := mergeDeepResults(context.Background(), nil, internalFanOutFinding(), CascadeOptions{}.defaulted(), results)

	if res.Action != ActionEscalated {
		t.Fatalf("1 resolve vs 2 suspicious (one fail-safed) must ESCALATE; got action=%q reason=%q", res.Action, res.Reason)
	}
	if !strings.Contains(res.Reason, "majority ESCALATE") {
		t.Fatalf("a majority-escalate terminal must be attributed to the majority-ESCALATE rule; got %q", res.Reason)
	}
	if !strings.Contains(res.Reason, "a deep tier failed safe") {
		t.Fatalf("the fail-safe SUFFIX must be appended when a deep tier failed safe; got %q", res.Reason)
	}
}
