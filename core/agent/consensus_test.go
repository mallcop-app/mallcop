package agent

// consensus_test.go — in-package unit test of the committee-consensus gate,
// mirroring the Python tests/unit/test_consensus.py case-for-case:
//
//	needs_consensus:  true on RESOLVED, false on ESCALATED / no-resolution.
//	run_consensus:    unanimous-resolve → resolve (original kept);
//	                  one-dissent → escalate; all-dissent → escalate;
//	                  runner error → escalate; no-resolution → escalate.
//
// The Go gate (runConsensusGate) re-runs the WHOLE cascade per voter rather than
// calling a mock runner, so the driver below controls each re-run's TERMINAL
// action through a content-aware client: every re-run starts with a triage call,
// and the outcome scripted for that re-run determines whether the cascade resolves
// (clean triage resolve, 1 call) or escalates (triage→investigate→escalate, 3
// calls). This is the same content-routing discipline the eval golden backend and
// fanout tests use, made deterministic regardless of call count.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// consensusVote is the terminal outcome scripted for one cascade re-run.
type consensusVote int

const (
	voteResolve  consensusVote = iota // clean triage resolve  → terminal ActionProceed
	voteEscalate                      // triage+investigate escalate → terminal ActionEscalated
	voteError                         // client returns an error → tier fail-safe → escalate
)

// scriptClient is a content-aware agent.Client driving runConsensusGate's re-runs.
// It serves a fixed list of per-re-run votes: a NEW triage call (system prompt
// carries the Triage Agent header) advances to the next vote. Within a re-run it
// returns the resolve or escalate JSON appropriate to the requesting tier, so a
// resolve re-run terminates at triage (1 call) and an escalate re-run runs the
// full triage→investigate→escalate chain (3 calls) — both deterministically.
type scriptClient struct {
	mu    sync.Mutex
	votes []consensusVote
	idx   int // -1 until the first triage call; then indexes votes
	calls int
}

const (
	cleanResolveJSON = `{"action":"resolve","confidence":5,"positive_evidence":true,"strong_evidence":false,"insufficient_data":false,"reason":"benign: positive evidence of legitimacy in baseline + events"}`
	escalateJSON     = `{"action":"escalate","confidence":3,"positive_evidence":false,"strong_evidence":false,"insufficient_data":false,"reason":"no positive evidence to clear; escalating"}`
)

func (c *scriptClient) Messages(ctx context.Context, req MessagesRequest) (MessagesResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++

	isTriage := strings.Contains(req.System, "# Triage Agent")
	if isTriage {
		c.idx++ // each re-run begins with exactly one triage call
	}
	if c.idx < 0 || c.idx >= len(c.votes) {
		// More re-runs than scripted votes: fail safe to escalate.
		return MessagesResponse{StopReason: "end_turn",
			Content: []ContentBlock{{Type: "text", Text: escalateJSON}}}, nil
	}
	vote := c.votes[c.idx]

	switch vote {
	case voteError:
		return MessagesResponse{}, errors.New("scripted client error")
	case voteResolve:
		// Triage clean resolve terminates the cascade at triage.
		return MessagesResponse{StopReason: "end_turn",
			Content: []ContentBlock{{Type: "text", Text: cleanResolveJSON}}}, nil
	default: // voteEscalate — every tier returns escalate (terminal escalate).
		text := escalateJSON
		if strings.Contains(req.System, "# Escalate Agent") {
			text = "SECURITY ALERT: escalated for human review."
		}
		return MessagesResponse{StopReason: "end_turn",
			Content: []ContentBlock{{Type: "text", Text: text}}}, nil
	}
}

// consensusOpts returns CascadeOptions that let a clean triage resolve TERMINATE:
// no consensus recursion (set by the gate), a tool runner supplying positive
// evidence so cleanResolve() holds, and RepoRoot pinned to a benign temp corpus so
// checkHardConstraints never force-escalates the test finding.
func consensusOpts(t *testing.T) CascadeOptions {
	t.Helper()
	return CascadeOptions{
		RepoRoot: writeCorpus(t, seedCorpus), // benign family below matches no route
		Tools: scriptedToolsInternal{
			toolCalls: 2, distinctTools: 2,
			baselineText: "baseline: actor known, frequency 412; relationships established",
			eventsText:   "events: evt_001 routine read by known actor",
		},
	}.defaulted()
}

// scriptedToolsInternal is the in-package twin of cascade_test.go's scriptedTools
// (that one lives in the external test package). It feeds the cascade deterministic
// positive evidence so a model resolve passes the triage rubric.
type scriptedToolsInternal struct {
	baselineText  string
	eventsText    string
	toolCalls     int
	distinctTools int
}

func (s scriptedToolsInternal) RunTools(_ context.Context, _ string, _ finding.Finding) (ToolEvidence, error) {
	return ToolEvidence{
		BaselineText:  s.baselineText,
		EventsText:    s.eventsText,
		ToolCalls:     s.toolCalls,
		DistinctTools: s.distinctTools,
	}, nil
}

// benignFinding is a low-severity, non-malicious-marker finding of a family that
// matches NO escalate route — so the cascade's terminal action is driven entirely
// by the model's scripted verdict, never by the floor or the triagerisk gate.
func benignFinding() finding.Finding {
	return finding.Finding{
		ID: "fnd_001", Type: "unusual-login", Severity: "low",
		Actor: "known-actor", Source: "azure",
		Reason: "first login from a new but plausible location",
	}
}

// firstResolve is the original resolve the gate is handed (the inner cascade's
// terminal ActionProceed). Reason/Family must survive a unanimous resolve.
func firstResolve() Resolution {
	return Resolution{Action: ActionProceed, Family: "unusual-login",
		Reason: "triage resolved (benign): looks benign"}
}

// --- needs_consensus parity (test_consensus.py::TestNeedsConsensus) ----------

func TestNeedsConsensus_TrueWhenResolved(t *testing.T) {
	if !needsConsensus(Resolution{Action: ActionProceed}) {
		t.Fatal("needsConsensus must be TRUE for a resolved (ActionProceed) result")
	}
}

func TestNeedsConsensus_FalseWhenEscalated(t *testing.T) {
	if needsConsensus(Resolution{Action: ActionEscalated}) {
		t.Fatal("needsConsensus must be FALSE for an escalated result (already going to a human)")
	}
}

// --- run_consensus parity (test_consensus.py::TestRunConsensus) --------------

func TestRunConsensus_UnanimousResolve_KeepsOriginal(t *testing.T) {
	opts := consensusOpts(t)
	client := &scriptClient{votes: []consensusVote{voteResolve, voteResolve}, idx: -1}
	first := firstResolve()

	got := runConsensusGate(context.Background(), client, benignFinding(), opts, first, 2)

	if got.Action != ActionProceed {
		t.Fatalf("unanimous resolve must stay RESOLVED (ActionProceed); got %q (%s)", got.Action, got.Reason)
	}
	// Original reason + family are preserved verbatim on a unanimous resolve.
	if got.Reason != first.Reason || got.Family != first.Family {
		t.Fatalf("unanimous resolve must return the ORIGINAL result; got reason=%q family=%q", got.Reason, got.Family)
	}
}

func TestRunConsensus_OneDissent_OverridesToEscalate(t *testing.T) {
	opts := consensusOpts(t)
	client := &scriptClient{votes: []consensusVote{voteResolve, voteEscalate}, idx: -1}

	got := runConsensusGate(context.Background(), client, benignFinding(), opts, firstResolve(), 2)

	if got.Action != ActionEscalated {
		t.Fatalf("one dissent must override to ESCALATE; got %q", got.Action)
	}
	if !strings.Contains(got.Reason, "Consensus escalation") {
		t.Fatalf("override reason must say 'Consensus escalation'; got %q", got.Reason)
	}
	// 1 original + 1 re-run resolve = 2 resolved, 1 escalated, of 3 voters.
	if !strings.Contains(got.Reason, "2/3 resolved") || !strings.Contains(got.Reason, "1/3 escalated") {
		t.Fatalf("override reason must tally 2/3 resolved, 1/3 escalated; got %q", got.Reason)
	}
	if got.ForceEscalated || got.RouteID != "" {
		t.Fatalf("a consensus override is a CHAIN escalation: ForceEscalated=false, RouteID=\"\"; got forceEsc=%v route=%q", got.ForceEscalated, got.RouteID)
	}
}

func TestRunConsensus_AllDissent_Escalates(t *testing.T) {
	opts := consensusOpts(t)
	client := &scriptClient{votes: []consensusVote{voteEscalate, voteEscalate, voteEscalate}, idx: -1}

	got := runConsensusGate(context.Background(), client, benignFinding(), opts, firstResolve(), 3)

	if got.Action != ActionEscalated {
		t.Fatalf("all dissent must ESCALATE; got %q", got.Action)
	}
	// 1 original resolve + 0 re-run resolves = 1/4 resolved, 3/4 escalated.
	if !strings.Contains(got.Reason, "1/4 resolved") || !strings.Contains(got.Reason, "3/4 escalated") {
		t.Fatalf("all-dissent reason must tally 1/4 resolved, 3/4 escalated; got %q", got.Reason)
	}
}

func TestRunConsensus_RunnerError_CountsAsEscalated(t *testing.T) {
	opts := consensusOpts(t)
	// A re-run whose model call errors fails safe to escalate inside the cascade —
	// the gate sees a non-ActionProceed terminal and counts it as a dissent.
	client := &scriptClient{votes: []consensusVote{voteError}, idx: -1}

	got := runConsensusGate(context.Background(), client, benignFinding(), opts, firstResolve(), 1)

	if got.Action != ActionEscalated {
		t.Fatalf("a re-run error must count as escalate (error = escalate); got %q", got.Action)
	}
}

func TestRunConsensus_EscalationPreservesOriginalReason(t *testing.T) {
	opts := consensusOpts(t)
	first := Resolution{Action: ActionProceed, Family: "unusual-login",
		Reason: "triage resolved (benign): looks benign"}
	client := &scriptClient{votes: []consensusVote{voteEscalate}, idx: -1}

	got := runConsensusGate(context.Background(), client, benignFinding(), opts, first, 1)

	if !strings.Contains(got.Reason, "looks benign") {
		t.Fatalf("override reason must carry the ORIGINAL reason; got %q", got.Reason)
	}
}

// --- STOCHASTICITY: the re-runs are dispatched with a NON-ZERO temperature so the
// committee samples independently (a deterministic re-run would make consensus
// vacuous). This proves the temperature is threaded all the way into every tier's
// MessagesRequest on the consensus path — and NOT set on a non-consensus call. ---

func TestRunConsensus_ReRunsCarryNonZeroTemperature(t *testing.T) {
	opts := consensusOpts(t)
	tc := &tempProbeClient{}
	// 2 resolve re-runs: each is a single triage call → 2 probed requests.
	runConsensusGate(context.Background(), tc, benignFinding(), opts, firstResolve(), 2)

	tc.mu.Lock()
	defer tc.mu.Unlock()
	if len(tc.temps) == 0 {
		t.Fatal("consensus gate made no model calls; cannot verify temperature threading")
	}
	for i, tp := range tc.temps {
		if tp == nil {
			t.Fatalf("consensus re-run call #%d carried NIL temperature; re-runs MUST set a non-zero temperature or the committee samples identically (vacuous consensus)", i)
		}
		if *tp != consensusTemperature {
			t.Fatalf("consensus re-run call #%d temperature = %v; want %v (the mandatory stochastic sampling temperature)", i, *tp, consensusTemperature)
		}
	}
}

// --- HOOK POINT: the gate is wired INSIDE ResolveFindingWith (the spec's hook),
// gated by ConsensusRuns>0, and fires on the terminal ActionProceed of the full
// cascade. With ConsensusRuns=0 the same finding resolves single-pass (no gate);
// with ConsensusRuns>0 a dissenting re-run flips the terminal to escalate. ------

func TestResolveFindingWith_ConsensusGate_FiresOnResolve(t *testing.T) {
	base := consensusOpts(t)

	// Re-runs of the WHOLE cascade: the first call is the original triage resolve
	// (vote 0), then ConsensusRuns re-runs. Script: original resolves, then one
	// re-run dissents (escalate) → override to escalate.
	t.Run("dissent_overrides", func(t *testing.T) {
		client := &scriptClient{votes: []consensusVote{voteResolve, voteResolve, voteEscalate, voteResolve}, idx: -1}
		opts := base
		opts.ConsensusRuns = 3
		res := ResolveFindingWith(context.Background(), client, benignFinding(), opts)
		if res.Action != ActionEscalated {
			t.Fatalf("ResolveFindingWith with a dissenting consensus re-run must ESCALATE; got %q (%s)", res.Action, res.Reason)
		}
		if !strings.Contains(res.Reason, "Consensus escalation") {
			t.Fatalf("terminal reason must cite the consensus override; got %q", res.Reason)
		}
	})

	// All voters resolve → the wrapper keeps the resolve.
	t.Run("unanimous_keeps_resolve", func(t *testing.T) {
		client := &scriptClient{votes: []consensusVote{voteResolve, voteResolve, voteResolve, voteResolve}, idx: -1}
		opts := base
		opts.ConsensusRuns = 3
		res := ResolveFindingWith(context.Background(), client, benignFinding(), opts)
		if res.Action != ActionProceed {
			t.Fatalf("ResolveFindingWith with a unanimous consensus must RESOLVE; got %q (%s)", res.Action, res.Reason)
		}
	})

	// ConsensusRuns=0 → no gate: the single-pass resolve stands with exactly the
	// original triage call (proves the gate is opt-in and the default path is
	// unchanged — what keeps every existing call-count test green).
	t.Run("disabled_when_zero_runs", func(t *testing.T) {
		client := &scriptClient{votes: []consensusVote{voteResolve}, idx: -1}
		opts := base
		opts.ConsensusRuns = 0
		res := ResolveFindingWith(context.Background(), client, benignFinding(), opts)
		if res.Action != ActionProceed {
			t.Fatalf("ConsensusRuns=0 must resolve single-pass; got %q", res.Action)
		}
		if client.calls != 1 {
			t.Fatalf("ConsensusRuns=0 must make exactly 1 (triage) model call, no re-runs; got %d", client.calls)
		}
	})
}

// tempProbeClient records the Temperature pointer on every request and always
// returns a clean triage resolve so the cascade terminates at triage (1 call/re-run).
type tempProbeClient struct {
	mu    sync.Mutex
	temps []*float64
}

func (c *tempProbeClient) Messages(ctx context.Context, req MessagesRequest) (MessagesResponse, error) {
	c.mu.Lock()
	c.temps = append(c.temps, req.Temperature)
	c.mu.Unlock()
	return MessagesResponse{StopReason: "end_turn",
		Content: []ContentBlock{{Type: "text", Text: cleanResolveJSON}}}, nil
}
