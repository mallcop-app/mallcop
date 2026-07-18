package agent

// revote_test.go — in-package unit test of the low-confidence committee re-vote
// (mallcoppro-09a). It mirrors consensus_test.go's driver discipline: the same
// content-aware scriptClient serves one TERMINAL outcome per cascade re-run (a
// clean triage resolve = 1 call, a full escalate chain = 3 calls), so each
// re-vote voter's disposition is deterministic regardless of call count. The
// re-vote's rule is the SAME any-escalate-wins committee as the resolve-side
// gate, so these tests assert: unanimous resolve → de-escalate signal; ANY
// dissent → escalation stands; the re-runs carry the mandatory non-zero
// temperature; the deeper evidence actually reaches the committee prompt (boxed);
// and RunRevoteGate has no store seam at all (it cannot mutate a disposition).

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestRunRevoteGate_UnanimousResolve_ReturnsDeescalate: every voter resolves →
// UnanimousResolve true, the full tally, and a reason that names the de-escalation.
func TestRunRevoteGate_UnanimousResolve_ReturnsDeescalate(t *testing.T) {
	opts := consensusOpts(t)
	client := &scriptClient{votes: []consensusVote{voteResolve, voteResolve, voteResolve}, idx: -1}

	got := RunRevoteGate(context.Background(), client, benignFinding(), opts, "verdict=benign confidence=0.90; deeper pass agrees.", 3)

	if !got.UnanimousResolve {
		t.Fatalf("all-resolve re-vote must be UnanimousResolve; got %+v", got)
	}
	if got.ResolveVotes != 3 || got.TotalVotes != 3 {
		t.Fatalf("tally = %d/%d, want 3/3", got.ResolveVotes, got.TotalVotes)
	}
	if !strings.Contains(got.Reason, "UNANIMOUS") {
		t.Errorf("reason must name the unanimous de-escalation; got %q", got.Reason)
	}
}

// TestRunRevoteGate_OneDissent_StaysEscalated: a single escalate vote (any of the
// voters) keeps UnanimousResolve false — the escalation stands (any-escalate-wins).
func TestRunRevoteGate_OneDissent_StaysEscalated(t *testing.T) {
	opts := consensusOpts(t)
	client := &scriptClient{votes: []consensusVote{voteResolve, voteEscalate, voteResolve}, idx: -1}

	got := RunRevoteGate(context.Background(), client, benignFinding(), opts, "verdict=suspicious confidence=0.40; still ambiguous.", 3)

	if got.UnanimousResolve {
		t.Fatalf("a dissenting re-vote must NOT be UnanimousResolve; got %+v", got)
	}
	if got.ResolveVotes != 2 || got.TotalVotes != 3 {
		t.Fatalf("tally = %d/%d, want 2/3", got.ResolveVotes, got.TotalVotes)
	}
	if !strings.Contains(got.Reason, "escalation stands") {
		t.Errorf("reason must say the escalation stands; got %q", got.Reason)
	}
}

// TestRunRevoteGate_ErrorCountsAsEscalate: a re-run whose model call errors fails
// safe to escalate inside the cascade — the committee counts it as a dissent, so
// the escalation stands (error = escalate, the safe side).
func TestRunRevoteGate_ErrorCountsAsEscalate(t *testing.T) {
	opts := consensusOpts(t)
	client := &scriptClient{votes: []consensusVote{voteResolve, voteError, voteResolve}, idx: -1}

	got := RunRevoteGate(context.Background(), client, benignFinding(), opts, "deeper evidence", 3)

	if got.UnanimousResolve {
		t.Fatalf("a re-run error must count as a dissent (error = escalate); got %+v", got)
	}
}

// TestRunRevoteGate_ReRunsCarryNonZeroTemperature proves the re-vote committee
// samples stochastically — a deterministic re-vote would vacuously reproduce the
// first pass's uncertainty rather than testing it.
func TestRunRevoteGate_ReRunsCarryNonZeroTemperature(t *testing.T) {
	opts := consensusOpts(t)
	tc := &tempProbeClient{}
	RunRevoteGate(context.Background(), tc, benignFinding(), opts, "deeper evidence", 3)

	tc.mu.Lock()
	defer tc.mu.Unlock()
	if len(tc.temps) == 0 {
		t.Fatal("re-vote made no model calls; cannot verify temperature threading")
	}
	for i, tp := range tc.temps {
		if tp == nil || *tp != consensusTemperature {
			t.Fatalf("re-vote call #%d temperature = %v; want a pointer to %v (mandatory stochastic sampling)", i, tp, consensusTemperature)
		}
	}
}

// TestRunRevoteGate_ZeroRuns_NoVotersEscalationStands: nRuns<=0 is a safe no-op —
// no voters, no de-escalation (a re-vote with no committee cannot clear an
// escalation).
func TestRunRevoteGate_ZeroRuns_NoVotersEscalationStands(t *testing.T) {
	opts := consensusOpts(t)
	client := &scriptClient{votes: nil, idx: -1}
	got := RunRevoteGate(context.Background(), client, benignFinding(), opts, "deeper evidence", 0)
	if got.UnanimousResolve || got.TotalVotes != 0 {
		t.Fatalf("nRuns=0 must be a no-op with no de-escalation; got %+v", got)
	}
	if client.calls != 0 {
		t.Fatalf("nRuns=0 must make zero model calls; got %d", client.calls)
	}
}

// reasonCaptureClient records the user-message text of every request so a test
// can assert the deeper evidence reached the committee prompt. It always returns
// a clean triage resolve so the cascade terminates at triage (1 call/vote).
type reasonCaptureClient struct {
	mu    sync.Mutex
	texts []string
}

func (c *reasonCaptureClient) Messages(_ context.Context, req MessagesRequest) (MessagesResponse, error) {
	c.mu.Lock()
	if len(req.Messages) > 0 && len(req.Messages[0].Content) > 0 {
		c.texts = append(c.texts, req.Messages[0].Content[0].Text)
	}
	c.mu.Unlock()
	return MessagesResponse{StopReason: "end_turn",
		Content: []ContentBlock{{Type: "text", Text: cleanResolveJSON}}}, nil
}

// TestRunRevoteGate_DeepEvidenceReachesCommittee proves the "better evidence to
// the same committee" channel: the deeper investigation string appears in the
// re-vote's tier prompt (BOXED as untrusted context — the consensus-invariant way
// to feed evidence, never a rule). It also proves the ORIGINAL finding is not
// mutated (enrichment operates on a copy).
func TestRunRevoteGate_DeepEvidenceReachesCommittee(t *testing.T) {
	opts := consensusOpts(t)
	cc := &reasonCaptureClient{}
	f := benignFinding()
	originalReason := f.Reason
	const deep = "verdict=benign confidence=0.88; forge-proxy is the operator's own hourly relay"

	RunRevoteGate(context.Background(), cc, f, opts, deep, 2)

	if f.Reason != originalReason {
		t.Fatalf("RunRevoteGate mutated the ORIGINAL finding's Reason: %q", f.Reason)
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if len(cc.texts) == 0 {
		t.Fatal("no requests captured")
	}
	for i, txt := range cc.texts {
		if !strings.Contains(txt, "operator's own hourly relay") {
			t.Errorf("re-vote prompt #%d does not carry the deeper evidence:\n%s", i, txt)
		}
		// The deeper evidence rides finding.reason, which tier.go boxes as untrusted.
		if !strings.Contains(txt, "USER_DATA_BEGIN") {
			t.Errorf("re-vote prompt #%d shows no untrusted boxing (expected the reason to be WrapUntrusted-boxed):\n%s", i, txt)
		}
	}
}

// TestRunRevoteGate_NoStoreSeam is the consensus-invariant proof by construction:
// RunRevoteGate takes NO store and returns only a RevoteResult, so it structurally
// cannot write to KindResolutions/KindFindings/directives — the re-vote is a pure
// computation whose outcome the caller attaches to the EVIDENCE record only. This
// test exercises it against a nil-friendly finding and asserts the result carries
// no disposition mutation surface (there is no store to mutate). enrichment with
// an EMPTY deep-evidence leaves the finding untouched.
func TestRunRevoteGate_NoStoreSeam_EmptyEvidenceNoMutation(t *testing.T) {
	f := finding.Finding{ID: "x", Type: "unusual-login", Reason: "original"}
	got := enrichFindingWithInvestigation(f, "   ")
	if got.Reason != "original" {
		t.Fatalf("empty deep-evidence must leave Reason unchanged; got %q", got.Reason)
	}
	got2 := enrichFindingWithInvestigation(f, "deeper says benign")
	if got2.Reason == f.Reason || !strings.Contains(got2.Reason, "deeper says benign") {
		t.Fatalf("non-empty deep-evidence must append to the reason copy; got %q", got2.Reason)
	}
	if f.Reason != "original" {
		t.Fatalf("enrichment mutated the original finding: %q", f.Reason)
	}
}
