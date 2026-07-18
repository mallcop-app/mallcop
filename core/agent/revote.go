// revote.go — the LOW-CONFIDENCE committee re-vote (mallcoppro-09a).
//
// MECHANISM: an escalated finding whose detection-time investigation
// (core/inquest) came back "ok" but with LOW investigator confidence is not
// trustworthy enough to ship customer-facing action-required copy as-is. The
// pipeline gathers deeper evidence (a forced, stronger investigation pass) and
// then hands that evidence to THIS gate, which puts the finding to N independent
// cascade voters — the SAME any-escalate-wins committee runConsensusGate uses
// (tallyConsensusVotes), seeded with the deeper evidence. Only a UNANIMOUS
// resolve (every voter resolves) reports UnanimousResolve=true; ANY escalate
// vote — or an error, panic, or no-resolution — keeps it false and the finding
// stays escalated.
//
// CONSENSUS INVARIANT (the #1 constraint, feedback_mallcop_consensus_not_rules):
// this is NOT a family-match suppress rule and NOT a "if benign && low-confidence
// then downgrade" shortcut. It is the EXACT SAME N-voter any-escalate-wins
// cascade the resolve-side gate runs, fed BETTER EVIDENCE (the deeper
// investigation narrative, boxed as untrusted context on the finding it
// re-votes). The committee re-decides freely; a single dissent keeps the
// escalation. RunRevoteGate NEVER writes to any store stream — it returns a
// result the pipeline attaches to the EVIDENCE record (investigations/<id>.json),
// never to findings/resolutions/directives. The original escalate disposition is
// never mutated or duplicated: this is a second opinion for the presentation
// layer, not a re-resolution.
//
// STOCHASTICITY: like the resolve-side gate, the re-runs force a non-zero
// consensusTemperature so the committee genuinely samples the model's
// distribution — a deterministic re-vote would vacuously reproduce the first
// pass's uncertainty rather than testing it.
package agent

import (
	"context"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// RevoteResult is the outcome of a low-confidence re-vote. It carries NO
// disposition change — the finding stays escalated; UnanimousResolve is the
// presentation-layer signal (was the committee, with deeper evidence,
// UNANIMOUS that this is benign?). ResolveVotes/TotalVotes are the tally and
// Reason is a human-readable summary.
type RevoteResult struct {
	ResolveVotes     int
	TotalVotes       int
	UnanimousResolve bool
	Reason           string
}

// RunRevoteGate runs nRuns independent cascade votes on an ENRICHED copy of the
// escalated finding f (its reason augmented with deepEvidence — the deeper
// investigation's verdict/confidence/narrative, better evidence to the SAME
// committee) and applies the any-escalate-wins rule via the shared
// tallyConsensusVotes. It NEVER mutates the store and NEVER changes f's
// disposition; it only reports what the committee concluded. nRuns <= 0 is a
// no-op that reports zero voters and UnanimousResolve=false (a re-vote with no
// voters cannot de-escalate anything — the safe side).
func RunRevoteGate(ctx context.Context, client Client, f finding.Finding, opts CascadeOptions, deepEvidence string, nRuns int) RevoteResult {
	if nRuns <= 0 {
		return RevoteResult{
			ResolveVotes: 0, TotalVotes: 0, UnanimousResolve: false,
			Reason: "Re-vote skipped: no voters configured; escalation stands.",
		}
	}

	opts = opts.defaulted()
	// Each vote is a COMPLETE single-pass cascade (ConsensusRuns=0 so the
	// resolve-side gate does not recurse), dispatched at the mandatory non-zero
	// temperature so the committee samples independently.
	reRunOpts := opts
	reRunOpts.ConsensusRuns = 0
	if reRunOpts.ConsensusTemperature == 0 {
		reRunOpts.ConsensusTemperature = consensusTemperature
	}

	enriched := enrichFindingWithInvestigation(f, deepEvidence)
	resolveCount, escalateCount := tallyConsensusVotes(ctx, client, enriched, reRunOpts, nRuns)

	unanimous := escalateCount == 0
	var reason string
	if unanimous {
		reason = "Consensus re-vote (deeper evidence): " +
			itoa(resolveCount) + "/" + itoa(nRuns) +
			" resolved — UNANIMOUS; the committee, re-weighing the deeper investigation, agrees the finding is benign. The escalate disposition still stands in the audit trail; customer-facing copy may frame this as investigated-benign rather than action-required."
	} else {
		reason = "Consensus re-vote (deeper evidence): " +
			itoa(resolveCount) + "/" + itoa(nRuns) + " resolved, " +
			itoa(escalateCount) + "/" + itoa(nRuns) +
			" escalated — any-escalate-wins: the escalation stands (a confident, deeper-evidenced escalation)."
	}

	return RevoteResult{
		ResolveVotes:     resolveCount,
		TotalVotes:       nRuns,
		UnanimousResolve: unanimous,
		Reason:           reason,
	}
}

// enrichFindingWithInvestigation returns a COPY of f whose Reason is augmented
// with the deeper investigation's evidence, so the re-vote committee re-decides
// WITH that evidence in context. deepEvidence is appended to (never replaces)
// the detector's original reason. It rides the finding.Reason field precisely
// because that is a field the cascade already renders — BOXED via WrapUntrusted
// (tier.go), so the deeper narrative enters as read-only untrusted CONTEXT the
// committee weighs, never as a trusted instruction. This is the "better evidence
// to the same committee" channel; it is NOT a rule and does not force any vote.
// An empty deepEvidence leaves f unchanged.
func enrichFindingWithInvestigation(f finding.Finding, deepEvidence string) finding.Finding {
	if strings.TrimSpace(deepEvidence) == "" {
		return f
	}
	enriched := f
	sep := "\n\n"
	if strings.TrimSpace(f.Reason) == "" {
		sep = ""
	}
	enriched.Reason = f.Reason + sep + "[detection-time deeper investigation] " + deepEvidence
	return enriched
}
