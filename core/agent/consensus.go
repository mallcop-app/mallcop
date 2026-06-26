// consensus.go — committee-consensus resolution gate (Go parity of the Python
// src/mallcop/consensus.py).
//
// MECHANISM (ported exactly from consensus.py's run_consensus):
//
//	When the actor chain RESOLVES a finding (terminal ActionProceed), run N=3
//	additional INDEPENDENT re-runs of the WHOLE cascade. If ANY re-run escalates
//	(or errors / returns no resolution) → override the original resolve to
//	ESCALATE (any-escalate-wins). Only a UNANIMOUS resolve (all N additional runs
//	also resolve) keeps the original resolve.
//
// WHY: this catches STOCHASTIC model failures on ambiguous findings where the
// model is sometimes right and sometimes wrong on the SAME input. One voter
// (the original chain run) plus N=3 independent re-runs = 4 voters; a single
// dissent is enough to send the finding to a human. The asymmetry matches the
// cascade's own §1 policy: escalate is the safe side, so any uncertainty across
// the committee escalates.
//
// FIRES ONLY ON A RESOLVE. needsConsensus() mirrors the Python check
// (result.resolution.action == RESOLVED): an ActionEscalated finding is already
// going to a human — re-running it 3 more times would only burn budget and can
// never change the safe outcome. The wrapper in cascade.go gates on
// ActionProceed before ever calling this file.
//
// STOCHASTICITY IS MANDATORY (the #1 correctness requirement). Each re-run is
// dispatched with ConsensusTemperature (default consensusTemperature = 1.0)
// threaded all the way into every tier's MessagesRequest.Temperature (tier.go).
// Without an explicit non-zero temperature the N re-runs against a deterministic
// endpoint would return IDENTICAL verdicts and consensus would be VACUOUS — it
// would always unanimously agree with the original, including the original's
// mistakes. The ORIGINAL (first) chain run is left at the provider default
// (Temperature=nil); only the re-runs force 1.0, so the committee genuinely
// samples the model's distribution.
//
// EACH RE-RUN IS A COMPLETE CASCADE. It goes through ResolveFindingWith (not
// resolveFindingInner) so it ALSO re-applies checkHardConstraints + triage +
// investigate + gate + fan-out — a finding that slipped past a corpus route on
// the first run gets a second chance to be caught. The re-run options set
// ConsensusRuns=0 so the gate does not recurse.
package agent

import (
	"context"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// DefaultConsensusRuns is the number of ADDITIONAL independent re-runs the gate
// performs beyond the original chain run (mirrors consensus.py
// DEFAULT_CONSENSUS_RUNS = 3). 1 original + 3 additional = 4 voters.
const DefaultConsensusRuns = 3

// consensusTemperature is the sampling temperature forced on every consensus
// re-run when CascadeOptions.ConsensusTemperature is left at 0. Non-zero is
// MANDATORY: at temperature 0 the re-runs would be deterministic and consensus
// vacuous (see file header). 1.0 makes the GLM tier models produce meaningfully
// different outputs on the same prompt so the committee is non-trivial.
const consensusTemperature = 1.0

// needsConsensus reports whether a Resolution warrants the consensus gate. Only a
// RESOLVE (terminal ActionProceed) does — an escalate is already going to a human
// and needs no double-check. Mirrors consensus.py needs_consensus():
// result.resolution.action == ResolutionAction.RESOLVED. (The cascade wrapper
// also guards on ActionProceed; this predicate keeps the rule explicit + unit
// testable in isolation.)
func needsConsensus(res Resolution) bool {
	return res.Action == ActionProceed
}

// runConsensusGate runs nRuns additional INDEPENDENT cascades on the same finding
// and applies the any-escalate-wins rule.
//
//   - first is the original resolve (terminal ActionProceed) the inner cascade
//     produced. opts is the ORIGINAL options (already defaulted()); the re-run
//     options are derived from it.
//   - Each re-run calls ResolveFindingWith with ConsensusRuns=0 (no recursion)
//     and a forced non-zero ConsensusTemperature (stochastic sampling).
//   - If EVERY re-run also resolves (ActionProceed) → UNANIMOUS: return the
//     ORIGINAL first result unchanged (its Reason, Family, RouteID stand).
//   - If ANY re-run escalates → override to ActionEscalated with the consensus
//     reason string (mirrors the Python reason format exactly). A panic in a
//     re-run counts as an escalation ("error = escalate"), recovered per-run so a
//     single panic cannot take down the gate.
//
// The override Resolution is a CHAIN escalation, not a floor escalation:
// ForceEscalated=false, RouteID="" (not a corpus route), Action=ActionEscalated,
// Reason=the consensus string. On a unanimous resolve the original Resolution is
// returned verbatim so its corpus attribution (Family/RouteID) and reason survive.
func runConsensusGate(ctx context.Context, client Client, f finding.Finding, opts CascadeOptions, first Resolution, nRuns int) Resolution {
	// Build the re-run options: same cascade, but recursion OFF and a forced
	// non-zero temperature so the committee samples independently.
	reRunOpts := opts
	reRunOpts.ConsensusRuns = 0
	if reRunOpts.ConsensusTemperature == 0 {
		reRunOpts.ConsensusTemperature = consensusTemperature
	}

	// Voter tally. The original run is the first "resolved" voter (it produced
	// first, an ActionProceed). Then nRuns additional voters.
	total := 1 + nRuns
	resolveCount := 1 // the original resolve
	escalateCount := 0

	for i := 0; i < nRuns; i++ {
		action := runOneConsensusVote(ctx, client, f, reRunOpts)
		if action == ActionProceed {
			resolveCount++
		} else {
			// ActionEscalated, an error, or no resolution all count as escalate
			// (the safe side) — exactly the Python "error = escalate" policy.
			escalateCount++
		}
	}

	if escalateCount == 0 {
		// UNANIMOUS resolve — accept the original result unchanged. (Token totals
		// are accumulated by the caller's recording client across all re-run model
		// calls; Resolution carries no token field, so there is nothing to sum here.)
		return first
	}

	// DISSENT — override to escalate. Reason mirrors consensus.py exactly:
	// "Consensus escalation: X/N resolved, Y/N escalated. Original reason: <...>".
	reason := "Consensus escalation: " +
		itoa(resolveCount) + "/" + itoa(total) + " resolved, " +
		itoa(escalateCount) + "/" + itoa(total) + " escalated. " +
		"Original reason: " + first.Reason
	return Resolution{
		ForceEscalated: false, // chain escalation, not a pre-LLM floor route
		Action:         ActionEscalated,
		Family:         first.Family,
		Reason:         reason,
		RouteID:        "", // not a corpus route
	}
}

// runOneConsensusVote runs ONE independent re-run cascade and returns its terminal
// Action. A panic inside the re-run is recovered and reported as ActionEscalated
// (the "error = escalate" policy): a re-run that blows up must not let the finding
// resolve, and must not crash the gate. A non-ActionProceed action (including the
// nil-client / fail-safe escalate) is returned as-is and the caller treats anything
// that is not ActionProceed as an escalate vote.
func runOneConsensusVote(ctx context.Context, client Client, f finding.Finding, reRunOpts CascadeOptions) (action Action) {
	defer func() {
		if r := recover(); r != nil {
			// error = escalate. Recover so a single panicking re-run cannot abort
			// the committee or flip the safe outcome.
			action = ActionEscalated
		}
	}()
	res := ResolveFindingWith(ctx, client, f, reRunOpts)
	return res.Action
}

// itoa renders a small non-negative int without pulling in fmt — the consensus
// reason is hot-path-adjacent and the values are tiny vote counts. Mirrors the
// exact "X/N" formatting of the Python reason string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
