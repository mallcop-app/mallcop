// fanout.go — the deep-investigate ×3 adversarial panel + evidence-aggregation
// merge + heal terminal (portable-agent-architecture.md §1).
//
// This is the false-negative catcher. It fires on the ONE dangerous path the
// whole topology exists to cover: investigate wants to RESOLVE but the
// structural-confidence gate blocked it (<0.55). ESCALATE paths never reach here
// — they are already on the safe side of the asymmetry (§1 asymmetric error
// policy). The model cannot opt out of the gate (it is code, not prompt text), so
// it cannot opt out of the fan-out either.
//
// Shape:
//
//	investigate RESOLVE, gate BLOCKS (<0.55)
//	   │
//	   ▼
//	write the parent's PARTIAL transcript (read-only context for the panel)
//	   │
//	   ▼
//	[deep-investigate ×3 CONCURRENTLY]   (goroutines; merge blocks on all 3)
//	   ├─ hypothesis:benign     "assume legitimate, find confirming evidence"
//	   ├─ hypothesis:malicious  "assume compromised, find the attack vector"
//	   └─ hypothesis:incomplete "assume the data is missing/incomplete"
//	   │   (each = investigate prompt + directed prior + parent transcript (boxed))
//	   ▼
//	[investigate-merge]  EVIDENCE AGGREGATION, not majority vote:
//	   ├─ all 3 agree         → that verdict, confidence = max(3)
//	   ├─ 2 vs 1              → majority, dissent's evidence cited, confidence −0.10
//	   ├─ strong malicious    → escalate against WEAK (no-positive-evidence) benign (aggregation)
//	   └─ 3 disagree          → HEAL (genuinely uncertain; terminal escalate w/ all evidence)
//
// INVARIANTS preserved here (each tested in fanout_test.go):
//   - ONE-WAY RATCHET: the fan-out can only refine — it can resolve a finding the
//     parent investigate WANTED to resolve, or escalate it, but it is never
//     reached on a triage/investigate ESCALATE path, so it can never un-escalate a
//     prior escalate.
//   - UNTRUSTED-DATA: the parent partial transcript handed to every deep tier and
//     every per-deep transcript handed to merge is WrapUntrusted + sanitized
//     before it enters any model context (runTierWithContext / the merge builder).
//   - VERDICT ISOLATION: deep verdicts AND the merge verdict are parsed ONLY from
//     model replies (parseVerdict over the reply, never over the boxed prompt).
package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// hypothesis is one directed prior for a deep-investigate tier.
type hypothesis struct {
	// name is the metadata tag ("benign" / "malicious" / "incomplete") used in the
	// audit trail and asserted by tests that the 3 distinct priors ran.
	name string
	// prior is the directed-hypothesis text spliced into the deep tier's system
	// prompt (TRUSTED — it tells the model which prior to adopt).
	prior string
}

// deepHypotheses is the fixed, ordered panel: benign / malicious / incomplete.
// Order is stable so the audit trail and tests are deterministic even though the
// three tiers RUN concurrently.
var deepHypotheses = []hypothesis{
	{name: "benign", prior: deepHypothesisBenign},
	{name: "malicious", prior: deepHypothesisMalicious},
	{name: "incomplete", prior: deepHypothesisIncomplete},
}

// deepResult is one deep-investigate tier's outcome, indexed back to its
// hypothesis so the merge aggregator can cite which prior produced which verdict.
type deepResult struct {
	hypothesis      string
	verdict         Verdict
	selfConf        int
	hasPosEvid      bool
	strongMalicious bool
	insufficient    bool
	reason          string
	failSafe        bool
}

// disposition is the merge's three-way classification of a deep result (§1:
// resolve / escalate-as-suspicious / escalate-as-insufficient-data). The terminal
// ACTION space is still two-valued (resolve/escalate), but the merge distinguishes
// the two escalate flavors so a genuine 3-way split routes to heal.
type disposition string

const (
	dispResolve      disposition = "resolve"      // benign, positive evidence
	dispSuspicious   disposition = "suspicious"   // escalate — indicators of compromise
	dispInsufficient disposition = "insufficient" // escalate — data missing, cannot determine
)

// dispositionOf classifies one deep result. A resolve is dispResolve. An escalate
// is dispInsufficient when the tier flagged insufficient-data (and found no strong
// malicious indicator), otherwise dispSuspicious. A fail-safed tier (already
// verdict=escalate) is treated as suspicious — ambiguity to the safe side.
func dispositionOf(r deepResult) disposition {
	if r.verdict == VerdictResolve {
		return dispResolve
	}
	if r.insufficient && !r.strongMalicious {
		return dispInsufficient
	}
	return dispSuspicious
}

// runFanOut is the entry point invoked from cascade.go when the structural gate
// BLOCKS an investigate resolve (<0.55). It writes the parent partial transcript,
// runs the 3 deep tiers concurrently, merges by evidence aggregation, and returns
// the terminal Resolution. A nil client cannot run the panel: fail SAFE (escalate).
func runFanOut(ctx context.Context, client Client, f finding.Finding, opts CascadeOptions, parent tierResult, gateWhy string) Resolution {
	if client == nil {
		return escalate(ctx, nil, f, opts, investigateStage,
			"fan-out blocked resolve but no inference client available; escalating (fail-safe): "+gateWhy)
	}

	// Write the parent's PARTIAL transcript. This is the read-only context every
	// deep tier sees. It is built from the parent investigate's observable signals
	// + reason; it carries no instruction, and it is boxed as untrusted when it
	// enters each deep tier's prompt (runTierWithContext).
	partial := buildPartialTranscript(f, parent, gateWhy)

	// Run the 3 deep tiers CONCURRENTLY. The merge blocks on all 3 (sync.WaitGroup);
	// results are written to fixed slots (no shared mutation race — each goroutine
	// owns its own index). Same model tier + tools as investigate.
	deepModel := opts.InvestigateModel
	results := make([]deepResult, len(deepHypotheses))
	var wg sync.WaitGroup
	for i, h := range deepHypotheses {
		wg.Add(1)
		go func(i int, h hypothesis) {
			defer wg.Done()
			results[i] = runDeepTier(ctx, client, f, deepModel, h, partial, opts.Tools, opts.ConsensusTemperature)
		}(i, h)
	}
	wg.Wait()

	// MERGE: evidence aggregation (NOT majority vote). The aggregator is pure code
	// over the three deep results — the model's per-deep verdicts are parsed from
	// replies, and the aggregation arithmetic is the runtime's, not a model's.
	return mergeDeepResults(ctx, client, f, opts, results)
}

// runDeepTier runs one deep-investigate tier with its directed hypothesis prior
// and the parent's (boxed) partial transcript. deep-investigate is NON-terminal:
// it returns a verdict for the merge, it never closes the finding itself.
func runDeepTier(ctx context.Context, client Client, f finding.Finding, model string, h hypothesis, partial string, tools ToolRunner, temperature float64) deepResult {
	system := deepInvestigateSystemPrompt(h.prior)
	tr := runTierWithContext(ctx, client, f, "deep-investigate:"+h.name, model, system, tools, partial, temperature)
	return deepResult{
		hypothesis:      h.name,
		verdict:         tr.verdict,
		selfConf:        tr.selfConf,
		hasPosEvid:      tr.hasPosEvid,
		strongMalicious: tr.strongMalicious,
		insufficient:    tr.insufficient,
		reason:          tr.reason,
		failSafe:        tr.failSafe,
	}
}

// mergeDeepResults aggregates the three deep verdicts by EVIDENCE, not by count
// (§1). It classifies each tier into a three-way disposition (resolve /
// suspicious / insufficient) so a genuine 3-way split routes to heal. Rules, in
// priority order:
//
//  1. STRONG MALICIOUS OVERRIDE (gated backstop) — if a deep tier flagged a
//     decisive malicious indicator (strong_evidence + escalate) AND no resolving
//     tier carried positive evidence, escalate. Aggregation, not count: one strong
//     malicious item outweighs WEAK (no-positive-evidence) benign concurrences. It
//     does NOT override a benign majority that DID carry positive evidence — that
//     case falls through to (3)/(4), which resolves a positively-evidenced majority
//     and escalates an unevidenced one (the kill-switch). One coherent rule: a
//     benign majority resolves IFF a resolving tier carries positive evidence.
//  2. 3 DISAGREE — exactly one resolve, one suspicious, one insufficient: the
//     system is genuinely uncertain → HEAL with all evidence (§1).
//  3. ALL 3 AGREE on resolve — resolve; confidence = max(3) self-conf.
//  4. 2 vs 1 — majority verdict; the dissent's evidence cited in the reason;
//     confidence penalized by 0.10 (recorded in the reason for the audit trail).
//  5. Otherwise (a non-resolve majority of any escalate flavor) — escalate.
//
// A merge that resolves is STILL gated like any resolve would be at the source —
// but the structural signal here is the AGGREGATE of three deep investigations,
// so a unanimous well-evidenced benign panel is exactly the false-positive
// recovery the panel exists to provide.
func mergeDeepResults(ctx context.Context, client Client, f finding.Finding, opts CascadeOptions, results []deepResult) Resolution {
	evidence := compileEvidence(results)

	// Classify each tier into the three-way disposition and bucket them.
	var resolves, suspicious, insufficient []deepResult
	strongMalicious := false
	anyFailSafe := false
	for _, r := range results {
		if r.failSafe {
			anyFailSafe = true
		}
		if r.strongMalicious && r.verdict == VerdictEscalate {
			strongMalicious = true
		}
		switch dispositionOf(r) {
		case dispResolve:
			resolves = append(resolves, r)
		case dispInsufficient:
			insufficient = append(insufficient, r)
		default: // dispSuspicious
			suspicious = append(suspicious, r)
		}
	}

	// (1) STRONG MALICIOUS OVERRIDE — the false-negative BACKSTOP, now gated to one
	// coherent merge rule with the anyPositiveEvidence kill-switch below. It fires
	// ONLY when NO resolving tier carried positive evidence of legitimacy — i.e. the
	// doc's "a single strong malicious piece outweighs two WEAK benign concurrences"
	// (weak == no positive evidence). A strong malicious indicator must NOT
	// unilaterally override a benign majority that DID carry positive evidence: with
	// the kill-switch at (3)/(4), a benign majority resolves IFF a resolving tier
	// carries positive evidence; otherwise the merge escalates — and when that benign
	// majority is itself unevidenced, this backstop attributes the escalation to the
	// strong malicious read (richer audit) instead of the generic kill-switch.
	if strongMalicious && !anyPositiveEvidence(resolves) {
		return escalate(ctx, client, f, opts, investigateStage,
			"deep panel: a single STRONG malicious indicator outweighs the WEAK (no-positive-evidence) benign concurrences (evidence aggregation, not vote); escalating. Evidence: "+evidence)
	}

	nResolve := len(resolves)
	nSusp := len(suspicious)
	nInsuff := len(insufficient)
	nEscalate := nSusp + nInsuff

	// (2) 3 DISAGREE — one of each disposition: genuinely uncertain → HEAL.
	if nResolve == 1 && nSusp == 1 && nInsuff == 1 {
		return runHeal(ctx, client, f, opts, "deep panel 3-way split (resolve / suspicious / insufficient-data): genuinely uncertain", evidence)
	}

	// (3)/(4) MAJORITY RESOLVE — strictly more resolves than escalates (of either
	// flavor). Confidence = max of the resolving tiers' self-conf; a 2-1 split
	// records the dissent and the −0.10 penalty.
	if nResolve > nEscalate {
		conf := maxSelfConf(resolves)
		reason := fmt.Sprintf("deep panel majority RESOLVE (%d resolve / %d escalate), confidence=max(%d). Evidence: %s",
			nResolve, nEscalate, conf, evidence)
		if nEscalate > 0 {
			reason += fmt.Sprintf(" Dissent (%s) cited; confidence penalized 0.10.", dissentNames(append(append([]deepResult(nil), suspicious...), insufficient...)))
		}
		// The merge resolve still requires positive evidence somewhere in the
		// resolving tiers — if none had positive evidence, this is not a clean
		// dismissal; fail safe to escalate (resolution requires positive evidence).
		if !anyPositiveEvidence(resolves) {
			return escalate(ctx, client, f, opts, investigateStage,
				"deep panel majority resolve had NO positive evidence of legitimacy; resolution requires positive evidence; escalating. Evidence: "+evidence)
		}
		return Resolution{
			ForceEscalated: false,
			Action:         ActionProceed, // resolved-as-benign (terminal)
			Family:         normalizeFamily(f.Type),
			Reason:         "deep panel resolved (benign, evidence-aggregated): " + reason,
		}
	}

	// (5) MAJORITY ESCALATE (suspicious and/or insufficient outnumber resolves).
	reason := fmt.Sprintf("deep panel majority ESCALATE (%d escalate [%d suspicious / %d insufficient-data] / %d resolve)",
		nEscalate, nSusp, nInsuff, nResolve)
	if nResolve > 0 {
		reason += fmt.Sprintf("; dissent (%s) cited", dissentNames(resolves))
	}
	if anyFailSafe {
		reason += "; a deep tier failed safe (ambiguity ⇒ escalate)"
	}
	return escalate(ctx, client, f, opts, investigateStage, reason+". Evidence: "+evidence)
}

// runHeal is the heal role (§1 role table): a cheap, mechanical terminal. Per
// heal/POST.md it is propose-not-apply; drift-patch generation is out of scope
// for this wave, so here it produces a TERMINAL escalate-with-all-evidence when
// the deep panel was genuinely uncertain (3-way split: resolve / suspicious /
// insufficient-data). It runs the escalate formatter so the human gets a real
// alert, carrying all panel evidence.
func runHeal(ctx context.Context, client Client, f finding.Finding, opts CascadeOptions, why, evidence string) Resolution {
	return escalate(ctx, client, f, opts, investigateStage,
		"heal (deep panel uncertain — "+why+"): escalating with all panel evidence (propose-not-apply; drift-patch out of scope). Evidence: "+evidence)
}

// buildPartialTranscript renders the parent investigate's partial work as the
// read-only context the deep panel sees. It is plain text describing what the
// parent did and why it could not reach confidence (the gate reason). It carries
// no instruction; it is boxed as untrusted when it enters each deep prompt.
func buildPartialTranscript(f finding.Finding, parent tierResult, gateWhy string) string {
	var b strings.Builder
	b.WriteString("PARENT INVESTIGATION (partial — could not reach confidence)\n")
	b.WriteString(fmt.Sprintf("finding: id=%s type=%s actor=%s\n", f.ID, f.Type, f.Actor))
	b.WriteString(fmt.Sprintf("parent proposed verdict: %s (self-confidence %d)\n", parent.verdict, parent.selfConf))
	b.WriteString(fmt.Sprintf("parent tool work: %d calls across %d distinct tools\n", parent.toolCalls, parent.distinctTools))
	b.WriteString("parent reason: " + parent.reason + "\n")
	b.WriteString("blocked because: " + gateWhy + "\n")
	return b.String()
}

// compileEvidence concatenates the three deep tiers' (hypothesis, verdict, reason)
// into one auditable evidence string for the merge reason. Sorted by hypothesis
// name so the output is deterministic regardless of goroutine completion order.
func compileEvidence(results []deepResult) string {
	sorted := append([]deepResult(nil), results...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].hypothesis < sorted[j].hypothesis })
	parts := make([]string, 0, len(sorted))
	for _, r := range sorted {
		tag := ""
		if r.strongMalicious {
			tag = " [STRONG-MALICIOUS]"
		}
		parts = append(parts, fmt.Sprintf("[%s→%s%s] %s", r.hypothesis, r.verdict, tag, r.reason))
	}
	return strings.Join(parts, " | ")
}

// maxSelfConf returns the highest self-reported confidence among results (0 when
// empty). Used for the all-agree resolve "confidence = max(3)" rule (§1).
func maxSelfConf(results []deepResult) int {
	m := 0
	for _, r := range results {
		if r.selfConf > m {
			m = r.selfConf
		}
	}
	return m
}

// anyPositiveEvidence reports whether at least one resolving deep tier claimed
// positive evidence of legitimacy. A merge resolve with NO positive evidence
// anywhere is not a clean dismissal (resolution requires positive evidence).
func anyPositiveEvidence(results []deepResult) bool {
	for _, r := range results {
		if r.hasPosEvid {
			return true
		}
	}
	return false
}

// dissentNames lists the hypothesis names of the dissenting deep tiers, sorted,
// for the audit trail ("dissent (malicious) cited").
func dissentNames(results []deepResult) string {
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.hypothesis)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
