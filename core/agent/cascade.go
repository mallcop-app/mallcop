// cascade.go — the TRIAGE → INVESTIGATE → ESCALATE tiered cascade
// (portable-agent-architecture.md §1 topology, §2 prompt patterns).
//
// ResolveFinding is the single entry point. It replaces the earlier one-shot
// stub (floor + a single advisory model call) with the real tiered chain:
//
//	checkHardConstraints (data-driven router; force-escalate routes skip the model)
//	   │  proceed
//	   ▼
//	[triage]  cheap model + tools, boolean rubric + confidence floor
//	   ├─► RESOLVE (rubric satisfied, confidence ≥ 4)  ──────────► CLOSED (benign)
//	   └─► ESCALATE  ─────────────────────────────────────────────┐
//	                                                               ▼
//	[investigate]  mid model + deeper tools + 5-point checklist
//	   │  + the STRUCTURAL-CONFIDENCE gate (GuardResolve): a RESOLVE whose
//	   │    structural score < 0.55 is BLOCKED.
//	   ├─► RESOLVE (gate ALLOWS)  ─────────────────────────────────► CLOSED (benign)
//	   ├─► RESOLVE (gate BLOCKS, score < 0.55)  ──► FAN-OUT (deep×3 panel; fanout.go)
//	   │        deep-investigate ×3 (benign/malicious/incomplete) ∥ → investigate-merge
//	   │        ├─ all agree → that verdict (max conf)
//	   │        ├─ 2 vs 1   → majority, dissent cited, conf −0.10
//	   │        ├─ strong malicious → escalate (aggregation, not count)
//	   │        └─ 3 disagree → heal → escalate-with-all-evidence
//	   └─► ESCALATE  ──────────────────────────────────────────────┐
//	                                                                ▼
//	[escalate]  cheap model, NO tools, formats the human-facing alert
//	                                                                ▼
//	                                                            CLOSED (suspicious)
//
// INVARIANTS this file enforces (each has a test in cascade_test.go):
//
//   - ONE-WAY RATCHET (§1): once triage emits ESCALATE, no downstream tier can
//     flip the finding back to resolve. Downstream only refines (suspicious vs
//     insufficient-data). Triage's escalate hands off to investigate; investigate
//     can only escalate or resolve-with-its-OWN-evidence — it never "un-escalates"
//     triage's call because triage's call was a HANDOFF, not a verdict to revisit.
//     The structural gate makes the ratchet airtight on the resolve side: a
//     downstream resolve must clear the gate; a blocked resolve becomes escalate.
//
//   - FAIL-SAFE (§2.5): ambiguous / tool-returned-empty / unparseable /
//     self-confidence 1-2 ⇒ ESCALATE. Never silently dismiss. Resolution requires
//     POSITIVE evidence. A nil client, a model error, or an unparseable model
//     reply all fail SAFE to escalate (never resolve, never fail open).
//
//   - UNTRUSTED-DATA (§2.7 / §3): every finding/event/tool-result string is
//     WrapUntrusted + sanitized before it enters model context, and every tier
//     prompt carries the ## Security block. A sanitized injection planted in
//     finding.Reason AND in a tool result cannot flip the model's verdict to
//     resolve (cascade_test.go drives the cannedbackend spy to prove it).
//
// SEAM DISCIPLINE: this package reaches the model ONLY through the Client
// interface and reaches tools ONLY through the injected ToolRunner. It imports
// no inference, no network, no core/tools — the import-lint (imports_test.go)
// keeps the floor honest, and the ToolRunner seam keeps the cascade testable
// against a scripted backend with no live tools.
package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// Verdict is the disposition a tier's model proposes. It is parsed from the
// model's reply, NEVER trusted as a final outcome on its own — the runtime gates
// (fail-safe + structural confidence) judge a proposed resolve before it stands.
type Verdict string

const (
	// VerdictResolve: the model proposes closing the finding as benign. Subject
	// to the fail-safe and structural-confidence gates before it is honored.
	VerdictResolve Verdict = "resolve"
	// VerdictEscalate: the model proposes escalating. Always honored — escalate is
	// the safe side of the asymmetric error policy (§1) and never gated down.
	VerdictEscalate Verdict = "escalate"
	// VerdictUnparseable: the reply could not be parsed into a disposition. Treated
	// as ambiguity by the fail-safe: escalate, never resolve.
	VerdictUnparseable Verdict = "unparseable"
)

// CascadeOptions configures the cascade's model tiers and (optional) tools.
// Model ids follow §1's split: a cheap/fast model for triage + escalate, a mid
// model for investigate. Empty values fall back to the documented defaults.
type CascadeOptions struct {
	// TriageModel is the cheap, high-throughput model for the triage tier. Runs on
	// every finding that clears the floor — cost is amortized across all volume.
	TriageModel string
	// InvestigateModel is the mid model for the investigate tier. Runs only on
	// triage's escalations — higher per-call value, smaller base.
	InvestigateModel string
	// EscalateModel is the cheap model for the escalate formatter. No tools.
	EscalateModel string

	// Tools, when non-nil, is the tool surface advertised to triage + investigate.
	// The cascade reaches tools ONLY through this seam — it never imports
	// core/tools, so the floor's import-lint holds and tests can run with a nil or
	// scripted ToolRunner. A nil ToolRunner means "no live tools this wave" — the
	// model decides from the pre-loaded (sanitized) finding context alone, and the
	// fail-safe still covers an empty/ambiguous read.
	Tools ToolRunner

	// RepoRoot, when non-empty, is the PER-INVOCATION corpus root the pre-LLM
	// floor reads its escalate_routes from — threaded explicitly through this one
	// call instead of resolved from a process-global. It is resolved ONCE at the
	// top of ResolveFindingWith and carried, immutable, through checkHardConstraints
	// → loadEscalateRoutes, so a concurrent test's repo-root cleanup (or its
	// fan-out goroutines) CANNOT clear the root mid-resolve and flip this finding's
	// corpus — the §11 logical-race flake this field closes.
	//
	// Empty means "resolve the production way": ResolveFindingWith fills it from
	// resolveRepoRoot() (the os.Executable walk / MALLCOP_REPO_ROOT fallback) on
	// entry. Production never sets it; tests set it per-call to pin the corpus
	// deterministically with NO shared-global mutation.
	RepoRoot string
}

// defaulted returns a copy of o with empty model ids filled from the §1 defaults.
func (o CascadeOptions) defaulted() CascadeOptions {
	if o.TriageModel == "" {
		o.TriageModel = "glm-4.7-flash"
	}
	if o.InvestigateModel == "" {
		o.InvestigateModel = "glm-5"
	}
	if o.EscalateModel == "" {
		o.EscalateModel = "glm-4.7-flash"
	}
	return o
}

// ToolRunner is the cascade's tool seam. A real implementation (a later wave,
// living OUTSIDE core/agent so the import-lint stays green) wraps core/tools:
// search-events (folding operator rules, §3.8), check-baseline, search-findings.
// RunTools returns the tool transcript the tier model sees as context AND the
// observable signals the structural-confidence gate scores.
//
// The result's text is treated as UNTRUSTED — the cascade sanitizes + boxes it
// before it enters model context. ToolEmpty=true (a relied-on tool returned no
// data) force-escalates per the fail-safe (§2.5 / §3.4: empty is a finding).
type ToolRunner interface {
	// RunTools gathers evidence for one finding at one tier and returns the
	// observable tool transcript + signals. tier is "triage" or "investigate" so
	// the runner can scope the toolset (triage: 2-3 tools; investigate: the deeper
	// sweep). ctx carries cancellation/deadline.
	RunTools(ctx context.Context, tier string, f finding.Finding) (ToolEvidence, error)
}

// ToolEvidence is what a ToolRunner observed for one tier. The text fields are the
// human/model-readable tool transcript (UNTRUSTED — each sanitized before use).
// The remaining fields are the OBSERVABLE signals the gates score / force on; they
// are measured by the runtime, never self-reported by the model.
//
// FIX 1 (DISCRIMINATION via visibility): the transcript is split into ONE FIELD
// PER TOOL — BaselineText (check-baseline), EventsText (search-events + matched
// rules), FindingsText (search-findings) — instead of a single concatenated blob.
// The cascade boxes EACH field as its OWN WrapUntrusted field, EACH independently
// sanitized + 1024-capped (sanitize.go). The old single-field boxing concatenated
// all three and the 1024 cap truncated the high-signal check-baseline + relationship
// evidence (VA-03's whole discriminator — ci-bot's ZERO relationship history with
// the storage targets it read — lived past char 1024 and never reached the model).
// Per-field boxing makes the salient baseline/relationship facts survive the cap.
// SECURITY INVARIANT PRESERVED: each field is still WrapUntrusted + sanitized
// (per-field 1024 cap), and the verdict is still parsed ONLY from the model reply.
type ToolEvidence struct {
	// Text is the legacy single-blob transcript. DEPRECATED in favor of the
	// per-tool fields below, but retained: a runner that only sets Text still works
	// (it is boxed as one tools.transcript field, the pre-FIX-1 behavior), and the
	// scriptedTools test seam sets it. When any per-tool field is set, the per-tool
	// fields are boxed individually and Text is ignored.
	Text string
	// BaselineText is the check-baseline transcript (known?, frequencies, and the
	// actor↔target RELATIONSHIPS — the high-signal zero-history discriminator).
	// Boxed as its OWN field so the relationship evidence survives the 1024 cap.
	BaselineText string
	// EventsText is the search-events transcript (matched event ids + per-event
	// salient fields + §3.8 matched_rules). Boxed as its own field.
	EventsText string
	// FindingsText is the search-findings transcript (investigate tier's deeper
	// sweep). Boxed as its own field. Empty on the triage tier.
	FindingsText string

	// ToolCalls is the number of tool calls made gathering this evidence.
	ToolCalls int
	// DistinctTools is the number of DIFFERENT tools used.
	DistinctTools int
	// ToolEmpty is true when a relied-on tool returned an empty result. Per the
	// fail-safe this force-escalates a resolve (an empty read is not a dismissal).
	ToolEmpty bool

	// FIX 3 (OBSERVABLE FORCE-ESCALATE, event-keyed): the two structural predicates
	// the triage gate forces a clean resolve to escalate on. Both are computed by
	// the runtime from the REAL tool output (relationships / surfaced events) — NOT
	// from the model and NOT from the untrusted transcript text — so they are
	// trustworthy gate inputs. They are keyed on EVENT CONTENT, never on detector
	// family, so VA-01-deploy-burst (all targets in baseline, no role grant) is NOT
	// caught.
	//
	// ZeroHistoryAccess is true when the actor accesses a target with a
	// relationship-history count of 0 in check-baseline (the actor has NEVER touched
	// this target before). VA-03: ci-bot reads storage targets absent from its
	// (deploy-only) relationships. CO-02: deploy-svc bulk-reads user-data outside
	// its established relationship set.
	ZeroHistoryAccess bool
	// ZeroHistoryDetail names the actor + the zero-history target(s) for the audit
	// trail (e.g. "ci-bot → atomstorage01/containers/backups"). Empty when
	// ZeroHistoryAccess is false. Free-form runtime text (not boxed — it is the
	// runtime's own audit string, not echoed model/attacker text).
	ZeroHistoryDetail string
	// RoleGrantByActor is true when the surfaced events show the FINDING ACTOR
	// performing a role-grant / privilege event (event_type role_assignment, or
	// action add_role_assignment) for which that actor has NO baseline history of
	// granting roles. UT-01 / IT-02: admin-user grants a role with role_assignment
	// frequency 0. ID-01 is NOT caught — there the role grant is authored by
	// admin-user (a known role-granter), not by the finding actor deploy-svc-new.
	RoleGrantByActor bool
	// RoleGrantDetail names the role-grant event for the audit trail. Empty when
	// RoleGrantByActor is false.
	RoleGrantDetail string
}

// hasPerToolText reports whether any per-tool transcript field is populated. When
// true, buildTierRequest boxes each per-tool field individually (FIX 1) and
// ignores the legacy single Text blob; when false it falls back to boxing Text as
// one field (pre-FIX-1 behavior, used by the scriptedTools test seam).
func (e ToolEvidence) hasPerToolText() bool {
	return strings.TrimSpace(e.BaselineText) != "" ||
		strings.TrimSpace(e.EventsText) != "" ||
		strings.TrimSpace(e.FindingsText) != ""
}

// ResolveFinding runs the full triage → investigate → escalate cascade for one
// finding and returns the terminal Resolution. This is the replacement for the
// earlier floor+single-call stub.
//
// Order is load-bearing and security-critical:
//
//  1. checkHardConstraints(f) FIRST. A force-escalate route short-circuits to a
//     human with the model NEVER touched (the spy tests prove call-count==0).
//     This is the §1 hard-constraint bypass: not every finding deserves agent
//     inference.
//  2. TRIAGE tier. Cheap model + tools. A clean resolve (rubric satisfied,
//     self-confidence ≥ 4, positive evidence, non-empty tools) closes the finding
//     as benign. Anything else ESCALATES — the default side of the asymmetry.
//  3. INVESTIGATE tier (only reached on a triage escalate — the one-way ratchet).
//     Mid model + deeper tools + the STRUCTURAL-CONFIDENCE gate. A resolve must
//     clear GuardResolve: a structural score < 0.55 is BLOCKED and FANS OUT to the
//     deep×3 adversarial panel + evidence-aggregation merge (runFanOut). An
//     investigate escalate ships directly (never fans out — safe side of §1).
//  4. ESCALATE role. Cheap model, no tools, formats the human alert from the
//     upstream data. The terminal action is ALWAYS escalated — the formatter
//     cannot resolve (ratchet).
//
// A nil client fails SAFE: escalate to a human rather than silently resolve.
func ResolveFinding(ctx context.Context, client Client, f finding.Finding) Resolution {
	return ResolveFindingWith(ctx, client, f, CascadeOptions{})
}

// ResolveFindingWith is ResolveFinding with explicit tiers + tools. ResolveFinding
// delegates here with zero options (documented defaults, no live tools).
func ResolveFindingWith(ctx context.Context, client Client, f finding.Finding, opts CascadeOptions) Resolution {
	opts = opts.defaulted()

	// Resolve the corpus root EXACTLY ONCE, here at entry, into an immutable local
	// that is threaded through the floor for the rest of this invocation. After
	// this point the cascade NEVER re-reads any process-global repo-root state, so
	// a concurrent test's SetRepoRootForTest("") cleanup (or this resolve's own
	// fan-out goroutines) cannot clear the root mid-resolve and walk to the real
	// shipped corpus — the §11 logical-race flake.
	//
	// opts.RepoRoot, when set (tests pin it per-call), wins with no global read.
	// When empty (production), it is filled from resolveRepoRoot() — the unchanged
	// os.Executable walk / MALLCOP_REPO_ROOT fallback. A resolve error is carried
	// as an empty root + the error, so checkHardConstraints fails safe exactly as
	// before (it escalates rather than guessing the corpus location).
	repoRoot := opts.RepoRoot
	var rootErr error
	if repoRoot == "" {
		repoRoot, rootErr = resolveRepoRoot()
	}

	// (1) The ONLY gate before any model call. A routed finding never reaches the
	// model — security-critical, spy-proven.
	if forceEscalate, res := checkHardConstraints(repoRoot, rootErr, f); forceEscalate {
		return res
	}

	// A nil client cannot run any tier. Fail SAFE: escalate, never resolve.
	if client == nil {
		return Resolution{
			ForceEscalated: false,
			Action:         ActionEscalated,
			Family:         normalizeFamily(f.Type),
			Reason:         "no inference client available; escalating for human review (fail-safe, not fail-open)",
		}
	}

	// (2) TRIAGE. Cheap model + tools. Decide resolve vs escalate.
	//
	// Triage has exactly ONE terminal outcome: a clean resolve (rubric satisfied).
	// EVERYTHING else — an explicit escalate, a resolve that did not clear the
	// rubric, OR a fail-safe (model/tool error, unparseable reply) — is a triage
	// ESCALATE that hands off to investigate. A fail-safe is NOT short-circuited to
	// the human-alert formatter: it is escalated to the deeper, stronger tier,
	// which may recover a parseable verdict. This keeps the §1 topology intact
	// (triage escalate → investigate) and the asymmetry honest (ambiguity goes
	// deeper, never silently dismissed). The fail-safe cause is carried forward in
	// the handoff reason for the audit trail.
	triage := runTier(ctx, client, f, "triage", opts.TriageModel, triageSystemPrompt, opts.Tools)

	if !triage.failSafe && triage.verdict == VerdictResolve {
		// Triage resolve is conditional on the rubric: positive evidence,
		// self-confidence ≥ 4 (the triage floor — confidence 1-2 or 3 is "not clean
		// enough to close cheap" and escalates to investigate via cleanResolve()==
		// false below), and a non-empty tool read. A clean triage resolve closes the
		// finding as benign — triage's only terminal outcome.
		if triage.cleanResolve() {
			// FIX 3 (LOAD-BEARING SAFETY FLOOR — checked FIRST, keyed on EVENT content,
			// doc §4.3 "the under-escalation cluster responds to pattern-match escalation
			// overrides keyed on event content"). The OBSERVABLE tool evidence drives two
			// DISTINCT forces, calibrated to the asymmetric error policy:
			//
			//  (1) ROLE-GRANT by the finding actor with no precedent → TERMINAL escalate
			//      (NEVER_AUTO_RESOLVE). This is the doc's "Privilege changes → always
			//      ESCALATE (non-negotiable)" override: a privilege/role grant is a
			//      structural invariant the model cannot re-resolve past, exactly like
			//      the pre-LLM hard-constraint floor. The corpus confirms ZERO
			//      benign-expected scenario carries this predicate, so it never flips a
			//      benign finding (discrimination preserved).
			//
			//  (2) ZERO-HISTORY ACCESS (the actor touched a target it has NO relationship
			//      history with) → HANDOFF to investigate (NOT terminal). Zero-history is
			//      genuinely a JUDGMENT signal, not a structural invariant: a known batch
			//      actor reading a NEW container under an account it already uses, an
			//      onboarding MFA enrollment, a deploy to a fresh app are all benign
			//      first-time accesses (the corpus has 5+ such resolved-expected
			//      scenarios). Terminally escalating them would tank benign-hard
			//      precision. So zero-history forces the finding OFF the cheap-triage
			//      terminal-resolve path INTO investigate, where the stronger model
			//      weighs it in combination (it RESOLVES the benign batch with positive
			//      evidence; it ESCALATES the out-of-scope exfil). The finding still gets
			//      GuardResolve + the <0.55 structural gate + the deep×3 panel before any
			//      close — it can never silently auto-resolve at the cheap tier.
			//
			// Both predicates are keyed on the EVENT the runner observed, never on the
			// detector family — so VA-01 (all targets IN baseline relationships, no role
			// grant) is NOT caught and keeps resolving. ID-01 is NOT caught (its role
			// grant is authored by a known granter, not the finding actor; the finding
			// actor performs no zero-history access). The signals are runtime-computed,
			// never read from the model reply or the untrusted transcript — verdict
			// isolation holds.
			if triage.roleGrantByActor {
				detail := triage.roleGrantDetail
				if detail == "" {
					detail = "the finding actor performed a role grant with no precedent"
				}
				return escalate(ctx, client, f, opts, triageStage,
					"observable safety floor [never-auto-resolve: privilege/role-grant]: "+detail+"; the model proposed resolve but a privilege change always escalates: "+triage.reason)
			}

			// FIX 2 (risky proposed-resolve) AND FIX 3 zero-history both HAND OFF to
			// investigate (the deeper tier weighs the signal; it does not auto-resolve
			// at the cheap tier). FIX 3 zero-history is checked first so its richer audit
			// reason is recorded; FIX 2 covers high/critical severity + malicious markers.
			handoff, why := false, ""
			if triage.zeroHistoryAccess {
				handoff = true
				detail := triage.zeroHistoryDetail
				if detail == "" {
					detail = "actor accessed a target with zero relationship history"
				}
				why = "zero-history access (" + detail + "): the actor accessed a never-before-touched target; a cheap-triage resolve is not trustworthy here — handing to investigate (GuardResolve + structural gate + deep panel)"
			}
			if !handoff {
				handoff, why = triageResolveMustEscalate(f)
			}
			if !handoff {
				return Resolution{
					ForceEscalated: false,
					Action:         ActionProceed, // proceed == resolved-as-benign (terminal)
					Family:         normalizeFamily(f.Type),
					Reason:         "triage resolved (benign): " + triage.reason,
				}
			} else {
				// Reuse the rubric-miss handoff: force verdict=escalate so the cascade
				// falls through to investigate (one-way ratchet, §1). The verdict is set
				// by the RUNTIME here, never read from prompt text — verdict isolation holds.
				triage.verdict = VerdictEscalate
				triage.reason = "triage proposed a resolve but the finding is risky [" + why + "]; not terminating at triage: " + triage.reason
			}
		} else {
			// A resolve the triage rubric did not clear is NOT a dismissal — it
			// escalates to investigate. Default-to-escalate on ambiguity (§2.5).
			triage.verdict = VerdictEscalate
			triage.reason = "triage resolve did not satisfy the rubric (positive evidence + confidence ≥ 4 + non-empty tools); escalating: " + triage.reason
		}
	}

	// (3) INVESTIGATE. The one-way ratchet: we are here ONLY because triage
	// escalated (an explicit escalate, a rubric-miss resolve, or a fail-safe) — and
	// no path below can flip the finding back to "never mind" without clearing the
	// structural gate. triageHandoff records why triage handed off, for the audit
	// trail on every downstream escalation. Mid model + deeper tools.
	triageHandoff := triage.reason
	if strings.TrimSpace(triageHandoff) == "" {
		triageHandoff = "triage escalated"
	}
	investigate := runTier(ctx, client, f, "investigate", opts.InvestigateModel, investigateSystemPrompt, opts.Tools)

	if investigate.failSafe {
		return escalate(ctx, client, f, opts, investigateStage,
			"triage handoff ["+triageHandoff+"]; investigate failed safe: "+investigate.reason)
	}

	if investigate.verdict == VerdictResolve {
		// The STRUCTURAL-CONFIDENCE GATE. A resolve the model is "sure" of but did
		// not actually work for (few tool calls, no distinct tools, no evidence
		// citations) scores low and CANNOT resolve. The model cannot talk past this
		// — it is code, not prompt text. GuardResolve runs the fail-safe checks
		// first, then the structural score.
		attempt := investigate.resolveAttempt()
		decision, why := GuardResolve(attempt)
		switch decision {
		case ResolveAllowed:
			// Investigate resolved with its OWN positive evidence and cleared the
			// gate. This is the only downstream path that closes a finding benign,
			// and it is gated — the ratchet holds.
			return Resolution{
				ForceEscalated: false,
				Action:         ActionProceed,
				Family:         normalizeFamily(f.Type),
				Reason:         "investigate resolved (benign, gate-cleared): " + investigate.reason + " [" + why + "]",
			}
		case ResolveFanOut:
			// Structural score < 0.55. This is the ONE dangerous path the deep panel
			// exists for (§1 asymmetric error policy): the single mid-tier model
			// wants to say "benign" but did not work hard enough to be trusted.
			// Fan out to the 3-hypothesis adversarial panel + evidence-aggregation
			// merge (fanout.go) — NOT a blanket escalate. ESCALATE paths never reach
			// here (they short-circuit above), so the fan-out can only refine a
			// proposed resolve; it can never un-escalate a prior escalate (ratchet).
			return runFanOut(ctx, client, f, opts, investigate, why)
		default: // ResolveEscalated — the fail-safe inside GuardResolve fired.
			return escalate(ctx, client, f, opts, investigateStage,
				"investigate resolve failed the fail-safe gate ("+why+"); escalating")
		}
	}

	// Investigate escalate (suspicious or insufficient-data) — ships to a human.
	return escalate(ctx, client, f, opts, investigateStage,
		"triage handoff ["+triageHandoff+"]; investigate confirmed escalation: "+investigate.reason)
}

// stage names the cascade stage that produced an escalation, for the alert.
type stage string

const (
	triageStage      stage = "triage"
	investigateStage stage = "investigate"
)

// escalate runs the ESCALATE role: a cheap, tool-less model pass that formats the
// human-facing alert from the upstream (sanitized) data. The terminal action is
// ALWAYS ActionEscalated — the formatter cannot resolve, which is what makes the
// one-way ratchet airtight at the end of the chain. If the escalate model itself
// fails, we STILL return an escalated Resolution carrying the upstream reason —
// failing to format an alert must never downgrade to a non-escalation.
func escalate(ctx context.Context, client Client, f finding.Finding, opts CascadeOptions, from stage, reason string) Resolution {
	upstream := fmt.Sprintf("escalated by %s: %s", from, reason)

	req := buildEscalateRequest(f, opts.EscalateModel, upstream)
	alert := upstream
	if client != nil {
		if resp, err := client.Messages(ctx, req); err == nil {
			if t := firstText(resp); strings.TrimSpace(t) != "" {
				alert = t
			}
		}
		// On a formatter error we keep the upstream reason as the alert — never
		// downgrade the escalation just because the cheap formatter call failed.
	}

	return Resolution{
		ForceEscalated: false, // escalated by the chain, not by the pre-LLM floor
		Action:         ActionEscalated,
		Family:         normalizeFamily(f.Type),
		Reason:         alert,
	}
}

// cascadeFanOutStatus records, in code, that the §1 deep panel is now WIRED: a
// structural-gate-BLOCKED investigate resolve (score < 0.55) fans out to the
// deep×3 adversarial panel (hypothesis benign / malicious / incomplete) + an
// evidence-aggregation investigate-merge + a heal terminal, in fanout.go —
// instead of the earlier escalate stand-in. The constant exists so the wiring is
// greppable; fanout_test.go proves the panel fires only on the <0.55 resolve path.
const cascadeFanOutStatus = "ResolveFanOut (<0.55) fans out to deep×3 + evidence-aggregation merge + heal (fanout.go)"
