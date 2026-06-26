// backend.go — the inference-Client backends the harness drives the core with,
// and the per-scenario GOLDEN SCRIPT generator for the creds-free MERGE-GATE.
//
// THE {base_url, key} PIVOT (§4.4, direct.go doc): the harness is parameterized
// over a single agent.Client seam. Two modes share it:
//
//   - MERGE-GATE (mode "canned"): a cannedbackend is scripted, PER SCENARIO, to
//     return that scenario's EXPECTED verdict (golden responses). With golden
//     responses the deterministic grader's chain_action axis PASSES for every
//     scenario — 0 pp of model noise. This gates HARNESS + GRADER regressions: if
//     someone breaks the loader, the runner, the verdict parser, the gate wiring,
//     or the grader, the merge-gate goes RED even though no model ran. It is
//     creds-free (no network beyond localhost) so CI runs it on every push.
//
//     THE MERGE-GATE IS EXPLICITLY NOT THE ACCURACY NUMBER. Golden responses say
//     "if the model returned the right answer, does the pipeline grade it right?"
//     — a pipeline-integrity check. The real accuracy number comes ONLY from the
//     real-model run, where the model decides the verdict and the eval measures
//     how often it is correct. Reporting the merge-gate's 100% as accuracy would
//     be a lie; the doc string and the README field both say so.
//
//   - REAL-MODEL (mode "real"): a core/inference.DirectClient pointed at
//     MALLCOP_INFERENCE_URL with MALLCOP_API_KEY. THIS path is WIRED but DELIBERATELY
//     NOT RUN here (no creds in this environment). RealClientFromEnv builds it; the
//     harness CLI / test refuses to run it without both env vars set.
//
// This file imports core/inference ONLY for the real path — it is the package
// boundary where the network client is allowed (core/eval is a harness, not the
// shipped product runtime; the import-lint guards core/, and a harness that wires
// the DirectClient is exactly the intended seam, mirrored on cmd/ + test/).
package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
)

// Mode selects the inference backend.
type Mode string

const (
	// ModeCanned is the creds-free merge-gate: cannedbackend golden responses.
	ModeCanned Mode = "canned"
	// ModeReal is the parity run against a live model via DirectClient. WIRED but
	// not run here (no creds).
	ModeReal Mode = "real"
)

// goldenScript returns the cannedbackend CannedContentFunc that makes ONE scenario
// reach its EXPECTED terminal action. It is CONTENT-AWARE: it routes each response
// by the TIER / DIRECTED HYPOTHESIS identifiable in the request's system prompt —
// NOT by a global call index — exactly like the scriptedPanelBackend in
// core/agent/fanout_test.go.
//
// WHY CONTENT-AWARE (the residual Rule-11 flake this kills). A scenario whose
// triage escalates and whose investigate proposes a resolve gets that resolve
// BLOCKED by the structural-confidence gate (the merge-gate runs tool-free, so the
// structural score is well below 0.55), which fans out to THREE deep-investigate
// tiers that run CONCURRENTLY. A script keyed on a global call index cannot return
// the right per-hypothesis verdict to each of the 3 concurrent deep calls — the
// index→response mapping is order-nondeterministic, which scrambles the golden
// responses and intermittently flips the gate's pinned exact pass rate (~10%/run).
// Routing on the system prompt's tier/hypothesis marker makes each of the 3
// concurrent deep calls deterministically get ITS hypothesis's golden response
// regardless of goroutine scheduling.
//
// The contract mirrors the cascade (cascade.go / tier.go / fanout.go):
//
//	expected resolved → triage returns a CLEAN resolve (action=resolve,
//	    confidence=5, positive_evidence=true → cleanResolve()==true) → terminal
//	    RESOLVED at triage (1 call). If such a scenario nonetheless reaches the
//	    fan-out, all 3 deep hypotheses also return a well-evidenced resolve so the
//	    panel resolves (benign) deterministically.
//
//	expected escalated → triage escalate, investigate escalate, escalate-formatter
//	    free-text alert → terminal ESCALATED (3 calls). The alert text embeds the
//	    scenario's reasoning_must_mention substrings so the (non-gating) Mentions
//	    axis also passes. If an escalated scenario instead routes triage-escalate →
//	    investigate-RESOLVE-blocked → fan-out, the deep tiers escalate (malicious
//	    with a strong indicator) so the panel escalates deterministically.
//
// A force-escalated scenario (priv-escalation / injection-probe / log-format-drift /
// secrets-exposure / boundary-violation — the E-001..E-005 hard constraints) makes
// ZERO model calls — the floor escalates pre-model — so the script is never invoked
// for it; the merge-gate still passes on chain_action via the floor.
func goldenScript(s *exam.Scenario) func(body []byte) string {
	expectResolved := false
	var mentions []string
	if exp := s.ExpectedResolution; exp != nil {
		expectResolved = strings.EqualFold(exp.ChainAction, "resolved")
		mentions = exp.ReasoningMustMention
	}

	// Golden response payloads, keyed by tier/hypothesis.
	//
	// RESOLVE side: a clean, positively-evidenced benign resolve. Used for the
	// triage tier of an expected-resolved scenario AND for all 3 deep hypotheses
	// of an expected-resolved scenario that fans out (so the panel resolves: 3
	// agree benign, each with positive evidence).
	resolveReason := "benign: positive evidence of legitimacy in events + baseline. " + mentionTail(mentions)
	cleanResolve := fmt.Sprintf(
		`{"action":"resolve","confidence":5,"positive_evidence":true,"strong_evidence":false,"insufficient_data":false,"reason":%q}`,
		resolveReason)

	// ESCALATE side: triage + investigate escalates, and per-hypothesis deep
	// escalates (malicious carries the strong indicator so a fanned-out escalate
	// scenario escalates via the strong-malicious aggregation rule, not a count).
	escTriage := `{"action":"escalate","confidence":3,"positive_evidence":false,"strong_evidence":false,"insufficient_data":false,"reason":"triage: no positive evidence to clear; escalating for investigation."}`
	escInvestigate := `{"action":"escalate","confidence":4,"positive_evidence":false,"strong_evidence":true,"insufficient_data":false,"reason":"investigate: confirmed suspicious pattern; escalating to a human."}`
	deepBenignEsc := `{"action":"escalate","confidence":2,"positive_evidence":false,"strong_evidence":false,"insufficient_data":false,"reason":"deep(benign): could not confirm benign; no positive evidence of legitimacy."}`
	deepMaliciousEsc := `{"action":"escalate","confidence":5,"positive_evidence":false,"strong_evidence":true,"insufficient_data":false,"reason":"deep(malicious): DECISIVE attack vector found; escalating."}`
	deepIncompleteEsc := `{"action":"escalate","confidence":3,"positive_evidence":false,"strong_evidence":false,"insufficient_data":true,"reason":"deep(incomplete): the disambiguating data is missing; cannot determine."}`
	// The escalate formatter returns free-text (no JSON verdict). Embed the
	// must-mention substrings here — this IS the terminal reason for an escalated
	// finding (cascade.escalate uses the formatter's text as the alert).
	alert := "SECURITY ALERT: suspicious activity requires human review. " + mentionTail(mentions)

	return func(body []byte) string {
		tier, hypothesis := routeFromBody(body)
		switch tier {
		case tierTriage:
			if expectResolved {
				return cleanResolve
			}
			return escTriage
		case tierInvestigate:
			// Reached only on the escalate path (a resolved scenario terminates at
			// triage). Investigate escalates → terminal escalate via the formatter.
			return escInvestigate
		case tierDeep:
			// Fan-out: each of the 3 concurrent deep calls is routed by ITS
			// directed hypothesis, so the verdict is deterministic regardless of
			// goroutine completion order.
			if expectResolved {
				return cleanResolve // 3 agree benign (positive evidence) → panel resolves
			}
			switch hypothesis {
			case hypMalicious:
				return deepMaliciousEsc
			case hypIncomplete:
				return deepIncompleteEsc
			default: // benign
				return deepBenignEsc
			}
		case tierEscalate:
			return alert
		default:
			// Unrecognized tier: fail to the scenario's expected side so the gate
			// stays meaningful rather than silently mis-scoring.
			if expectResolved {
				return cleanResolve
			}
			return alert
		}
	}
}

// goldenTier / goldenHypothesis are the content-routing keys derived from a
// request's system prompt.
type goldenTier int

const (
	tierUnknown goldenTier = iota
	tierTriage
	tierInvestigate
	tierDeep
	tierEscalate
)

type goldenHypothesis int

const (
	hypNone goldenHypothesis = iota
	hypBenign
	hypMalicious
	hypIncomplete
)

// goldenRequest is the minimal shape we decode from the Anthropic-wire request
// body to read the system prompt. The cannedbackend hands goldenScript the raw
// body; we only need the "system" field to route by tier/hypothesis.
type goldenRequest struct {
	System string `json:"system"`
}

// routeFromBody decodes the request body's system prompt and classifies it into a
// tier (+ hypothesis for the deep tier). The markers are the literal section
// headers / directed-prior text baked into core/agent/prompts.go — the same
// markers core/agent/fanout_test.go's content-aware backend routes on. The deep
// check comes FIRST because a deep prompt embeds the full investigate prompt
// (deepInvestigateSystemPrompt = preamble + prior + investigateSystemPrompt), so
// it also contains "# Investigation Agent"; the "# Deep Investigation Agent"
// preamble disambiguates it.
func routeFromBody(body []byte) (goldenTier, goldenHypothesis) {
	var req goldenRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return tierUnknown, hypNone
	}
	sys := req.System
	switch {
	case strings.Contains(sys, "# Deep Investigation Agent"):
		switch {
		case strings.Contains(sys, "BENIGN: Assume the activity is legitimate"):
			return tierDeep, hypBenign
		case strings.Contains(sys, "MALICIOUS: Assume the credentials are compromised"):
			return tierDeep, hypMalicious
		case strings.Contains(sys, "INCOMPLETE: Assume the parent could not resolve"):
			return tierDeep, hypIncomplete
		default:
			return tierDeep, hypNone
		}
	case strings.Contains(sys, "# Investigation Agent"):
		return tierInvestigate, hypNone
	case strings.Contains(sys, "# Triage Agent"):
		return tierTriage, hypNone
	case strings.Contains(sys, "# Escalate Agent"):
		return tierEscalate, hypNone
	default:
		return tierUnknown, hypNone
	}
}

// mentionTail renders the must-mention substrings into a sentence so the golden
// reason/alert contains every required substring verbatim (Mentions axis). When
// there are none it returns "".
func mentionTail(mentions []string) string {
	if len(mentions) == 0 {
		return ""
	}
	return "Evidence cited: " + strings.Join(mentions, "; ") + "."
}

// newCannedClient starts a cannedbackend scripted with the scenario's golden
// responses and returns an agent.Client (a DirectClient pointed at it) plus a
// stop func. The caller MUST call stop when the scenario is done.
func newCannedClient(s *exam.Scenario) (agent.Client, func(), error) {
	// CannedContentFunc (content-aware) — NOT CannedResolutionFunc (call-index) —
	// so the golden responses are deterministic under the fan-out's 3 concurrent
	// deep calls. See goldenScript.
	be := &cannedbackend.CannedBackend{CannedContentFunc: goldenScript(s)}
	if err := be.Start(); err != nil {
		return nil, func() {}, fmt.Errorf("start canned backend: %w", err)
	}
	client := &inference.DirectClient{BaseURL: be.URL(), Model: "merge-gate-canned"}
	return client, be.Stop, nil
}

// RealClientFromEnv builds the real-model DirectClient from the environment. It
// is the {base_url,key} pivot's REAL leg: BaseURL=MALLCOP_INFERENCE_URL,
// Key=MALLCOP_API_KEY, Model=MALLCOP_MODEL (optional). It returns an error when
// either required var is unset — the harness REFUSES to run real mode without
// creds, which is why no real call happens in this environment.
func RealClientFromEnv() (agent.Client, error) {
	url := strings.TrimSpace(os.Getenv("MALLCOP_INFERENCE_URL"))
	key := strings.TrimSpace(os.Getenv("MALLCOP_API_KEY"))
	model := strings.TrimSpace(os.Getenv("MALLCOP_MODEL"))
	if url == "" || key == "" {
		return nil, fmt.Errorf("real-model mode requires MALLCOP_INFERENCE_URL and MALLCOP_API_KEY (both must be set); refusing to run without creds")
	}
	if model == "" {
		model = "glm-5"
	}
	return &inference.DirectClient{BaseURL: url, Key: key, Model: model}, nil
}
