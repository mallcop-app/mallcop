// tier.go — one tier of the cascade: build the (untrusted-data-safe) prompt,
// run the model, gather tool evidence, parse the model's verdict, and assemble
// the structural signals the gate scores.
//
// A "tier" is triage or investigate. Both follow the same shape:
//
//  1. Gather tool evidence (via the injected ToolRunner seam — never core/tools
//     directly). The evidence Text is UNTRUSTED.
//  2. Build the user message: the finding fields AND the tool transcript are
//     each WrapUntrusted + sanitized (§2.7 ## Security + §3 untrusted data) before
//     they enter model context. The system prompt is the ported POST.md, which
//     carries the ## Security block.
//  3. Call the model once (this wave: the canned/real backend returns a verdict
//     as text; a later wave adds the multi-turn tool-use loop). Parse the reply
//     into a verdict + self-confidence + reason.
//  4. Assemble tierResult: the parsed verdict + the OBSERVABLE structural signals
//     (tool calls, distinct tools, iterations, reason text) the confidence gate
//     scores. None of the structural signals is self-reported by the model.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// tierResult is the outcome of running one cascade tier. It separates the model's
// PROPOSAL (verdict, selfConfidence, reason) from the OBSERVABLE signals
// (toolCalls, distinctTools, toolEmpty) the runtime measured — the gates judge
// the proposal using the observable signals, never the model's self-assessment.
type tierResult struct {
	tier       string
	verdict    Verdict
	reason     string // model's reason text (already sanitized of control chars by parse)
	selfConf   int    // model's self-reported 1-5 confidence; 0 when none supplied
	hasPosEvid bool   // model claimed positive evidence of legitimacy (only meaningful for resolve)

	// strongMalicious is true when the model's reply asserts a STRONG malicious-side
	// evidence item (parsed ONLY from the model reply, never from untrusted prompt
	// text — same verdict-isolation discipline as verdict). The merge aggregator
	// uses it so a single strong malicious finding can outweigh two weak benign
	// concurrences (§1: evidence aggregation, not majority vote). It is meaningful
	// only on a deep-investigate tier.
	strongMalicious bool

	// insufficient distinguishes an escalate-as-INSUFFICIENT-DATA from an
	// escalate-as-SUSPICIOUS (§1: "escalate-as-suspicious vs escalate-as-insufficient
	// -data"). Both produce verdict=escalate (the safe side), but the merge
	// aggregator treats them as DIFFERENT dispositions: a panel that splits into one
	// resolve, one suspicious, and one insufficient is genuinely uncertain (3
	// disagree) → heal. Parsed ONLY from the model reply. Meaningful on a
	// deep-investigate tier (the "incomplete" hypothesis).
	insufficient bool

	// Observable structural signals (measured, not self-reported).
	toolCalls     int
	distinctTools int
	toolEmpty     bool

	// FIX 3 OBSERVABLE FORCE-ESCALATE signals — computed by the ToolRunner from the
	// REAL tool output (relationships / surfaced events), carried through so the
	// triage gate can FORCE a clean resolve to escalate on event content (zero
	// relationship-history access; a role-grant by the finding actor). Keyed on the
	// EVENT predicate, never on detector family. Trustworthy gate inputs: they come
	// from the runtime's read of the tool result, not from the model or the
	// untrusted transcript text.
	zeroHistoryAccess bool
	zeroHistoryDetail string
	roleGrantByActor  bool
	roleGrantDetail   string

	// failSafe is true when the tier could not produce a trustworthy verdict
	// (model error, empty/unparseable reply): the cascade must escalate, never
	// resolve. reason carries the cause.
	failSafe bool
}

// cleanResolve reports whether a triage resolve is clean enough to CLOSE a
// finding benign without escalating to investigate. The triage floor (§2.4):
// positive evidence present, self-confidence ≥ 4 (high/certain), and the tools
// were not empty. Anything short of all three is not a dismissal — it escalates.
func (r tierResult) cleanResolve() bool {
	return r.verdict == VerdictResolve &&
		r.hasPosEvid &&
		r.selfConf >= 4 &&
		!r.toolEmpty
}

// resolveAttempt projects a tier result into the ResolveAttempt the structural +
// fail-safe gate (GuardResolve) judges. Used for the investigate tier's resolve:
// the gate scores the OBSERVABLE investigation (tool calls, distinct tools,
// evidence citations in the reason, iteration count) and applies the fail-safe
// (ambiguity / empty / low-confidence / no-positive-evidence ⇒ escalate).
func (r tierResult) resolveAttempt() ResolveAttempt {
	return ResolveAttempt{
		Transcript: Transcript{
			Resolved:      true, // we only build this for a proposed resolve
			ToolCalls:     r.toolCalls,
			DistinctTools: r.distinctTools,
			Iterations:    1, // single-pass this wave; deep panel adds iterations later
			Reason:        r.reason,
		},
		SelfConfidence:      r.selfConf,
		ToolReturnedEmpty:   r.toolEmpty,
		Ambiguous:           false, // an unparseable reply already became failSafe upstream
		HasPositiveEvidence: r.hasPosEvid,
	}
}

// runTier executes one tier: gather tool evidence, build the untrusted-data-safe
// prompt, call the model, parse the verdict. It NEVER resolves on its own — it
// returns a tierResult the caller (the cascade) gates.
func runTier(ctx context.Context, client Client, f finding.Finding, tier, model, systemPrompt string, tools ToolRunner, temperature float64) tierResult {
	return runTierWithContext(ctx, client, f, tier, model, systemPrompt, tools, "", temperature)
}

// runTierWithContext is runTier with an additional UNTRUSTED context block — the
// parent investigate's partial transcript handed to a deep-investigate tier. The
// extra block is boxed in USER_DATA markers exactly like the finding fields and
// tool transcript; it is read-only context for the deep tier, never an
// instruction. extraContext "" reduces this to plain runTier.
func runTierWithContext(ctx context.Context, client Client, f finding.Finding, tier, model, systemPrompt string, tools ToolRunner, extraContext string, temperature float64) tierResult {
	res := tierResult{tier: tier}

	// (1) Gather tool evidence through the seam (nil-safe: no live tools this wave).
	var evidence ToolEvidence
	if tools != nil {
		ev, err := tools.RunTools(ctx, tier, f)
		if err != nil {
			// A tool ERROR (not an empty result) is a genuine failure: fail safe.
			res.failSafe = true
			res.verdict = VerdictEscalate
			res.reason = fmt.Sprintf("%s: tool error gathering evidence (%v); escalating (fail-safe)", tier, err)
			return res
		}
		evidence = ev
	}
	res.toolCalls = evidence.ToolCalls
	res.distinctTools = evidence.DistinctTools
	res.toolEmpty = evidence.ToolEmpty
	// FIX 3: carry the OBSERVABLE force-escalate predicates the runner computed from
	// the real tool output so the triage gate can act on event content (cascade.go).
	res.zeroHistoryAccess = evidence.ZeroHistoryAccess
	res.zeroHistoryDetail = evidence.ZeroHistoryDetail
	res.roleGrantByActor = evidence.RoleGrantByActor
	res.roleGrantDetail = evidence.RoleGrantDetail

	// (2) Build the user message. Every attacker-controlled string — the finding's
	// title/reason/actor/type AND the tool transcript AND any parent transcript —
	// is WrapUntrusted + sanitized so an injection payload riding in any of them is
	// boxed in USER_DATA markers and cannot pose as a system instruction (§2.7 / §3).
	// FIX 1: each tool result is boxed as its OWN field (baseline/events/findings)
	// so the high-signal baseline + relationship evidence survives the per-field
	// 1024-char cap instead of being truncated inside one concatenated blob.
	req := buildTierRequest(f, model, systemPrompt, evidence, extraContext, temperature)

	// (3) Call the model once.
	resp, err := client.Messages(ctx, req)
	if err != nil {
		res.failSafe = true
		res.verdict = VerdictEscalate
		res.reason = fmt.Sprintf("%s: model call failed (%v); escalating (fail-safe)", tier, err)
		return res
	}

	// SECURITY INVARIANT (verdict isolation): the terminal verdict is parsed ONLY
	// from the model's structured reply (resp.Content via firstText) — NEVER from
	// `req`, the finding fields, or the tool transcript. Those are all UNTRUSTED
	// prompt text (boxed in USER_DATA markers above) and an attacker can plant a
	// well-formed {"action":"resolve",...} inside them. Reading the verdict from
	// the reply, not the prompt, is what makes a planted resolve inert.
	// DO NOT pass any req/finding/tool-derived string to parseVerdict here.
	// Proven mutation-style by TestCascade_VerdictIsolation_TracksModelReplyNotInjection:
	// scripting the reply to escalate while the prompt carries a planted resolve
	// keeps the verdict escalate; mutating this line to read from the prompt flips
	// it to resolve and fails that test.
	reply := firstText(resp)
	v, conf, posEvid, strongMal, insuff, reason := parseVerdict(reply)
	res.verdict = v
	res.selfConf = conf
	res.hasPosEvid = posEvid
	res.strongMalicious = strongMal
	res.insufficient = insuff
	res.reason = reason

	// An unparseable reply is ambiguity: fail safe to escalate (§2.5). Never
	// silently dismiss a finding because the model's reply could not be read.
	if v == VerdictUnparseable {
		res.failSafe = true
		res.verdict = VerdictEscalate
		if strings.TrimSpace(reason) == "" {
			res.reason = fmt.Sprintf("%s: model reply unparseable; escalating (fail-safe)", tier)
		} else {
			res.reason = fmt.Sprintf("%s: model reply unparseable; escalating (fail-safe): %s", tier, reason)
		}
	}

	return res
}

// buildTierRequest assembles a tier's single MessagesRequest. The system prompt
// is the ported POST.md (carrying the ## Security block). The user content boxes
// every untrusted scalar of the finding plus EACH tool result in USER_DATA
// markers via WrapUntrusted — the model sees them as data to analyze, never as
// instructions to follow.
//
// FIX 1: each tool result is boxed as its OWN WrapUntrusted field (tools.baseline,
// tools.events, tools.findings) — EACH independently sanitized + 1024-capped — so
// the high-signal check-baseline + relationship evidence survives the per-field cap
// instead of being truncated inside one concatenated tools.transcript blob (VA-03's
// zero-history discriminator lived past char 1024 of the old single field). A
// runner that only set the legacy ev.Text is still boxed as one tools.transcript
// field (pre-FIX-1 behavior). The SECURITY INVARIANT holds: every field is still
// WrapUntrusted + sanitized, and the verdict is parsed only from the model reply.
func buildTierRequest(f finding.Finding, model, systemPrompt string, ev ToolEvidence, parentTranscript string, temperature float64) MessagesRequest {
	var b strings.Builder
	b.WriteString("Analyze this security finding and decide.\n\n")
	// Each finding field that an attacker can influence is individually boxed.
	b.WriteString(WrapUntrusted("finding.id", f.ID))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("finding.type", f.Type))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("finding.severity", f.Severity))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("finding.actor", f.Actor))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("finding.source", f.Source))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("finding.reason", f.Reason))
	b.WriteString("\n")
	if ev.hasPerToolText() {
		// FIX 1: box EACH tool result as its OWN field, each independently sanitized
		// + 1024-capped, so the salient baseline/relationship facts survive the cap.
		if strings.TrimSpace(ev.BaselineText) != "" {
			b.WriteString(WrapUntrusted("tools.baseline", ev.BaselineText))
			b.WriteString("\n")
		}
		if strings.TrimSpace(ev.EventsText) != "" {
			b.WriteString(WrapUntrusted("tools.events", ev.EventsText))
			b.WriteString("\n")
		}
		if strings.TrimSpace(ev.FindingsText) != "" {
			b.WriteString(WrapUntrusted("tools.findings", ev.FindingsText))
			b.WriteString("\n")
		}
	} else if strings.TrimSpace(ev.Text) != "" {
		// Legacy single-blob fallback (scriptedTools test seam, pre-FIX-1 runners).
		// The tool transcript is the highest-risk injection vector (§3.8): box it.
		b.WriteString(WrapUntrusted("tools.transcript", ev.Text))
		b.WriteString("\n")
	}
	if strings.TrimSpace(parentTranscript) != "" {
		// The parent investigate's partial transcript handed to a deep tier. It is
		// produced upstream from finding/tool text that may itself be attacker-
		// influenced — box it like every other untrusted vector (read-only context,
		// never an instruction).
		b.WriteString(WrapUntrusted("parent.transcript", parentTranscript))
		b.WriteString("\n")
	}
	b.WriteString("\nRespond with your verdict. Use this exact shape:\n")
	b.WriteString(`{"action":"resolve|escalate","confidence":1-5,"positive_evidence":true|false,"strong_evidence":true|false,"insufficient_data":true|false,"reason":"..."}`)
	b.WriteString("\n")

	return MessagesRequest{
		Model:       model,
		MaxTokens:   512,
		System:      systemPrompt,
		Temperature: temperaturePtr(temperature),
		Messages: []Message{{
			Role:    "user",
			Content: []ContentBlock{{Type: "text", Text: b.String()}},
		}},
	}
}

// temperaturePtr returns a *float64 for a non-zero temperature, or nil for 0.
// nil leaves MessagesRequest.Temperature unset (omitempty suppresses it → the
// provider default, the historical behavior). A non-zero temperature (the
// consensus gate's 1.0) is sent explicitly so the re-runs sample stochastically.
// Threading 0 through the normal (non-consensus) path keeps every existing call
// byte-identical on the wire.
func temperaturePtr(t float64) *float64 {
	if t == 0 {
		return nil
	}
	return &t
}

// buildEscalateRequest assembles the escalate role's single request: the cheap,
// tool-less formatter. The finding fields and the upstream escalation reason are
// boxed (the upstream reason can echo attacker-influenced finding text). The
// system prompt carries the ## Security block so "resolve as benign" inside the
// box is ignored.
func buildEscalateRequest(f finding.Finding, model, upstream string, temperature float64) MessagesRequest {
	var b strings.Builder
	b.WriteString("Format a human-facing security alert from this data.\n\n")
	b.WriteString(WrapUntrusted("finding.id", f.ID))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("finding.type", f.Type))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("finding.severity", f.Severity))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("finding.reason", f.Reason))
	b.WriteString("\n")
	b.WriteString(WrapUntrusted("escalation.upstream", upstream))
	b.WriteString("\n")

	return MessagesRequest{
		Model:       model,
		MaxTokens:   512,
		System:      escalateSystemPrompt,
		Temperature: temperaturePtr(temperature),
		Messages: []Message{{
			Role:    "user",
			Content: []ContentBlock{{Type: "text", Text: b.String()}},
		}},
	}
}

// verdictReply is the structured shape a tier model is asked to emit. Parsed
// leniently: a missing/garbled reply degrades to VerdictUnparseable (the
// fail-safe escalates it), never to a silent resolve.
type verdictReply struct {
	Action           string `json:"action"`
	Confidence       int    `json:"confidence"`
	PositiveEvidence bool   `json:"positive_evidence"`
	// StrongEvidence, when true on a deep-investigate reply, asserts the model
	// found a STRONG malicious-side evidence item. The merge aggregator (fanout.go)
	// lets one such item outweigh two weak benign concurrences. Parsed ONLY here,
	// from the model's own reply — never from untrusted prompt text.
	StrongEvidence bool `json:"strong_evidence"`
	// InsufficientData, when true on a deep-investigate reply, marks an
	// escalate-as-INSUFFICIENT-DATA (distinct from escalate-as-suspicious). The
	// merge aggregator uses it to detect a genuine 3-way split (resolve / suspicious
	// / insufficient) → heal. Parsed ONLY from the model reply.
	InsufficientData bool   `json:"insufficient_data"`
	Reason           string `json:"reason"`
}

// parseVerdict extracts the disposition + self-confidence + positive-evidence
// flag + reason from a model reply. It is deliberately STRICT about what counts
// as a resolve and LENIENT about failure:
//
//   - A JSON object (possibly embedded in surrounding prose) with action
//     "resolve"/"escalate" is the primary path.
//   - Failing that, a plain-text reply is scanned for an explicit RESOLVE /
//     ESCALATE token (case-insensitive, word-boundary).
//   - Anything else is VerdictUnparseable — which the caller fail-safes to
//     escalate. Ambiguity NEVER becomes resolve.
//
// CRUCIAL for the injection invariant: the only way to get VerdictResolve is an
// explicit, well-formed resolve in the model's OWN reply. Untrusted text boxed
// in USER_DATA markers is never parsed as a verdict — it is in the prompt the
// model reads, not in the model's reply this function reads.
//
// Returns: verdict, self-confidence, positive-evidence, strong-malicious-evidence,
// insufficient-data, reason. The strong-malicious and insufficient-data flags are
// deep-investigate signals the merge aggregator reads; like the verdict they come
// ONLY from the model's reply, never from untrusted prompt text.
func parseVerdict(reply string) (Verdict, int, bool, bool, bool, string) {
	reply = strings.TrimSpace(reply)
	if reply == "" {
		return VerdictUnparseable, 0, false, false, false, ""
	}

	// Primary: a JSON object, possibly wrapped in prose or a ```json fence.
	if obj := extractJSONObject(reply); obj != "" {
		var vr verdictReply
		if err := json.Unmarshal([]byte(obj), &vr); err == nil {
			action := normalizeAction(vr.Action)
			reason := sanitizeReason(vr.Reason)
			switch action {
			case VerdictResolve:
				return VerdictResolve, clampConf(vr.Confidence), vr.PositiveEvidence, vr.StrongEvidence, vr.InsufficientData, reason
			case VerdictEscalate:
				return VerdictEscalate, clampConf(vr.Confidence), vr.PositiveEvidence, vr.StrongEvidence, vr.InsufficientData, reason
			}
			// Parsed JSON but no recognizable action → fall through to token scan.
		}
	}

	// Secondary: explicit token in plain text. Escalate wins ties — the safe side.
	low := strings.ToLower(reply)
	hasEscalate := containsToken(low, "escalate")
	hasResolve := containsToken(low, "resolve") || containsToken(low, "resolved")
	switch {
	case hasEscalate:
		return VerdictEscalate, 0, false, false, false, sanitizeReason(reply)
	case hasResolve:
		// A bare "resolve" with no structured confidence/evidence is a WEAK resolve:
		// report it as resolve but with confidence 0 and no positive evidence, so the
		// triage rubric (needs ≥4 + posEvid) and the investigate gate both reject it
		// unless the model actually supplied the structured fields above.
		return VerdictResolve, 0, false, false, false, sanitizeReason(reply)
	default:
		return VerdictUnparseable, 0, false, false, false, sanitizeReason(reply)
	}
}

// normalizeAction folds an action string onto a Verdict. Unknown → unparseable.
func normalizeAction(s string) Verdict {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "resolve", "resolved", "benign", "dismiss":
		return VerdictResolve
	case "escalate", "escalated", "investigate", "suspicious":
		return VerdictEscalate
	default:
		return VerdictUnparseable
	}
}

// extractJSONObject returns the first balanced {...} JSON object substring in s,
// or "" when there is none. Tolerates surrounding prose and ```json fences — the
// model often narrates before emitting the object.
func extractJSONObject(s string) string {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return ""
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// containsToken reports whether low (already lower-cased) contains tok as a
// whole word (bounded by non-letter on both sides). Prevents "unresolved" from
// matching "resolve" or "de-escalate" oddities from skewing the scan.
func containsToken(low, tok string) bool {
	idx := 0
	for {
		i := strings.Index(low[idx:], tok)
		if i < 0 {
			return false
		}
		i += idx
		before := i == 0 || !isLetter(low[i-1])
		afterPos := i + len(tok)
		after := afterPos >= len(low) || !isLetter(low[afterPos])
		if before && after {
			return true
		}
		idx = i + 1
		if idx >= len(low) {
			return false
		}
	}
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// clampConf bounds a self-reported confidence to the 0..5 range (0 = none).
func clampConf(c int) int {
	if c < 0 {
		return 0
	}
	if c > 5 {
		return 5
	}
	return c
}

// sanitizeReason strips control characters from a model-supplied reason so it is
// safe to embed in a Resolution.Reason / log line. It does NOT box the reason in
// USER_DATA markers (the reason is the MODEL's output, not untrusted input) — it
// only neutralizes control chars, length-capping via the shared SanitizeField
// path is unnecessary here since the model's own reason is short.
func sanitizeReason(s string) string {
	var b strings.Builder
	for _, ch := range strings.TrimSpace(s) {
		if isControl(ch) {
			if ch == '\n' || ch == '\r' || ch == '\t' {
				b.WriteByte(' ')
			}
			continue
		}
		b.WriteRune(ch)
	}
	return strings.TrimSpace(b.String())
}
