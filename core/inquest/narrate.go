// narrate.go — the ONE metered model call per investigated finding: the fixed
// system prompt, the user-document builder, the deterministic STRICT response
// validation matrix, and the belt-and-suspenders credential-shape scrub over
// the narrative text.
package inquest

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// systemPrompt is the FIXED narrate system prompt (modelCall §design). It is
// never templated with per-finding data — every fact the model may cite lives
// in the user document, already scrubbed by tools.GetRawEvent.
const systemPrompt = `You are mallcop's detection-time investigator. The committee has already ESCALATED this finding; you do not and cannot change that resolution — you produce an evidence narrative for the operator. You are given a fully assembled, pre-verified evidence chain; you have NO tools; do not request any. Reply with ONLY a JSON object {"verdict":"benign|suspicious|threat","confidence":0.0-1.0,"narrative":"..."}. The narrative (<=150 words) MUST name the caller identity fields verbatim from evidence.identity, MUST state the recurrence cadence and scan-schedule correlation from evidence, MUST — when evidence.identity.grantor and evidence.identity.grantee are BOTH non-empty — explain the ACTION in plain language: name which principal is the grantor (already held the authority) and which is the grantee (newly gained access), name evidence.identity.capability as what the grantee can now do, and state which direction access now flows (grantor -> grantee); this direction+capability sentence is REQUIRED even when caller/target identity fields are empty, and you MUST NOT invent a grant, direction, or capability when those grantor/grantee fields are empty, MUST stay consistent with evidence.recurrence.prior_investigations unless current evidence materially differs (say so explicitly if it does), MUST NOT claim any datum is unavailable if it appears in the evidence, and MUST NOT recommend destructive action (revoke/rotate/block) unless verdict is threat. HARD CONSISTENCY RULES (violating any of these makes the narrative wrong): if evidence.recurrence.occurrences > 1 the activity IS recurring — state the count and first_seen and NEVER write "no prior history", "first time", or equivalent; if evidence.baseline.known_actor is true the actor IS previously observed — never call it unknown. INTERPRETATION: a long-recurring pattern (high occurrences over days+) from a baseline-known actor, especially when scan_correlation shows many occurrences near scheduled scans, is characteristically operational infrastructure — verdict "threat" then requires evidence the established pattern does NOT explain (novel target or privilege, baseline-unknown actor, or a material break from the recurring shape), and you must name that evidence. CONFIDENCE: 0.8+ requires that no evidence section materially cuts against your verdict; when sections conflict, lower the confidence and say which evidence cuts which way.`

// narrateFinding is the finding-fields projection of the user document — the
// fields the prompt names explicitly, kept separate from the full
// finding.Finding so the wire shape stays fixed regardless of Finding's own
// evolution.
type narrateFinding struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Actor     string `json:"actor"`
	Reason    string `json:"reason"`
	Timestamp string `json:"timestamp"`
}

// narrateUserDoc is the single JSON document sent as the user message.
// Everything inside it already passed the get_raw_event scrub (Evidence.
// Identity) — the model can only narrate already-redacted material.
type narrateUserDoc struct {
	Finding    narrateFinding `json:"finding"`
	Resolution ResolutionRef  `json:"resolution"`
	Evidence   Evidence       `json:"evidence"`
}

// buildUserMessage renders the fixed-shape user document for one finding.
func buildUserMessage(f finding.Finding, res ResolutionRef, ev Evidence) (string, error) {
	doc := narrateUserDoc{
		Finding: narrateFinding{
			ID:        f.ID,
			Type:      f.Type,
			Severity:  f.Severity,
			Actor:     f.Actor,
			Reason:    f.Reason,
			Timestamp: f.Timestamp.UTC().Format(time.RFC3339),
		},
		Resolution: res,
		Evidence:   ev,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("inquest: marshal narrate user document: %w", err)
	}
	return string(b), nil
}

// narrateOutput is the outcome of one narrate call — always populated with a
// Status; Verdict/Confidence/Narrative are meaningful ONLY when Status ==
// StatusOK.
type narrateOutput struct {
	Verdict    Verdict
	Confidence float64
	Narrative  string
	Status     NarrativeStatus
	Model      string
	Usage      Usage
	// Err is the underlying transport/validation error, for the caller's
	// non-fatal log line — never surfaced in the committed Record.
	Err error
}

// narrate performs exactly ONE client.Messages call (retries:0 — see the
// package doc's failure-semantics note: a failed/invalid call degrades the
// record, it is never retried within this call). model == "" lets the
// injected client fall back to its OWN configured default model (the
// "inherit the scan's resolved model" config semantic) — a per-request Model
// always wins over a client default when set (core/inference.DirectClient's
// documented contract).
func narrate(ctx context.Context, client agent.Client, model string, maxTokens int, userDoc string) narrateOutput {
	if maxTokens <= 0 {
		maxTokens = 1024
	}
	temp := 0.0
	req := agent.MessagesRequest{
		Model:       model,
		MaxTokens:   maxTokens,
		System:      systemPrompt,
		Temperature: &temp,
		Messages: []agent.Message{
			{Role: "user", Content: []agent.ContentBlock{{Type: "text", Text: userDoc}}},
		},
	}

	resp, err := client.Messages(ctx, req)
	if err != nil {
		return narrateOutput{Status: StatusAbsentModelError, Err: fmt.Errorf("inquest: narrate call: %w", err), Model: model}
	}

	text := extractText(resp)
	verdict, confidence, narrative, verr := parseModelReply(text)
	if verr != nil {
		return narrateOutput{Status: StatusAbsentInvalidOutput, Err: verr, Model: model}
	}
	narrative = scrubCredentialShapes(narrative)

	return narrateOutput{
		Verdict:    verdict,
		Confidence: confidence,
		Narrative:  narrative,
		Status:     StatusOK,
		Model:      model,
	}
}

// extractText concatenates every "text" content block in resp, in order.
func extractText(resp agent.MessagesResponse) string {
	var sb strings.Builder
	for _, c := range resp.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	return sb.String()
}

// modelReply is the wire shape the system prompt demands.
type modelReply struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Narrative  string  `json:"narrative"`
}

// parseModelReply runs the deterministic STRICT validation matrix: strip
// optional code fences, extract the first balanced JSON object, decode, and
// validate verdict ∈ {benign,suspicious,threat}, confidence ∈ [0,1], and a
// non-empty narrative <= maxNarrativeBytes. Any failure returns a non-nil
// error and the caller maps it to StatusAbsentInvalidOutput — there is no
// partial-credit parse.
func parseModelReply(text string) (Verdict, float64, string, error) {
	stripped := stripFences(text)
	obj, err := firstBalancedJSONObject(stripped)
	if err != nil {
		return "", 0, "", fmt.Errorf("inquest: narrate reply: %w", err)
	}

	var raw modelReply
	if err := json.Unmarshal([]byte(obj), &raw); err != nil {
		return "", 0, "", fmt.Errorf("inquest: narrate reply: decode: %w", err)
	}

	v := Verdict(strings.ToLower(strings.TrimSpace(raw.Verdict)))
	switch v {
	case VerdictBenign, VerdictSuspicious, VerdictThreat:
	default:
		return "", 0, "", fmt.Errorf("inquest: narrate reply: verdict %q is not one of benign|suspicious|threat", raw.Verdict)
	}

	if raw.Confidence < 0 || raw.Confidence > 1 {
		return "", 0, "", fmt.Errorf("inquest: narrate reply: confidence %v is out of [0,1]", raw.Confidence)
	}

	narrative := strings.TrimSpace(raw.Narrative)
	if narrative == "" {
		return "", 0, "", fmt.Errorf("inquest: narrate reply: empty narrative")
	}
	if len(narrative) > maxNarrativeBytes {
		return "", 0, "", fmt.Errorf("inquest: narrate reply: narrative is %d bytes, exceeds cap %d", len(narrative), maxNarrativeBytes)
	}

	return v, raw.Confidence, narrative, nil
}

// stripFences removes a single leading/trailing ``` or ```json code fence, if
// present. A reply with no fence is returned trimmed and unchanged.
func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[idx+1:]
	} else {
		s = strings.TrimPrefix(s, "```")
	}
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

// firstBalancedJSONObject scans s for the first '{' and returns the substring
// through its matching '}', respecting JSON string literals (so a brace
// inside a quoted string is not counted) and backslash escapes within them.
func firstBalancedJSONObject(s string) (string, error) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return "", fmt.Errorf("no '{' found in reply")
	}

	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1], nil
			}
		}
	}
	return "", fmt.Errorf("no balanced '{...}' found in reply")
}

// akiaKeyPattern matches AWS access-key-id shapes (AKIA/ASIA + 16 uppercase
// alphanumerics) — a belt-and-suspenders catch for a credential shape the
// model's own text might echo/invent, independent of tools.GetRawEvent's
// structural scrub over the SOURCE payload.
var akiaKeyPattern = regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)

// sessionTokenPattern matches a "sessionToken"-labeled long base64-ish run —
// the shape a leaked STS session token takes when echoed as prose.
var sessionTokenPattern = regexp.MustCompile(`(?i)(sessionToken["']?\s*[:=]\s*["']?)[A-Za-z0-9+/=]{20,}`)

// scrubCredentialShapes replaces any AKIA/ASIA-shaped key id or
// sessionToken-labeled long base64 run in s with "[REDACTED]". This is a
// second, independent line of defense over the NARRATIVE text specifically —
// tools.GetRawEvent's structural redaction already prevents these bytes from
// reaching the prompt in the first place (see assemble.go's IDENTITY
// section); this catches the case where the model's own generated prose
// invents/echoes something credential-shaped regardless.
func scrubCredentialShapes(s string) string {
	s = akiaKeyPattern.ReplaceAllString(s, "[REDACTED]")
	s = sessionTokenPattern.ReplaceAllString(s, "${1}[REDACTED]")
	return s
}
