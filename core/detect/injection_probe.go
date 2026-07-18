package detect

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(injectionProbeDetector{}) }

type injectionProbeDetector struct{}

func (injectionProbeDetector) Name() string { return "injection-probe" }

func (injectionProbeDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		out = append(out, injectionProbeEvaluate(ev, bl)...)
	}
	return out
}

// injectionPatterns are compiled regexes for known prompt injection signals.
// SECURITY-CRITICAL: these patterns must be comprehensive and conservatively
// tuned to avoid false negatives on adversarial inputs.
var injectionPatterns = []injectionRule{
	// Direct instruction overrides — highest severity.
	{
		re:       regexp.MustCompile(`(?i)\bignore\s+(all\s+)?previous\s+instructions?\b`),
		name:     "ignore-previous-instructions",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\bforget\s+(all\s+)?previous\s+instructions?\b`),
		name:     "forget-previous-instructions",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(a\s+)?(\w+\s+)*(assistant|ai|bot|model|gpt|claude|llm)\b`),
		name:     "persona-override",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\bact\s+as\s+(?:an?\s+)?(?:jailbroken|uncensored|unrestricted|evil|malicious)\b`),
		name:     "jailbreak-persona",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\bdisregard\s+(your\s+)?(previous|prior|earlier|all)\s+(instructions?|rules?|constraints?|guidelines?)\b`),
		name:     "disregard-instructions",
		severity: "critical",
	},
	// System prompt leakage / extraction attempts.
	{
		re:       regexp.MustCompile(`(?i)\bprint\s+(your\s+)?(system\s+prompt|instructions?|context)\b`),
		name:     "system-prompt-leak",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\breveal\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt)\b`),
		name:     "system-prompt-leak",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\brepeat\s+(everything|all)\s+(above|before|from\s+the\s+beginning)\b`),
		name:     "context-extraction",
		severity: "high",
	},
	// XML/CDATA injection markers (used to escape context).
	{
		re:       regexp.MustCompile(`(?i)<\s*/?system\s*>`),
		name:     "xml-system-tag",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)<\s*/?instructions?\s*>`),
		name:     "xml-instructions-tag",
		severity: "high",
	},
	{
		re:       regexp.MustCompile(`(?i)<\s*/?prompt\s*>`),
		name:     "xml-prompt-tag",
		severity: "high",
	},
	// Markdown injection: headings used to inject new context sections.
	{
		re:       regexp.MustCompile(`(?m)^#{1,3}\s+(system|instructions?|new\s+task|ignore|override)\b`),
		name:     "markdown-header-injection",
		severity: "high",
	},
	// DAN / jailbreak keywords.
	{
		re:       regexp.MustCompile(`(?i)\bDAN\s+mode\b|\bdo\s+anything\s+now\b`),
		name:     "dan-jailbreak",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\bjailbreak\b`),
		name:     "jailbreak-keyword",
		severity: "high",
	},
	// Token injection / delimiter attacks.
	{
		re:       regexp.MustCompile(`<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>`),
		name:     "token-delimiter-injection",
		severity: "critical",
	},
	// Indirect injection via role confusion.
	{
		re:       regexp.MustCompile(`(?i)\bassistant\s*:\s*(ignore|disregard|forget|override)\b`),
		name:     "role-confusion",
		severity: "high",
	},

	// ---------------------------------------------------------------------
	// Classic web/system injection signatures (SQLi / XSS / command).
	//
	// R9-clean design note: this is a GENERAL signal family that recognizes
	// the *attack syntax* of an injection payload — the breakout tokens an
	// attacker uses to escape a query/markup/shell context — NOT a lookup of
	// any one scenario, and NOT a bare "contains SQL keywords" match. The
	// distinction is deliberate: a benign application log that merely contains
	// a legitimate query ("SELECT count FROM metrics_table WHERE ts > NOW()")
	// carries no breakout syntax and MUST stay silent, while an injection
	// probe ("' OR 1=1 --" in a User-Agent header) carries a quote-break +
	// boolean tautology + comment terminator. The scanner already walks EVERY
	// string field in the payload (identity/request fields — User-Agent,
	// headers, path, params — included), so no field is special-cased.

	// SQLi — quote-break boolean tautology (e.g. `' OR 1=1`, `" AND 'a'='a`).
	// The leading quote is the string-context breakout that separates an
	// injection payload from an in-context legitimate query.
	{
		re:       regexp.MustCompile(`(?i)['"]\s*(?:or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?`),
		name:     "sqli-tautology",
		severity: "critical",
	},
	// SQLi — numeric tautology even without a quote (`OR 1=1`, `AND 7=7`).
	{
		re:       regexp.MustCompile(`(?i)\b(?:or|and)\s+(\d+)\s*=\s*\d+\b`),
		name:     "sqli-numeric-tautology",
		severity: "critical",
	},
	// SQLi — comment terminator used to truncate the rest of a query. Anchored
	// to a preceding quote so a single hyphen in ordinary prose ("NOW() -
	// INTERVAL") is not mistaken for a `--` comment.
	{
		re:       regexp.MustCompile(`(?i)['"][^'"]*\s(?:--|#)(?:\s|$)`),
		name:     "sqli-comment-terminator",
		severity: "high",
	},
	// SQLi — UNION-based extraction.
	{
		re:       regexp.MustCompile(`(?i)\bunion\s+(?:all\s+)?select\b`),
		name:     "sqli-union",
		severity: "critical",
	},
	// SQLi — stacked destructive query.
	{
		re:       regexp.MustCompile(`(?i);\s*(?:drop|delete|truncate|update|insert|alter)\b`),
		name:     "sqli-stacked-query",
		severity: "critical",
	},
	// XSS — inline <script> injection.
	{
		re:       regexp.MustCompile(`(?i)<\s*script\b`),
		name:     "xss-script-tag",
		severity: "critical",
	},
	// XSS — javascript: URI scheme.
	{
		re:       regexp.MustCompile(`(?i)\bjavascript:\s*\S`),
		name:     "xss-js-uri",
		severity: "high",
	},
	// XSS — inline event-handler attribute injection (onerror=, onload=, ...).
	{
		re:       regexp.MustCompile(`(?i)\bon(?:error|load|click|mouseover|focus|submit)\s*=\s*['"]?\S`),
		name:     "xss-event-handler",
		severity: "high",
	},
	// Command injection — shell metacharacter chained to a known binary.
	{
		re:       regexp.MustCompile(`(?i)(?:;|\|\||&&|\|)\s*(?:cat|ls|rm|wget|curl|nc|ncat|bash|sh|zsh|whoami|id|uname|chmod|chown|kill|nslookup|dig|ping)\b`),
		name:     "command-injection-chain",
		severity: "critical",
	},
	// Command injection — command substitution ($(...) or backticks).
	{
		re:       regexp.MustCompile("(?:\\$\\([^)]{1,120}\\)|`[^`]{1,120}`)"),
		name:     "command-injection-substitution",
		severity: "high",
	},
}

type injectionRule struct {
	re       *regexp.Regexp
	name     string
	severity string
}

// injectionProbeEvaluate scans all string-valued fields in the event payload
// for injection patterns. It also checks base64-decoded versions of field
// values. Returns one finding per detected pattern (first match per pattern
// wins). This is a pure function: no I/O, no globals mutated.
func injectionProbeEvaluate(ev event.Event, _ *baseline.Baseline) []finding.Finding {
	if len(ev.Payload) == 0 {
		return nil
	}

	// Extract all string values from payload for scanning.
	texts := injectionExtractStrings(ev.Payload)

	// Also decode any base64-encoded values and scan those.
	var decoded []string
	for _, t := range texts {
		if d, ok := tryBase64Decode(t); ok {
			decoded = append(decoded, d)
		}
	}
	texts = append(texts, decoded...)

	if len(texts) == 0 {
		return nil
	}

	var findings []finding.Finding
	seen := map[string]bool{}

	for _, rule := range injectionPatterns {
		if seen[rule.name] {
			continue
		}
		for _, text := range texts {
			if rule.re.MatchString(text) {
				matched := rule.re.FindString(text)
				// Truncate match for evidence to avoid embedding hostile content verbatim.
				if len(matched) > 80 {
					matched = matched[:80] + "..."
				}
				evidence, _ := json.Marshal(map[string]string{
					"actor":    ev.Actor,
					"pattern":  rule.name,
					"match":    matched,
					"rule":     "injection-pattern",
					"event_id": ev.ID,
				})
				findings = append(findings, finding.Finding{
					ID:        "finding-" + ev.ID + "-inj-" + rule.name,
					Source:    "detector:injection-probe",
					Severity:  rule.severity,
					Type:      "injection-probe",
					Actor:     ev.Actor,
					Timestamp: ev.Timestamp,
					Reason:    "prompt injection pattern detected: " + rule.name,
					Evidence:  evidence,
					EventIDs:  []string{ev.ID},
				})
				seen[rule.name] = true
				break
			}
		}
	}

	return findings
}

// injectionExtractStrings recursively extracts all string values from a JSON value.
func injectionExtractStrings(raw json.RawMessage) []string {
	var out []string

	// Try as object.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for _, v := range obj {
			out = append(out, injectionExtractStrings(v)...)
		}
		return out
	}

	// Try as array.
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, v := range arr {
			out = append(out, injectionExtractStrings(v)...)
		}
		return out
	}

	// Try as string.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s != "" {
			out = append(out, s)
		}
	}

	return out
}

// tryBase64Decode attempts to base64-decode s. Returns the decoded string and
// true only when the result is valid UTF-8 and long enough to be meaningful.
func tryBase64Decode(s string) (string, bool) {
	// Only attempt decoding for strings that look like base64 (length ≥ 20,
	// only base64 characters).
	if len(s) < 20 {
		return "", false
	}
	b64re := regexp.MustCompile(`^[A-Za-z0-9+/\-_]+=*$`)
	if !b64re.MatchString(strings.TrimSpace(s)) {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return "", false
			}
		}
	}
	decoded := string(b)
	// Must be printable text.
	for _, r := range decoded {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return "", false
		}
	}
	return decoded, len(decoded) > 0
}
