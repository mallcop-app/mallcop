package detect

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/event"
)

// injEvent builds an http_request-shaped event whose metadata carries the given
// key/value pairs — the same projection the exam runner produces (payload =
// {action,target,severity,metadata:{...}}), so these tests exercise the exact
// string set the detector sees in the corpus.
func injEvent(t *testing.T, actor string, meta map[string]any) event.Event {
	t.Helper()
	payload := map[string]any{
		"action":   "api_request",
		"target":   "acme-corp/api/v1/users",
		"severity": "critical",
		"metadata": meta,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return event.Event{
		ID: "e1", Source: "azure", Type: "http_request",
		Actor: actor, Timestamp: ts(18, 0), Payload: b,
	}
}

func firesInjection(t *testing.T, ev event.Event) bool {
	t.Helper()
	for _, f := range injectionProbeEvaluate(ev, nil) {
		if f.Type == "injection-probe" {
			return true
		}
	}
	return false
}

// TestInjectionProbeClassicSignals is the GENERAL-behavior test for the classic
// web/system injection signal family (SQLi / XSS / command). It asserts the
// mechanism fires on *attack syntax* regardless of which field carries it —
// including identity/request fields like User-Agent — and NEVER special-cases a
// scenario string (R9). Each malicious case pairs the payload with the field it
// rides in to prove field-agnostic scanning.
func TestInjectionProbeClassicSignals(t *testing.T) {
	malicious := []struct {
		name  string
		field string
		value string
	}{
		// The IP-01 corpus payload: a textbook SQLi probe in the User-Agent
		// header. This is the labeled gap the family closes.
		{"sqli-tautology-user-agent", "user_agent", "' OR 1=1 --"},
		// Same family, different field and different tautology form.
		{"sqli-tautology-quoted", "query", "name=' OR 'a'='a"},
		{"sqli-numeric-tautology", "path", "/x?id=5 OR 7=7"},
		{"sqli-union", "referer", "1 UNION SELECT username,password FROM users"},
		{"sqli-stacked", "search", "foo'; DROP TABLE users; --"},
		{"xss-script-tag", "user_agent", "<script>document.cookie</script>"},
		{"xss-js-uri", "referer", "javascript:alert(document.domain)"},
		{"xss-event-handler", "comment", `<img src=x onerror="steal()">`},
		{"command-injection-chain", "filename", "report.pdf; cat /etc/passwd"},
		{"command-injection-substitution", "hostname", "srv-$(whoami).internal"},
	}
	for _, tc := range malicious {
		t.Run("fires/"+tc.name, func(t *testing.T) {
			ev := injEvent(t, "ext-user-7f3a", map[string]any{tc.field: tc.value})
			if !firesInjection(t, ev) {
				t.Fatalf("expected injection-probe to fire on %s payload %q in field %q, got no finding",
					tc.name, tc.value, tc.field)
			}
		})
	}

	// Benign twins: legitimate content that MUST stay silent. A general
	// signal family that fired here would be a family-of-false-positives —
	// the exact failure R9 forbids (keyword-matching instead of recognizing
	// breakout syntax).
	benign := []struct {
		name  string
		field string
		value string
	}{
		// The IP-02 corpus benign twin: a real internal metrics query logged
		// by an application. Real SQL, but no injection breakout syntax.
		{"benign-metrics-query", "log_message", "Executing metrics query: SELECT count FROM metrics_table WHERE ts > NOW() - INTERVAL 5m"},
		// Ordinary user agents and prose containing hyphens/keywords.
		{"benign-user-agent", "user_agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"},
		{"benign-log-agent", "user_agent", "log-agent/1.0"},
		{"benign-prose-and", "note", "review the report and update the dashboard"},
		{"benign-select-word", "note", "please select an option from the menu"},
	}
	for _, tc := range benign {
		t.Run("silent/"+tc.name, func(t *testing.T) {
			ev := injEvent(t, "deploy-svc", map[string]any{tc.field: tc.value})
			if firesInjection(t, ev) {
				fs := injectionProbeEvaluate(ev, nil)
				var got []string
				for _, f := range fs {
					got = append(got, string(f.Evidence))
				}
				t.Fatalf("expected NO injection-probe on benign %s payload %q in field %q, but it fired: %s",
					tc.name, tc.value, tc.field, strings.Join(got, " | "))
			}
		})
	}
}
