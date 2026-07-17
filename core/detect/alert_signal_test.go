package detect

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// asBase is the fixed anchor timestamp every alert-signal fixture below is
// built relative to, so window-boundary math (alertCorrelationWindow = 72h) in
// the test cases is easy to eyeball.
var asBase = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// asEvent builds an event.Event with a JSON-marshaled payload. org is written
// to the top-level Event.Org field (never inside payload) — exactly how a real
// connector shapes an event (see pkg/event.Event and connect/github/normalize.go).
func asEvent(t *testing.T, id, evType, actor, org string, tsv time.Time, payload map[string]any) event.Event {
	t.Helper()
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		raw = b
	}
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      evType,
		Actor:     actor,
		Org:       org,
		Timestamp: tsv,
		Payload:   raw,
	}
}

// asEvidence unmarshals a finding's Evidence into a generic map for assertions.
func asEvidence(t *testing.T, f finding.Finding) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(f.Evidence, &m); err != nil {
		t.Fatalf("unmarshal evidence: %v (raw: %s)", err, string(f.Evidence))
	}
	return m
}

// asFindings runs ONLY the alert-signal detector (not the full registry) over
// events, so these tests are immune to unrelated detectors' behavior.
func asFindings(events []event.Event) []finding.Finding {
	return alertSignalDetector{}.Detect(events, &baseline.Baseline{})
}

// ---------------------------------------------------------------------------
// 1. alert-only: base finding, severity mapped from the alert's own field.
// ---------------------------------------------------------------------------

func TestAlertSignal_BaseFinding_SeverityFromAlert(t *testing.T) {
	cases := []struct {
		evType   string
		rawSev   string
		wantSev  string
		wantType string
	}{
		{"dependabot_alert", "critical", "critical", "dependabot_alert"},
		{"dependabot_alert", "high", "high", "dependabot_alert"},
		{"dependabot_alert", "medium", "medium", "dependabot_alert"},
		{"dependabot_alert", "moderate", "medium", "dependabot_alert"}, // CVSS-style alias
		{"dependabot_alert", "low", "low", "dependabot_alert"},
		{"code_scanning_alert", "critical", "critical", "code_scanning_alert"},
		{"code_scanning_alert", "high", "high", "code_scanning_alert"},
		{"secret_scanning_alert", "critical", "critical", "secret_scanning_alert"},
	}
	for _, tc := range cases {
		t.Run(tc.evType+"/"+tc.rawSev, func(t *testing.T) {
			ev := asEvent(t, "e-"+tc.rawSev, tc.evType, "github-actions", "acme", asBase, map[string]any{
				"signal_class": "alert",
				"alert_number": 1,
				"alert_state":  "open",
				"severity":     tc.rawSev,
				"repo":         "acme/widgets",
			})
			findings := asFindings([]event.Event{ev})
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.Type != "alert-signal" {
				t.Errorf("Type = %q, want alert-signal", f.Type)
			}
			if f.Source != "detector:alert-signal" {
				t.Errorf("Source = %q, want detector:alert-signal", f.Source)
			}
			if f.Severity != tc.wantSev {
				t.Errorf("Severity = %q, want %q", f.Severity, tc.wantSev)
			}
			ev2 := asEvidence(t, f)
			if ev2["severity_source"] != "alert" {
				t.Errorf("severity_source = %v, want %q (severity came from the payload)", ev2["severity_source"], "alert")
			}
			if ev2["escalated"] != false {
				t.Errorf("escalated = %v, want false (no correlation input in this fixture)", ev2["escalated"])
			}
		})
	}
}

// TestAlertSignal_BaseFinding_SeverityFloor_WhenAbsentOrUnrecognized proves the
// per-type floor: never a per-alert guess, always the documented default, and
// always disclosed via severity_source="policy-default".
func TestAlertSignal_BaseFinding_SeverityFloor_WhenAbsentOrUnrecognized(t *testing.T) {
	cases := []struct {
		name    string
		evType  string
		rawSev  string // "" = field omitted entirely
		wantSev string
	}{
		{"dependabot absent severity floors to medium", "dependabot_alert", "", "medium"},
		{"code_scanning unrecognized severity floors to medium", "code_scanning_alert", "banana", "medium"},
		{"secret_scanning absent severity floors to high", "secret_scanning_alert", "", "high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{
				"signal_class": "alert",
				"alert_number": 2,
				"alert_state":  "open",
				"repo":         "acme/widgets",
			}
			if tc.rawSev != "" {
				payload["severity"] = tc.rawSev
			}
			ev := asEvent(t, "e-floor-"+tc.evType, tc.evType, "github-actions", "acme", asBase, payload)
			findings := asFindings([]event.Event{ev})
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.Severity != tc.wantSev {
				t.Errorf("Severity = %q, want floor %q", f.Severity, tc.wantSev)
			}
			evd := asEvidence(t, f)
			if evd["severity_source"] != "policy-default" {
				t.Errorf("severity_source = %v, want policy-default (no derivable severity)", evd["severity_source"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. correlated: both rules fire, escalate, and carry concrete evidence.
// ---------------------------------------------------------------------------

// TestAlertSignal_Correlated_DependencyActivelyChanged proves rule 1:
// dependabot_alert + dependency_update on the SAME package/repo inside the
// window escalates to critical with the corroborating event id in evidence.
func TestAlertSignal_Correlated_DependencyActivelyChanged(t *testing.T) {
	alert := asEvent(t, "alert-1", "dependabot_alert", "github-actions", "acme", asBase, map[string]any{
		"signal_class": "alert",
		"alert_number": 42,
		"alert_state":  "open",
		"severity":     "medium",
		"repo":         "acme/widgets",
		"package":      "left-pad",
		"ecosystem":    "npm",
	})
	// Same package, SAME "repo" key (present on the dependency event's payload
	// too — proves the repo-field-match path, not just the org fallback), 2h
	// after the alert — inside the 72h window.
	depChange := asEvent(t, "dep-1", "dependency_update", "svc-renovate", "acme", asBase.Add(2*time.Hour), map[string]any{
		"package":     "left-pad",
		"ecosystem":   "npm",
		"old_version": "1.3.0",
		"new_version": "1.3.1",
		"repo":        "acme/widgets",
	})

	findings := asFindings([]event.Event{alert, depChange})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (dependency_update fires no alert-signal finding of its own): %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("Severity = %q, want critical (escalated)", f.Severity)
	}
	evd := asEvidence(t, f)
	if evd["escalated"] != true {
		t.Fatalf("escalated = %v, want true", evd["escalated"])
	}
	if evd["correlation_rule"] != "vulnerable-dependency-actively-changed" {
		t.Errorf("correlation_rule = %v, want vulnerable-dependency-actively-changed", evd["correlation_rule"])
	}
	ids, ok := evd["correlated_event_ids"].([]any)
	if !ok || len(ids) == 0 {
		t.Fatalf("correlated_event_ids missing or empty: %v (HARD RULE: every escalation must carry concrete evidence)", evd["correlated_event_ids"])
	}
	if ids[0] != "dep-1" {
		t.Errorf("correlated_event_ids = %v, want [dep-1]", ids)
	}
	if f.Reason == "" || !strings.Contains(f.Reason, "ESCALATED") {
		t.Errorf("Reason does not read as escalated: %q", f.Reason)
	}
}

// TestAlertSignal_Correlated_DependencyActivelyChanged_OrgFallback proves the
// SAME rule still fires when neither event carries an explicit "repo" key —
// dependency_add/update events currently never do (see depPayload) — by
// falling back to the shared Org.
func TestAlertSignal_Correlated_DependencyActivelyChanged_OrgFallback(t *testing.T) {
	alert := asEvent(t, "alert-org-1", "dependabot_alert", "github-actions", "acme", asBase, map[string]any{
		"alert_number": 43,
		"alert_state":  "open",
		"severity":     "high",
		"package":      "requests",
		"ecosystem":    "pypi",
		// deliberately NO "repo" key — forces the Org fallback.
	})
	depChange := asEvent(t, "dep-org-1", "dependency_add", "svc-renovate", "acme", asBase.Add(-3*time.Hour), map[string]any{
		"package":     "requests",
		"ecosystem":   "pypi",
		"new_version": "2.31.0",
		"direct":      true,
	})

	findings := asFindings([]event.Event{alert, depChange})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	evd := asEvidence(t, findings[0])
	if evd["escalated"] != true {
		t.Fatalf("escalated = %v, want true (org-scope match)", evd["escalated"])
	}
}

// TestAlertSignal_Correlated_LeakedSecretWithRecentActivity proves rule 2:
// secret_scanning_alert + push by the SAME actor inside the window escalates
// to critical with the corroborating event id in evidence.
func TestAlertSignal_Correlated_LeakedSecretWithRecentActivity(t *testing.T) {
	alert := asEvent(t, "alert-2", "secret_scanning_alert", "mallory", "acme", asBase, map[string]any{
		"alert_number": 9,
		"alert_state":  "open",
		"severity":     "critical",
		"repo":         "acme/widgets",
		"secret_type":  "aws_access_key_id",
	})
	push := asEvent(t, "push-1", "push", "mallory", "acme", asBase.Add(-1*time.Hour), map[string]any{
		"ref": "refs/heads/main",
	})

	findings := asFindings([]event.Event{alert, push})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	evd := asEvidence(t, f)
	if evd["correlation_rule"] != "leaked-secret-with-recent-activity" {
		t.Errorf("correlation_rule = %v, want leaked-secret-with-recent-activity", evd["correlation_rule"])
	}
	ids, ok := evd["correlated_event_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != "push-1" {
		t.Fatalf("correlated_event_ids = %v, want [push-1]", evd["correlated_event_ids"])
	}
}

// TestAlertSignal_Correlated_SecretAccessAlsoCorroborates proves rule 2 also
// recognizes secret_access (not just push) as corroborating raw activity, per
// the spec's "push/secret_access" alternation.
func TestAlertSignal_Correlated_SecretAccessAlsoCorroborates(t *testing.T) {
	alert := asEvent(t, "alert-3", "secret_scanning_alert", "mallory", "acme", asBase, map[string]any{
		"alert_number": 10,
		"alert_state":  "open",
		"secret_type":  "stripe_live_key",
	})
	access := asEvent(t, "sa-1", "secret_access", "mallory", "acme", asBase.Add(30*time.Minute), map[string]any{
		"target": "vault/prod/stripe",
	})

	findings := asFindings([]event.Event{alert, access})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	evd := asEvidence(t, findings[0])
	if evd["escalated"] != true {
		t.Fatalf("escalated = %v, want true", evd["escalated"])
	}
}

// ---------------------------------------------------------------------------
// 3. noisy: unrelated activity present — proves no false-fire escalation.
// ---------------------------------------------------------------------------

func TestAlertSignal_Noisy_NoFalseFire(t *testing.T) {
	alert := asEvent(t, "alert-noisy", "dependabot_alert", "github-actions", "acme", asBase, map[string]any{
		"alert_number": 5,
		"alert_state":  "open",
		"severity":     "high",
		"repo":         "acme/widgets",
		"package":      "left-pad",
		"ecosystem":    "npm",
	})
	secretAlert := asEvent(t, "alert-noisy-secret", "secret_scanning_alert", "carol", "acme", asBase, map[string]any{
		"alert_number": 6,
		"alert_state":  "open",
		"secret_type":  "github_pat",
		"repo":         "acme/widgets",
	})

	unrelated := []event.Event{
		// Different package entirely — must not match rule 1.
		asEvent(t, "noise-1", "dependency_update", "svc-renovate", "acme", asBase.Add(1*time.Hour), map[string]any{
			"package": "lodash", "ecosystem": "npm", "old_version": "4.17.0", "new_version": "4.17.1",
		}),
		// SAME package, but a DIFFERENT repo scope — scope mismatch, must not match.
		asEvent(t, "noise-2", "dependency_update", "svc-renovate", "other-org", asBase.Add(1*time.Hour), map[string]any{
			"package": "left-pad", "ecosystem": "npm", "old_version": "1.0.0", "new_version": "1.0.1", "repo": "other-org/other-repo",
		}),
		// SAME package, SAME repo, but WAY outside the 72h correlation window.
		asEvent(t, "noise-3", "dependency_update", "svc-renovate", "acme", asBase.Add(200*time.Hour), map[string]any{
			"package": "left-pad", "ecosystem": "npm", "old_version": "1.0.0", "new_version": "1.0.1", "repo": "acme/widgets",
		}),
		// Push by a DIFFERENT actor than the secret alert's — must not match rule 2.
		asEvent(t, "noise-4", "push", "dave", "acme", asBase.Add(1*time.Hour), map[string]any{"ref": "refs/heads/main"}),
		// Push by the RIGHT actor, but WAY outside the window.
		asEvent(t, "noise-5", "push", "carol", "acme", asBase.Add(200*time.Hour), map[string]any{"ref": "refs/heads/main"}),
		// Unrelated event type entirely.
		asEvent(t, "noise-6", "login", "carol", "acme", asBase.Add(1*time.Hour), map[string]any{"ip": "1.2.3.4"}),
	}

	findings := asFindings(append([]event.Event{alert, secretAlert}, unrelated...))
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per alert, neither escalated): %+v", len(findings), findings)
	}
	for _, f := range findings {
		evd := asEvidence(t, f)
		if evd["escalated"] != false {
			t.Errorf("finding %s: escalated = %v, want false — noisy unrelated activity must not force an escalation", f.ID, evd["escalated"])
		}
		if _, has := evd["correlation_rule"]; has {
			t.Errorf("finding %s: unexpected correlation_rule in evidence: %v", f.ID, evd["correlation_rule"])
		}
		if f.Severity == "critical" {
			t.Errorf("finding %s: Severity = critical but nothing corroborated it — this would be an evidence-free force-escalate, the HARD RULE this detector must never violate", f.ID)
		}
	}
}

// TestAlertSignal_CodeScanningAlert_NeverEscalates proves code_scanning_alert
// has no correlation rule defined (the spec names exactly two rules, for
// dependabot_alert and secret_scanning_alert) — even surrounded by activity
// that WOULD satisfy the other two rules' shape, it stays base-only.
func TestAlertSignal_CodeScanningAlert_NeverEscalates(t *testing.T) {
	alert := asEvent(t, "alert-cs", "code_scanning_alert", "carol", "acme", asBase, map[string]any{
		"alert_number": 11,
		"alert_state":  "open",
		"severity":     "high",
		"repo":         "acme/widgets",
		"rule":         "js/sql-injection",
		"package":      "left-pad", // even if it happened to carry a package field
	})
	surroundingActivity := []event.Event{
		asEvent(t, "cs-noise-1", "dependency_update", "svc-renovate", "acme", asBase.Add(1*time.Hour), map[string]any{
			"package": "left-pad", "ecosystem": "npm", "old_version": "1.0.0", "new_version": "1.0.1", "repo": "acme/widgets",
		}),
		asEvent(t, "cs-noise-2", "push", "carol", "acme", asBase.Add(1*time.Hour), map[string]any{"ref": "refs/heads/main"}),
	}
	findings := asFindings(append([]event.Event{alert}, surroundingActivity...))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	evd := asEvidence(t, findings[0])
	if evd["escalated"] != false {
		t.Errorf("code_scanning_alert escalated = %v, want false (no correlation rule defined for this type)", evd["escalated"])
	}
}

// ---------------------------------------------------------------------------
// 4. sparse-payload: the audit-feed classifier's shape — no crash, base
//    finding still surfaces, correlation degrades gracefully per-field.
// ---------------------------------------------------------------------------

// TestAlertSignal_SparsePayload_AuditFeedShape mirrors
// connect/github/normalize.go's synthPayload: action/target_user/collaborator/
// repo/org, no alert_number/alert_state/severity/package/ecosystem/secret_type/
// rule at all. Must not crash, and must still surface exactly one base finding
// at the type's severity floor.
func TestAlertSignal_SparsePayload_AuditFeedShape(t *testing.T) {
	ev := asEvent(t, "audit-1", "dependabot_alert", "unknown", "acme", asBase, map[string]any{
		"action":       "dependabot_alert.create",
		"target_user":  "",
		"collaborator": "",
		"repo":         "acme/widgets",
		"org":          "acme",
		"raw":          map[string]any{"@timestamp": "1735689600000"},
	})
	findings := asFindings([]event.Event{ev})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "medium" {
		t.Errorf("Severity = %q, want medium floor (no severity field in the sparse shape)", f.Severity)
	}
	evd := asEvidence(t, f)
	if evd["escalated"] != false {
		t.Errorf("escalated = %v, want false (no package field to correlate on, actor is unknown)", evd["escalated"])
	}
	if evd["severity_source"] != "policy-default" {
		t.Errorf("severity_source = %v, want policy-default", evd["severity_source"])
	}
}

// TestAlertSignal_SparsePayload_MalformedJSON_NeverCrashes proves totally
// broken JSON in the payload degrades to the same floor behavior instead of
// panicking Detect (which would quarantine the whole detector for the scan —
// see detect.go's runDetectorSafely).
func TestAlertSignal_SparsePayload_MalformedJSON_NeverCrashes(t *testing.T) {
	ev := event.Event{
		ID: "broken-1", Source: "github", Type: "secret_scanning_alert",
		Actor: "unknown", Org: "acme", Timestamp: asBase,
		Payload: json.RawMessage(`{not valid json`),
	}
	empty := event.Event{
		ID: "broken-2", Source: "github", Type: "code_scanning_alert",
		Actor: "unknown", Org: "acme", Timestamp: asBase,
		// Payload is nil (len == 0) — the other degenerate shape.
	}
	findings := asFindings([]event.Event{ev, empty})
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (both alerts still surface despite unusable payloads): %+v", len(findings), findings)
	}
}

// TestAlertSignal_SparsePayload_StillCorrelatesWhenActorKnown proves the
// degradation is PER-FIELD, not a blanket "sparse shape never correlates":
// rule 2 only needs the top-level Actor, which the sparse shape DOES carry
// when the underlying audit-log actor isn't the generic "unknown" bucket.
func TestAlertSignal_SparsePayload_StillCorrelatesWhenActorKnown(t *testing.T) {
	alert := asEvent(t, "audit-2", "secret_scanning_alert", "mallory", "acme", asBase, map[string]any{
		"action": "secret_scanning_alert.create",
		"repo":   "acme/widgets",
		"org":    "acme",
	})
	push := asEvent(t, "audit-push-1", "push", "mallory", "acme", asBase.Add(1*time.Hour), map[string]any{"ref": "refs/heads/main"})

	findings := asFindings([]event.Event{alert, push})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	evd := asEvidence(t, findings[0])
	if evd["escalated"] != true {
		t.Fatalf("escalated = %v, want true — the sparse shape still carries a usable actor", evd["escalated"])
	}
}

// ---------------------------------------------------------------------------
// 5. dedupe: same alert (id+state) across a re-scan-accumulated corpus
//    collapses to one finding; a REAL state transition does not.
// ---------------------------------------------------------------------------

func TestAlertSignal_Dedupe_SameAlertRepeatedInCorpus(t *testing.T) {
	// Two DISTINCT events (different ev.ID, as a fresh poll would mint) that
	// both describe the SAME underlying alert: same type, repo, alert_number,
	// alert_state.
	first := asEvent(t, "poll-1", "dependabot_alert", "github-actions", "acme", asBase, map[string]any{
		"alert_number": 77, "alert_state": "open", "severity": "high", "repo": "acme/widgets", "package": "left-pad",
	})
	second := asEvent(t, "poll-2", "dependabot_alert", "github-actions", "acme", asBase.Add(1*time.Hour), map[string]any{
		"alert_number": 77, "alert_state": "open", "severity": "high", "repo": "acme/widgets", "package": "left-pad",
	})

	findings := asFindings([]event.Event{first, second})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (re-scan of the same open alert must not multiply findings): %+v", len(findings), findings)
	}
}

func TestAlertSignal_Dedupe_StateTransitionIsNotCollapsed(t *testing.T) {
	open := asEvent(t, "poll-3", "dependabot_alert", "github-actions", "acme", asBase, map[string]any{
		"alert_number": 78, "alert_state": "open", "severity": "high", "repo": "acme/widgets", "package": "left-pad",
	})
	fixed := asEvent(t, "poll-4", "dependabot_alert", "github-actions", "acme", asBase.Add(24*time.Hour), map[string]any{
		"alert_number": 78, "alert_state": "fixed", "severity": "high", "repo": "acme/widgets", "package": "left-pad",
	})

	findings := asFindings([]event.Event{open, fixed})
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (a real state transition is a distinct lifecycle record, not a duplicate): %+v", len(findings), findings)
	}
}

func TestAlertSignal_Dedupe_SparseShape_SameAuditEntryTwice(t *testing.T) {
	// The sparse shape has no alert number/state, so dedup falls back to the
	// event's own ID: the SAME event ID appearing twice (a corpus store that
	// didn't de-dup at ingestion) must still collapse to one finding.
	ev := asEvent(t, "audit-dup-1", "secret_scanning_alert", "unknown", "acme", asBase, map[string]any{
		"action": "secret_scanning_alert.create", "repo": "acme/widgets", "org": "acme",
	})
	findings := asFindings([]event.Event{ev, ev})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
}
