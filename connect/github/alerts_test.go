package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- fixture builders ---------------------------------------------------------
//
// map[string]any + json.Marshal (not fmt.Sprintf %q chains) so field values are
// never at risk of breaking JSON quoting, and timestamps are generated fresh
// (time.Now().Add(-ago)) so every fixture sits inside the connector's default
// GITHUB_LOOKBACK window without a placeholder-substitution pass.

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

// depAlertFixture builds one org-wide (or per-repo, via includeRepo=false)
// dependabot alert list item.
func depAlertFixture(t *testing.T, number int, state, fullName, severity, pkg, ecosystem string, ago time.Duration, includeRepo bool) map[string]any {
	t.Helper()
	ts := time.Now().Add(-ago).UTC().Format(time.RFC3339)
	m := map[string]any{
		"number":     number,
		"state":      state,
		"created_at": ts,
		"updated_at": ts,
		"html_url":   fmt.Sprintf("https://github.com/%s/security/dependabot/%d", fullName, number),
		"dependency": map[string]any{
			"package": map[string]any{"name": pkg, "ecosystem": ecosystem},
		},
		"security_vulnerability": map[string]any{"severity": severity},
	}
	if includeRepo {
		name := fullName
		if i := strings.LastIndex(fullName, "/"); i >= 0 {
			name = fullName[i+1:]
		}
		m["repository"] = map[string]any{"name": name, "full_name": fullName}
	}
	return m
}

func codeScanAlertFixture(t *testing.T, number int, state, fullName, ruleID, secSevLevel string, ago time.Duration, includeRepo bool) map[string]any {
	t.Helper()
	ts := time.Now().Add(-ago).UTC().Format(time.RFC3339)
	m := map[string]any{
		"number":     number,
		"state":      state,
		"created_at": ts,
		"updated_at": ts,
		"html_url":   fmt.Sprintf("https://github.com/%s/security/code-scanning/%d", fullName, number),
		"rule": map[string]any{
			"id":                      ruleID,
			"severity":                "warning",
			"security_severity_level": secSevLevel,
		},
	}
	if includeRepo {
		name := fullName
		if i := strings.LastIndex(fullName, "/"); i >= 0 {
			name = fullName[i+1:]
		}
		m["repository"] = map[string]any{"name": name, "full_name": fullName}
	}
	return m
}

// secretAlertFixture builds one secret-scanning alert list item INCLUDING the
// real API's "secret" field (the leaked value) — TestSecretScanningRedaction
// proves that value never survives normalization.
func secretAlertFixture(t *testing.T, number int, state, fullName, secretType, leaked string, ago time.Duration, includeRepo bool) map[string]any {
	t.Helper()
	ts := time.Now().Add(-ago).UTC().Format(time.RFC3339)
	m := map[string]any{
		"number":      number,
		"state":       state,
		"created_at":  ts,
		"updated_at":  ts,
		"html_url":    fmt.Sprintf("https://github.com/%s/security/secret-scanning/%d", fullName, number),
		"secret_type": secretType,
		"secret":      leaked,
	}
	if includeRepo {
		name := fullName
		if i := strings.LastIndex(fullName, "/"); i >= 0 {
			name = fullName[i+1:]
		}
		m["repository"] = map[string]any{"name": name, "full_name": fullName}
	}
	return m
}

func jsonArray(t *testing.T, items ...map[string]any) []byte {
	t.Helper()
	arr := make([]any, len(items))
	for i, it := range items {
		arr[i] = it
	}
	return mustJSON(t, arr)
}

// patConnector builds a PAT-auth connector pointed at srv. App-token minting is
// already proven end-to-end for the events feed by appConnector/TestAppAuthAnd
// PullAndNormalize in github_test.go; the alert-family tests use the simpler
// BYO-PAT path so each test's fixture wiring stays focused on the alert
// endpoints.
func patConnector(t *testing.T, srv *httptest.Server, org string) *Connector {
	t.Helper()
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_APP_ID", "")
	t.Setenv("GITHUB_INSTALLATION_ID", "")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "")
	t.Setenv("GITHUB_TOKEN", "ghp_pat")
	t.Setenv("GITHUB_AUDIT_LOG", "")
	c, err := NewFromEnv(org)
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	c.httpClient = srv.Client()
	return c
}

// decodePayload unmarshals an event.Event's flat payload into a generic map for
// field assertions.
func decodePayload(t *testing.T, payload json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("decode payload: %v (payload=%s)", err, payload)
	}
	return m
}

// --- org-wide happy path, all three families ----------------------------------

// TestAlertFamiliesOrgWide proves all three dedicated alert REST APIs are
// pulled org-wide and normalized with the shared alert contract: Type values
// dependabot_alert/code_scanning_alert/secret_scanning_alert, flat payload with
// signal_class="alert", alert_number, alert_state, severity, repo, html_url,
// plus the family-specific fields (package+ecosystem / rule / secret_type).
func TestAlertFamiliesOrgWide(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	mux.HandleFunc("/orgs/acme-corp/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t, depAlertFixture(t, 7, "open", "acme-corp/webapp", "high", "django", "pip", time.Minute, true)))
	})
	mux.HandleFunc("/orgs/acme-corp/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t, codeScanAlertFixture(t, 3, "open", "acme-corp/webapp", "js/sql-injection", "critical", 2*time.Minute, true)))
	})
	mux.HandleFunc("/orgs/acme-corp/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t, secretAlertFixture(t, 5, "open", "acme-corp/webapp", "github_personal_access_token", "ghp_LEAKEDLEAKEDLEAKEDLEAKEDLEAK", 3*time.Minute, true)))
	})

	c := patConnector(t, srv, "acme-corp")
	evs, err := c.pullAlerts(context.Background(), time.Now().Add(-c.lookback))
	if err != nil {
		t.Fatalf("pullAlerts: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d alert events, want 3 (one per family)", len(evs))
	}

	byType := map[string]map[string]any{}
	for _, ev := range evs {
		if ev.Source != sourceGitHub {
			t.Errorf("event %s Source=%q, want %q", ev.ID, ev.Source, sourceGitHub)
		}
		byType[ev.Type] = decodePayload(t, ev.Payload)
	}

	dep, ok := byType[typeDependabotAlert]
	if !ok {
		t.Fatal("no dependabot_alert event")
	}
	if dep["signal_class"] != "alert" {
		t.Errorf("dependabot signal_class=%v, want alert", dep["signal_class"])
	}
	if dep["alert_number"] != float64(7) {
		t.Errorf("dependabot alert_number=%v, want 7", dep["alert_number"])
	}
	if dep["alert_state"] != "open" {
		t.Errorf("dependabot alert_state=%v, want open", dep["alert_state"])
	}
	if dep["severity"] != "high" {
		t.Errorf("dependabot severity=%v, want high", dep["severity"])
	}
	if dep["repo"] != "acme-corp/webapp" {
		t.Errorf("dependabot repo=%v, want acme-corp/webapp", dep["repo"])
	}
	if dep["package"] != "django" || dep["ecosystem"] != "pip" {
		t.Errorf("dependabot package/ecosystem=%v/%v, want django/pip", dep["package"], dep["ecosystem"])
	}
	if dep["html_url"] == "" || dep["html_url"] == nil {
		t.Errorf("dependabot html_url empty")
	}

	cs, ok := byType[typeCodeScanningAlert]
	if !ok {
		t.Fatal("no code_scanning_alert event")
	}
	if cs["rule"] != "js/sql-injection" {
		t.Errorf("code-scanning rule=%v, want js/sql-injection", cs["rule"])
	}
	if cs["severity"] != "critical" {
		t.Errorf("code-scanning severity=%v, want critical (security_severity_level)", cs["severity"])
	}

	ss, ok := byType[typeSecretScanningAlert]
	if !ok {
		t.Fatal("no secret_scanning_alert event")
	}
	if ss["secret_type"] != "github_personal_access_token" {
		t.Errorf("secret-scanning secret_type=%v, want github_personal_access_token", ss["secret_type"])
	}
}

// TestSecretScanningRedaction is the CRITICAL redaction proof: the secret-
// scanning alert API response embeds the leaked secret value itself. This test
// asserts the literal secret string is ABSENT from the entire serialized event
// (not just a specific field) — a redaction that missed a copy elsewhere (e.g.
// the "raw" verbatim passthrough every other normalize* function uses) would
// fail here.
func TestSecretScanningRedaction(t *testing.T) {
	const leaked = "ghp_THISISATOTALLYREALLEAKEDTOKENVALUE1234"
	raw := mustJSON(t, secretAlertFixture(t, 9, "open", "acme-corp/webapp", "github_personal_access_token", leaked, time.Minute, true))

	ev, ok := normalizeSecretScanningAlert(raw, "acme-corp", "")
	if !ok {
		t.Fatal("normalizeSecretScanningAlert ok=false")
	}

	// (1) the leaked value must not appear anywhere in the stored payload,
	// including inside the verbatim "raw" sub-object.
	if strings.Contains(string(ev.Payload), leaked) {
		t.Fatalf("REDACTION FAILURE: leaked secret present in stored payload: %s", ev.Payload)
	}
	// (2) sanity: the full event, JSON-encoded as it would be for storage/export,
	// also never contains it (guards a future field that might re-embed raw).
	full, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if strings.Contains(string(full), leaked) {
		t.Fatalf("REDACTION FAILURE: leaked secret present in serialized event: %s", full)
	}

	// (3) the redaction must not silently drop the whole record — secret_type
	// and the other alert fields must still be present and correct.
	pl := decodePayload(t, ev.Payload)
	if pl["secret_type"] != "github_personal_access_token" {
		t.Errorf("secret_type=%v, want github_personal_access_token (redaction over-scrubbed)", pl["secret_type"])
	}
	if pl["alert_number"] != float64(9) {
		t.Errorf("alert_number=%v, want 9", pl["alert_number"])
	}
	if _, ok := pl["raw"]; !ok {
		t.Fatalf("payload has no raw field: %v", pl)
	}
	var rawObj map[string]any
	if err := json.Unmarshal(ev_PayloadRawField(t, ev.Payload), &rawObj); err != nil {
		t.Fatalf("decode raw sub-object: %v", err)
	}
	if rawObj["secret"] != "[REDACTED]" {
		t.Errorf("raw.secret=%v, want the [REDACTED] marker (present but scrubbed)", rawObj["secret"])
	}
	if rawObj["secret_type"] != "github_personal_access_token" {
		t.Errorf("raw.secret_type=%v, want preserved (only \"secret\" is redacted)", rawObj["secret_type"])
	}
}

// ev_PayloadRawField pulls the raw json.RawMessage bytes for the "raw" key out
// of a flat synthPayload JSON blob (json.RawMessage marshals as an embedded
// object, not a string, so a generic map[string]any decode already gives the
// sub-object — this helper re-extracts the raw bytes for a second, stricter
// unmarshal in the redaction test).
func ev_PayloadRawField(t *testing.T, payload json.RawMessage) json.RawMessage {
	t.Helper()
	var m struct {
		Raw json.RawMessage `json:"raw"`
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("decode payload for raw field: %v", err)
	}
	return m.Raw
}

// TestRedactSecretFieldFailsClosed proves redactSecretField degrades to
// dropping the WHOLE raw object (never a pass-through) when the input can't be
// parsed as a JSON object — the fail-safe direction for a redaction gate.
func TestRedactSecretFieldFailsClosed(t *testing.T) {
	out := redactSecretField(json.RawMessage(`not valid json`))
	if strings.Contains(string(out), "not valid json") {
		t.Fatalf("unparseable input was not dropped: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("fail-closed output must still be valid JSON: %v", err)
	}
}

// --- pagination -----------------------------------------------------------

// TestAlertsPaginationAndSSRFGuard proves the alert pulls reuse the SAME
// paginate/rel=next/host-allowlist machinery pullEvents uses: two dependabot
// alert pages are followed via a same-host rel=next link, and a rel=next
// pointing at a foreign host is refused.
func TestAlertsPaginationAndSSRFGuard(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	page1 := jsonArray(t, depAlertFixture(t, 1, "open", "acme-corp/webapp", "high", "django", "pip", time.Minute, true))
	page2 := jsonArray(t, depAlertFixture(t, 2, "open", "acme-corp/webapp", "critical", "requests", "pip", 2*time.Minute, true))

	mux.HandleFunc("/orgs/acme-corp/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(page2)
			return
		}
		next := fmt.Sprintf("%s/orgs/acme-corp/dependabot/alerts?per_page=100&page=2", srv.URL)
		w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", next))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(page1)
	})
	mux.HandleFunc("/orgs/acme-corp/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t))
	})
	mux.HandleFunc("/orgs/acme-corp/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t))
	})

	c := patConnector(t, srv, "acme-corp")
	evs, err := c.pullAlerts(context.Background(), time.Now().Add(-c.lookback))
	if err != nil {
		t.Fatalf("pullAlerts: %v", err)
	}
	var depCount int
	for _, ev := range evs {
		if ev.Type == typeDependabotAlert {
			depCount++
		}
	}
	if depCount != 2 {
		t.Fatalf("got %d dependabot_alert events, want 2 (both pages followed via rel=next)", depCount)
	}
}

// --- 403/404 org-wide -> per-repo fallback ------------------------------------

// TestAlertOrgWideDeniedFallsBackPerRepo proves a 403 on the org-wide endpoint
// (e.g. GHAS not licensed for org-wide alert visibility) falls back to listing
// the org's repos and pulling per-repo, and that the per-repo response (which
// omits the "repository" sub-object) gets its repo field filled from the
// request URL via repoHint.
func TestAlertOrgWideDeniedFallsBackPerRepo(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	mux.HandleFunc("/orgs/acme-corp/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		// 403 WITHOUT rate-limit headers => denied (plan/GHAS gating), not a rate error.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Dependabot alerts are not enabled for this organization"}`))
	})
	mux.HandleFunc("/orgs/acme-corp/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	})
	mux.HandleFunc("/orgs/acme-corp/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	})
	mux.HandleFunc("/orgs/acme-corp/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mustJSON(t, []map[string]any{
			{"name": "repo-a"},
			{"name": "repo-b"},
		}))
	})
	mux.HandleFunc("/repos/acme-corp/repo-a/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t, depAlertFixture(t, 11, "open", "acme-corp/repo-a", "medium", "lodash", "npm", time.Minute, false)))
	})
	mux.HandleFunc("/repos/acme-corp/repo-b/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t, depAlertFixture(t, 12, "open", "acme-corp/repo-b", "low", "axios", "npm", time.Minute, false)))
	})
	// code-scanning/secret-scanning genuinely unavailable per-repo too (404) —
	// exercises the "per-repo also denied -> skip that repo" path (not fatal).
	mux.HandleFunc("/repos/acme-corp/repo-a/code-scanning/alerts", http.NotFound)
	mux.HandleFunc("/repos/acme-corp/repo-b/code-scanning/alerts", http.NotFound)
	mux.HandleFunc("/repos/acme-corp/repo-a/secret-scanning/alerts", http.NotFound)
	mux.HandleFunc("/repos/acme-corp/repo-b/secret-scanning/alerts", http.NotFound)

	c := patConnector(t, srv, "acme-corp")
	evs, err := c.pullAlerts(context.Background(), time.Now().Add(-c.lookback))
	if err != nil {
		t.Fatalf("pullAlerts must degrade gracefully through the per-repo fallback, got error: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("got %d events, want 2 (one dependabot alert per repo via per-repo fallback)", len(evs))
	}
	byRepo := map[string]bool{}
	for _, ev := range evs {
		if ev.Type != typeDependabotAlert {
			t.Errorf("unexpected event type %q from per-repo fallback", ev.Type)
		}
		pl := decodePayload(t, ev.Payload)
		repo, _ := pl["repo"].(string)
		byRepo[repo] = true
	}
	if !byRepo["acme-corp/repo-a"] || !byRepo["acme-corp/repo-b"] {
		t.Fatalf("per-repo fallback did not fill repo from repoHint: got repos %v", byRepo)
	}
}

// TestAlertFamilyDeniedEverywhereDegradesGracefully proves the terminal
// degrade path: org-wide AND per-repo (via a denied repo listing) are both
// unavailable, so the family contributes zero events and Pull/pullAlerts
// returns NO error — mirroring the audit-log -> events fallback's contract that
// a denied feed is never a hard failure.
func TestAlertFamilyDeniedEverywhereDegradesGracefully(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	// Every alert endpoint AND the repo-listing endpoint used for fallback are
	// 404 — nothing to enumerate, nothing to fall back to.
	mux.HandleFunc("/orgs/acme-corp/", http.NotFound)

	c := patConnector(t, srv, "acme-corp")
	evs, err := c.pullAlerts(context.Background(), time.Now().Add(-c.lookback))
	if err != nil {
		t.Fatalf("pullAlerts must degrade to zero events, not error, got: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("got %d events, want 0", len(evs))
	}
}

// --- rate-limit backoff --------------------------------------------------

// TestAlertRateLimitPropagatesHardError proves a 403 carrying rate-limit
// headers is NOT treated as "feed unavailable, degrade" — it must surface as a
// hard error so the caller backs off instead of silently under-reporting
// alerts. Reuses the exact isRateLimited gate pullEvents/pullAuditLog rely on.
func TestAlertRateLimitPropagatesHardError(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	mux.HandleFunc("/orgs/acme-corp/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1700000000")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	})

	c := patConnector(t, srv, "acme-corp")
	_, err := c.pullAlerts(context.Background(), time.Now().Add(-c.lookback))
	if err == nil {
		t.Fatal("pullAlerts must return an error on a rate-limited 403, not degrade silently")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("error = %v, want a rate-limit error", err)
	}
}

// --- deterministic IDs / dedup ---------------------------------------------

// TestAlertDeterministicIDsAndStateDedup proves the store-dedup contract:
// re-normalizing the SAME alert (same family/repo/number/state) yields the
// IDENTICAL event ID (so a re-scan of an unchanged alert dedupes in the store),
// while a state transition (open -> fixed) yields a DIFFERENT ID (so the
// transition is recorded as a new occurrence, not silently swallowed).
func TestAlertDeterministicIDsAndStateDedup(t *testing.T) {
	open1 := mustJSON(t, depAlertFixture(t, 42, "open", "acme-corp/webapp", "high", "django", "pip", time.Minute, true))
	open2 := mustJSON(t, depAlertFixture(t, 42, "open", "acme-corp/webapp", "high", "django", "pip", time.Minute, true))
	fixed := mustJSON(t, depAlertFixture(t, 42, "fixed", "acme-corp/webapp", "high", "django", "pip", time.Minute, true))

	evA, ok := normalizeDependabotAlert(open1, "acme-corp", "")
	if !ok {
		t.Fatal("normalize open1 ok=false")
	}
	evB, ok := normalizeDependabotAlert(open2, "acme-corp", "")
	if !ok {
		t.Fatal("normalize open2 ok=false")
	}
	evFixed, ok := normalizeDependabotAlert(fixed, "acme-corp", "")
	if !ok {
		t.Fatal("normalize fixed ok=false")
	}

	if evA.ID != evB.ID {
		t.Errorf("same alert/state produced different IDs: %s vs %s (store would not dedup a re-scan)", evA.ID, evB.ID)
	}
	if evA.ID == evFixed.ID {
		t.Errorf("state transition (open->fixed) produced the SAME ID %s (transition would be silently swallowed)", evA.ID)
	}
}

// TestAlertHighWaterUsesUpdatedAt proves the lookback cutoff is applied against
// updated_at (not created_at): an alert created long ago but updated recently
// (a state transition) must still be pulled, and one whose last update fell
// outside the window must not.
func TestAlertHighWaterUsesUpdatedAt(t *testing.T) {
	stale := time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339)
	recent := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)

	inWindow := map[string]any{
		"number": 1, "state": "fixed",
		"created_at": stale, "updated_at": recent,
		"html_url":               "https://github.com/acme-corp/webapp/security/dependabot/1",
		"repository":             map[string]any{"name": "webapp", "full_name": "acme-corp/webapp"},
		"dependency":             map[string]any{"package": map[string]any{"name": "django", "ecosystem": "pip"}},
		"security_vulnerability": map[string]any{"severity": "high"},
	}
	outOfWindow := map[string]any{
		"number": 2, "state": "open",
		"created_at": stale, "updated_at": stale,
		"html_url":               "https://github.com/acme-corp/webapp/security/dependabot/2",
		"repository":             map[string]any{"name": "webapp", "full_name": "acme-corp/webapp"},
		"dependency":             map[string]any{"package": map[string]any{"name": "requests", "ecosystem": "pip"}},
		"security_vulnerability": map[string]any{"severity": "low"},
	}

	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	mux.HandleFunc("/orgs/acme-corp/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t, inWindow, outOfWindow))
	})
	mux.HandleFunc("/orgs/acme-corp/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jsonArray(t))
	})
	mux.HandleFunc("/orgs/acme-corp/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jsonArray(t))
	})

	c := patConnector(t, srv, "acme-corp")
	evs, err := c.pullAlerts(context.Background(), time.Now().Add(-c.lookback))
	if err != nil {
		t.Fatalf("pullAlerts: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 (only the recently-UPDATED alert)", len(evs))
	}
	pl := decodePayload(t, evs[0].Payload)
	if pl["alert_number"] != float64(1) {
		t.Errorf("kept alert_number=%v, want 1 (the one with updated_at inside the window)", pl["alert_number"])
	}
}

// --- full Pull() wiring ----------------------------------------------------

// TestPullMergesEventsAndAlerts is the end-to-end wiring proof: Connector.Pull
// (the ONLY method the core/connect.Connector seam calls) must return BOTH the
// activity-feed events AND the alert-family events in one batch — a regression
// guard against the alert pulls being wired in but never reaching the seam the
// scan pipeline actually calls.
func TestPullMergesEventsAndAlerts(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	mux.HandleFunc("/orgs/acme-corp/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(loadFixture(t, "events_page1.json"))
	})
	mux.HandleFunc("/orgs/acme-corp/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonArray(t, depAlertFixture(t, 21, "open", "acme-corp/webapp", "high", "django", "pip", time.Minute, true)))
	})
	mux.HandleFunc("/orgs/acme-corp/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jsonArray(t))
	})
	mux.HandleFunc("/orgs/acme-corp/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jsonArray(t))
	})

	c := patConnector(t, srv, "acme-corp")
	evs, err := c.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	var sawPush, sawDependabot bool
	for _, ev := range evs {
		switch ev.Type {
		case "push":
			sawPush = true
		case typeDependabotAlert:
			sawDependabot = true
			pl := decodePayload(t, ev.Payload)
			if pl["alert_number"] != float64(21) {
				t.Errorf("dependabot alert_number=%v, want 21", pl["alert_number"])
			}
		}
	}
	if !sawPush {
		t.Error("Pull() dropped the events-feed \"push\" event when alerts were merged in")
	}
	if !sawDependabot {
		t.Error("Pull() did not include the dependabot_alert event")
	}
}
