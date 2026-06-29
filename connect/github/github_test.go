package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// genTestKeyPEM returns a throwaway RSA private key PEM (PKCS#1, GitHub's .pem
// shape). The fixture server does not verify the JWT signature, so the key need
// not match any real App — App auth is exercised end-to-end (PEM parse -> sign ->
// POST -> decode) with a self-generated key and zero real GitHub App.
func genTestKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// loadFixture reads a testdata file and substitutes __TSn__ placeholders with
// fresh RFC3339 timestamps inside the lookback window so the connector's
// client-side filter keeps them.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	s := string(b)
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		ts := now.Add(time.Duration(-i) * time.Minute).Format(time.RFC3339)
		s = strings.ReplaceAll(s, fmt.Sprintf("__TS%d__", i), ts)
	}
	return []byte(s)
}

// tokenFixture is the canned 201 installation-token response.
func tokenFixture() string {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`{"token":"ghs_test","expires_at":%q,"permissions":{}}`, exp)
}

// newServer wires an httptest server. tokenHits counts installation-token POSTs;
// the events handler serves page1 with a Link: rel=next back to the server, then
// page2 with no Link, exercising pagination + the SSRF host allowlist.
func newServer(t *testing.T, tokenHits *int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)

	page1 := loadFixture(t, "events_page1.json")
	page2 := loadFixture(t, "events_page2.json")

	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(tokenHits, 1)
		if !strings.HasSuffix(r.URL.Path, "/access_tokens") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(tokenFixture()))
	})

	mux.HandleFunc("/orgs/acme-corp/events", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(page2)
			return
		}
		// page 1 -> point rel=next back at THIS server (allowlisted host).
		next := fmt.Sprintf("%s/orgs/acme-corp/events?per_page=100&page=2", srv.URL)
		w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", next))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(page1)
	})

	return srv
}

// appConnector builds an App-auth connector pointed at the test server. It
// swaps in the server's TLS client so the self-signed cert is trusted, and uses
// the server URL as the API base (so the SSRF allowlist host == the test host).
func appConnector(t *testing.T, srv *httptest.Server) *Connector {
	t.Helper()
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_APP_ID", "12345")
	t.Setenv("GITHUB_INSTALLATION_ID", "67890")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(genTestKeyPEM(t)))
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_AUDIT_LOG", "")

	c, err := NewFromEnv("acme-corp")
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	c.httpClient = srv.Client()
	c.app.SetHTTPClient(srv.Client())
	return c
}

// TestAppAuthAndPullAndNormalize is the end-to-end creds-free test: self-generated
// key -> JWT -> 201 token -> events pull -> normalization with detector-gate
// assertions, pagination, and token caching.
func TestAppAuthAndPullAndNormalize(t *testing.T) {
	var tokenHits int64
	srv := newServer(t, &tokenHits)
	defer srv.Close()
	c := appConnector(t, srv)

	evs, err := c.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	// (1) App auth: token minted exactly once (cached for the second page fetch).
	if got := atomic.LoadInt64(&tokenHits); got != 1 {
		t.Errorf("installation-token requests = %d, want 1 (cache must serve page-2 fetch)", got)
	}

	// (3) pagination: both pages consumed (3 + 3 entries).
	if len(evs) != 6 {
		t.Fatalf("got %d events, want 6 (both pages followed via rel=next allowlist)", len(evs))
	}

	byRawID := map[string]event.Event{}
	for _, ev := range evs {
		if ev.Source != sourceGitHub {
			t.Errorf("event %s Source=%q, want %q", ev.ID, ev.Source, sourceGitHub)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("event %s has zero timestamp", ev.ID)
		}
		if ev.Org == "" {
			t.Errorf("event %s has empty Org", ev.ID)
		}
		if len(ev.Payload) == 0 {
			t.Errorf("event %s has empty Payload", ev.ID)
		}
		byRawID[ev.ID] = ev
	}

	// (2) normalization: assert the EXACT detector-gate strings.
	want := map[string]string{ // makeEventID(rawGitHubID) -> normalized Type
		makeEventID("EVT-PUSH-1"):       "push",
		makeEventID("EVT-MEMBER-ADD-1"): "repo.add_collaborator",
		makeEventID("EVT-ORG-ADD-1"):    "org.add_member",
		makeEventID("EVT-MEMBER-RM-1"):  "collaborator_removed",
		makeEventID("EVT-PUBLIC-1"):     "repo_visibility_changed",
		makeEventID("EVT-UNKNOWN-1"):    "github_other",
	}
	for id, wantType := range want {
		ev, ok := byRawID[id]
		if !ok {
			t.Errorf("expected event id %s missing", id)
			continue
		}
		if ev.Type != wantType {
			t.Errorf("event %s Type=%q, want %q (detector gate)", id, ev.Type, wantType)
		}
	}

	// deterministic ID: makeEventID is stable across runs.
	if got := makeEventID("EVT-PUSH-1"); got != makeEventID("EVT-PUSH-1") {
		t.Fatalf("makeEventID not deterministic")
	}

	// (cache) second Token() within grace does NOT re-hit the server.
	if _, err := c.app.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got := atomic.LoadInt64(&tokenHits); got != 1 {
		t.Errorf("after cached Token(), token requests = %d, want 1", got)
	}

	// payload shape: the org.add_member event carries the synthesized target user
	// where new-external-access / priv-escalation read it.
	orgAdd := byRawID[makeEventID("EVT-ORG-ADD-1")]
	var sp map[string]any
	if err := json.Unmarshal(orgAdd.Payload, &sp); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if sp["target_user"] != "newhire" {
		t.Errorf("org.add_member payload target_user=%v, want newhire", sp["target_user"])
	}
}

// TestNormalizedTypesFireDetectors proves the normalized types are not just
// strings but actually trip the detector floor: the collaborator-add event must
// produce a new-external-access finding (the most security-relevant GitHub signal
// on a non-Enterprise org). This is the test-asserted invariant that an off-by-one
// type string silently disabling a detector cannot pass.
func TestNormalizedTypesFireDetectors(t *testing.T) {
	var tokenHits int64
	srv := newServer(t, &tokenHits)
	defer srv.Close()
	c := appConnector(t, srv)

	evs, err := c.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	findings := detect.Detect(evs, &baseline.Baseline{})
	var sawExternal bool
	for _, f := range findings {
		if f.Type == "new-external-access" {
			sawExternal = true
		}
	}
	if !sawExternal {
		t.Fatalf("no new-external-access finding from a collaborator-add event; "+
			"normalized types do not reach the detector gates (findings: %d)", len(findings))
	}
}

// TestAuditLog403FallsBackToEvents is the regression guard against the Python
// connector's unhandled-403: with GITHUB_AUDIT_LOG=1, a 403 on /audit-log must
// fall back to /events and still return events — no hard failure.
func TestAuditLog403FallsBackToEvents(t *testing.T) {
	var tokenHits int64
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	page1 := loadFixture(t, "events_page1.json")

	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&tokenHits, 1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(tokenFixture()))
	})
	mux.HandleFunc("/orgs/acme-corp/audit-log", func(w http.ResponseWriter, r *http.Request) {
		// 403 WITHOUT rate-limit headers => Enterprise-denied => fallback.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"audit log requires GitHub Enterprise"}`))
	})
	mux.HandleFunc("/orgs/acme-corp/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(page1)
	})

	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_APP_ID", "12345")
	t.Setenv("GITHUB_INSTALLATION_ID", "67890")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(genTestKeyPEM(t)))
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_AUDIT_LOG", "1")

	c, err := NewFromEnv("acme-corp")
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	c.httpClient = srv.Client()
	c.app.SetHTTPClient(srv.Client())

	evs, err := c.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull must fall back to events on audit-log 403, got error: %v", err)
	}
	if len(evs) == 0 {
		t.Fatalf("fallback returned 0 events; the 403->events fallback did not fire")
	}
}

// TestPATAuthPath exercises the GITHUB_TOKEN (BYO) path: no App key, bearer is the
// PAT, no token-mint round trip.
func TestPATAuthPath(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	page1 := loadFixture(t, "events_page1.json")

	var gotAuth string
	mux.HandleFunc("/orgs/acme-corp/events", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(page1)
	})

	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_APP_ID", "")
	t.Setenv("GITHUB_INSTALLATION_ID", "")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "")
	t.Setenv("GITHUB_TOKEN", "ghp_pat_token")
	t.Setenv("GITHUB_AUDIT_LOG", "")

	c, err := NewFromEnv("acme-corp")
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	c.httpClient = srv.Client()

	evs, err := c.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(evs) == 0 {
		t.Fatalf("PAT path returned 0 events")
	}
	if gotAuth != "Bearer ghp_pat_token" {
		t.Errorf("Authorization=%q, want Bearer ghp_pat_token", gotAuth)
	}
}

// TestSSRFGuardRejectsForeignHost asserts the pagination allowlist refuses a
// rel=next pointing at a different host.
func TestSSRFGuardRejectsForeignHost(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	page1 := loadFixture(t, "events_page1.json")

	mux.HandleFunc("/orgs/acme-corp/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example.com/orgs/acme-corp/events?page=2>; rel="next"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(page1)
	})

	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_APP_ID", "")
	t.Setenv("GITHUB_INSTALLATION_ID", "")
	t.Setenv("GITHUB_TOKEN", "ghp_pat")
	t.Setenv("GITHUB_AUDIT_LOG", "")

	c, err := NewFromEnv("acme-corp")
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	c.httpClient = srv.Client()

	_, err = c.Pull(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unexpected host") {
		t.Fatalf("expected SSRF host rejection, got: %v", err)
	}
}
