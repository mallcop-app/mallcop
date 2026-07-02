package decl

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestRejectNonPublicIP is the dial-guard predicate table: every private /
// loopback / link-local / ULA / metadata form is refused; public unicast passes.
func TestRejectNonPublicIP(t *testing.T) {
	reject := []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", // cloud metadata
		"::1", "fc00::1", "fe80::1", "0.0.0.0", "224.0.0.1",
	}
	for _, s := range reject {
		if err := rejectNonPublicIP(net.ParseIP(s)); err == nil {
			t.Errorf("rejectNonPublicIP(%s) = nil, want rejection", s)
		}
	}
	allow := []string{"8.8.8.8", "1.1.1.1", "140.82.113.3", "2606:4700:4700::1111"}
	for _, s := range allow {
		if err := rejectNonPublicIP(net.ParseIP(s)); err != nil {
			t.Errorf("rejectNonPublicIP(%s) = %v, want nil", s, err)
		}
	}
}

// TestDialGuardRejectsPrivateDestination proves the REAL guarded transport
// rejects a connection to a private address at DIAL time (the Control callback
// fires post-resolution on the actual dial IP). This IS the DNS-rebinding
// defense: no matter how the destination IP was produced — a private IP literal,
// OR a HOSTNAME that RESOLVES to a private IP (the "localhost" case below goes
// through the real resolver, exactly the rebinding shape: a name resolves to a
// private address and Control catches it post-DNS) — Control inspects the
// address actually being dialed and refuses a non-public one; the connection
// never opens. A construction-time-only string/resolve check (connect/github's
// guard) would miss the rebinding case; this dialer does not.
func TestDialGuardRejectsPrivateDestination(t *testing.T) {
	client := &http.Client{Transport: guardedTransport(rejectNonPublicIP), Timeout: 3 * time.Second}
	targets := []string{
		"https://127.0.0.1:9/",
		"https://10.0.0.1:9/",
		"https://169.254.169.254/latest/meta-data/", // cloud metadata
		"https://localhost:9/",                      // NAME -> loopback, caught post-resolution
	}
	for _, target := range targets {
		_, err := client.Get(target)
		if err == nil {
			t.Errorf("GET %s succeeded through the guarded transport; the dial guard did not fire", target)
			continue
		}
		if !strings.Contains(err.Error(), "non-public") {
			t.Errorf("GET %s error = %v, want SSRF dial rejection", target, err)
		}
	}
}

// validSpecExcept returns a minimal spec that would construct, with baseURL
// overridden to the given value and no credential (auth none).
func validSpecExcept(baseURL string) *Spec {
	return &Spec{
		SourceID:   "acme",
		BaseURL:    baseURL,
		AuthScheme: AuthNone,
		Endpoints: []Endpoint{{
			Path:         "/x",
			Pagination:   PageNone,
			ResponsePath: "events",
			FieldMap:     FieldMap{ID: "id", Actor: "who", Action: "act"},
		}},
	}
}

// TestNewFromSpecConstructionRejections covers every construction-time SSRF /
// scheme rejection through the PRODUCTION guard (NewFromSpec).
func TestNewFromSpecConstructionRejections(t *testing.T) {
	cases := []struct {
		name, baseURL, wantSub string
	}{
		{"non-https", "http://8.8.8.8", "https"},
		{"loopback-literal", "https://127.0.0.1", "non-public"},
		{"rfc1918", "https://10.0.0.1", "non-public"},
		{"link-local-metadata", "https://169.254.169.254", "non-public"},
		{"localhost", "https://localhost", "non-public"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewFromSpec(validSpecExcept(tc.baseURL), nil)
			if err == nil {
				t.Fatalf("NewFromSpec(%s) = nil error, want rejection", tc.baseURL)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q missing %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestActionMapValidatedAgainstKnownEventTypes proves an ActionMap target that
// is not a KnownEventTypes member is a hard construction error naming it.
func TestActionMapValidatedAgainstKnownEventTypes(t *testing.T) {
	spec := validSpecExcept("https://8.8.8.8") // public IP literal: passes host check w/o DNS
	spec.Endpoints[0].ActionMap = map[string]string{"foo": "not_a_real_event_type"}
	_, err := NewFromSpec(spec, nil)
	if err == nil {
		t.Fatal("expected rejection for unknown ActionMap target, got nil")
	}
	for _, want := range []string{"not_a_real_event_type", "unknown event_type"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestCredentialByNameUnsetEnvRejected proves a credential-by-name whose env var
// is unset is a hard error — and the secret is never carried in the spec.
func TestCredentialByNameUnsetEnvRejected(t *testing.T) {
	spec := validSpecExcept("https://8.8.8.8")
	spec.AuthScheme = AuthBearer
	spec.CredentialRef = "DEFINITELY_UNSET_DECL_VAR"
	_, err := NewFromSpec(spec, nil)
	if err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("expected unset-env rejection, got: %v", err)
	}
}

// TestSpecRejectsInlineSecretField proves the strict decode refuses any field
// outside the Spec schema — so an inline secret (`token:`) cannot be smuggled in;
// the only credential surface is credential_ref (an env var name).
func TestSpecRejectsInlineSecretField(t *testing.T) {
	yaml := `
source_id: acme
base_url: https://api.acme.example
auth_scheme: bearer
credential_ref: ACME_TOKEN
token: ghp_thisisasecretpastedinline
endpoints:
  - path: /x
    pagination: none
`
	_, err := ParseSpec([]byte(yaml))
	if err == nil {
		t.Fatal("expected strict-decode rejection of an inline `token:` field, got nil")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error %q should name the offending field", err.Error())
	}
}

// TestNewFromSpecRejectsHostileEndpointPath proves the HOST PIN closes the
// endpoint-path takeover: an ep.Path that, string-concatenated onto the base the
// legacy way, would move the request authority off the allowlisted host (the
// "@evil.com" userinfo/host-swap that the public-IP dial guard would happily
// dial, leaking the auth header to the attacker) is a hard CONSTRUCTION error.
// Every syntactic authority-injection form is rejected up front.
func TestNewFromSpecRejectsHostileEndpointPath(t *testing.T) {
	cases := []struct{ name, path string }{
		{"userinfo-host-takeover", "@evil.com/x"},    // base+path => host=evil.com, base=>userinfo (credential exfil)
		{"protocol-relative", "//evil.com/x"},        // leading // => authority evil.com
		{"absolute-url", "https://evil.com/x"},       // a full off-host URL
		{"absolute-url-http", "http://evil.com/x"},   // scheme downgrade + off-host
		{"userinfo-then-host", "@169.254.169.254/x"}, // metadata endpoint via userinfo swap
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpecExcept("https://8.8.8.8") // public IP literal: base passes host check w/o DNS
			spec.Endpoints[0].Path = tc.path
			_, err := NewFromSpec(spec, nil)
			if err == nil {
				t.Fatalf("NewFromSpec accepted hostile endpoint path %q — the host pin did not fire", tc.path)
			}
			// The rejection must name the offending path and the authority concern.
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("error %q should name the offending path %q", err.Error(), tc.path)
			}
		})
	}
}

// TestEndpointURLStructurallyPinsHost is the request-time BACKSTOP behind the
// construction belt: even if a hostile path reached URL construction, endpointURL
// resolves it against the parsed base and takes ONLY the path+query, so the
// authority can NEVER leave the allowlisted host. Built directly (no network) so
// it exercises endpointURL past the construction guard that would otherwise
// reject these paths first.
func TestEndpointURLStructurallyPinsHost(t *testing.T) {
	base, err := url.Parse("https://api.acme.example")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	c := &Connector{base: base, apiHost: base.Host}
	for _, path := range []string{"/audit", "@evil.com/x", "//evil.com/x", "https://evil.com/x", "/audit?scope=all"} {
		got, err := c.endpointURL(path)
		if err != nil {
			t.Fatalf("endpointURL(%q) errored: %v", path, err)
		}
		u, perr := url.Parse(got)
		if perr != nil {
			t.Fatalf("endpointURL(%q) produced unparseable URL %q: %v", path, got, perr)
		}
		if u.Host != base.Host {
			t.Errorf("endpointURL(%q) = %q — host %q escaped the pinned host %q", path, got, u.Host, base.Host)
		}
		if u.User != nil {
			t.Errorf("endpointURL(%q) = %q — userinfo %q was introduced (credential-exfil vector)", path, got, u.User)
		}
	}
}

// TestFetchRefusesRedirect proves the guarded client refuses to FOLLOW any
// redirect. A 3xx to a public off-host target would otherwise leak the custom
// auth header (AuthScheme=header), since net/http strips only the standard
// sensitive headers cross-host. The server issues a 302 to a foreign host; Pull
// must fail with the redirect-refusal, and the leaked secret must never appear.
func TestFetchRefusesRedirect(t *testing.T) {
	t.Setenv("TEST_DECL_HDR", "sekret-header-value")

	var authHeaderSeen string
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	mux.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		authHeaderSeen = r.Header.Get("X-Api-Token")
		http.Redirect(w, r, "https://evil.example.com/steal", http.StatusFound)
	})

	spec := &Spec{
		SourceID:      "acme",
		BaseURL:       srv.URL,
		AuthScheme:    AuthHeader,
		HeaderName:    "X-Api-Token",
		CredentialRef: "TEST_DECL_HDR",
		Endpoints: []Endpoint{{
			Path:         "/audit",
			Pagination:   PageLinkHeader,
			ResponsePath: "events",
			FieldMap:     FieldMap{ID: "id", Actor: "who", Action: "act"},
		}},
	}
	c := permissiveConnector(t, spec, nil, srv)

	_, err := c.Pull(context.Background())
	if err == nil {
		t.Fatal("Pull followed a redirect; the guarded client did not refuse it")
	}
	if !strings.Contains(err.Error(), "refusing to follow redirect") {
		t.Fatalf("error %q is not the redirect refusal", err.Error())
	}
	// The redirect target's host must never appear as a dialed error, and the
	// secret must never leak into the surfaced error.
	if strings.Contains(err.Error(), "sekret-header-value") {
		t.Fatalf("the auth header value leaked into the error: %q", err.Error())
	}
	// The header WAS sent to the (trusted) origin on the first hop — that is
	// expected; what matters is the redirect to evil.example.com was NOT followed.
	if authHeaderSeen != "sekret-header-value" {
		t.Errorf("first-hop auth header = %q, want the credential (sanity check the header was applied)", authHeaderSeen)
	}
}

// TestPaginationRejectsHostileNextLink proves a rel=next pointing at a foreign
// host is refused (the string belt-check), even before the dial guard would see
// its IP.
func TestPaginationRejectsHostileNextLink(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ts := time.Now().UTC().Format(time.RFC3339)
	mux.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example.com/audit?page=2>; rel="next"`)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"events":[{"id":"a1","ts":%q,"who":"x","act":"sign_in"}]}`, ts)
	})

	spec := &Spec{
		SourceID:   "acme",
		BaseURL:    srv.URL,
		AuthScheme: AuthNone,
		Endpoints: []Endpoint{{
			Path:         "/audit",
			Pagination:   PageLinkHeader,
			ResponsePath: "events",
			FieldMap:     FieldMap{ID: "id", Timestamp: "ts", Actor: "who", Action: "act"},
			ActionMap:    map[string]string{"sign_in": "login"},
		}},
	}
	c := permissiveConnector(t, spec, nil, srv)

	_, err := c.Pull(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unexpected host") {
		t.Fatalf("expected hostile rel=next rejection, got: %v", err)
	}
}
