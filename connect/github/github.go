// Package github is the portable GitHub Connector: it pulls org activity from the
// GitHub API and normalizes it to []event.Event so the detector floor (core/detect)
// and the rest of the scan pipeline run unchanged.
//
// It lives OUTSIDE core/ on purpose. core/connect (the input seam) is pure stdlib
// + pkg/event and forbids transport/SDK dependencies via core/lint; a real cloud
// connector that does HTTP lives outside core/ and adapts its output to
// []event.Event before crossing the seam (see core/connect/connect.go:12-16). This
// package imports core/connect only for the Connector interface type and pkg/event
// for the Event struct, plus pkg/ghauth for GitHub App auth.
//
// API choice (this is the key correction over the Python reference, which called
// ONLY /orgs/{org}/audit-log and 403'd on non-Enterprise orgs with no fallback):
//
//   - PRIMARY: GET /orgs/{org}/events — the org events feed, available on free/
//     Team orgs. This is the default and works on a standard org.
//   - OPTIONAL: GET /orgs/{org}/audit-log (GITHUB_AUDIT_LOG=1) — richer
//     security-relevant actions, Enterprise-only. If it 403s, the connector logs
//     one warning and falls back to the events feed automatically.
package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/connect/overlay"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/ghauth"
)

// defaults bound a single Pull and frame the time window.
const (
	defaultBaseURL  = "https://api.github.com"
	defaultMaxPages = 10
	defaultLookback = 24 * time.Hour
	perPage         = 100
	sourceGitHub    = "github"
	defaultEventTy  = "github_other"
)

// Connector pulls and normalizes GitHub org activity. Construct with NewFromEnv.
type Connector struct {
	org        string
	baseURL    string
	httpClient *http.Client

	// auth path: exactly one of {app, token} is set.
	app   *ghauth.Client // App installation token (managed path)
	token string         // GITHUB_TOKEN PAT/OAuth (BYO-token path)

	auditLog bool          // GITHUB_AUDIT_LOG=1: try audit-log feed first
	lookback time.Duration // client-side time window
	maxPages int           // page cap per Pull

	// apiHost is the allowlisted host for pagination (SSRF guard): only rel=next
	// URLs to this exact host over https are followed.
	apiHost string

	// overlay is the optional learned-mapping overlay (github-first). When set,
	// an action/type that classifyEventType/classifyAuditAction leaves at the
	// default bucket ("github_other") is consulted against overlay["github"];
	// base-wins is enforced structurally by Overlay.Apply. nil => byte-identical
	// to the pre-overlay behavior.
	overlay *overlay.Overlay
}

// SetOverlay attaches a learned-mapping overlay (github-first). A nil overlay
// leaves classification byte-identical. Called by the scan wiring after
// NewFromEnv so the constructor signature stays credential-only.
func (c *Connector) SetOverlay(ov *overlay.Overlay) { c.overlay = ov }

// compile-time proof the connector satisfies the seam.
var _ connect.Connector = (*Connector)(nil)

// NewFromEnv builds a GitHub connector for org from environment credentials.
// Secrets never come from argv.
//
// Auth priority (App first, then PAT):
//  1. GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY (or GITHUB_APP_PRIVATE_KEY_FILE) +
//     GITHUB_INSTALLATION_ID — App installation token (managed path).
//  2. GITHUB_TOKEN — PAT/OAuth bearer (individual / BYO-token path).
//
// Other env: GITHUB_API_URL overrides the base (GHES/tests); GITHUB_LOOKBACK
// (Go duration, default 24h) sets the client-side window; GITHUB_AUDIT_LOG=1 opts
// into the Enterprise audit-log feed (auto-falls-back to events on 403);
// GITHUB_MAX_PAGES caps pages (default 10).
func NewFromEnv(org string) (*Connector, error) {
	if strings.TrimSpace(org) == "" {
		return nil, fmt.Errorf("github: org is required")
	}
	baseURL := defaultBaseURL
	if v := strings.TrimSpace(os.Getenv("GITHUB_API_URL")); v != "" {
		baseURL = strings.TrimRight(v, "/")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("github: invalid GITHUB_API_URL %q: %w", baseURL, err)
	}

	c := &Connector{
		org:        org,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		auditLog:   os.Getenv("GITHUB_AUDIT_LOG") == "1",
		lookback:   defaultLookback,
		maxPages:   defaultMaxPages,
		apiHost:    parsed.Host,
	}

	if v := strings.TrimSpace(os.Getenv("GITHUB_LOOKBACK")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("github: invalid GITHUB_LOOKBACK %q: %w", v, err)
		}
		c.lookback = d
	}
	if v := strings.TrimSpace(os.Getenv("GITHUB_MAX_PAGES")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("github: invalid GITHUB_MAX_PAGES %q (want positive int)", v)
		}
		c.maxPages = n
	}

	// Auth: App path first, then GITHUB_TOKEN.
	appID := strings.TrimSpace(os.Getenv("GITHUB_APP_ID"))
	instID := strings.TrimSpace(os.Getenv("GITHUB_INSTALLATION_ID"))
	if appID != "" && instID != "" {
		pemBytes, err := readAppKey()
		if err != nil {
			return nil, err
		}
		id, err := strconv.ParseInt(instID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("github: invalid GITHUB_INSTALLATION_ID %q: %w", instID, err)
		}
		ac, err := ghauth.New(appID, pemBytes, id)
		if err != nil {
			return nil, err
		}
		ac.SetBaseURL(baseURL)
		c.app = ac
		return c, nil
	}

	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		c.token = tok
		return c, nil
	}

	return nil, fmt.Errorf("github: no credentials — set GITHUB_APP_ID+GITHUB_INSTALLATION_ID+" +
		"GITHUB_APP_PRIVATE_KEY[_FILE] (App) or GITHUB_TOKEN (PAT)")
}

// readAppKey reads the App private key PEM from GITHUB_APP_PRIVATE_KEY (inline
// PEM) or GITHUB_APP_PRIVATE_KEY_FILE (path — friendlier in CI shells).
func readAppKey() ([]byte, error) {
	if pem := os.Getenv("GITHUB_APP_PRIVATE_KEY"); strings.TrimSpace(pem) != "" {
		return []byte(pem), nil
	}
	if path := strings.TrimSpace(os.Getenv("GITHUB_APP_PRIVATE_KEY_FILE")); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("github: read GITHUB_APP_PRIVATE_KEY_FILE %q: %w", path, err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("github: GITHUB_APP_ID set but no GITHUB_APP_PRIVATE_KEY[_FILE]")
}

// Pull fetches the most-recent pages from the chosen feed, normalizes each entry
// to an event.Event, and filters client-side to the lookback window. It returns a
// materialized batch (the detector floor is whole-corpus). ctx is honored between
// page fetches.
func (c *Connector) Pull(ctx context.Context) ([]event.Event, error) {
	cutoff := time.Now().Add(-c.lookback)

	if c.auditLog {
		evs, err := c.pullAuditLog(ctx, cutoff)
		if err == nil {
			return evs, nil
		}
		if isEnterpriseDenied(err) {
			log.Printf("github: audit-log requires GitHub Enterprise; falling back to /orgs/%s/events", c.org)
			// fall through to events feed
		} else {
			return nil, err
		}
	}

	return c.pullEvents(ctx, cutoff)
}

// pullEvents pulls and normalizes the /orgs/{org}/events feed (primary path).
func (c *Connector) pullEvents(ctx context.Context, cutoff time.Time) ([]event.Event, error) {
	start := fmt.Sprintf("%s/orgs/%s/events?per_page=%d", c.baseURL, url.PathEscape(c.org), perPage)
	var out []event.Event
	err := c.paginate(ctx, start, func(body []byte) error {
		var raws []json.RawMessage
		if err := json.Unmarshal(body, &raws); err != nil {
			return fmt.Errorf("github: decode events page: %w", err)
		}
		for _, raw := range raws {
			ev, ok := normalizeEvent(raw, c.org, c.overlay)
			if !ok {
				continue
			}
			if ev.Timestamp.Before(cutoff) {
				continue
			}
			out = append(out, ev)
		}
		return nil
	})
	return out, err
}

// pullAuditLog pulls and normalizes the /orgs/{org}/audit-log feed (Enterprise,
// opt-in). A 403 here is surfaced as an enterpriseDenied error so Pull can fall
// back to the events feed.
func (c *Connector) pullAuditLog(ctx context.Context, cutoff time.Time) ([]event.Event, error) {
	start := fmt.Sprintf("%s/orgs/%s/audit-log?per_page=%d", c.baseURL, url.PathEscape(c.org), perPage)
	var out []event.Event
	err := c.paginate(ctx, start, func(body []byte) error {
		var entries []json.RawMessage
		if err := json.Unmarshal(body, &entries); err != nil {
			return fmt.Errorf("github: decode audit-log page: %w", err)
		}
		for _, raw := range entries {
			ev, ok := normalizeAuditEntry(raw, c.org, c.overlay)
			if !ok {
				continue
			}
			if ev.Timestamp.Before(cutoff) {
				continue
			}
			out = append(out, ev)
		}
		return nil
	})
	return out, err
}

// linkNextRe extracts the rel="next" URL from a GitHub Link header.
var linkNextRe = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// paginate walks pages starting at startURL, calling onPage with each page body,
// following rel=next links (SSRF-guarded to the allowlisted host) up to maxPages.
// ctx is honored before each fetch.
func (c *Connector) paginate(ctx context.Context, startURL string, onPage func([]byte) error) error {
	next := startURL
	for page := 0; page < c.maxPages && next != ""; page++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("github: cancelled after %d pages: %w", page, err)
		}
		body, link, err := c.fetch(ctx, next)
		if err != nil {
			return err
		}
		if err := onPage(body); err != nil {
			return err
		}
		nextURL := parseNextLink(link)
		if nextURL == "" {
			return nil
		}
		if err := c.validateNextLink(nextURL); err != nil {
			// A bad next link is a hard stop, not a silent truncation of a tampered
			// pagination chain.
			return err
		}
		next = nextURL
	}
	return nil
}

// fetch performs one authenticated GET, returning the body and Link header. On a
// 401 it invalidates the App token cache and retries once (the installation may
// have been revoked mid-life). A 403 carrying rate-limit headers is a clear rate
// error (not the audit-log-fallback path); a 403 without them is an
// enterpriseDenied error (drives the audit-log -> events fallback).
func (c *Connector) fetch(ctx context.Context, rawURL string) ([]byte, string, error) {
	body, link, status, hdr, err := c.do(ctx, rawURL)
	if err != nil {
		return nil, "", err
	}
	if status == http.StatusUnauthorized && c.app != nil {
		c.app.Invalidate()
		body, link, status, hdr, err = c.do(ctx, rawURL)
		if err != nil {
			return nil, "", err
		}
	}
	switch {
	case status == http.StatusOK:
		return body, link, nil
	case status == http.StatusForbidden && isRateLimited(hdr):
		reset := hdr.Get("X-RateLimit-Reset")
		return nil, "", fmt.Errorf("github: rate limited (403); X-RateLimit-Reset=%s — back off, do not retry-storm", reset)
	case status == http.StatusForbidden:
		return nil, "", &enterpriseDenied{url: rawURL}
	default:
		return nil, "", fmt.Errorf("github: GET %s returned %d: %s", rawURL, status, truncate(body, 200))
	}
}

// do issues the GET with the correct Authorization header for the active auth
// path and returns body, Link header, status, response headers.
func (c *Connector) do(ctx context.Context, rawURL string) ([]byte, string, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("github: build request: %w", err)
	}
	bearer, err := c.bearer(ctx)
	if err != nil {
		return nil, "", 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("github: GET %s failed: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("github: read body: %w", err)
	}
	return body, resp.Header.Get("Link"), resp.StatusCode, resp.Header, nil
}

// bearer returns the token for the active auth path: a (cached) App installation
// token, or the PAT.
func (c *Connector) bearer(ctx context.Context) (string, error) {
	if c.app != nil {
		return c.app.Token(ctx)
	}
	return c.token, nil
}

// validateNextLink is the SSRF guard ported from _util.validate_next_link: only
// follow rel=next URLs whose scheme is https and host is exactly the configured
// API host.
func (c *Connector) validateNextLink(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("github: unparseable pagination URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("github: refusing non-https pagination URL %q", raw)
	}
	if u.Host != c.apiHost {
		return fmt.Errorf("github: refusing pagination URL to unexpected host %q (allowed: %q)", u.Host, c.apiHost)
	}
	return nil
}

// parseNextLink extracts the rel="next" URL from a Link header, or "" if absent.
func parseNextLink(link string) string {
	m := linkNextRe.FindStringSubmatch(link)
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// enterpriseDenied marks a 403 that means "this feed needs Enterprise" — the
// signal that drives the audit-log -> events fallback.
type enterpriseDenied struct{ url string }

func (e *enterpriseDenied) Error() string {
	return fmt.Sprintf("github: %s returned 403 (Enterprise-only feed)", e.url)
}

func isEnterpriseDenied(err error) bool {
	_, ok := err.(*enterpriseDenied)
	return ok
}

// isRateLimited reports whether a 403 carries the rate-limit signal
// (X-RateLimit-Remaining: 0). Such a 403 is a quota error, not an Enterprise
// gate.
func isRateLimited(h http.Header) bool {
	return h.Get("X-RateLimit-Remaining") == "0"
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// makeEventID ports _util.make_event_id: "evt_" + first 12 hex of SHA-256(rawID).
// Deterministic so re-pulls produce identical event IDs (and thus stable finding
// IDs downstream).
func makeEventID(rawID string) string {
	sum := sha256.Sum256([]byte(rawID))
	return "evt_" + hex.EncodeToString(sum[:])[:12]
}
