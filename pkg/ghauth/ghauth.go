// Package ghauth mints GitHub App installation access tokens with a stdlib-only
// RS256 JWT. It is the auth sub-dependency of the portable GitHub connector
// (connect/github) and lives OUTSIDE core/ on purpose: the input seam
// (core/connect) is pure stdlib + pkg/event and carries no transport, while a
// real cloud connector that does HTTP lives outside core/ and adapts its output
// to []event.Event before crossing the seam (see core/connect/connect.go).
//
// Two-step App auth, structurally identical to the server-side ghapp.Client but
// with a local installation-token cache (the portable connector is constructed
// once and Pull may run repeatedly, so a fresh mint per call is wasteful):
//
//  1. Mint an App JWT (iss=appID, iat=now-60s, exp=now+10m, alg=RS256) signed
//     with the App private key.
//  2. POST {baseURL}/app/installations/{installationID}/access_tokens with the
//     JWT as a Bearer; decode the {token, expires_at, permissions} response.
//
// JWT is hand-rolled on crypto/rsa + crypto/sha256 + encoding/base64 +
// encoding/json — a GitHub App JWT is trivial (fixed header, three registered
// claims) and a stdlib path keeps the portable core's dependency surface
// minimal and unambiguously import-lint clean.
package ghauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// DefaultBaseURL is the public GitHub API host. Override via SetBaseURL for GHES
// or tests (GITHUB_API_URL at the connector layer).
const DefaultBaseURL = "https://api.github.com"

// tokenGrace is the early-refresh window: a cached installation token is
// considered expired once now >= ExpiresAt-tokenGrace, so we re-mint before a
// token actually lapses mid-request. Ports the Python is_token_expired 5-minute
// grace (github_auth.py).
const tokenGrace = 5 * time.Minute

// Client mints and caches GitHub App installation access tokens.
//
// The cache is guarded by a mutex: Pull is documented non-racing through the
// connector seam, but the mutex is free insurance and makes Token concurrency
// safe regardless.
type Client struct {
	appID          string
	installationID int64
	privateKey     *rsa.PrivateKey
	httpClient     *http.Client
	baseURL        string

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

// InstallationToken is GitHub's create-installation-token response.
type InstallationToken struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Permissions map[string]string `json:"permissions"`
}

// New builds a Client from the App ID, the PEM-encoded App private key, and the
// installation ID. The PEM is parsed eagerly so a bad key fails at construction,
// not on first Pull. GitHub's downloaded .pem is PKCS#1 ("RSA PRIVATE KEY"); a
// PKCS#8 ("PRIVATE KEY") re-encode is also accepted for robustness.
func New(appID string, pemKey []byte, installationID int64) (*Client, error) {
	key, err := parsePrivateKey(pemKey)
	if err != nil {
		return nil, err
	}
	return &Client{
		appID:          appID,
		installationID: installationID,
		privateKey:     key,
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		baseURL:        DefaultBaseURL,
	}, nil
}

// SetBaseURL overrides the GitHub API base URL (GHES host, or an httptest server
// in tests). Empty resets to the public default.
func (c *Client) SetBaseURL(url string) {
	if url == "" {
		url = DefaultBaseURL
	}
	c.baseURL = url
}

// SetHTTPClient overrides the HTTP client (tests). A nil client is ignored.
func (c *Client) SetHTTPClient(h *http.Client) {
	if h != nil {
		c.httpClient = h
	}
}

// parsePrivateKey decodes a PEM private key, trying PKCS#1 (GitHub's .pem) then
// PKCS#8 ("PRIVATE KEY" re-encode), type-asserting the PKCS#8 result to RSA.
func parsePrivateKey(pemKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, fmt.Errorf("ghauth: no PEM block found in private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ghauth: parse private key (tried PKCS#1 and PKCS#8): %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ghauth: PKCS#8 key is %T, not *rsa.PrivateKey", parsed)
	}
	return rsaKey, nil
}

// Token returns a valid installation token, reusing the cached one while it is
// within the grace window and otherwise re-minting (fresh JWT + exchange) and
// refreshing the cache.
func (c *Client) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != "" && time.Now().Before(c.expiresAt.Add(-tokenGrace)) {
		return c.cached, nil
	}
	it, err := c.exchange(ctx)
	if err != nil {
		return "", err
	}
	c.cached = it.Token
	c.expiresAt = it.ExpiresAt
	return c.cached, nil
}

// Invalidate drops the cached token so the next Token call re-mints. Called by
// the connector on a 401 from a data endpoint (the installation may have been
// revoked mid-life), so a single re-mint is attempted before failing.
func (c *Client) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cached = ""
	c.expiresAt = time.Time{}
}

// exchange mints the App JWT and POSTs it for an installation token. Caller holds
// the mutex.
func (c *Client) exchange(ctx context.Context) (*InstallationToken, error) {
	jwtStr, err := c.mintJWT(time.Now())
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, c.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ghauth: build token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ghauth: installation-token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		var errBody struct {
			Message string `json:"message"`
		}
		if derr := json.NewDecoder(resp.Body).Decode(&errBody); derr != nil {
			errBody.Message = fmt.Sprintf("<unparseable error body: %v>", derr)
		}
		return nil, fmt.Errorf("ghauth: GitHub returned %d creating installation token: %s",
			resp.StatusCode, errBody.Message)
	}
	var it InstallationToken
	if err := json.NewDecoder(resp.Body).Decode(&it); err != nil {
		return nil, fmt.Errorf("ghauth: decode installation token: %w", err)
	}
	if it.Token == "" {
		return nil, fmt.Errorf("ghauth: installation-token response carried an empty token")
	}
	return &it, nil
}

// mintJWT builds a signed GitHub App JWT for the given clock. Header is the fixed
// {"alg":"RS256","typ":"JWT"}; claims are iss=appID, iat=now-60s (clock-skew
// buffer), exp=now+10m. Signature is RSASSA-PKCS1-v1_5 over SHA-256 of the
// base64url(header).base64url(claims) signing input.
func (c *Client) mintJWT(now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iss": c.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("ghauth: marshal JWT header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("ghauth: marshal JWT claims: %w", err)
	}

	var b bytes.Buffer
	b.WriteString(base64.RawURLEncoding.EncodeToString(headerJSON))
	b.WriteByte('.')
	b.WriteString(base64.RawURLEncoding.EncodeToString(claimsJSON))
	signingInput := b.Bytes()

	digest := sha256.Sum256(signingInput)
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("ghauth: sign JWT: %w", err)
	}
	b.WriteByte('.')
	b.WriteString(base64.RawURLEncoding.EncodeToString(sig))
	return b.String(), nil
}
