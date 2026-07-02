// Package decl is the DECLARATIVE connector engine — the primary moat-killer's
// runtime half. A declarative connector Spec (authored as DATA, see spec.go) is
// interpreted by this human-written engine to pull a new source and normalize it
// to []event.Event, so mallcop learns to "connect to anything" without anyone
// writing per-source transport code. The Spec is a runtime input (supplied at
// scan time via --connector-spec), not committed loop data: its safety boundary
// is the SSRF guard + ActionMap-vs-KnownEventTypes validation here, not the
// self-extension merge gate.
//
// It lives OUTSIDE core/ on purpose (like connect/github): a real connector does
// HTTP, so it may import net/http here and adapts its output to []event.Event
// before crossing the pure core/connect seam.
//
// SSRF DEFENSE (two layers, the dialer is the real one):
//   - construction: BaseURL must be https and its host must resolve to a PUBLIC
//     unicast address (loopback / RFC1918 / link-local / 169.254.169.254 / ULA /
//     localhost rejected, plus the IANA special-purpose ranges in nonPublicCIDRs:
//     CGNAT 100.64/10, benchmarking, TEST-NET, reserved, and the NAT64 prefix);
//   - EVERY connection: a net.Dialer.Control callback inspects the ALREADY-
//     RESOLVED dial IP and rejects any non-public destination. Control runs
//     post-DNS on the real IP, so it closes the DNS-rebinding TOCTOU that a
//     construction-time-only string/resolve check leaves open (connect/github's
//     string-only guard has that hole; this engine does not).
package decl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mallcop-app/mallcop/connect/overlay"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/event"
)

const (
	defaultMaxPages     = 20
	bodyReadCap         = 16 << 20 // per-page response body read cap
	defaultTimestampFmt = time.RFC3339
	dialTimeout         = 10 * time.Second
	clientTimeout       = 30 * time.Second
)

// envVarNameRe validates a CredentialRef: a POSIX-ish env var NAME (never a
// secret value). A pasted secret will not match and/or will not resolve.
var envVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// sourceIDRe keeps SourceID a simple token so "<sourceID>_other" is a sane,
// collision-free default event type.
var sourceIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// linkNextRe extracts the rel="next" URL from a Link header (same shape as
// connect/github).
var linkNextRe = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// Connector pulls and normalizes a source described by a Spec. Construct with
// NewFromSpec. It satisfies core/connect.Connector.
type Connector struct {
	spec       *Spec
	base       *url.URL // parsed, validated base URL; request URLs are built from THIS, never string-concatenated
	apiHost    string   // allowlisted host for the pagination + endpoint-URL belt-check
	authValue  string   // resolved Authorization value (or header value); "" for none
	httpClient *http.Client
	overlay    *overlay.Overlay
	maxPages   int
}

var _ connect.Connector = (*Connector)(nil)

// ipGuardFunc rejects a resolved dial IP (non-public => error). It is a field so
// tests can point the engine at an httptest server on loopback while production
// (NewFromSpec) always uses rejectNonPublicIP.
type ipGuardFunc func(net.IP) error

// NewFromSpec validates spec and builds a production connector whose transport
// refuses to dial any non-public address. ov may be nil (no learned-mapping
// overlay). All construction failures are hard errors (fail-loud).
func NewFromSpec(spec *Spec, ov *overlay.Overlay) (*Connector, error) {
	return newFromSpec(spec, ov, rejectNonPublicIP)
}

// newFromSpec is the injectable core: ipGuard is rejectNonPublicIP in
// production. Tests pass a permissive guard to reach an httptest server.
func newFromSpec(spec *Spec, ov *overlay.Overlay, ipGuard ipGuardFunc) (*Connector, error) {
	if spec == nil {
		return nil, fmt.Errorf("decl: nil spec")
	}
	if !sourceIDRe.MatchString(spec.SourceID) {
		return nil, fmt.Errorf("decl: source_id %q must be a non-empty [A-Za-z0-9_.-] token", spec.SourceID)
	}

	// BaseURL: https-only + host resolves to a PUBLIC unicast address.
	u, err := url.Parse(strings.TrimSpace(spec.BaseURL))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("decl: invalid base_url %q: %v", spec.BaseURL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("decl: base_url must be https, got scheme %q in %q", u.Scheme, spec.BaseURL)
	}
	if err := checkPublicHost(u.Hostname(), ipGuard); err != nil {
		return nil, fmt.Errorf("decl: base_url host %q: %w", u.Hostname(), err)
	}

	// Auth: resolve the credential by ENV VAR NAME (never inline).
	authValue, err := resolveAuth(spec)
	if err != nil {
		return nil, err
	}

	// Endpoints.
	if len(spec.Endpoints) == 0 {
		return nil, fmt.Errorf("decl: spec has no endpoints")
	}
	for i, ep := range spec.Endpoints {
		if strings.TrimSpace(ep.Path) == "" {
			return nil, fmt.Errorf("decl: endpoint[%d] has empty path", i)
		}
		// HOST PIN (construction belt): an endpoint path must be host-relative and
		// cannot introduce an authority. This closes the "@attacker/x" host-takeover
		// + credential-exfil (base+"@evil.com" reparses with host=evil.com, which the
		// public-IP dial guard would happily dial). The request-time endpointURL is
		// the structural backstop; this fails such a spec LOUD at construction.
		if err := validateEndpointPath(u, ep.Path); err != nil {
			return nil, fmt.Errorf("decl: endpoint[%d]: %w", i, err)
		}
		switch ep.Pagination {
		case PageNone, PageLinkHeader:
		case PagePageParam:
			if ep.PageParam == "" {
				return nil, fmt.Errorf("decl: endpoint[%d] pagination page_param requires page_param", i)
			}
		case PageCursor:
			if ep.CursorPath == "" || ep.CursorParam == "" {
				return nil, fmt.Errorf("decl: endpoint[%d] pagination cursor requires cursor_path and cursor_param", i)
			}
		default:
			return nil, fmt.Errorf("decl: endpoint[%d] unknown pagination %q", i, ep.Pagination)
		}
		for rawAction, target := range ep.ActionMap {
			if !detect.IsKnownEventType(target) {
				return nil, fmt.Errorf(
					"decl: endpoint[%d] action %q maps to unknown event_type %q (not in detect.KnownEventTypes)",
					i, rawAction, target)
			}
		}
	}

	return &Connector{
		spec:      spec,
		base:      u,
		apiHost:   u.Host,
		authValue: authValue,
		httpClient: &http.Client{
			Timeout:   clientTimeout,
			Transport: guardedTransport(ipGuard),
			// Refuse to follow ANY redirect: a declarative connector paginates via
			// Link/cursor, never 3xx, and net/http does NOT strip a custom auth
			// header (AuthScheme=header) on a cross-host redirect — only
			// Authorization/WWW-Authenticate/Cookie — so following a 3xx to a public
			// off-host target would leak the credential. Stop at the redirect.
			CheckRedirect: refuseRedirect,
		},
		overlay:  ov,
		maxPages: defaultMaxPages,
	}, nil
}

// resolveAuth validates the auth scheme and resolves the credential from the
// named env var, returning the header VALUE to send (or "" for scheme none).
func resolveAuth(spec *Spec) (string, error) {
	switch spec.AuthScheme {
	case AuthNone:
		return "", nil
	case AuthBearer, AuthHeader, AuthBasic:
		if spec.AuthScheme == AuthHeader && strings.TrimSpace(spec.HeaderName) == "" {
			return "", fmt.Errorf("decl: auth_scheme header requires header_name")
		}
		if !envVarNameRe.MatchString(spec.CredentialRef) {
			return "", fmt.Errorf("decl: credential_ref %q is not a valid env var NAME (a spec must reference a credential by env var name, never carry a secret value)", spec.CredentialRef)
		}
		val := os.Getenv(spec.CredentialRef)
		if val == "" {
			return "", fmt.Errorf("decl: credential env var %q is not set", spec.CredentialRef)
		}
		switch spec.AuthScheme {
		case AuthBearer:
			return "Bearer " + val, nil
		case AuthBasic:
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(val)), nil
		default: // header
			return val, nil
		}
	default:
		return "", fmt.Errorf("decl: unknown auth_scheme %q (want bearer|header|basic|none)", spec.AuthScheme)
	}
}

// applyAuth sets the auth header on a request per the spec scheme.
func (c *Connector) applyAuth(req *http.Request) {
	if c.authValue == "" {
		return
	}
	if c.spec.AuthScheme == AuthHeader {
		req.Header.Set(c.spec.HeaderName, c.authValue)
		return
	}
	req.Header.Set("Authorization", c.authValue)
}

// Pull fetches every endpoint, paginates per its strategy, extracts the event
// array at ResponsePath, and normalizes each item to event.Event. It returns a
// materialized batch (the detector floor is whole-corpus). ctx is honored
// between page fetches.
func (c *Connector) Pull(ctx context.Context) ([]event.Event, error) {
	var out []event.Event
	for i := range c.spec.Endpoints {
		evs, err := c.pullEndpoint(ctx, &c.spec.Endpoints[i])
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	return out, nil
}

// pullEndpoint pulls and paginates one endpoint.
func (c *Connector) pullEndpoint(ctx context.Context, ep *Endpoint) ([]event.Event, error) {
	var out []event.Event

	first, err := c.endpointURL(ep.Path)
	if err != nil {
		return nil, err
	}

	switch ep.Pagination {
	case PageNone:
		body, _, err := c.fetch(ctx, first)
		if err != nil {
			return nil, err
		}
		evs, err := c.normalizePage(ep, body)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)

	case PageLinkHeader:
		next := first
		for page := 0; page < c.maxPages && next != ""; page++ {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("decl: cancelled after %d pages: %w", page, err)
			}
			body, link, err := c.fetch(ctx, next)
			if err != nil {
				return nil, err
			}
			evs, err := c.normalizePage(ep, body)
			if err != nil {
				return nil, err
			}
			out = append(out, evs...)
			nextURL := parseNextLink(link)
			if nextURL == "" {
				break
			}
			if err := c.validateNextLink(nextURL); err != nil {
				return nil, err
			}
			next = nextURL
		}

	case PagePageParam:
		for page := 1; page <= c.maxPages; page++ {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("decl: cancelled after %d pages: %w", page-1, err)
			}
			pageURL, err := withQuery(first, ep.PageParam, strconv.Itoa(page))
			if err != nil {
				return nil, err
			}
			body, _, err := c.fetch(ctx, pageURL)
			if err != nil {
				return nil, err
			}
			evs, err := c.normalizePage(ep, body)
			if err != nil {
				return nil, err
			}
			if len(evs) == 0 {
				break
			}
			out = append(out, evs...)
		}

	case PageCursor:
		cursor := ""
		for page := 0; page < c.maxPages; page++ {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("decl: cancelled after %d pages: %w", page, err)
			}
			pageURL := first
			if cursor != "" {
				var err error
				pageURL, err = withQuery(pageURL, ep.CursorParam, cursor)
				if err != nil {
					return nil, err
				}
			}
			body, _, err := c.fetch(ctx, pageURL)
			if err != nil {
				return nil, err
			}
			evs, err := c.normalizePage(ep, body)
			if err != nil {
				return nil, err
			}
			out = append(out, evs...)
			var root any
			if err := json.Unmarshal(body, &root); err != nil {
				return nil, fmt.Errorf("decl: decode cursor page: %w", err)
			}
			cursor = pathString(root, ep.CursorPath)
			if cursor == "" {
				break
			}
		}
	}

	return out, nil
}

// normalizePage decodes a page body, extracts the event array at ResponsePath,
// and builds an event.Event per item.
func (c *Connector) normalizePage(ep *Endpoint, body []byte) ([]event.Event, error) {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("decl: decode page for %s: %w", ep.Path, err)
	}
	items, ok := pathSlice(root, ep.ResponsePath)
	if !ok {
		// A page whose array path is absent is an empty page (e.g. a cursor tail),
		// not an error: the source simply returned no events here.
		return nil, nil
	}
	out := make([]event.Event, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, c.buildEvent(ep, obj))
	}
	return out, nil
}

// buildEvent maps one decoded item to an event.Event. The synthesized payload
// mirrors connect/github/normalize.go: the mapped action/org at the top level
// (where the typed detectors read them) plus the verbatim item under "raw" so
// the scan-all detectors (injection-probe, secrets-exposure) inspect the source
// content, not a lossy projection.
func (c *Connector) buildEvent(ep *Endpoint, item map[string]any) event.Event {
	fm := ep.FieldMap
	action := pathString(item, fm.Action)
	org := pathString(item, fm.Org)
	actor := pathString(item, fm.Actor)
	if actor == "" {
		actor = "unknown"
	}

	// Classify: ActionMap wins; else the overlay may fill the default bucket;
	// else the "<sourceID>_other" fallback. base-wins is enforced in Apply.
	//
	// EMISSION SOUNDNESS (invariant 10): the mapped target is emitted in the SAME
	// canonical form IsKnownEventType validated it against (detect.CanonicalEventType
	// = lower+trim). Without this, a validated-but-non-canonical target like "PUSH"
	// or " login " would pass construction validation yet be emitted verbatim and
	// silently never match a case-sensitive typed gate (git_oops `ev.Type=="push"`,
	// unusual_login `ev.Type=="login"`) — a dead mapping. The default bucket is left
	// as-is (no detector gates on it, so its casing is immaterial).
	base := c.spec.SourceID + "_other"
	if t, ok := ep.ActionMap[action]; ok {
		base = detect.CanonicalEventType(t)
	}
	typ := c.overlay.Apply(c.spec.SourceID, action, base)

	ts := parseTimestamp(pathString(item, fm.Timestamp), fm.TimestampFormat)

	idSrc := pathString(item, fm.ID)
	if idSrc == "" {
		idSrc = c.spec.SourceID + "|" + action + "|" + actor + "|" + ts.Format(time.RFC3339Nano)
	}

	payload := map[string]any{"raw": item}
	if action != "" {
		payload["action"] = action
	}
	if org != "" {
		payload["org"] = org
	}
	payloadBytes, _ := json.Marshal(payload)

	return event.Event{
		ID:        makeEventID(idSrc),
		Source:    c.spec.SourceID,
		Type:      typ,
		Actor:     actor,
		Timestamp: ts,
		Org:       org,
		Payload:   payloadBytes,
	}
}

// fetch performs one authenticated GET, returning the body and Link header.
func (c *Connector) fetch(ctx context.Context, rawURL string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("decl: build request: %w", err)
	}
	c.applyAuth(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("decl: GET %s failed: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, bodyReadCap))
	if err != nil {
		return nil, "", fmt.Errorf("decl: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("decl: GET %s returned %d: %s", rawURL, resp.StatusCode, truncate(body, 200))
	}
	return body, resp.Header.Get("Link"), nil
}

// validateNextLink is the pagination host belt-check (mirrors connect/github):
// a rel=next URL must be https and point at the same host. The dialer's IP guard
// is the real defense; this catches an obvious off-host redirect early.
func (c *Connector) validateNextLink(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("decl: unparseable pagination URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("decl: refusing non-https pagination URL %q", raw)
	}
	if u.Host != c.apiHost {
		return fmt.Errorf("decl: refusing pagination URL to unexpected host %q (allowed: %q)", u.Host, c.apiHost)
	}
	return nil
}

// endpointURL builds the absolute request URL for an endpoint path by RESOLVING
// it against the parsed base — taking ONLY the path and query and discarding any
// authority/scheme the path might carry — then running the same host+scheme belt-
// check as a rel=next link. This is the STRUCTURAL host pin: the endpoint path is
// only ever assigned to url.Path, never string-concatenated into the authority,
// so it cannot move the request off c.apiHost regardless of what it contains
// ("@evil.com", "//evil.com", "https://evil.com" all resolve back onto the base
// host). The construction-time validateEndpointPath belt rejects such paths loud
// up front; this is the request-time backstop.
func (c *Connector) endpointURL(epPath string) (string, error) {
	rel, err := url.Parse(epPath)
	if err != nil {
		return "", fmt.Errorf("decl: unparseable endpoint path %q: %w", epPath, err)
	}
	ref := &url.URL{Path: rel.Path, RawQuery: rel.RawQuery}
	final := c.base.ResolveReference(ref).String()
	if err := c.validateNextLink(final); err != nil {
		return "", err
	}
	return final, nil
}

// validateEndpointPath rejects, at construction, any endpoint path that would
// alter the request authority. Two independent checks:
//
//  1. Parsed STANDALONE, the path may not itself carry a scheme, host, userinfo,
//     or a leading "//" (a protocol-relative "//host" reference).
//  2. CONCATENATED onto the base the legacy way (base+path), the resulting URL's
//     authority must be UNCHANGED — this is what closes the "@evil.com" takeover:
//     "https://api.example"+"@evil.com/x" reparses with host=evil.com and the
//     base moved into userinfo, so the credentialed request would go to (and leak
//     its auth header at) evil.com, which the public-IP dial guard would allow.
func validateEndpointPath(base *url.URL, epPath string) error {
	rel, err := url.Parse(epPath)
	if err != nil {
		return fmt.Errorf("unparseable path %q: %w", epPath, err)
	}
	if rel.IsAbs() || rel.Scheme != "" || rel.Host != "" || rel.User != nil || strings.HasPrefix(epPath, "//") {
		return fmt.Errorf("path %q must be host-relative — it may not carry a scheme, host, userinfo, or a leading '//'", epPath)
	}
	combined, err := url.Parse(base.String() + epPath)
	if err != nil {
		return fmt.Errorf("path %q makes an unparseable URL: %w", epPath, err)
	}
	if combined.Scheme != base.Scheme || combined.Host != base.Host || combined.User != nil {
		return fmt.Errorf("path %q alters the request authority (would target host %q) — a path may not introduce a host, scheme, or userinfo", epPath, combined.Host)
	}
	return nil
}

// refuseRedirect is the http.Client.CheckRedirect for the guarded client: it
// refuses to follow ANY redirect. A declarative connector paginates via
// Link/cursor, never 3xx. Crucially, net/http strips only the STANDARD sensitive
// headers (Authorization / WWW-Authenticate / Cookie) on a cross-host redirect —
// NOT a custom header — so following a 3xx to a public off-host target would leak
// a custom-header credential (AuthScheme=header). Stopping at the redirect
// response (returned to fetch as a non-2xx, then a hard error) closes that leak.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("decl: refusing to follow redirect to %q — declarative connectors paginate via Link/cursor, not 3xx; a redirect could leak the auth header off-host", req.URL.Redacted())
}

// ---- SSRF primitives --------------------------------------------------------

// guardedTransport builds an http.Transport whose dialer rejects any resolved
// dial address that ipGuard refuses. The Control callback runs AFTER DNS
// resolution on the real dial IP, closing the rebinding window.
func guardedTransport(ipGuard ipGuardFunc) *http.Transport {
	d := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("decl: bad dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("decl: dial address %q is not an IP", host)
			}
			return ipGuard(ip)
		},
	}
	return &http.Transport{
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// nonPublicCIDRs are IANA special-purpose ranges that Go's net stdlib predicates
// (IsPrivate / IsLoopback / IsLinkLocal* / IsMulticast / IsUnspecified) do NOT
// cover but which are never a valid PUBLIC unicast destination for a declarative
// connector. Blocking them explicitly closes SSRF avenues that ride these ranges:
//   - 100.64.0.0/10   RFC6598 shared address space (CGNAT) — commonly the
//     Kubernetes/cloud pod- and service-network CIDR, so a rebind or misconfigured
//     base_url must NOT be able to reach cluster-internal services;
//   - 198.18.0.0/15   RFC2544 benchmarking;
//   - 192.0.2.0/24    RFC5737 TEST-NET-1;
//   - 198.51.100.0/24 RFC5737 TEST-NET-2;
//   - 203.0.113.0/24  RFC5737 TEST-NET-3;
//   - 192.0.0.0/24    RFC6890 IETF protocol assignments;
//   - 240.0.0.0/4     RFC1112 reserved (former class E);
//   - 64:ff9b::/96    RFC6052 NAT64 well-known prefix (an embedded IPv4 that a
//     NAT64 gateway would translate back to a v4 destination we must also block).
//
// ip.IsPrivate() does not report true for any of these, so we test membership
// explicitly (net.ParseCIDR + IPNet.Contains).
var nonPublicCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",
		"198.18.0.0/15",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"192.0.0.0/24",
		"240.0.0.0/4",
		"64:ff9b::/96",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("decl: bad nonPublicCIDR %q: %v", c, err))
		}
		out = append(out, n)
	}
	return out
}()

// rejectNonPublicIP is the production dial guard: it refuses loopback, RFC1918,
// link-local (incl. 169.254.169.254), ULA (fc00::/7), unspecified, multicast, AND
// the IANA special-purpose ranges in nonPublicCIDRs (CGNAT / benchmarking /
// TEST-NET / reserved / NAT64) — anything that is not a public unicast destination.
func rejectNonPublicIP(ip net.IP) error {
	if isPublicIP(ip) {
		return nil
	}
	return fmt.Errorf("decl: refusing to dial non-public address %s (SSRF guard)", ip)
}

// isPublicIP reports whether ip is a routable public unicast address.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, n := range nonPublicCIDRs {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// checkPublicHost resolves host and requires every resolved address to pass
// ipGuard. A literal "localhost" resolves to loopback and is rejected there. An
// IP literal is checked directly (no DNS). Resolution failures are hard errors.
func checkPublicHost(host string, ipGuard ipGuardFunc) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("empty host")
	}
	ips, err := resolveHostIPs(host)
	if err != nil {
		return fmt.Errorf("cannot resolve: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolved to no addresses")
	}
	for _, ip := range ips {
		if err := ipGuard(ip); err != nil {
			return err
		}
	}
	return nil
}

// resolveHostIPs returns the IPs for host. An IP literal short-circuits DNS.
func resolveHostIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// ---- helpers ----------------------------------------------------------------

// withQuery returns rawURL with key=value set on its query string.
func withQuery(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("decl: build page URL %q: %w", rawURL, err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// parseNextLink extracts the rel="next" URL from a Link header, or "".
func parseNextLink(link string) string {
	m := linkNextRe.FindStringSubmatch(link)
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// parseTimestamp parses ts with layout (default RFC3339). An empty or
// unparseable timestamp yields the zero time (the event still emits; only
// unusual-timing depends on a real timestamp, and it defers without a baseline).
func parseTimestamp(ts, layout string) time.Time {
	if ts == "" {
		return time.Time{}
	}
	if layout == "" {
		layout = defaultTimestampFmt
	}
	t, err := time.Parse(layout, ts)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// makeEventID mirrors connect/github: "evt_" + first 12 hex of SHA-256(idSrc),
// so re-pulls produce stable event (and thus finding) IDs.
func makeEventID(idSrc string) string {
	sum := sha256.Sum256([]byte(idSrc))
	return "evt_" + hex.EncodeToString(sum[:])[:12]
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
