// github_actor.go — the github_actor LIVE lookup tool, the one net-new tool in
// the chat<->investigate protocol (mallcop-pro docs/chat-investigate-protocol.md).
//
// Unlike the rest of this package (pure functions over an already-loaded
// store/baseline), GithubActor makes a real, read-only HTTP call to
// api.github.com: GET /users/{login} for the public profile, then
// GET /users/{login}/events/public for recent public activity. Both are
// public GitHub REST endpoints — unauthenticated calls work (60 req/hr); a
// GITHUB_TOKEN in the environment is sent as a bearer token when present
// (10x'ing the rate limit), the same env var connect/github.NewFromEnv reads
// for its PAT auth path. This tool does not construct a connect/github
// Connector (that type is org-events-scoped and carries state this per-actor
// lookup does not need) — it reuses only the auth/transport DISCIPLINE: a
// bearer header built from GITHUB_TOKEN, and an SSRF guard on every URL
// fetched, mirroring connect/github.validateNextLink (https + exact
// allowlisted host, refuse anything else).
//
// # The ghost tombstone
//
// github.com/ghost is GitHub's real, reserved placeholder account: commits
// and other activity originally authored by a DELETED GitHub account are
// permanently reattributed to `ghost` rather than left dangling. `ghost` is
// not itself a deleted account — it is a live, real, public profile (created
// 2008) that exists specifically to be "this used to be someone." This is
// the exact question the current chat invents three wrong theories about
// ("who is ghost?"); GithubActor answers it for real by asking GitHub.
//
// # Envelope discipline (envelope.go)
//
// GithubActorEnvelope carries the same keys on every call — empty string/
// slice, never an omitted field, never bare null. GithubActor returns an
// error only for a genuine schema violation (empty login, unparseable API
// base URL, a transport failure, or an unexpected non-200/404 status).
// "Login not found" (404) is a legitimate, common result — it comes back as
// Found=false with an explanatory Notes, never an error.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// githubActorDefaultBaseURL is the production GitHub REST API host.
	// GITHUB_API_URL overrides it (GHES, tests) — same env var
	// connect/github.NewFromEnv reads.
	githubActorDefaultBaseURL = "https://api.github.com"

	// githubActorGhostLogin is GitHub's reserved deleted-account tombstone
	// login. See package doc.
	githubActorGhostLogin = "ghost"

	// githubActorMaxEvents caps how many recent public events are projected
	// into the envelope (the events/public endpoint itself returns up to
	// githubActorEventsPerPage per page; only the first page is fetched).
	githubActorMaxEvents     = 10
	githubActorEventsPerPage = 30

	// githubActorHTTPTimeout bounds a single request. GithubActor manages its
	// own timeout rather than relying on caller ctx cancellation, matching
	// the rest of this tool's dispatch (core/investigate.ExecuteTool calls
	// every tool ctx-free today).
	githubActorHTTPTimeout = 15 * time.Second
)

// GithubActorInput is the input for GithubActor. Login is the GitHub
// username to look up (required).
type GithubActorInput struct {
	Login string `json:"login"`
}

// GithubActorEvent is one recent public activity entry projected from
// GET /users/{login}/events/public.
type GithubActorEvent struct {
	Type      string `json:"type"`
	Repo      string `json:"repo"`
	Timestamp string `json:"timestamp"`
}

// GithubActorEnvelope is the canonical, always-same-shape output of
// GithubActor.
//
//   - Found reports whether GET /users/{login} returned a real profile
//     (200). A 404 is Found=false with Notes explaining why — not an error.
//   - Ghost is true exactly when Login is the reserved `ghost` tombstone
//     login (see package doc) — the one hardcoded, load-bearing signal this
//     tool exists to surface.
//   - LooksDeleted is true for Ghost, or (best-effort heuristic) when a
//     non-ghost profile's name/bio reads like a deactivated-account
//     placeholder. The heuristic case is always explained in Notes — it is
//     not an API-confirmed fact the way Ghost is.
//   - AccountType mirrors GitHub's `type` field ("User", "Organization",
//     "Bot"); empty when Found is false.
//   - RecentEvents is empty (never nil) when the account has no public
//     activity, the events call failed, or (see Notes) was rate-limited.
type GithubActorEnvelope struct {
	Login        string             `json:"login"`
	Found        bool               `json:"found"`
	Ghost        bool               `json:"ghost"`
	LooksDeleted bool               `json:"looks_deleted"`
	AccountType  string             `json:"account_type"`
	Name         string             `json:"name"`
	Bio          string             `json:"bio"`
	ProfileURL   string             `json:"profile_url"`
	CreatedAt    string             `json:"created_at"`
	PublicRepos  int                `json:"public_repos"`
	Followers    int                `json:"followers"`
	RecentEvents []GithubActorEvent `json:"recent_events"`
	Notes        string             `json:"notes"`
}

// githubActorProfile is the subset of GET /users/{login} this tool projects.
type githubActorProfile struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Bio         string `json:"bio"`
	HTMLURL     string `json:"html_url"`
	CreatedAt   string `json:"created_at"`
	PublicRepos int    `json:"public_repos"`
	Followers   int    `json:"followers"`
}

// githubActorRawEvent is the subset of one GET /users/{login}/events/public
// entry this tool projects.
type githubActorRawEvent struct {
	Type      string `json:"type"`
	CreatedAt string `json:"created_at"`
	Repo      struct {
		Name string `json:"name"`
	} `json:"repo"`
}

// GithubActor performs a live, read-only lookup of a GitHub login: its
// public profile plus recent public activity. Returns an error only for a
// genuine input/transport failure — never for "user not found", which is a
// valid Found=false result.
func GithubActor(ctx context.Context, in GithubActorInput) (GithubActorEnvelope, error) {
	login := strings.TrimSpace(in.Login)
	if login == "" {
		return GithubActorEnvelope{}, fmt.Errorf("github_actor: login is required")
	}

	env := GithubActorEnvelope{
		Login:        login,
		RecentEvents: []GithubActorEvent{},
	}
	if strings.EqualFold(login, githubActorGhostLogin) {
		env.Ghost = true
	}

	baseURL := githubActorBaseURL()
	allowedHost, err := githubActorAllowedHost(baseURL)
	if err != nil {
		return GithubActorEnvelope{}, fmt.Errorf("github_actor: %w", err)
	}
	client := &http.Client{Timeout: githubActorHTTPTimeout}

	profileURL := fmt.Sprintf("%s/users/%s", baseURL, url.PathEscape(login))
	status, body, ferr := githubActorFetch(ctx, client, allowedHost, profileURL)
	if ferr != nil {
		return GithubActorEnvelope{}, fmt.Errorf("github_actor: fetch profile: %w", ferr)
	}
	if done, err := githubActorApplyProfileStatus(&env, status, body, profileURL); err != nil {
		return GithubActorEnvelope{}, err
	} else if done {
		// 404 or a transient/upstream degrade — return the (soft) envelope now.
		// The follow-up events fetch would fail the same way, so skip it.
		return env, nil
	}

	switch {
	case env.Ghost:
		env.LooksDeleted = true
		env.Notes = githubActorAppendNote(env.Notes, "`ghost` is GitHub's reserved placeholder account: commits "+
			"and other activity from deleted GitHub accounts are permanently reattributed to github.com/ghost. "+
			"This is the real, live tombstone profile — not a hallucinated or bugged actor.")
	case githubActorLooksDeleted(env.Name, env.Bio):
		env.LooksDeleted = true
		env.Notes = githubActorAppendNote(env.Notes, "heuristic: name/bio reads like a deactivated-account "+
			"placeholder; this is NOT an API-confirmed deletion signal the way the ghost login is.")
	}

	eventsURL := fmt.Sprintf("%s/users/%s/events/public?per_page=%d", baseURL, url.PathEscape(login), githubActorEventsPerPage)
	evStatus, evBody, everr := githubActorFetch(ctx, client, allowedHost, eventsURL)
	switch {
	case everr != nil:
		env.Notes = githubActorAppendNote(env.Notes, fmt.Sprintf("recent activity unavailable: %v", everr))
	case evStatus == http.StatusOK:
		var raws []githubActorRawEvent
		if err := json.Unmarshal(evBody, &raws); err != nil {
			env.Notes = githubActorAppendNote(env.Notes, fmt.Sprintf("recent activity unavailable: decode error: %v", err))
			break
		}
		for i, r := range raws {
			if i >= githubActorMaxEvents {
				break
			}
			env.RecentEvents = append(env.RecentEvents, GithubActorEvent{
				Type:      r.Type,
				Repo:      r.Repo.Name,
				Timestamp: r.CreatedAt,
			})
		}
	case evStatus == http.StatusForbidden:
		env.Notes = githubActorAppendNote(env.Notes, "recent activity unavailable: rate limited (403) — profile data above is still authoritative.")
	default:
		env.Notes = githubActorAppendNote(env.Notes, fmt.Sprintf("recent activity unavailable: GET events returned %d", evStatus))
	}

	return env, nil
}

// githubActorApplyProfileStatus maps a profile-fetch HTTP status onto env,
// mirroring the events fetch's graceful degrade: a 403/429/5xx is a soft note,
// never a hard error (mallcoppro-2a9). It returns done=true when the caller
// should return (env, nil) immediately — a 404 or a transient/upstream degrade,
// both of which also make the follow-up events fetch pointless. A genuinely
// unexpected status (e.g. 401 bad token, 400) stays a hard error so a real
// auth/config fault surfaces loudly instead of masquerading as "not found".
func githubActorApplyProfileStatus(env *GithubActorEnvelope, status int, body []byte, profileURL string) (done bool, err error) {
	switch {
	case status == http.StatusOK:
		var p githubActorProfile
		if err := json.Unmarshal(body, &p); err != nil {
			return false, fmt.Errorf("github_actor: decode profile: %w", err)
		}
		env.Found = true
		env.AccountType = p.Type
		env.Name = p.Name
		env.Bio = p.Bio
		env.ProfileURL = p.HTMLURL
		env.CreatedAt = p.CreatedAt
		env.PublicRepos = p.PublicRepos
		env.Followers = p.Followers
		return false, nil
	case status == http.StatusNotFound:
		env.Notes = githubActorAppendNote(env.Notes, "GitHub returned 404 for this login: it does not currently exist under this exact "+
			"name. That can mean it never existed, was renamed, or was deleted WITHOUT reattribution to "+
			"the ghost tombstone (reattribution to ghost applies to commit authorship, not every trace of "+
			"an account).")
		return true, nil
	case status == http.StatusForbidden || status == http.StatusTooManyRequests || status >= 500:
		reason := fmt.Sprintf("HTTP %d", status)
		if status == http.StatusForbidden || status == http.StatusTooManyRequests {
			reason = fmt.Sprintf("rate limited (HTTP %d)", status)
		}
		env.Notes = githubActorAppendNote(env.Notes, fmt.Sprintf("profile unavailable: GitHub returned %s — a "+
			"transient/upstream condition, not a statement that the login does not exist. found=false here "+
			"means \"could not confirm\", not \"deleted\".", reason))
		return true, nil
	default:
		return false, fmt.Errorf("github_actor: GET %s returned %d: %s", profileURL, status, githubActorTruncate(body, 200))
	}
}

// githubActorBaseURL resolves the API base URL: GITHUB_API_URL overrides the
// production default (GHES, tests) — same env var connect/github.NewFromEnv
// reads.
func githubActorBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("GITHUB_API_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return githubActorDefaultBaseURL
}

// githubActorAllowedHost parses the host component out of baseURL for the
// SSRF allowlist check.
func githubActorAllowedHost(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid API base URL %q: %w", baseURL, err)
	}
	return u.Host, nil
}

// githubActorValidateURL is the SSRF guard, ported from
// connect/github.validateNextLink: only https URLs to the exact allowlisted
// host are fetched. Every URL this tool requests — not just a followed
// pagination link — is checked, so a tampered/misconfigured base URL cannot
// redirect a "GitHub" lookup at an arbitrary host.
func githubActorValidateURL(rawURL, allowedHost string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("unparseable URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-https URL %q", rawURL)
	}
	if u.Host != allowedHost {
		return fmt.Errorf("refusing URL to unexpected host %q (allowed: %q)", u.Host, allowedHost)
	}
	return nil
}

// githubActorFetch validates rawURL against the SSRF allowlist, then issues
// one authenticated (when GITHUB_TOKEN is set) GET, returning the status and
// body. A non-2xx/404 status is NOT an error here — the caller inspects
// status and decides; only a genuine request/transport failure returns err.
func githubActorFetch(ctx context.Context, client *http.Client, allowedHost, rawURL string) (int, []byte, error) {
	if err := githubActorValidateURL(rawURL, allowedHost); err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("GET %s failed: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("read body: %w", err)
	}
	return resp.StatusCode, body, nil
}

// githubActorLooksDeleted is a best-effort heuristic for a non-ghost profile
// that presents as a deactivated placeholder. Never authoritative the way
// the Ghost flag is — every caller site that sets LooksDeleted via this path
// also appends an explanatory Notes entry.
func githubActorLooksDeleted(name, bio string) bool {
	hay := strings.ToLower(name + " " + bio)
	signals := []string{
		"deleted user", "deleted account", "this account has been deleted",
		"account suspended", "account has been suspended",
	}
	for _, s := range signals {
		if strings.Contains(hay, s) {
			return true
		}
	}
	return false
}

// githubActorAppendNote joins note onto existing with a separating space,
// or returns note alone when existing is empty — Notes accumulates multiple
// observations (e.g. the ghost explanation AND a rate-limit warning) without
// clobbering.
func githubActorAppendNote(existing, note string) string {
	if existing == "" {
		return note
	}
	return existing + " " + note
}

// githubActorTruncate caps b for inclusion in an error message.
func githubActorTruncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
