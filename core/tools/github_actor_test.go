package tools

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestGithubActorLive_Ghost hits the REAL api.github.com (unauthenticated,
// public — 60 req/hr) for the reserved `ghost` login and asserts the tool
// reports it as GitHub's deleted-account tombstone/placeholder. This is the
// exact case the current chat hallucinates about ("who is ghost?") — the
// done condition for mallcoppro-5d08 is that this assertion runs against the
// real API, never a mock.
//
// If the sandbox genuinely has no network reachability to api.github.com,
// this test is skipped with an explicit message rather than silently mocked
// — a mocked github_actor test would prove nothing about the real tombstone
// signal this tool exists to surface.
func TestGithubActorLive_Ghost(t *testing.T) {
	requireGithubNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env, err := GithubActor(ctx, GithubActorInput{Login: "ghost"})
	if err != nil {
		t.Fatalf("GithubActor(ghost) returned error: %v", err)
	}

	if !env.Ghost {
		t.Errorf("GithubActor(ghost).Ghost = false, want true (this is the exact tombstone signal the tool exists to surface)")
	}
	if !env.Found {
		t.Errorf("GithubActor(ghost).Found = false, want true — github.com/ghost is a real, live profile")
	}
	if !env.LooksDeleted {
		t.Errorf("GithubActor(ghost).LooksDeleted = false, want true")
	}
	if !strings.Contains(strings.ToLower(env.Notes), "tombstone") && !strings.Contains(strings.ToLower(env.Notes), "reattribut") {
		t.Errorf("GithubActor(ghost).Notes = %q, want an explanation mentioning the reattribution/tombstone signal", env.Notes)
	}
	if env.RecentEvents == nil {
		t.Errorf("GithubActor(ghost).RecentEvents is nil, want a non-nil (possibly empty) slice — envelope discipline")
	}
}

// TestGithubActorLive_KnownPublicLogin hits the REAL api.github.com for a
// long-lived, stable public login (GitHub's own "octocat" mascot account)
// and asserts the tool reports a real, non-ghost, non-deleted profile.
func TestGithubActorLive_KnownPublicLogin(t *testing.T) {
	requireGithubNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env, err := GithubActor(ctx, GithubActorInput{Login: "octocat"})
	if err != nil {
		t.Fatalf("GithubActor(octocat) returned error: %v", err)
	}
	if !env.Found {
		t.Errorf("GithubActor(octocat).Found = false, want true")
	}
	if env.Ghost {
		t.Errorf("GithubActor(octocat).Ghost = true, want false")
	}
	if env.AccountType == "" {
		t.Errorf("GithubActor(octocat).AccountType is empty, want a real GitHub account type")
	}
}

// TestGithubActor_EmptyLogin proves the tool returns an error (not a silent
// empty envelope) for a malformed input — no network call is made.
func TestGithubActor_EmptyLogin(t *testing.T) {
	if _, err := GithubActor(context.Background(), GithubActorInput{Login: "  "}); err == nil {
		t.Fatal("GithubActor(empty login) returned nil error, want an error")
	}
}

// TestGithubActor_EnvelopeAlwaysPopulatesRecentEvents proves the envelope
// discipline (envelope.go): RecentEvents is always a non-nil slice, even on
// the not-found path, never a bare null.
func TestGithubActor_EnvelopeAlwaysPopulatesRecentEvents(t *testing.T) {
	requireGithubNetwork(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// A login GitHub reserves and will not allow a real account to register
	// under (leading double-hyphen is invalid in a GitHub username), so this
	// reliably 404s without depending on any specific account's lifecycle.
	env, err := GithubActor(ctx, GithubActorInput{Login: "--definitely-not-a-real-login--"})
	if err != nil {
		t.Fatalf("GithubActor(bogus login) returned error: %v", err)
	}
	if env.Found {
		t.Fatalf("GithubActor(bogus login).Found = true, want false")
	}
	if env.RecentEvents == nil {
		t.Errorf("GithubActor(bogus login).RecentEvents is nil, want non-nil empty slice")
	}
	if env.Notes == "" {
		t.Errorf("GithubActor(bogus login).Notes is empty, want an explanation of the 404")
	}
}

// requireGithubNetwork skips (with an explicit message, per the item's
// dependency-escalation instruction) when api.github.com is genuinely
// unreachable from this sandbox, rather than silently mocking the call.
func requireGithubNetwork(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/", nil)
	if err != nil {
		t.Fatalf("build network-probe request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("api.github.com unreachable from this sandbox (%v) — mallcoppro-5d08 requires a LIVE test; "+
			"escalate as a dependency rather than mocking the GitHub API", err)
	}
	_ = resp.Body.Close()
}
