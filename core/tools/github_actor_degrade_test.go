package tools

import (
	"strings"
	"testing"
)

// TestGithubActorApplyProfileStatus covers the mallcoppro-2a9 graceful-degrade
// contract for the PROFILE fetch, mirroring the events fetch: 403/429/5xx are
// soft notes (found=false, err==nil, done=true), 200 populates the envelope,
// 404 is the existing not-found note, and a genuinely unexpected status stays a
// hard error. Driven through the pure helper because the network path's SSRF
// guard rejects httptest servers.
func TestGithubActorApplyProfileStatus(t *testing.T) {
	const okBody = `{"type":"User","name":"Octo Cat","bio":"hi","html_url":"https://github.com/octocat","created_at":"2011-01-25T18:44:36Z","public_repos":8,"followers":100}`

	tests := []struct {
		name        string
		status      int
		body        string
		wantDone    bool
		wantErr     bool
		wantFound   bool
		noteSubstr  string // "" = no note expected
		checkFields bool   // assert the 200 fields landed
	}{
		{name: "200 populates", status: 200, body: okBody, wantDone: false, wantFound: true, checkFields: true},
		{name: "404 not found", status: 404, body: `{}`, wantDone: true, wantFound: false, noteSubstr: "does not currently exist"},
		{name: "403 rate limited", status: 403, body: `{"message":"rate limit"}`, wantDone: true, wantFound: false, noteSubstr: "rate limited (HTTP 403)"},
		{name: "429 rate limited", status: 429, body: ``, wantDone: true, wantFound: false, noteSubstr: "rate limited (HTTP 429)"},
		{name: "500 upstream", status: 500, body: ``, wantDone: true, wantFound: false, noteSubstr: "profile unavailable: GitHub returned HTTP 500"},
		{name: "503 upstream", status: 503, body: ``, wantDone: true, wantFound: false, noteSubstr: "HTTP 503"},
		{name: "401 unexpected is a hard error", status: 401, body: `{}`, wantErr: true},
		{name: "400 unexpected is a hard error", status: 400, body: `{}`, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := &GithubActorEnvelope{Login: "octocat", RecentEvents: []GithubActorEvent{}}
			done, err := githubActorApplyProfileStatus(env, tc.status, []byte(tc.body), "https://api.github.com/users/octocat")

			if tc.wantErr {
				if err == nil {
					t.Fatalf("status %d: expected a hard error, got nil (done=%v)", tc.status, done)
				}
				return
			}
			if err != nil {
				t.Fatalf("status %d: unexpected error: %v", tc.status, err)
			}
			if done != tc.wantDone {
				t.Errorf("status %d: done=%v, want %v", tc.status, done, tc.wantDone)
			}
			if env.Found != tc.wantFound {
				t.Errorf("status %d: Found=%v, want %v", tc.status, env.Found, tc.wantFound)
			}
			// The envelope must never be an error on a degrade — RecentEvents
			// stays the non-nil empty slice (envelope discipline).
			if env.RecentEvents == nil {
				t.Errorf("status %d: RecentEvents is nil — envelope discipline broken", tc.status)
			}
			if tc.noteSubstr != "" && !strings.Contains(env.Notes, tc.noteSubstr) {
				t.Errorf("status %d: notes = %q, want substring %q", tc.status, env.Notes, tc.noteSubstr)
			}
			if tc.checkFields {
				if env.AccountType != "User" || env.Name != "Octo Cat" || env.PublicRepos != 8 || env.Followers != 100 {
					t.Errorf("200 fields not populated: %+v", env)
				}
			}
		})
	}
}

// TestGithubActorApplyProfileStatus_GhostPreservedOnDegrade proves a ghost login
// that hits a transient 403 keeps its Ghost signal (set before the fetch) even
// though the profile could not be confirmed.
func TestGithubActorApplyProfileStatus_GhostPreservedOnDegrade(t *testing.T) {
	env := &GithubActorEnvelope{Login: "ghost", Ghost: true, RecentEvents: []GithubActorEvent{}}
	done, err := githubActorApplyProfileStatus(env, 403, []byte(`{}`), "https://api.github.com/users/ghost")
	if err != nil || !done {
		t.Fatalf("ghost 403: done=%v err=%v, want done=true err=nil", done, err)
	}
	if !env.Ghost {
		t.Error("ghost signal was lost on a degraded profile fetch")
	}
	if env.Found {
		t.Error("Found should be false on a 403 degrade")
	}
}
