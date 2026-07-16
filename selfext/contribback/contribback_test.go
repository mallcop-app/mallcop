package contribback

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/autonomy"
)

// fakePR is a PROpener that records OpenPR calls AND exposes a Merge method the
// production Opener can never reach (PROpener has no Merge). The test asserts
// mergeCalls stays 0 at every dial — proving by construction that contribute-back
// never merges regardless of the autonomy dial.
type fakePR struct {
	openCalls  int
	mergeCalls int
	lastReq    PRRequest
	url        string
	err        error
}

func (f *fakePR) OpenPR(_ context.Context, req PRRequest) (PRResult, error) {
	f.openCalls++
	f.lastReq = req
	if f.err != nil {
		return PRResult{}, f.err
	}
	url := f.url
	if url == "" {
		url = "https://github.com/mallcop-app/mallcop/pull/1"
	}
	return PRResult{URL: url}, nil
}

// Merge is deliberately NOT part of the PROpener interface. It exists only so the
// test can prove the Opener never invokes any merge path: if a future change ever
// wired merging in, this counter would have to move, and the invariant test would
// fail. Today it can never be called through the Opener.
func (f *fakePR) Merge(context.Context, PRRequest) error {
	f.mergeCalls++
	return nil
}

func eligibleArtifact() Artifact {
	return Artifact{
		Fingerprint: "abcdef0123456789",
		Consented:   true,
		Universal:   true,
		Title:       "selfext(contribute-back): universal detection widen",
		Body:        "body",
	}
}

func enabledOpener(pr PROpener) *Opener {
	return &Opener{
		Config: Config{Enabled: true, Repo: "mallcop-app/mallcop"},
		PR:     pr,
	}
}

// (a) Contribute-back is OFF BY DEFAULT: the zero-value Config is disabled, so an
// eligible, consented, universal artifact opens NO shared-OSS PR.
func TestContributeOffByDefault(t *testing.T) {
	pr := &fakePR{}
	// Zero-value Config — the operator did nothing to opt in.
	o := &Opener{PR: pr}
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, eligibleArtifact())
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if out.Opened || out.Attempted {
		t.Fatalf("default-off Opener opened/attempted a PR: %+v", out)
	}
	if pr.openCalls != 0 {
		t.Fatalf("default-off Opener called OpenPR %d times, want 0", pr.openCalls)
	}
	if !strings.Contains(out.SkipReason, "disabled") {
		t.Errorf("SkipReason = %q, want a 'disabled' reason", out.SkipReason)
	}
}

// (b) At EVERY dial — including the most-autonomous "fully"/yolo tier and even an
// unrecognized "more autonomous than fully" value — an enabled + eligible
// contribute-back OPENS the shared-OSS PR but NEVER merges it.
func TestContributeOpensButNeverMergesAtEveryDial(t *testing.T) {
	dials := []autonomy.Dial{
		autonomy.NonAutonomy,
		autonomy.SemiAutonomy,
		autonomy.FullyAutonomy,            // the most-autonomous defined tier == "yolo"
		autonomy.Dial("yolo"),             // the R3 name for the top tier, unrecognized here
		autonomy.Dial("ultra-permissive"), // a hypothetical value beyond the dial
	}
	for _, dial := range dials {
		t.Run(string(dial), func(t *testing.T) {
			pr := &fakePR{}
			o := enabledOpener(pr)
			out, err := o.Contribute(context.Background(), dial, eligibleArtifact())
			if err != nil {
				t.Fatalf("Contribute(dial=%q): %v", dial, err)
			}
			if !out.Opened {
				t.Fatalf("dial=%q: PR not opened: %+v", dial, out)
			}
			if pr.openCalls != 1 {
				t.Fatalf("dial=%q: OpenPR called %d times, want 1", dial, pr.openCalls)
			}
			// THE HARD LINE: no merge, at any dial.
			if pr.mergeCalls != 0 {
				t.Fatalf("dial=%q: contribute-back MERGED the shared-OSS PR (mergeCalls=%d) — hard-line violation", dial, pr.mergeCalls)
			}
			if out.PRURL == "" {
				t.Errorf("dial=%q: opened PR has no URL", dial)
			}
		})
	}
}

// (c) DISABLED → no shared PR, even for a fully-eligible artifact at the top dial.
func TestContributeDisabledNoSharedPR(t *testing.T) {
	pr := &fakePR{}
	o := &Opener{Config: Config{Enabled: false, Repo: "mallcop-app/mallcop"}, PR: pr}
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, eligibleArtifact())
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if pr.openCalls != 0 || out.Opened {
		t.Fatalf("disabled Opener opened a PR: openCalls=%d out=%+v", pr.openCalls, out)
	}
}

// Defense in depth: even enabled, a non-consented artifact opens no PR.
func TestContributeNotConsentedNoPR(t *testing.T) {
	pr := &fakePR{}
	o := enabledOpener(pr)
	art := eligibleArtifact()
	art.Consented = false
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, art)
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if pr.openCalls != 0 || out.Opened {
		t.Fatalf("non-consented artifact opened a PR: %+v", out)
	}
	if !strings.Contains(out.SkipReason, "consent") {
		t.Errorf("SkipReason = %q, want a 'consent' reason", out.SkipReason)
	}
}

// Defense in depth: a tenant-specific (non-universal) widen opens no PR.
func TestContributeNotUniversalNoPR(t *testing.T) {
	pr := &fakePR{}
	o := enabledOpener(pr)
	art := eligibleArtifact()
	art.Universal = false
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, art)
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if pr.openCalls != 0 || out.Opened {
		t.Fatalf("non-universal artifact opened a PR: %+v", out)
	}
	if !strings.Contains(out.SkipReason, "universal") {
		t.Errorf("SkipReason = %q, want a 'universal' reason", out.SkipReason)
	}
}

// The Opener passes the configured target repo + branch through to the PR opener.
func TestContributeUsesConfiguredRepoAndBranch(t *testing.T) {
	pr := &fakePR{}
	o := &Opener{Config: Config{Enabled: true, Repo: "mallcop-app/mallcop", BaseBranch: "trunk"}, PR: pr}
	if _, err := o.Contribute(context.Background(), autonomy.SemiAutonomy, eligibleArtifact()); err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if pr.lastReq.Repo != "mallcop-app/mallcop" {
		t.Errorf("repo = %q, want mallcop-app/mallcop", pr.lastReq.Repo)
	}
	if pr.lastReq.BaseBranch != "trunk" {
		t.Errorf("base = %q, want trunk", pr.lastReq.BaseBranch)
	}
	if pr.lastReq.HeadBranch != "contribback/abcdef012345" {
		t.Errorf("head = %q, want contribback/abcdef012345", pr.lastReq.HeadBranch)
	}
}

// ghArgs never carries a token/credential flag — the operator's ambient gh auth
// opens the PR (R8: no standing write credential).
func TestGHArgsCarriesNoCredential(t *testing.T) {
	args := ghArgs(PRRequest{
		Repo: "mallcop-app/mallcop", BaseBranch: "main", HeadBranch: "contribback/x",
		Title: "t", Body: "b",
	})
	joined := strings.ToLower(strings.Join(args, " "))
	for _, banned := range []string{"token", "--auth", "password", "credential", "gh_token", "github_token"} {
		if strings.Contains(joined, banned) {
			t.Errorf("gh args contain a credential-ish flag %q: %v", banned, args)
		}
	}
	// Sanity: the essential PR flags are present.
	for _, want := range []string{"pr", "create", "--repo", "--base", "--head", "--title", "--body"} {
		if !containsArg(args, want) {
			t.Errorf("gh args missing %q: %v", want, args)
		}
	}
}

// ghOpener parses the PR URL from gh's output and never merges.
func TestGHOpenerParsesURL(t *testing.T) {
	g := &ghOpener{run: func(_ context.Context, _ string, _ ...string) (string, error) {
		return "https://github.com/mallcop-app/mallcop/pull/42\n", nil
	}}
	res, err := g.OpenPR(context.Background(), PRRequest{Repo: "mallcop-app/mallcop", BaseBranch: "main", HeadBranch: "contribback/x", Title: "t", Body: "b"})
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if res.URL != "https://github.com/mallcop-app/mallcop/pull/42" {
		t.Errorf("URL = %q", res.URL)
	}
}

// LoadArtifact distills a router-emitted OSS-PR artifact into an eligible
// Artifact (Consented + Universal), wiring the router's output to the opener.
func TestLoadArtifactFromRouterEmission(t *testing.T) {
	// Shape mirrors router.ossArtifact's on-disk JSON (proposal/gate/provenance/note).
	raw := map[string]any{
		"proposal": map[string]any{
			"kind": "mapping",
			"mapping": map[string]any{
				"source": "github", "raw_action": "repo.rename", "event_type": "config_change",
			},
			"universal":   true,
			"fingerprint": "deadbeefcafebabe0001",
			"model":       "investigate",
		},
		"note": "OSS contribute-back proposal.",
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "oss-pr-deadbeefcafe-20260713-000000.json")
	data, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	art, err := LoadArtifact(path)
	if err != nil {
		t.Fatalf("LoadArtifact: %v", err)
	}
	if !art.Consented {
		t.Error("loaded artifact must be Consented (router only emits on consent)")
	}
	if !art.Universal {
		t.Error("loaded artifact must be Universal")
	}
	if art.Fingerprint != "deadbeefcafebabe0001" {
		t.Errorf("fingerprint = %q", art.Fingerprint)
	}
	if !strings.Contains(art.Title, "config_change") {
		t.Errorf("title = %q, want the mapping target", art.Title)
	}
	if !strings.Contains(art.Body, "NOT auto-merged") {
		t.Errorf("body must state the PR is not auto-merged: %q", art.Body)
	}
	if art.HeadBranch() != "contribback/deadbeefcafe" {
		t.Errorf("head branch = %q", art.HeadBranch())
	}

	// End-to-end wiring: the loaded artifact opens a PR (not merged) when enabled.
	pr := &fakePR{}
	o := enabledOpener(pr)
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, art)
	if err != nil {
		t.Fatalf("Contribute(loaded): %v", err)
	}
	if !out.Opened || pr.mergeCalls != 0 {
		t.Fatalf("loaded artifact: opened=%v merges=%d, want opened + zero merges", out.Opened, pr.mergeCalls)
	}
}

// LoadCodeArtifact distills a CODE-lane authored-detector artifact into an
// eligible Artifact (Consented + Universal, Lane=code), maps each customer-repo
// file to its OSS core/detect/authored/<name>/ destination, and composes a PR
// body that states the promotion must pass the OSS repo's own exam.yml +
// CODEOWNERS review and is never auto-merged. (the code lane
// had no artifact at all.)
func TestLoadCodeArtifact_MapsToPRRequest(t *testing.T) {
	raw := map[string]any{
		"kind": "authored_detector",
		"detector": map[string]any{
			"name": "deploy-burst",
			"files": []string{
				"detectors/deploy-burst/detector.go",
				"detectors/deploy-burst/detector_test.go",
				"detectors/deploy-burst/scenarios/burst.jsonl",
			},
		},
		"provenance": map[string]any{
			"fingerprint": "c0ffee1234567890abcd",
			"gate_ref":    "headsha-abc123",
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "code-pr-c0ffee123456-20260714-000000.json")
	data, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	art, err := LoadCodeArtifact(path)
	if err != nil {
		t.Fatalf("LoadCodeArtifact: %v", err)
	}
	if art.Lane != LaneCode {
		t.Errorf("lane = %q, want %q", art.Lane, LaneCode)
	}
	if !art.Consented || !art.Universal {
		t.Errorf("code artifact must be Consented+Universal: %+v", art)
	}
	if art.DetectorName != "deploy-burst" {
		t.Errorf("detector name = %q", art.DetectorName)
	}
	if art.GateRef != "headsha-abc123" {
		t.Errorf("gate ref = %q", art.GateRef)
	}
	// Every promoted file maps detectors/<name>/... -> core/detect/authored/<name>/...
	wantDest := map[string]string{
		"detectors/deploy-burst/detector.go":           "core/detect/authored/deploy-burst/detector.go",
		"detectors/deploy-burst/detector_test.go":      "core/detect/authored/deploy-burst/detector_test.go",
		"detectors/deploy-burst/scenarios/burst.jsonl": "core/detect/authored/deploy-burst/scenarios/burst.jsonl",
	}
	if len(art.Files) != len(wantDest) {
		t.Fatalf("promoted %d files, want %d: %+v", len(art.Files), len(wantDest), art.Files)
	}
	for _, f := range art.Files {
		if wantDest[f.Src] != f.Dest {
			t.Errorf("file %q -> %q, want %q", f.Src, f.Dest, wantDest[f.Src])
		}
	}
	// Deterministic head branch stays contribback/<short-fp> (idempotent re-run).
	if art.HeadBranch() != "contribback/c0ffee123456" {
		t.Errorf("head branch = %q", art.HeadBranch())
	}
	if !strings.Contains(art.Title, "deploy-burst") || !strings.Contains(art.Title, "promote") {
		t.Errorf("title = %q, want the promotion + detector name", art.Title)
	}
	for _, want := range []string{"NOT auto-merged", "exam.yml", "CODEOWNERS", "c0ffee1234567890abcd", "core/detect/authored/deploy-burst"} {
		if !strings.Contains(art.Body, want) {
			t.Errorf("body missing %q:\n%s", want, art.Body)
		}
	}

	// End-to-end: the loaded code artifact maps to a PRRequest and opens a PR
	// (NOT merged) when enabled, at the top dial.
	pr := &fakePR{}
	o := enabledOpener(pr)
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, art)
	if err != nil {
		t.Fatalf("Contribute(code): %v", err)
	}
	if !out.Opened || pr.mergeCalls != 0 {
		t.Fatalf("code artifact: opened=%v merges=%d, want opened + zero merges", out.Opened, pr.mergeCalls)
	}
	if pr.lastReq.HeadBranch != "contribback/c0ffee123456" {
		t.Errorf("PRRequest head branch = %q", pr.lastReq.HeadBranch)
	}
	if pr.lastReq.Title != art.Title {
		t.Errorf("PRRequest title = %q, want %q", pr.lastReq.Title, art.Title)
	}
}

// A code artifact with the wrong kind (a DATA-lane file) is rejected — the two
// lanes never cross-load.
func TestLoadCodeArtifact_RejectsWrongKind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oss-pr.json")
	if err := os.WriteFile(path, []byte(`{"proposal":{"kind":"mapping","fingerprint":"abc"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCodeArtifact(path); err == nil {
		t.Fatal("expected LoadCodeArtifact to reject a non-authored_detector file")
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
