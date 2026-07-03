package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScaffoldDeployAssetsWritesAllExpectedFiles proves scaffoldDeployAssets
// is offline/pure: it writes go.mod (D1 pin), .gitignore, detectors/README.md,
// connectors/README.md, and .github/workflows/scan.yml, with no network and
// no git — fully covered by t.TempDir().
func TestScaffoldDeployAssetsWritesAllExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.7.0"); err != nil {
		t.Fatalf("scaffoldDeployAssets: %v", err)
	}

	goMod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("go.mod not written: %v", err)
	}
	if !strings.Contains(string(goMod), "module github.com/acme/mallcop-deploy") {
		t.Fatalf("go.mod missing module line: %s", goMod)
	}
	if !strings.Contains(string(goMod), "require github.com/mallcop-app/mallcop v0.7.0") {
		t.Fatalf("go.mod missing D1 pin: %s", goMod)
	}

	gitignore, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf(".gitignore not written: %v", err)
	}
	if !strings.Contains(string(gitignore), "/store/") {
		t.Fatalf(".gitignore does not exclude store/ (D3 same-repo-but-separate-branch): %s", gitignore)
	}

	for _, p := range []string{
		filepath.Join("detectors", "README.md"),
		filepath.Join("connectors", "README.md"),
		filepath.Join(".github", "workflows", "scan.yml"),
	} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}

	workflow, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "scan.yml"))
	if err != nil {
		t.Fatalf("reading scan.yml: %v", err)
	}
	w := string(workflow)

	// D2+2fd: the pinned release binary is installed, never rebuilt from
	// customer code; only detectors/<name> compiles, and only to wasip1/wasm.
	if !strings.Contains(w, `MALLCOP_VERSION: "v0.7.0"`) {
		t.Fatalf("scan.yml does not pin MALLCOP_VERSION to v0.7.0:\n%s", w)
	}
	if !strings.Contains(w, "releases/download/${MALLCOP_VERSION}/mallcop-${MALLCOP_ASSET}.tar.gz") {
		t.Fatalf("scan.yml does not install the pinned release binary from GitHub Releases:\n%s", w)
	}
	// The asset name must be resolved from the runner's actual OS/arch, never
	// hardcoded to a single platform -- the release publishes linux-amd64,
	// linux-arm64, AND darwin-arm64 (see the release-assets test below).
	if !strings.Contains(w, "RUNNER_OS") || !strings.Contains(w, "RUNNER_ARCH") {
		t.Fatalf("scan.yml does not resolve the release asset from RUNNER_OS/RUNNER_ARCH:\n%s", w)
	}
	for _, want := range []string{"linux-amd64", "linux-arm64", "darwin-arm64"} {
		if !strings.Contains(w, want) {
			t.Fatalf("scan.yml platform-detection step is missing the %q asset mapping:\n%s", want, w)
		}
	}
	if !strings.Contains(w, "GOOS=wasip1 GOARCH=wasm go build") {
		t.Fatalf("scan.yml does not build sidecars to wasip1/wasm:\n%s", w)
	}
	if !strings.Contains(w, "GOFLAGS: -mod=mod") {
		t.Fatalf("scan.yml sidecar build step does not set GOFLAGS=-mod=mod (see cli/sidecars.go buildAndRegisterSourceSidecar for why a customer's detectors/ build needs it):\n%s", w)
	}
	if strings.Contains(w, "go build -o mallcop") || strings.Contains(w, "go build ./cmd/mallcop") {
		t.Fatalf("scan.yml must never rebuild the whole mallcop binary from customer code:\n%s", w)
	}
	if !strings.Contains(w, "mallcop scan") {
		t.Fatalf("scan.yml does not run 'mallcop scan':\n%s", w)
	}
	// The workflow must be BOTH schedulable (real "scheduled scan") AND
	// manually triggerable (workflow_dispatch -- how this item's live proof
	// runs it deterministically instead of waiting on a cron tick).
	if !strings.Contains(w, "schedule:") || !strings.Contains(w, "cron:") {
		t.Fatalf("scan.yml is missing a cron schedule trigger:\n%s", w)
	}
	if !strings.Contains(w, "workflow_dispatch:") {
		t.Fatalf("scan.yml is missing a workflow_dispatch trigger:\n%s", w)
	}
	if !strings.Contains(w, "mallcop-findings") {
		t.Fatalf("scan.yml does not reference the findings-persistence branch:\n%s", w)
	}
	if !strings.Contains(w, "git -C store push") {
		t.Fatalf("scan.yml does not push the findings store:\n%s", w)
	}
	// Live proof (mallcoppro-f3b) found 'mallcop scan' can leave store/'s
	// working tree in a deletion-staged-but-uncommitted state after it
	// returns; a manual 'git add -A && git commit' in this workflow would
	// capture that as a real (destructive) commit. The workflow must only
	// ever push whatever store/ already committed internally.
	if strings.Contains(w, "add -A") || strings.Contains(w, `commit -q -m "scan:`) {
		t.Fatalf("scan.yml must not run its own git add/commit inside store/ (see mallcoppro-f3b finding):\n%s", w)
	}
}

// TestScaffoldDeployAssetsIdempotent proves a re-run never clobbers existing
// deploy-repo assets, mirroring TestInitIdempotent's convention for the base
// scaffold.
func TestScaffoldDeployAssetsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.7.0"); err != nil {
		t.Fatalf("first scaffoldDeployAssets: %v", err)
	}
	goModPath := filepath.Join(dir, "go.mod")
	edited := "module github.com/acme/mallcop-deploy\n\ngo 1.24\n\nrequire github.com/mallcop-app/mallcop v0.7.0\n\nreplace foo => bar\n"
	if err := os.WriteFile(goModPath, []byte(edited), 0o644); err != nil {
		t.Fatalf("edit go.mod: %v", err)
	}

	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.9.0"); err != nil {
		t.Fatalf("second scaffoldDeployAssets: %v", err)
	}

	got, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if string(got) != edited {
		t.Fatalf("re-run clobbered edited go.mod:\n%s", got)
	}
}

// TestSplitOwnerRepo covers the "owner/name" parse used by both runInit's
// --create-repo flag and createAndPushDeployRepo.
func TestSplitOwnerRepo(t *testing.T) {
	cases := []struct {
		in        string
		wantOwner string
		wantName  string
		wantOK    bool
	}{
		{"acme/mallcop-deploy", "acme", "mallcop-deploy", true},
		{"noslash", "", "", false},
		{"/name", "", "", false},
		{"owner/", "", "", false},
		{"owner/name/extra", "", "", false},
	}
	for _, c := range cases {
		owner, name, ok := splitOwnerRepo(c.in)
		if ok != c.wantOK || owner != c.wantOwner || name != c.wantName {
			t.Errorf("splitOwnerRepo(%q) = (%q, %q, %v), want (%q, %q, %v)", c.in, owner, name, ok, c.wantOwner, c.wantName, c.wantOK)
		}
	}
}

// TestProAppTokenExchangesInstallationForToken proves the GitHub-App-authorize
// seam's wire shape against an httptest stand-in of mallcop-pro's real POST
// /v1/github/token (see mallcop-pro/internal/server/github_token.go): bearer
// API key in, installation_id in the JSON body, {"token": "..."} out. This is
// the seam described in deployrepo.go's package doc -- not exercised against
// the live api.mallcop.app in this item's proof, but real code, really tested.
func TestProAppTokenExchangesInstallationForToken(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody struct {
		InstallationID int64 `json:"installation_id"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":       "ghs_faketokenfortest",
			"expires_at":  "2026-01-01T00:00:00Z",
			"permissions": map[string]string{"contents": "write"},
		})
	}))
	defer srv.Close()

	tok := proAppToken{endpoint: srv.URL, apiKey: "mallcop-sk-test", installationID: 116376961}
	got, err := tok.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "ghs_faketokenfortest" {
		t.Fatalf("Token = %q, want ghs_faketokenfortest", got)
	}
	if gotAuth != "Bearer mallcop-sk-test" {
		t.Fatalf("Authorization header = %q, want Bearer mallcop-sk-test", gotAuth)
	}
	if gotPath != "/v1/github/token" {
		t.Fatalf("path = %q, want /v1/github/token", gotPath)
	}
	if gotBody.InstallationID != 116376961 {
		t.Fatalf("installation_id = %d, want 116376961", gotBody.InstallationID)
	}
}

// TestProAppTokenSurfacesServerError proves a non-200 from mallcop-pro is a
// loud error, not a silently empty token.
func TestProAppTokenSurfacesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "GitHub App not configured"})
	}))
	defer srv.Close()

	tok := proAppToken{endpoint: srv.URL, apiKey: "mallcop-sk-test", installationID: 1}
	_, err := tok.Token(context.Background())
	if err == nil {
		t.Fatal("expected an error from a 503 response, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error does not mention the status code: %v", err)
	}
}

// TestEnvGitHubTokenMissing proves a clear, loud error (not a silent empty
// token) when the configured env var isn't set.
func TestEnvGitHubTokenMissing(t *testing.T) {
	t.Setenv("MALLCOP_GITHUB_TOKEN_TEST_UNSET", "")
	os.Unsetenv("MALLCOP_GITHUB_TOKEN_TEST_UNSET")
	tok := envGitHubToken{envVar: "MALLCOP_GITHUB_TOKEN_TEST_UNSET"}
	if _, err := tok.Token(context.Background()); err == nil {
		t.Fatal("expected an error when the token env var is unset")
	}
}
