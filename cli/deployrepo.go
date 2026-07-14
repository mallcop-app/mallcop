// Deploy-repo scaffold + creation (mallcoppro-f3b): `mallcop init --create-repo
// owner/name` turns the plain local scaffold runInit already writes
// (mallcop.yaml, store/, events.jsonl) into a customer DEPLOYMENT repo pushed
// to a real GitHub repository, so the customer never compiles mallcop
// locally — a scheduled GitHub Action does.
//
// Rulings this file implements:
//
//   - D1 THIN-EMBED: the repo pins mallcop via go.mod (require
//     github.com/mallcop-app/mallcop <version>) so a customer authoring a
//     detectors/<name> sidecar gets the real core/detect + pkg/detectorhost
//     types from the published module — never a fork, never vendored source.
//   - D2+2fd WASM SIDECARS: the scaffolded CI workflow builds each
//     detectors/<name> to wasip1 .wasm into detectors/bin/ (matching
//     cfg.Detectors.Sidecars.Dir's default — see resolveSidecarsDir in
//     sidecars.go). It NEVER rebuilds the whole mallcop binary from customer
//     code — the core binary is always the pinned prebuilt release tarball
//     downloaded from GitHub Releases.
//   - D3 SAME-REPO: findings live in store/ inside the SAME GitHub repo, not
//     a separate one. store/ is (per core/store's own design — see
//     openOrInitStore in scan.go) its own nested git repository, so it can't
//     ride along on the deployment repo's main branch across ephemeral
//     Actions runs. The scaffolded workflow instead backs store/ with a
//     dedicated branch (mallcopFindingsBranch) of the SAME repo: restore it
//     before the scan, push it back after. Main branch's .gitignore excludes
//     store/ so an operator's ordinary "git add -A" on main can never
//     swallow findings history into the wrong branch.
//
// GitHub App authorize seam (explicit, NOT exercised by this item's live
// proof): mallcop-pro already holds the GitHub App private key server-side
// and exposes POST /v1/github/token (see
// mallcop-pro/internal/server/github_token.go) to exchange a customer's
// donut-rail API key + their App installation_id for a scoped installation
// access token. proAppToken below implements that exact exchange and is unit
// tested against an httptest stand-in of the endpoint. It is not exercised
// against the live api.mallcop.app here — that needs a funded customer
// account and a real App installation, which is out of scope for the
// smallest honest v1 (see the item's DISCOVER FIRST note). The transport
// actually exercised live is envGitHubToken: a raw token from an environment
// variable (e.g. `gh auth token`'s output), used as a personal access token
// would be.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// splitOwnerRepo parses "owner/name" into its two parts. ok is false for
// anything else (missing slash, empty owner, empty name, extra slashes).
func splitOwnerRepo(ownerRepo string) (owner, name string, ok bool) {
	owner, name, found := strings.Cut(ownerRepo, "/")
	if !found || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return owner, name, true
}

// mallcopFindingsBranch is the dedicated branch (of the SAME deployment repo)
// the scaffolded workflow uses to persist store/'s nested git history across
// ephemeral Actions runs. See the D3 SAME-REPO note in the package doc.
const mallcopFindingsBranch = "mallcop-findings"

// mallcopChatBranch is the dedicated branch (of the SAME deployment repo,
// separate from mallcopFindingsBranch so scan pushes and chat pushes never
// collide) the scaffolded mallcop-investigate.yml workflow mounts the
// browser<->runner mailbox on -- see mallcop-pro's
// docs/chat-investigate-protocol.md §1 and core/investigate/gitmailbox.go
// (mallcoppro-067).
const mallcopChatBranch = "mallcop-chat"

// repoToken produces a bearer token authorized to create a repo under, and
// push to, the customer's GitHub account/org.
type repoToken interface {
	Token(ctx context.Context) (string, error)
}

// envGitHubToken reads a raw GitHub token from the named environment
// variable. This is the transport `mallcop init --create-repo` actually uses
// live in v1: whatever authorization the caller already has is passed
// through unchanged.
type envGitHubToken struct{ envVar string }

func (e envGitHubToken) Token(_ context.Context) (string, error) {
	v := os.Getenv(e.envVar)
	if v == "" {
		return "", fmt.Errorf("deploy-repo: $%s is not set (export a GitHub token with repo-create scope, e.g. `export %s=$(gh auth token)`)", e.envVar, e.envVar)
	}
	return v, nil
}

// proAppToken is the GitHub-App-authorize seam described in the package doc:
// it exchanges a mallcop donut-rail API key + GitHub App installation ID for
// a scoped installation access token via mallcop-pro's POST
// {endpoint}/v1/github/token.
type proAppToken struct {
	endpoint       string
	apiKey         string
	installationID int64
	httpClient     *http.Client
}

func (p proAppToken) Token(ctx context.Context) (string, error) {
	client := p.httpClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	body, err := json.Marshal(struct {
		InstallationID int64 `json:"installation_id"`
	}{p.installationID})
	if err != nil {
		return "", fmt.Errorf("deploy-repo: marshal token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.endpoint, "/")+"/v1/github/token", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("deploy-repo: build token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("deploy-repo: github token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", fmt.Errorf("deploy-repo: mallcop-pro returned %d: %s", resp.StatusCode, errBody.Error)
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("deploy-repo: decode token response: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("deploy-repo: mallcop-pro returned an empty token")
	}
	return out.Token, nil
}

// scaffoldDeployAssets adds the deployment-repo-only assets to dir, on top of
// whatever runInit already wrote (mallcop.yaml, store/, events.jsonl):
// go.mod (D1 pin), .gitignore (excludes store/ from main — see D3 note),
// detectors/README.md, connectors/README.md, and the scheduled-scan
// workflow. It is pure and offline — no network, no git, no GitHub calls —
// so it is fully covered by t.TempDir() unit tests. moduleName is the Go
// module name for the deployment repo's own go.mod (customer-facing,
// cosmetic); mallcopVersion is the mallcop release tag to pin (both the
// go.mod require version AND the release-binary download URL in the
// workflow point at it).
func scaffoldDeployAssets(dir, moduleName, mallcopVersion string) error {
	goModPath := filepath.Join(dir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		goMod := fmt.Sprintf("module %s\n\ngo 1.24\n\nrequire github.com/mallcop-app/mallcop %s\n", moduleName, mallcopVersion)
		if err := os.WriteFile(goModPath, []byte(goMod), 0o644); err != nil {
			return fmt.Errorf("deploy-repo: writing go.mod: %w", err)
		}
	}

	gitignorePath := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(gitignorePath); err != nil {
		gitignore := "# store/ is backed by its own git history on the '" + mallcopFindingsBranch + "' branch\n" +
			"# of this same repo (D3 SAME-REPO) -- never committed on main. See\n" +
			"# .github/workflows/scan.yml.\n/store/\ndetectors/bin/\n"
		if err := os.WriteFile(gitignorePath, []byte(gitignore), 0o644); err != nil {
			return fmt.Errorf("deploy-repo: writing .gitignore: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Join(dir, "detectors"), 0o755); err != nil {
		return fmt.Errorf("deploy-repo: creating detectors/: %w", err)
	}
	detectorsReadmePath := filepath.Join(dir, "detectors", "README.md")
	if _, err := os.Stat(detectorsReadmePath); err != nil {
		if err := os.WriteFile(detectorsReadmePath, []byte(detectorsReadmeContent), 0o644); err != nil {
			return fmt.Errorf("deploy-repo: writing detectors/README.md: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Join(dir, "connectors"), 0o755); err != nil {
		return fmt.Errorf("deploy-repo: creating connectors/: %w", err)
	}
	connectorsReadmePath := filepath.Join(dir, "connectors", "README.md")
	if _, err := os.Stat(connectorsReadmePath); err != nil {
		if err := os.WriteFile(connectorsReadmePath, []byte(connectorsReadmeContent), 0o644); err != nil {
			return fmt.Errorf("deploy-repo: writing connectors/README.md: %w", err)
		}
	}

	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		return fmt.Errorf("deploy-repo: creating .github/workflows/: %w", err)
	}
	workflowPath := filepath.Join(workflowDir, "scan.yml")
	if _, err := os.Stat(workflowPath); err != nil {
		if err := os.WriteFile(workflowPath, []byte(renderScanWorkflow(mallcopVersion)), 0o644); err != nil {
			return fmt.Errorf("deploy-repo: writing .github/workflows/scan.yml: %w", err)
		}
	}

	investigateWorkflowPath := filepath.Join(workflowDir, "mallcop-investigate.yml")
	if _, err := os.Stat(investigateWorkflowPath); err != nil {
		if err := os.WriteFile(investigateWorkflowPath, []byte(renderInvestigateWorkflow(mallcopVersion)), 0o644); err != nil {
			return fmt.Errorf("deploy-repo: writing .github/workflows/mallcop-investigate.yml: %w", err)
		}
	}

	return nil
}

// renderScanWorkflow fills scanWorkflowTemplate's version+branch placeholders.
func renderScanWorkflow(mallcopVersion string) string {
	w := strings.ReplaceAll(scanWorkflowTemplate, "{{VERSION}}", mallcopVersion)
	return strings.ReplaceAll(w, "{{FINDINGS_BRANCH}}", mallcopFindingsBranch)
}

// renderInvestigateWorkflow fills investigateWorkflowTemplate's placeholders.
func renderInvestigateWorkflow(mallcopVersion string) string {
	w := strings.ReplaceAll(investigateWorkflowTemplate, "{{VERSION}}", mallcopVersion)
	w = strings.ReplaceAll(w, "{{FINDINGS_BRANCH}}", mallcopFindingsBranch)
	return strings.ReplaceAll(w, "{{CHAT_BRANCH}}", mallcopChatBranch)
}

// refreshDeployWorkflows re-writes BOTH generated CI workflows to the pinned
// mallcopVersion, ALWAYS overwriting whatever is there (unlike
// scaffoldDeployAssets' skip-if-exists). This is the `mallcop migrate` seam:
// an existing customer deploy repo may carry a stale scan.yml and be missing
// mallcop-investigate.yml entirely (added in v0.10) — a version bump must
// force both to the current pinned release. The workflows are generated
// assets, never hand-edited, so overwriting is safe.
func refreshDeployWorkflows(dir, mallcopVersion string) error {
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		return fmt.Errorf("deploy-repo: creating .github/workflows/: %w", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "scan.yml"), []byte(renderScanWorkflow(mallcopVersion)), 0o644); err != nil {
		return fmt.Errorf("deploy-repo: writing .github/workflows/scan.yml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "mallcop-investigate.yml"), []byte(renderInvestigateWorkflow(mallcopVersion)), 0o644); err != nil {
		return fmt.Errorf("deploy-repo: writing .github/workflows/mallcop-investigate.yml: %w", err)
	}
	return nil
}

// refreshGoMod bumps the pinned github.com/mallcop-app/mallcop require version
// in dir/go.mod to mallcopVersion, so sidecar-detector builds in CI compile
// against the SAME release the workflow downloads (D1 THIN-EMBED). It only
// rewrites the one require line; the module name and go directive are left
// untouched. A go.mod with no mallcop require line, or no go.mod at all, is
// left as-is (returns hadPin=false) so the caller can warn rather than fail.
func refreshGoMod(dir, mallcopVersion string) (hadPin bool, err error) {
	goModPath := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("deploy-repo: reading go.mod: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	rewrote := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "require github.com/mallcop-app/mallcop ") {
			lines[i] = "require github.com/mallcop-app/mallcop " + mallcopVersion
			rewrote = true
		}
	}
	if !rewrote {
		return false, nil
	}
	if err := os.WriteFile(goModPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return false, fmt.Errorf("deploy-repo: writing go.mod: %w", err)
	}
	return true, nil
}

const detectorsReadmeContent = `# detectors/

Author a wasip1 WASM sidecar detector here, one subdirectory per detector
(package main). The scheduled Action (../.github/workflows/scan.yml) builds
every detectors/<name>/ with a main.go to detectors/bin/<name>.wasm and
'mallcop scan' loads it exactly like a built-in framework detector (see
cfg.Detectors.Sidecars.Dir).

Minimal shape (see github.com/mallcop-app/mallcop/examples/sidecar-detector
in the pinned mallcop module — go.mod at the repo root — for the full
worked example):

    package main

    import (
        "os"

        "github.com/mallcop-app/mallcop/core/detect"
        "github.com/mallcop-app/mallcop/pkg/baseline"
        "github.com/mallcop-app/mallcop/pkg/detectorhost"
        "github.com/mallcop-app/mallcop/pkg/event"
        "github.com/mallcop-app/mallcop/pkg/finding"
    )

    type myDetector struct{}

    func (myDetector) Name() string { return "my-detector" }
    func (myDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
        // ...
        return nil
    }

    func main() { os.Exit(detectorhost.Run(myDetector{})) }

D1 THIN-EMBED: this repo's go.mod pins github.com/mallcop-app/mallcop so you
get these types from the published module — never fork or vendor mallcop's
source. NEVER hand-write the CI build step to compile the whole mallcop
binary from this directory: the core 'mallcop' binary running in CI is
always the pinned prebuilt release; only detectors/<name>/ compiles here, and
only to wasip1/wasm.
`

const connectorsReadmeContent = `# connectors/

Author a new connector here as a standalone Go binary (AI-written code, same
shape as the shipped sibling connectors in
github.com/mallcop-app/mallcop-connectors) — never a declarative spec file.
There is no data->engine loader for connectors: a connector is a real program
that reads its source's audit log and emits normalized event JSONL on stdout.

Wire it into a scan via a 'kind: cloud' entry in '../mallcop.yaml':

    connectors:
      - kind: cloud
        id: my-source
        source: my-source
        binary: ./connectors/bin/mallcop-connector-my-source
        env: [MY_SOURCE_TOKEN]

'mallcop scan' forks 'binary' (or 'mallcop-connector-<source>' on $PATH when
binary is empty) as a subprocess and reads its stdout as event JSONL — the
same convention the shipped standalone connectors (AWS CloudTrail, Azure
Activity Log, GCP Cloud Logging, GitHub Audit Log, M365, Okta) already use.
Build it into 'connectors/bin/' however you like (a Go program, 'go build');
this repo's scaffolded CI does not compile it for you.
`

// scanWorkflowTemplate is the scheduled-scan Action SKELETON (mallcoppro-f3b
// scope): checkout, install the pinned mallcop release binary, build wasip1
// sidecar detectors, run 'mallcop scan', persist findings. The scan/notify/
// triage CONTENT beyond this build+basic-scan skeleton belongs to a
// different item (977) — this workflow is the seam it extends.
const scanWorkflowTemplate = `name: mallcop scheduled scan

# SKELETON (mallcoppro-f3b; self-heal S5 rev): checkout, install the pinned
# mallcop release binary, build wasip1 sidecar detectors, run 'mallcop scan',
# persist findings on the '{{FINDINGS_BRANCH}}' branch, publish coverage gaps
# (store/gaps.json) for 'mallcop status', and FAIL the run on a recall red
# (Baron FAIL-ON-MISS). Scan/notify/triage CONTENT beyond this build+basic-scan
# skeleton is a separate item (977) that extends this workflow.
#
# D2+2fd ruling: this workflow NEVER rebuilds the whole mallcop binary from
# repo content. The core binary is always the pinned prebuilt release
# tarball below; the only thing ever compiled from this repo is each
# detectors/<name>/, and only to wasip1/wasm.
on:
  schedule:
    - cron: '0 * * * *'
  workflow_dispatch: {}

permissions:
  contents: write

env:
  MALLCOP_VERSION: "{{VERSION}}"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout deployment repo
        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1 -- pinned by commit SHA (mallcoppro-796): a mutable tag can be repointed at malicious code, and these workflows run with contents:write and hold MALLCOP_API_KEY

      - name: Determine pinned-release asset for this runner
        # Maps the Actions-provided RUNNER_OS/RUNNER_ARCH to the exact asset
        # name mallcop's release workflow publishes (see mallcop-app/mallcop's
        # releases: mallcop-linux-amd64.tar.gz, mallcop-linux-arm64.tar.gz,
        # mallcop-darwin-arm64.tar.gz). Never hardcodes a single arch, so this
        # workflow keeps working if the customer ever moves scan.yml's
        # runs-on to an arm64 or macOS runner.
        id: platform
        run: |
          set -euo pipefail
          case "${RUNNER_OS}-${RUNNER_ARCH}" in
            Linux-X64) echo "asset=linux-amd64" >> "$GITHUB_OUTPUT" ;;
            Linux-ARM64) echo "asset=linux-arm64" >> "$GITHUB_OUTPUT" ;;
            macOS-ARM64) echo "asset=darwin-arm64" >> "$GITHUB_OUTPUT" ;;
            *)
              echo "no published mallcop release asset for ${RUNNER_OS}-${RUNNER_ARCH}" >&2
              exit 1
              ;;
          esac

      - name: Install pinned mallcop release binary
        env:
          MALLCOP_ASSET: ${{ steps.platform.outputs.asset }}
        run: |
          set -euo pipefail
          curl -fsSLO "https://github.com/mallcop-app/mallcop/releases/download/${MALLCOP_VERSION}/mallcop-${MALLCOP_ASSET}.tar.gz"
          curl -fsSLO "https://github.com/mallcop-app/mallcop/releases/download/${MALLCOP_VERSION}/mallcop-${MALLCOP_ASSET}.tar.gz.sha256"
          # INTEGRITY, not authenticity (mallcoppro-796): the .sha256 is co-hosted
          # on the same Releases URL as the tarball, so this catches corruption/
          # truncation but NOT a compromised release that swaps both files. Real
          # tamper-resistance (keyless build-provenance attestation verified with
          # gh attestation verify) is tracked as a follow-up; it must ship in
          # the release pipeline BEFORE the templates verify, or every scan breaks.
          sha256sum -c "mallcop-${MALLCOP_ASSET}.tar.gz.sha256"
          tar -xzf "mallcop-${MALLCOP_ASSET}.tar.gz"
          echo "$PWD/bin" >> "$GITHUB_PATH"

      - name: Set up Go (sidecar builds only -- never the core binary)
        uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5.6.0 -- pinned by commit SHA (mallcoppro-796)
        with:
          go-version: '1.24'

      - name: Build wasip1 sidecar detectors
        # GOFLAGS=-mod=mod mirrors cli/sidecars.go's
        # buildAndRegisterSourceSidecar: this repo's go.mod pins
        # github.com/mallcop-app/mallcop (D1 THIN-EMBED) but a customer
        # editing detectors/ may not have re-run 'go mod tidy' after adding an
        # import -- -mod=mod lets 'go build' complete the go.sum itself
        # (from the module cache or GOPROXY) instead of hard-failing with
        # "missing go.sum entry", exactly like a customer's own 'go build'
        # would need to.
        env:
          GOFLAGS: -mod=mod
        run: |
          set -euo pipefail
          mkdir -p detectors/bin
          shopt -s nullglob
          any=0
          for d in detectors/*/; do
            [ -f "${d}main.go" ] || continue
            any=1
          done
          if [ "$any" = "1" ]; then
            go mod tidy
          fi
          for d in detectors/*/; do
            name="$(basename "$d")"
            [ -f "${d}main.go" ] || continue
            echo "building sidecar: ${name}"
            GOOS=wasip1 GOARCH=wasm go build -o "detectors/bin/${name}.wasm" "./${d}"
          done

      - name: Restore findings store from previous runs
        run: |
          set -euo pipefail
          rm -rf store
          git clone --quiet --depth 1 --branch "{{FINDINGS_BRANCH}}" --single-branch \
            "https://x-access-token:${TOKEN}@github.com/${REPO}.git" store \
            || mkdir -p store
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
          REPO: ${{ github.repository }}

      - name: Run mallcop scan
        # Exit codes (see cli/main.go): 0 = no findings, 1 = findings
        # detected (expected, NOT a workflow failure), 2 = real scan failure.
        # MALLCOP_API_KEY is scoped to only THIS step's env (mallcoppro-c32):
        # a job-level env would expose the inference credential to every
        # other step in this job, including the third-party
        # actions/setup-go@v5 action above.
        env:
          MALLCOP_API_KEY: ${{ secrets.MALLCOP_API_KEY }}
        run: |
          set +e
          mallcop scan
          code=$?
          set -e
          if [ "$code" != "0" ] && [ "$code" != "1" ]; then
            exit "$code"
          fi

      - name: Publish coverage gaps (self-heal loop)
        # SELF-HEAL (S5): mine THIS scan's store for coverage gaps and publish
        # them as store/gaps.json on the '{{FINDINGS_BRANCH}}' branch so
        # 'mallcop status' can surface per-operator detected misses (operator
        # report-miss reports + override/dissent gaps). Offline, deterministic,
        # NO inference key needed. gaps.json is committed on ONLY its own path
        # (it stages just that one file, never the whole tree) so this never
        # restages the working tree the way the mallcoppro-f3b finding warned about.
        run: |
          set -euo pipefail
          if [ -d store/.git ]; then
            mallcop collect --json --store ./store > store/gaps.json
            git -C store add gaps.json
            git -C store -c user.name=mallcop-collect -c user.email=collect@mallcop.app \
              diff --cached --quiet \
              || git -C store -c user.name=mallcop-collect -c user.email=collect@mallcop.app \
                   commit --quiet -m "mallcop collect: publish coverage gaps"
          fi

      - name: Push findings store
        # 'mallcop scan' (core/store) already durably COMMITS every stream
        # write as it runs -- this step only PUSHES whatever store/'s current
        # HEAD is to the '{{FINDINGS_BRANCH}}' branch so it survives past this
        # ephemeral runner. It deliberately never runs its own 'git add'/
        # 'git commit' inside store/: that would restage the working tree,
        # which a live proof run of this item found can be left in a
        # deletion-staged (but uncommitted) state after 'mallcop scan' exits
        # -- see mallcoppro-f3b's reported finding. Pushing HEAD as-is only
        # ever ships what mallcop scan itself already committed.
        run: |
          set -euo pipefail
          if [ -d store/.git ]; then
            git -C store push --quiet \
              "https://x-access-token:${TOKEN}@github.com/${REPO}.git" \
              HEAD:refs/heads/{{FINDINGS_BRANCH}}
          fi
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
          REPO: ${{ github.repository }}

      - name: Fail on recall red (missed known attack)
        # BARON FAIL-ON-MISS RULING (S5): a RECALL RED — a missed known attack on
        # a non-reserved label, i.e. an operator report-miss (or a detect_miss
        # when an exam fidelity dump is supplied) — must FAIL the scheduled scan
        # at EVERY autonomy dial. Precision-only gaps (override_fp, dissent) do
        # NOT gate. 'mallcop collect --gate' exits 1 iff a recall red is present.
        # This step runs LAST, AFTER the store + gaps.json are already pushed, so
        # the coverage evidence is durably published even on a failing run.
        run: |
          set -euo pipefail
          mallcop collect --gate --store ./store
`

// investigateWorkflowTemplate is the mallcop-investigate.yml SKELETON
// (mallcoppro-067): workflow_dispatch(session_id) -> install the pinned
// mallcop release binary (never rebuilds from customer code, same D2+2fd
// ruling as scanWorkflowTemplate) -> restore the findings store from
// '{{FINDINGS_BRANCH}}' (same pattern as scan.yml) -> run the long-lived
// `mallcop investigate --serve --session <id> --chat-branch {{CHAT_BRANCH}}`
// session-mailbox loop (core/investigate/gitmailbox.go). Boundary invariant
// (docs/chat-investigate-protocol.md): all agent logic, store contents, and
// the inference credential stay in THIS runner -- only the natural-language
// question/answer trace crosses via the '{{CHAT_BRANCH}}' branch of this
// same repo, never findings/events/baseline/credentials.
const investigateWorkflowTemplate = `name: mallcop investigate (chat)

# SKELETON (mallcoppro-067): checkout the deployment repo, install the pinned
# mallcop release binary, restore the findings store, and run the
# long-lived 'mallcop investigate --serve' session-mailbox loop for
# inputs.session_id. See core/investigate/gitmailbox.go and mallcop-pro's
# docs/chat-investigate-protocol.md for the full protocol this implements.
#
# D2+2fd ruling (shared with scan.yml): this workflow NEVER rebuilds the
# whole mallcop binary from repo content -- the core binary run here is
# always the pinned prebuilt release tarball below.
on:
  workflow_dispatch:
    inputs:
      session_id:
        description: 'Chat session id -- sessions/<session_id>/ on the {{CHAT_BRANCH}} branch'
        required: true
        type: string

permissions:
  contents: write

env:
  MALLCOP_VERSION: "{{VERSION}}"

jobs:
  investigate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout deployment repo
        # fetch-depth 1 (shallow): a FULL-history checkout (fetch-depth 0)
        # HANGS on real deploy repos whose store branches carry a large,
        # ever-growing events.jsonl in history (mallcoppro-5b7). The runner
        # does NOT need full history here: GitMailbox.OpenGitMailbox does its
        # own explicit git fetch of the {{CHAT_BRANCH}} branch before checking
        # out / creating the mailbox branch, and actions/checkout@v4's
        # persisted 'origin' credential authorizes that fetch/push.
        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1 -- pinned by commit SHA (mallcoppro-796): a mutable tag can be repointed at malicious code, and these workflows run with contents:write and hold MALLCOP_API_KEY
        with:
          fetch-depth: 1

      - name: Determine pinned-release asset for this runner
        # Maps the Actions-provided RUNNER_OS/RUNNER_ARCH to the exact asset
        # name mallcop's release workflow publishes -- mirrors scan.yml's
        # own platform-detection step exactly.
        id: platform
        run: |
          set -euo pipefail
          case "${RUNNER_OS}-${RUNNER_ARCH}" in
            Linux-X64) echo "asset=linux-amd64" >> "$GITHUB_OUTPUT" ;;
            Linux-ARM64) echo "asset=linux-arm64" >> "$GITHUB_OUTPUT" ;;
            macOS-ARM64) echo "asset=darwin-arm64" >> "$GITHUB_OUTPUT" ;;
            *)
              echo "no published mallcop release asset for ${RUNNER_OS}-${RUNNER_ARCH}" >&2
              exit 1
              ;;
          esac

      - name: Install pinned mallcop release binary
        env:
          MALLCOP_ASSET: ${{ steps.platform.outputs.asset }}
        run: |
          set -euo pipefail
          curl -fsSLO "https://github.com/mallcop-app/mallcop/releases/download/${MALLCOP_VERSION}/mallcop-${MALLCOP_ASSET}.tar.gz"
          curl -fsSLO "https://github.com/mallcop-app/mallcop/releases/download/${MALLCOP_VERSION}/mallcop-${MALLCOP_ASSET}.tar.gz.sha256"
          # INTEGRITY, not authenticity (mallcoppro-796): the .sha256 is co-hosted
          # on the same Releases URL as the tarball, so this catches corruption/
          # truncation but NOT a compromised release that swaps both files. Real
          # tamper-resistance (keyless build-provenance attestation verified with
          # gh attestation verify) is tracked as a follow-up; it must ship in
          # the release pipeline BEFORE the templates verify, or every scan breaks.
          sha256sum -c "mallcop-${MALLCOP_ASSET}.tar.gz.sha256"
          tar -xzf "mallcop-${MALLCOP_ASSET}.tar.gz"
          echo "$PWD/bin" >> "$GITHUB_PATH"

      - name: Restore findings store from previous runs
        # Identical pattern to scan.yml: store/ is its own nested git repo
        # (D3 SAME-REPO), backed by the '{{FINDINGS_BRANCH}}' branch of this
        # same deployment repo, restored via an explicit x-access-token URL
        # because this nested checkout is NOT covered by the top-level
        # actions/checkout@v4 credential above.
        run: |
          set -euo pipefail
          rm -rf store
          git clone --quiet --depth 1 --branch "{{FINDINGS_BRANCH}}" --single-branch \
            "https://x-access-token:${TOKEN}@github.com/${REPO}.git" store \
            || mkdir -p store
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
          REPO: ${{ github.repository }}

      - name: Run mallcop investigate --serve
        # The long-lived session-mailbox loop: reads
        # sessions/<session_id>/inbox.jsonl and appends
        # sessions/<session_id>/outbox.jsonl on the '{{CHAT_BRANCH}}' branch
        # of THIS repo (--repo .), self-exiting on idle timeout or a
        # control:shutdown record -- see core/investigate/gitmailbox.go.
        # Inference is metered via MALLCOP_API_KEY (the mallcop-sk repo
        # secret), same rail as 'mallcop scan'. MALLCOP_API_KEY is scoped to
        # only THIS step's env (mallcoppro-c32): a job-level env would expose
        # the inference credential to every other step in this job, including
        # the third-party actions/checkout@v4 action above.
        run: |
          set -euo pipefail
          mallcop investigate --serve \
            --session "${SESSION_ID}" \
            --chat-branch "{{CHAT_BRANCH}}" \
            --chat-remote origin \
            --repo . \
            --store ./store
        env:
          SESSION_ID: ${{ inputs.session_id }}
          MALLCOP_API_KEY: ${{ secrets.MALLCOP_API_KEY }}
`

// deployRepoResult is returned by createAndPushDeployRepo with everything a
// caller (runInit's --create-repo path) needs to print.
type deployRepoResult struct {
	HTMLURL  string
	CloneURL string
}

// githubAPIRepo is the subset of GitHub's repo-creation response this file
// reads.
type githubAPIRepo struct {
	HTMLURL  string `json:"html_url"`
	CloneURL string `json:"clone_url"`
}

// createGitHubRepo creates a new repository named `name` for `owner` via
// GitHub's REST API. It tries the org-repos endpoint first (POST
// /orgs/{owner}/repos); a 404 there means owner isn't an org (the common
// case: owner is the authenticated user), so it falls back to POST
// /user/repos, which creates the repo under whichever account the token
// belongs to (the caller is responsible for passing a token whose account
// matches `owner` in that case).
func createGitHubRepo(ctx context.Context, httpClient *http.Client, token, owner, name string) (*githubAPIRepo, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	payload, err := json.Marshal(map[string]any{
		"name":        name,
		"private":     true,
		"description": "mallcop scheduled-scan deployment repo",
	})
	if err != nil {
		return nil, fmt.Errorf("deploy-repo: marshal create-repo request: %w", err)
	}

	do := func(url string) (*githubAPIRepo, int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, 0, fmt.Errorf("deploy-repo: build create-repo request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("deploy-repo: create-repo request failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			var errBody struct {
				Message string `json:"message"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&errBody)
			return nil, resp.StatusCode, fmt.Errorf("deploy-repo: github returned %d creating %s: %s", resp.StatusCode, url, errBody.Message)
		}
		var out githubAPIRepo
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("deploy-repo: decode create-repo response: %w", err)
		}
		return &out, resp.StatusCode, nil
	}

	orgURL := fmt.Sprintf("https://api.github.com/orgs/%s/repos", owner)
	repo, status, err := do(orgURL)
	if err == nil {
		return repo, nil
	}
	if status != http.StatusNotFound {
		return nil, err
	}
	// owner isn't an org (or the token can't see it as one) -- fall back to
	// the authenticated user's own account.
	repo, _, err = do("https://api.github.com/user/repos")
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// runGit runs a git subcommand rooted at dir, returning combined output on
// error so failures are debuggable (mirrors core/store.go's own git-wrapping
// convention).
func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("deploy-repo: git %v in %q: %w\n%s", args, dir, err, out)
	}
	return nil
}

// createAndPushDeployRepo creates a real GitHub repo for ownerRepo
// ("owner/name") and pushes dir's current contents to it as the initial
// commit on main. dir must already be scaffolded (runInit + scaffoldDeployAssets).
func createAndPushDeployRepo(ctx context.Context, dir, ownerRepo string, tok repoToken) (*deployRepoResult, error) {
	owner, name, ok := splitOwnerRepo(ownerRepo)
	if !ok {
		return nil, fmt.Errorf("deploy-repo: --create-repo wants \"owner/name\", got %q", ownerRepo)
	}

	token, err := tok.Token(ctx)
	if err != nil {
		return nil, err
	}

	repo, err := createGitHubRepo(ctx, nil, token, owner, name)
	if err != nil {
		return nil, err
	}

	if err := runGit(dir, "init", "-q", "-b", "main"); err != nil {
		return nil, err
	}
	if err := runGit(dir, "add", "-A"); err != nil {
		return nil, err
	}
	if err := runGit(dir, "-c", "user.name=mallcop-init", "-c", "user.email=init@mallcop.app", "commit", "-q", "-m", "mallcop init: scaffold deployment repo"); err != nil {
		return nil, err
	}

	remoteURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, owner, name)
	if err := runGit(dir, "remote", "add", "origin", remoteURL); err != nil {
		return nil, err
	}
	if err := runGit(dir, "push", "-q", "-u", "origin", "main"); err != nil {
		return nil, err
	}

	return &deployRepoResult{HTMLURL: repo.HTMLURL, CloneURL: repo.CloneURL}, nil
}

// latestMallcopRelease queries GitHub for the latest published
// mallcop-app/mallcop release tag, used as the default --mallcop-version
// when the flag is omitted.
func latestMallcopRelease(ctx context.Context, httpClient *http.Client) (string, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/mallcop-app/mallcop/releases/latest", nil)
	if err != nil {
		return "", fmt.Errorf("deploy-repo: build latest-release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("deploy-repo: latest-release request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("deploy-repo: github returned %d fetching latest release", resp.StatusCode)
	}
	var out struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("deploy-repo: decode latest-release response: %w", err)
	}
	if out.TagName == "" {
		return "", fmt.Errorf("deploy-repo: github returned no tag_name for the latest release")
	}
	return out.TagName, nil
}
