package contribback

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runFunc runs a command and returns its combined output. Injectable for tests;
// the default shells out via os/exec.
type runFunc func(ctx context.Context, name string, args ...string) (string, error)

func execRun(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// IMPORTANT (design ruling R8): we do NOT set GH_TOKEN, GITHUB_TOKEN, or any
	// credential into the child environment. gh authenticates as the OPERATOR
	// from their ambient `gh auth` state. The operator binary holds no standing
	// write credential to the shared repo — the operator's own identity opens the PR.
	// cmd.Env stays nil so the child inherits the operator's environment verbatim.
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ghOpener opens the shared-OSS PR by shelling out to `gh pr create` under the
// OPERATOR's identity. It stores NO credential: `gh` resolves auth from the
// operator's ambient environment. There is no merge method — merging is the OSS
// maintainers' job (R3/R8).
type ghOpener struct {
	// bin is the gh binary name/path. Empty defaults to "gh".
	bin string
	// run is the command runner. Nil defaults to execRun.
	run runFunc
}

// NewGHOpener returns a PROpener that opens shared-OSS PRs via `gh pr create`
// under the operator's ambient identity. bin empty → "gh".
func NewGHOpener(bin string) PROpener {
	return &ghOpener{bin: bin}
}

func (g *ghOpener) binary() string {
	if strings.TrimSpace(g.bin) == "" {
		return "gh"
	}
	return g.bin
}

func (g *ghOpener) runner() runFunc {
	if g.run != nil {
		return g.run
	}
	return execRun
}

// ghArgs builds the `gh pr create` argument vector for req. Factored out so a
// test can assert the exact arguments — and, critically, that NO token/credential
// flag is ever included (operator identity, R8).
func ghArgs(req PRRequest) []string {
	return []string{
		"pr", "create",
		"--repo", req.Repo,
		"--base", req.BaseBranch,
		"--head", req.HeadBranch,
		"--title", req.Title,
		"--body", req.Body,
	}
}

// OpenPR shells out to `gh pr create` and returns the opened PR URL (gh prints
// the URL to stdout). The head branch must already be pushed to the shared repo
// (or the operator's fork) — pushing is the operator's git step, done under their
// identity; this call only opens the PR. It NEVER merges.
func (g *ghOpener) OpenPR(ctx context.Context, req PRRequest) (PRResult, error) {
	if strings.TrimSpace(req.Repo) == "" {
		return PRResult{}, fmt.Errorf("ghOpener: empty repo")
	}
	out, err := g.runner()(ctx, g.binary(), ghArgs(req)...)
	if err != nil {
		return PRResult{}, fmt.Errorf("gh pr create: %w: %s", err, strings.TrimSpace(out))
	}
	url := parsePRURL(out)
	if url == "" {
		return PRResult{}, fmt.Errorf("gh pr create: no PR URL in output: %q", strings.TrimSpace(out))
	}
	return PRResult{URL: url}, nil
}

// parsePRURL extracts the first GitHub PR URL from gh's output.
func parsePRURL(out string) string {
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "https://") && strings.Contains(f, "/pull/") {
			return f
		}
	}
	return ""
}
