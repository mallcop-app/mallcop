// Package sandbox provides a git-worktree write jail and an env-scrubbed
// subprocess environment for mallcop's self-extension code-authoring engine.
//
// The jail is a detached git worktree of the TARGET repo (the repository being
// extended), NOT the caller's own working repo. The code-authoring subprocess
// (opencode) is confined to the worktree via its --dir flag; the safety gate
// later runs with the worktree as its cwd. On teardown the worktree is
// force-removed.
//
// # Egress / isolation — HONEST LIMIT
//
// ScrubbedEnv builds a minimal env allowlist and deliberately omits every
// operator credential (the inference provider's admin key, credential-manager
// sessions, cloud keys, VCS tokens). That prevents CREDENTIAL INHERITANCE and
// points the child at the inference endpoint — but it is NOT an OS-level egress
// jail. Without a netns/Landlock/seccomp sandbox the child process retains raw
// network + filesystem syscall capability; process-env scrubbing cannot truly
// confine egress. The real OS-level jail (an ephemeral GHA runner + network
// policy) is tracked separately and is the required follow-on before this engine
// runs authored code with real spend outside review.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// defaultBaseRef is the ref a Jail worktrees when Jail.BaseRef is empty.
const defaultBaseRef = "origin/main"

// ProviderName is the opencode provider key the subprocess config declares.
// The authoring model is referenced as "<ProviderName>/<lane>" — an
// OpenAI-compatible provider pointed at the inference endpoint.
const ProviderName = "forge"

// Jail creates detached git worktrees of a target repository.
type Jail struct {
	// TargetRepo is the path to the target git repository (the repo being
	// extended). It MUST be a real git repo, validated by Open before use. It is
	// NOT the caller's own working repo.
	TargetRepo string
	// BaseRef is the ref the worktree is checked out from. Empty → "origin/main".
	BaseRef string
}

// Worktree is an open detached worktree write jail plus its throwaway scratch
// dirs. Dir is the path passed to the subprocess (--dir) and to the gate (cwd).
type Worktree struct {
	// Dir is the worktree write-jail path.
	Dir string
	// BaseSHA is the resolved commit the worktree was created from.
	BaseSHA string

	repo    string // the target repo path (for worktree remove)
	tmpRoot string // parent temp dir holding Dir + scratch dirs
	homeDir string // throwaway $HOME for the subprocess
	tmpDir  string // throwaway $TMPDIR for the subprocess
}

// Open validates the target repo, resolves the base ref to a SHA, and creates
// a detached worktree plus throwaway HOME/TMPDIR scratch dirs. On any failure
// it cleans up whatever it created and returns an error.
func (j *Jail) Open(ctx context.Context) (*Worktree, error) {
	if j.TargetRepo == "" {
		return nil, errors.New("sandbox: TargetRepo is empty")
	}
	baseRef := j.BaseRef
	if baseRef == "" {
		baseRef = defaultBaseRef
	}

	// Validate TargetRepo is a git repository before touching anything.
	if _, err := runGit(ctx, j.TargetRepo, "rev-parse", "--git-dir"); err != nil {
		return nil, fmt.Errorf("sandbox: %q is not a git repository: %w", j.TargetRepo, err)
	}

	// Resolve the base ref to a concrete commit SHA.
	out, err := runGit(ctx, j.TargetRepo, "rev-parse", "--verify", baseRef+"^{commit}")
	if err != nil {
		return nil, fmt.Errorf("sandbox: resolve base ref %q: %w", baseRef, err)
	}
	baseSHA := strings.TrimSpace(string(out))

	tmpRoot, err := os.MkdirTemp("", "selfext-jail-")
	if err != nil {
		return nil, fmt.Errorf("sandbox: create temp root: %w", err)
	}
	wtDir := filepath.Join(tmpRoot, "worktree") // git creates this; must not pre-exist
	homeDir := filepath.Join(tmpRoot, "home")
	tmpDir := filepath.Join(tmpRoot, "tmp")
	for _, d := range []string{homeDir, tmpDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			_ = os.RemoveAll(tmpRoot)
			return nil, fmt.Errorf("sandbox: create scratch dir %q: %w", d, err)
		}
	}

	if _, err := runGit(ctx, j.TargetRepo, "worktree", "add", "--detach", wtDir, baseSHA); err != nil {
		_ = os.RemoveAll(tmpRoot)
		return nil, fmt.Errorf("sandbox: add worktree: %w", err)
	}

	return &Worktree{
		Dir:     wtDir,
		BaseSHA: baseSHA,
		repo:    j.TargetRepo,
		tmpRoot: tmpRoot,
		homeDir: homeDir,
		tmpDir:  tmpDir,
	}, nil
}

// ScrubbedEnv builds the minimal environment for the code-authoring subprocess.
// It exposes ONLY: PATH (so node/opencode resolve), a throwaway HOME and
// TMPDIR inside the jail, and OPENCODE_CONFIG_CONTENT carrying an
// OpenAI-compatible provider config with the inference endpoint base URL and the
// run key.
//
// It NEVER copies os.Environ() wholesale and deliberately omits operator
// credentials (the inference provider's API key, credential-manager sessions,
// cloud keys, VCS tokens). The run key is embedded only inside the provider
// config — never as a bare env var. See the package doc for the honest
// egress-isolation limit.
func (w *Worktree) ScrubbedEnv(subkey, forgeBaseURL string) []string {
	cfg := opencodeConfig{
		Schema: "https://opencode.ai/config.json",
		Provider: map[string]opencodeProvider{
			ProviderName: {
				NPM:  "@ai-sdk/openai-compatible",
				Name: "Forge",
				Options: opencodeProviderOptions{
					BaseURL: openAIBaseURL(forgeBaseURL),
					APIKey:  subkey,
				},
			},
		},
	}
	// Marshal cannot fail for this concrete struct.
	blob, _ := json.Marshal(cfg)

	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + w.homeDir,
		"TMPDIR=" + w.tmpDir,
		"OPENCODE_CONFIG_CONTENT=" + string(blob),
	}
}

// CommitAuthored stages every change in the worktree and commits it so HEAD is
// a ref the gate can diff against. The message is written to a temp file and
// passed via `commit -F` (never inline -m). A throwaway identity is set on the
// invocation so the commit succeeds regardless of the repo's git config.
// Returns the new HEAD SHA.
func (w *Worktree) CommitAuthored(ctx context.Context, msg string) (string, error) {
	if _, err := runGit(ctx, w.Dir, "add", "-A"); err != nil {
		return "", fmt.Errorf("sandbox: stage changes: %w", err)
	}
	msgFile := filepath.Join(w.tmpRoot, "commit-msg.txt")
	if err := os.WriteFile(msgFile, []byte(msg), 0o600); err != nil {
		return "", fmt.Errorf("sandbox: write commit message: %w", err)
	}
	if _, err := runGit(ctx, w.Dir,
		"-c", "user.name=mallcop-selfext",
		"-c", "user.email=selfext@mallcop.app",
		"commit", "-F", msgFile,
	); err != nil {
		return "", fmt.Errorf("sandbox: commit: %w", err)
	}
	out, err := runGit(ctx, w.Dir, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("sandbox: resolve HEAD: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Diff returns the unified diff from the base SHA to HEAD — the artifact patch
// emitted for human review.
func (w *Worktree) Diff(ctx context.Context) ([]byte, error) {
	out, err := runGit(ctx, w.Dir, "diff", w.BaseSHA+"..HEAD")
	if err != nil {
		return nil, fmt.Errorf("sandbox: diff: %w", err)
	}
	return out, nil
}

// MergeToTargetBranch is the "fully" autonomy MERGE AUTOMATION step: it
// force-updates branch in the TARGET repo (w.repo, NOT the
// worktree) to point at the worktree's current HEAD.
//
// This is a plain local ref update (`git branch -f`), never a checkout, a
// push, or a PR: it never touches the target repo's own checked-out working
// tree (if any), and nothing leaves the local git object database — the
// worktree and the target repo already share one (linked worktrees), so the
// commit is already present there; this just names it. The worktree jail's
// env-scrubbed subprocess (ScrubbedEnv) never carries GITHUB_TOKEN/GH_TOKEN in
// the first place, so a push was never possible even if code tried.
func (w *Worktree) MergeToTargetBranch(ctx context.Context, branch string) error {
	if strings.TrimSpace(branch) == "" {
		return errors.New("sandbox: MergeToTargetBranch: branch is empty")
	}
	head, err := runGit(ctx, w.Dir, "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("sandbox: resolve worktree HEAD: %w", err)
	}
	if _, err := runGit(ctx, w.repo, "branch", "-f", branch, strings.TrimSpace(string(head))); err != nil {
		return fmt.Errorf("sandbox: merge automation: force-update branch %q: %w", branch, err)
	}
	return nil
}

// Close force-removes the worktree and deletes the throwaway scratch dirs. It
// is best-effort: it always attempts both steps and joins any errors. Safe to
// call in a defer even after ctx is canceled (it uses a fresh context).
func (w *Worktree) Close() error {
	var errs []error
	if w.repo != "" && w.Dir != "" {
		if _, err := runGit(context.Background(), w.repo, "worktree", "remove", "--force", w.Dir); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: remove worktree: %w", err))
		}
	}
	if w.tmpRoot != "" {
		if err := os.RemoveAll(w.tmpRoot); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: remove temp root: %w", err))
		}
	}
	return errors.Join(errs...)
}

// JailWritePaths is the exact set of directories the OS-enforced authoring jail
// (the jail package) must grant the opencode child READ+WRITE access to —
// everything else on the filesystem is read-only. It is:
//
//   - tmpRoot: the parent of the worktree, throwaway HOME, and TMPDIR, so the
//     child can author files, populate its scratch HOME, and use its TMPDIR; and
//   - the target repo's .git dir: a detached worktree writes its index/HEAD/logs
//     through the main repo's .git/worktrees/<name>, so git operations the child
//     runs under --dir must be able to write there — but NOT to the repo's tracked
//     working tree, which stays read-only so authoring cannot alter source outside
//     its own worktree.
//
// Only existing directories are returned (Landlock rejects a rule for a missing
// path); a caller applying these is fail-closed by construction.
func (w *Worktree) JailWritePaths() []string {
	var out []string
	if w.tmpRoot != "" {
		if fi, err := os.Stat(w.tmpRoot); err == nil && fi.IsDir() {
			out = append(out, w.tmpRoot)
		}
	}
	if w.repo != "" {
		gitDir := filepath.Join(w.repo, ".git")
		if fi, err := os.Stat(gitDir); err == nil && fi.IsDir() {
			out = append(out, gitDir)
		}
	}
	return out
}

// opencodeConfig is the subset of the opencode config schema we emit: a single
// OpenAI-compatible provider pointed at the inference endpoint.
type opencodeConfig struct {
	Schema   string                      `json:"$schema"`
	Provider map[string]opencodeProvider `json:"provider"`
}

type opencodeProvider struct {
	NPM     string                  `json:"npm"`
	Name    string                  `json:"name"`
	Options opencodeProviderOptions `json:"options"`
}

type opencodeProviderOptions struct {
	BaseURL string `json:"baseURL"`
	APIKey  string `json:"apiKey"`
}

// openAIBaseURL derives the OpenAI-compatible base URL (the inference endpoint
// serves POST /v1/chat/completions) from the endpoint base URL, appending /v1
// unless already present.
func openAIBaseURL(forgeBaseURL string) string {
	b := strings.TrimRight(forgeBaseURL, "/")
	if strings.HasSuffix(b, "/v1") {
		return b
	}
	return b + "/v1"
}

// runGit runs `git -C dir <args...>`, returning stdout. On failure the error
// carries stderr for diagnosis.
func runGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	full := append([]string{"-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
