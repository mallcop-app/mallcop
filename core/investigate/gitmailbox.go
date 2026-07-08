// gitmailbox.go — the git-branch mailbox transport specified in
// docs/chat-investigate-protocol.md §1, §2, §4, §6 (mallcop-pro repo,
// mallcoppro-067). serve.go (mallcoppro-255/#158) already implements the
// inbox/outbox READ/APPEND loop against plain local files; this file backs
// those files with a real git working tree checked out to a dedicated
// `mallcop-chat` branch of the customer's own repo, so the browser and the
// runner rendezvous through the repo instead of through mallcop-pro's
// servers.
//
// Single-writer-per-file (protocol §1) is enforced structurally, not by
// convention: GitMailbox's Push only ever `git add`s the session's
// outbox.jsonl. It never stages, reads-to-mutate, or commits inbox.jsonl or
// meta.json — those are the browser's files. Serve (the only caller of
// Pull/Push) never opens inbox.jsonl for writing either. As long as no other
// code path in this package writes to InboxPath/MetaPath, no git merge
// conflict is possible on the hot path, matching the protocol's stated
// invariant.
package investigate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// sessionIDPattern is the strict charset SessionID must match: a UUID or
// slug-shaped identifier, nothing else. SessionID is used unvalidated as a
// path component (sessionDir/relOutboxPath both filepath.Join it under
// "sessions/"), so this is the boundary that keeps a malicious or malformed
// session id (e.g. "../evil", "a/b") from ever resolving outside the
// sessions/ tree -- there is no path separator, "..", or any other
// filesystem-meaningful character in the allowed set.
var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Default tunables for GitMailbox, matching the protocol doc.
const (
	DefaultPushInterval = 1 * time.Second
	DefaultGCMaxAge     = 30 * 24 * time.Hour
)

// GitSyncer is Serve's hook into a git-backed mailbox: Pull refreshes the
// local inbox file from the remote branch before each poll; Push
// commits+pushes the local outbox file, coalescing unless force is set. A
// nil GitSyncer on ServeOptions (the zero value, and every case in
// serve_test.go) means Serve operates on plain local files with no git
// operations at all -- laptop/local mode and the existing test suite are
// unaffected by this file.
type GitSyncer interface {
	Pull() error
	Push(force bool) error
}

// GitMailboxOptions configures a session's git-branch mailbox.
type GitMailboxOptions struct {
	// RepoPath is an existing git working tree (already cloned; the GHA
	// scaffold's "Checkout deployment repo" step does this for the real
	// runner).
	RepoPath string
	// Branch is the dedicated chat branch, e.g. "mallcop-chat". Separate
	// from the findings-store branch so scan pushes and chat pushes never
	// collide (protocol §1).
	Branch string
	// SessionID is the browser-generated session id (sessions/<id>/...).
	SessionID string
	// Remote is the git remote name to pull/push against, e.g. "origin". An
	// empty Remote disables all network operations (Pull/Push become
	// local-only no-ops beyond the local commit) -- useful for a
	// single-clone laptop session with no rendezvous needed.
	Remote string
	// PushInterval bounds outbox push frequency (protocol §4: "~1/s or on
	// answer/done"). <= 0 uses DefaultPushInterval.
	PushInterval time.Duration
	// GCMaxAge prunes sessions/* older than this at Open time (protocol §6).
	// <= 0 disables GC.
	GCMaxAge time.Duration
	// Now, if set, is used instead of time.Now for GC age comparisons
	// (tests only).
	Now func() time.Time
}

func (o GitMailboxOptions) pushInterval() time.Duration {
	if o.PushInterval > 0 {
		return o.PushInterval
	}
	return DefaultPushInterval
}

func (o GitMailboxOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// sessionMeta is the subset of meta.json GC reads to compute session age.
// The browser is meta.json's sole writer (protocol §1); GitMailbox only ever
// reads it.
type sessionMeta struct {
	CreatedAt string `json:"created_at"`
}

// GitMailbox is a session's live handle on the chat branch: it resolves the
// session's inbox/outbox paths inside RepoPath and implements GitSyncer so
// Serve can pull/push against the real branch.
type GitMailbox struct {
	opts GitMailboxOptions

	mu       sync.Mutex
	lastPush time.Time
}

// OpenGitMailbox checks out (creating if absent) opts.Branch in opts.RepoPath,
// runs session-dir GC if configured, and ensures the session directory
// exists -- implementing protocol §2 step 3 ("creates the chat branch if
// absent") and §6 ("Runner boot ... GC"). It never creates or touches
// inbox.jsonl/meta.json; those are the browser's files and may not exist yet
// (readInbox already tolerates an absent inbox path).
func OpenGitMailbox(opts GitMailboxOptions) (*GitMailbox, error) {
	if opts.RepoPath == "" {
		return nil, fmt.Errorf("investigate: gitmailbox: RepoPath is required")
	}
	if opts.Branch == "" {
		return nil, fmt.Errorf("investigate: gitmailbox: Branch is required")
	}
	if opts.SessionID == "" {
		return nil, fmt.Errorf("investigate: gitmailbox: SessionID is required")
	}
	if !sessionIDPattern.MatchString(opts.SessionID) {
		return nil, fmt.Errorf("investigate: gitmailbox: SessionID %q is invalid (must match %s)", opts.SessionID, sessionIDPattern.String())
	}
	if _, err := os.Stat(filepath.Join(opts.RepoPath, ".git")); err != nil {
		return nil, fmt.Errorf("investigate: gitmailbox: %q is not a git repository: %w", opts.RepoPath, err)
	}

	m := &GitMailbox{opts: opts}

	if opts.Remote != "" {
		// Best effort: the branch may not exist on the remote yet (fresh
		// session on a fresh repo), which is not a fatal error here --
		// ensureBranch below handles every case.
		_, _ = runGitIn(opts.RepoPath, "fetch", "-q", opts.Remote, opts.Branch)
	}

	if err := m.ensureBranch(); err != nil {
		return nil, err
	}

	if opts.GCMaxAge > 0 {
		if _, err := PruneSessions(opts.RepoPath, opts.Branch, opts.Remote, opts.GCMaxAge, opts.now()); err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(m.SessionDir(), 0o755); err != nil {
		return nil, fmt.Errorf("investigate: gitmailbox: create session dir: %w", err)
	}

	return m, nil
}

// SessionDir, InboxPath, OutboxPath, MetaPath resolve this session's files
// under RepoPath. Serve reads InboxPath and appends to OutboxPath; MetaPath
// is exposed for callers (tests, GC) that need to read the browser-written
// session metadata -- GitMailbox itself never writes it.
func (m *GitMailbox) SessionDir() string { return sessionDir(m.opts.RepoPath, m.opts.SessionID) }
func (m *GitMailbox) InboxPath() string  { return filepath.Join(m.SessionDir(), "inbox.jsonl") }
func (m *GitMailbox) OutboxPath() string { return filepath.Join(m.SessionDir(), "outbox.jsonl") }
func (m *GitMailbox) MetaPath() string   { return filepath.Join(m.SessionDir(), "meta.json") }

func sessionDir(repoPath, sessionID string) string {
	return filepath.Join(repoPath, "sessions", sessionID)
}

func (m *GitMailbox) relOutboxPath() string {
	return filepath.Join("sessions", m.opts.SessionID, "outbox.jsonl")
}

// ensureBranch implements protocol §2 step 3's "creates the chat branch if
// absent": checkout the branch if it exists locally, track the remote
// branch if it exists there, or create a fresh orphan branch and push it.
func (m *GitMailbox) ensureBranch() error {
	if out, err := runGitIn(m.opts.RepoPath, "rev-parse", "--verify", "--quiet", m.opts.Branch); err == nil && strings.TrimSpace(out) != "" {
		_, err := runGitIn(m.opts.RepoPath, "checkout", "-q", m.opts.Branch)
		return err
	}

	if m.opts.Remote != "" {
		ref := m.opts.Remote + "/" + m.opts.Branch
		if out, err := runGitIn(m.opts.RepoPath, "rev-parse", "--verify", "--quiet", ref); err == nil && strings.TrimSpace(out) != "" {
			_, err := runGitIn(m.opts.RepoPath, "checkout", "-q", "-b", m.opts.Branch, ref)
			return err
		}
	}

	if _, err := runGitIn(m.opts.RepoPath, "checkout", "-q", "--orphan", m.opts.Branch); err != nil {
		return fmt.Errorf("investigate: gitmailbox: create orphan branch %s: %w", m.opts.Branch, err)
	}
	if _, err := runGitIn(m.opts.RepoPath, "rm", "-rqf", "--ignore-unmatch", "."); err != nil {
		return fmt.Errorf("investigate: gitmailbox: clear orphan work tree: %w", err)
	}
	keep := filepath.Join(m.opts.RepoPath, ".gitkeep")
	if err := os.WriteFile(keep, []byte("mallcop-chat branch root -- see docs/chat-investigate-protocol.md\n"), 0o644); err != nil {
		return fmt.Errorf("investigate: gitmailbox: write .gitkeep: %w", err)
	}
	if _, err := runGitIn(m.opts.RepoPath, "add", ".gitkeep"); err != nil {
		return fmt.Errorf("investigate: gitmailbox: stage .gitkeep: %w", err)
	}
	if _, err := runGitIn(m.opts.RepoPath, gitIdentityArgs("commit", "-q", "-m", "chat: create "+m.opts.Branch)...); err != nil {
		return fmt.Errorf("investigate: gitmailbox: commit orphan root: %w", err)
	}
	if m.opts.Remote != "" {
		if _, err := runGitIn(m.opts.RepoPath, "push", "-q", "-u", m.opts.Remote, m.opts.Branch); err != nil {
			return fmt.Errorf("investigate: gitmailbox: push new branch: %w", err)
		}
	}
	return nil
}

// Pull implements GitSyncer: fetch+merge opts.Branch from opts.Remote so the
// browser's inbox appends become visible locally (protocol §4 "Runner poll:
// git pull inbox ~2s"). A no-op when Remote is empty. Because the runner
// never touches inbox.jsonl/meta.json and the browser never touches
// outbox.jsonl (single-writer-per-file), this merge is always a clean
// fast-forward or a trivial non-overlapping three-way merge -- never a
// conflict.
func (m *GitMailbox) Pull() error {
	if m.opts.Remote == "" {
		return nil
	}
	if _, err := runGitIn(m.opts.RepoPath, "pull", "--no-rebase", "-q", m.opts.Remote, m.opts.Branch); err != nil {
		return fmt.Errorf("investigate: gitmailbox: pull inbox: %w", err)
	}
	return nil
}

// Push implements GitSyncer: stages ONLY this session's outbox.jsonl,
// commits if it changed, and pushes -- coalescing at opts.PushInterval
// unless force is set, per protocol §4 ("the runner batches appends and
// pushes at most ~1x/s (or immediately on answer/done)"). serve.go calls
// Push(true) after ready/answer/done/exit records and Push(false) after
// everything else (ack/tool_call/tool_result/heartbeat), so a coalesced
// window still flushes promptly on every turn boundary.
func (m *GitMailbox) Push(force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := runGitIn(m.opts.RepoPath, "add", "--", m.relOutboxPath()); err != nil {
		return fmt.Errorf("investigate: gitmailbox: stage outbox: %w", err)
	}
	staged, err := hasStagedChanges(m.opts.RepoPath)
	if err != nil {
		return err
	}
	if !staged {
		return nil
	}
	if !force && time.Since(m.lastPush) < m.opts.pushInterval() {
		return nil // coalesced: stays staged, flushed by a later force or interval push
	}

	if _, err := runGitIn(m.opts.RepoPath, gitIdentityArgs("commit", "-q", "-m", "chat: outbox update "+m.opts.SessionID)...); err != nil {
		return fmt.Errorf("investigate: gitmailbox: commit outbox: %w", err)
	}
	m.lastPush = time.Now()

	if m.opts.Remote == "" {
		return nil
	}
	return m.pushWithRetry()
}

// pushWithRetry retries push-then-pull-then-push a bounded number of times so
// a race with a concurrent browser push (which never touches the same file,
// per single-writer-per-file) resolves via an ordinary non-conflicting
// merge rather than surfacing a transient non-fast-forward rejection to the
// caller.
func (m *GitMailbox) pushWithRetry() error {
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if _, err := runGitIn(m.opts.RepoPath, "push", "-q", m.opts.Remote, m.opts.Branch); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if _, err := runGitIn(m.opts.RepoPath, "pull", "--no-rebase", "-q", m.opts.Remote, m.opts.Branch); err != nil {
			return fmt.Errorf("investigate: gitmailbox: push retry pull failed: %w (push error: %v)", err, lastErr)
		}
	}
	return fmt.Errorf("investigate: gitmailbox: push failed after %d attempts: %w", maxAttempts, lastErr)
}

// PruneSessions implements protocol §6's "session-dir GC (prune sessions/*
// older than N days, configurable)". It removes every sessions/<id>/ whose
// age exceeds maxAge -- age is meta.json's created_at when present and
// parseable, else the session directory's mtime -- committing the removal(s)
// as one commit and pushing when remote is non-empty. repoPath must already
// have branch checked out (OpenGitMailbox's caller path) or be any working
// tree with the branch checked out (direct GC test/CLI use).
func PruneSessions(repoPath, branch, remote string, maxAge time.Duration, now time.Time) ([]string, error) {
	if maxAge <= 0 {
		return nil, nil
	}
	sessionsRoot := filepath.Join(repoPath, "sessions")
	entries, err := os.ReadDir(sessionsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("investigate: gitmailbox: gc: read sessions dir: %w", err)
	}

	var pruned []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		age, ok := sessionAge(filepath.Join(sessionsRoot, id), now)
		if !ok || age < maxAge {
			continue
		}
		if _, err := runGitIn(repoPath, "rm", "-rq", "--ignore-unmatch", filepath.Join("sessions", id)); err != nil {
			return nil, fmt.Errorf("investigate: gitmailbox: gc: git rm sessions/%s: %w", id, err)
		}
		pruned = append(pruned, id)
	}
	if len(pruned) == 0 {
		return nil, nil
	}
	if _, err := runGitIn(repoPath, gitIdentityArgs("commit", "-q", "-m", fmt.Sprintf("chat: gc %d stale session(s)", len(pruned)))...); err != nil {
		return nil, fmt.Errorf("investigate: gitmailbox: gc: commit: %w", err)
	}
	if remote != "" {
		if _, err := runGitIn(repoPath, "push", "-q", remote, branch); err != nil {
			return nil, fmt.Errorf("investigate: gitmailbox: gc: push: %w", err)
		}
	}
	return pruned, nil
}

// sessionAge returns dir's age as of now: meta.json's created_at when the
// file exists and parses as RFC3339, else dir's own mtime. ok is false only
// when dir doesn't exist at all (already-removed, racing GC).
func sessionAge(dir string, now time.Time) (time.Duration, bool) {
	if b, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil {
		var meta sessionMeta
		if json.Unmarshal(b, &meta) == nil && meta.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, meta.CreatedAt); err == nil {
				return now.Sub(t), true
			}
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		return 0, false
	}
	return now.Sub(info.ModTime()), true
}

// hasStagedChanges reports whether the git index currently has staged
// changes relative to HEAD, distinguishing "clean, nothing to commit" (exit
// 0) from "dirty" (exit 1) from an actual git failure (any other exit/err).
func hasStagedChanges(dir string) (bool, error) {
	cmd := exec.Command("git", "diff", "--cached", "--quiet")
	cmd.Dir = dir
	err := cmd.Run()
	if err == nil {
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return true, nil
	}
	return false, fmt.Errorf("investigate: gitmailbox: diff --cached: %w", err)
}

// gitIdentityArgs prepends explicit -c user.name/user.email flags to a git
// subcommand so commits succeed even when the runner has no configured git
// identity (a bare CI checkout, or a test repo) -- mirroring
// cli/deployrepo.go's createAndPushDeployRepo convention.
func gitIdentityArgs(args ...string) []string {
	return append([]string{"-c", "user.name=mallcop-chat", "-c", "user.email=chat@mallcop.app"}, args...)
}

// runGitIn runs a git subcommand rooted at dir, returning combined output on
// error so failures are debuggable (mirrors core/store.go's and
// cli/deployrepo.go's own git-wrapping convention).
func runGitIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("git %v in %q: %w: %s", args, dir, err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}
