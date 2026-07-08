package investigate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/inference"
)

// --- git test plumbing -------------------------------------------------
//
// These helpers build a REAL bare "origin" plus two independent working-tree
// clones (a "browser" clone and a "runner" clone) so the mailbox tests prove
// an actual git push/pull round trip through a shared remote -- exactly the
// topology the browser and a GHA runner have in production, both cloning the
// customer's real repo independently.

func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %q: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

// newBareOrigin creates an empty bare repo standing in for the customer's
// real GitHub remote.
func newBareOrigin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "init", "-q", "--bare", "-b", "main")
	return dir
}

// cloneRepo clones bareDir into a fresh temp dir and configures a local
// commit identity, with no content assumptions -- used for every clone
// AFTER the first (the "root content already exists on origin" case).
func cloneRepo(t *testing.T, bareDir string) string {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "clone", "-q", bareDir, dir)
	for _, args := range [][]string{
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		mustGit(t, dir, args...)
	}
	return dir
}

// newSeededClone clones bareDir, configures a local commit identity, and
// leaves a root commit on main pushed back to origin -- a stand-in for the
// customer's already-existing repo content before any chat session starts.
// Call this exactly once per bare origin (it's the clone that CREATES main's
// content); every other participant clone should use cloneRepo instead.
func newSeededClone(t *testing.T, bareDir string) string {
	t.Helper()
	dir := cloneRepo(t, bareDir)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("customer repo\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	mustGit(t, dir, "add", "README.md")
	mustGit(t, dir, "commit", "-q", "-m", "root")
	mustGit(t, dir, "push", "-q", "-u", "origin", "main")
	return dir
}

// writeBrowserSession creates the mallcop-chat branch (orphan, as a real
// browser dispatch does) in browserDir, writes meta.json + inbox.jsonl for
// sessionID with the given inbox records, and pushes it -- simulating
// protocol §2 steps 1-2 ("browser writes meta.json ... appends question to
// inbox"). Only meta.json and inbox.jsonl are ever written here, matching
// the browser's single-writer-per-file role.
func writeBrowserSession(t *testing.T, browserDir, branch, sessionID string, inboxLines []map[string]any) {
	t.Helper()
	mustGit(t, browserDir, "checkout", "-q", "--orphan", branch)
	mustGit(t, browserDir, "rm", "-rqf", "--ignore-unmatch", ".")

	sessDir := filepath.Join(browserDir, "sessions", sessionID)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir session dir: %v", err)
	}
	meta := map[string]any{"session_id": sessionID, "created_at": time.Now().UTC().Format(time.RFC3339)}
	metaBytes, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(sessDir, "meta.json"), metaBytes, 0o644); err != nil {
		t.Fatalf("write meta.json: %v", err)
	}

	var sb strings.Builder
	for _, rec := range inboxLines {
		b, _ := json.Marshal(rec)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(sessDir, "inbox.jsonl"), []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write inbox.jsonl: %v", err)
	}

	mustGit(t, browserDir, "add", "sessions")
	mustGit(t, browserDir, "commit", "-q", "-m", "chat: session start")
	mustGit(t, browserDir, "push", "-q", "-u", "origin", branch)
}

// fetchOutbox re-clones bareDir fresh (a THIRD, independent clone -- proving
// the records really landed in the shared remote, not just the runner's
// local working tree) and returns every outbox.jsonl record for sessionID on
// branch, in file order.
func fetchOutbox(t *testing.T, bareDir, branch, sessionID string) []map[string]any {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "clone", "-q", "--branch", branch, bareDir, dir)
	raw, err := os.ReadFile(filepath.Join(dir, "sessions", sessionID, "outbox.jsonl"))
	if err != nil {
		t.Fatalf("read outbox.jsonl from fresh clone: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal outbox line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// commitFileLists re-clones bareDir fresh and returns, per commit on branch
// (oldest first), the sorted list of files that commit touched -- the tool
// TestGitMailbox_SingleWriterPerFileHolds uses to prove the runner's commits
// never touch inbox.jsonl/meta.json.
func commitFileLists(t *testing.T, bareDir, branch string) [][]string {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "clone", "-q", "--branch", branch, bareDir, dir)
	shaOut := mustGit(t, dir, "log", "--reverse", "--format=%H", branch)
	var out [][]string
	for _, sha := range strings.Fields(shaOut) {
		filesOut := mustGit(t, dir, "show", "--name-only", "--pretty=format:", sha)
		var files []string
		for _, f := range strings.Split(strings.TrimSpace(filesOut), "\n") {
			if f != "" {
				files = append(files, filepath.ToSlash(f))
			}
		}
		out = append(out, files)
	}
	return out
}

func typesOf(t *testing.T, records []map[string]any) []string {
	t.Helper()
	var types []string
	for _, r := range records {
		tp, _ := r["type"].(string)
		types = append(types, tp)
	}
	return types
}

// --- the mailbox tests --------------------------------------------------

// TestGitMailbox_FullLifecycleRoundTrip is the DONE CONDITION test: a real
// git repo, a real question appended to inbox.jsonl on the mallcop-chat
// branch by an independent "browser" clone, Serve wired to a real
// GitMailbox, and a THIRD independent clone proving the outbox landed as
// real, ordered, monotonically-sequenced commits -- ready -> ack ->
// tool_call -> tool_result -> answer -> done -> heartbeat* -> exit(idle).
func TestGitMailbox_FullLifecycleRoundTrip(t *testing.T) {
	const branch = "mallcop-chat"
	const sessionID = "sess-abc123"

	bare := newBareOrigin(t)
	browserDir := newSeededClone(t, bare)
	writeBrowserSession(t, browserDir, branch, sessionID, []map[string]any{
		{"type": "question", "seq": 1, "id": "q_1", "text": "What has ghost been doing?", "ts": time.Now().UTC().Format(time.RFC3339)},
	})

	runnerDir := cloneRepo(t, bare)

	st := seedStore(t)
	bl := seedBaseline(t)
	srv, _ := scriptedServer(t)
	defer srv.Close()
	client := &inference.DirectClient{BaseURL: srv.URL, Model: "test-model"}

	mb, err := OpenGitMailbox(GitMailboxOptions{
		RepoPath:  runnerDir,
		Branch:    branch,
		SessionID: sessionID,
		Remote:    "origin",
	})
	if err != nil {
		t.Fatalf("OpenGitMailbox: %v", err)
	}

	opts := ServeOptions{
		Options:         Options{Client: client, Model: "test-model", Store: st, Baseline: bl},
		InboxPath:       mb.InboxPath(),
		OutboxPath:      mb.OutboxPath(),
		Mailbox:         mb,
		IdleTimeout:     200 * time.Millisecond,
		PollInterval:    20 * time.Millisecond,
		HeartbeatPeriod: time.Hour,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}

	records := fetchOutbox(t, bare, branch, sessionID)
	types := typesOf(t, records)
	wantPrefix := []string{"ready", "ack", "tool_call", "tool_result", "answer", "done"}
	if len(types) < len(wantPrefix) {
		t.Fatalf("outbox has %d records %v, want at least %d starting with %v", len(types), types, len(wantPrefix), wantPrefix)
	}
	for i, want := range wantPrefix {
		if types[i] != want {
			t.Fatalf("outbox record %d type = %q, want %q (full sequence: %v)", i, types[i], want, types)
		}
	}
	if last := types[len(types)-1]; last != "exit" {
		t.Fatalf("last outbox record type = %q, want exit (idle timeout)", last)
	}
	if reason, _ := records[len(records)-1]["reason"].(string); reason != "idle" {
		t.Fatalf("exit record reason = %q, want idle", reason)
	}

	// seq is monotonic per file (protocol §4: "runner assigns outbox seq").
	lastSeq := 0
	for i, rec := range records {
		seqF, ok := rec["seq"].(float64)
		if !ok {
			t.Fatalf("record %d (%s) has no numeric seq field: %#v", i, types[i], rec)
		}
		seq := int(seqF)
		if seq <= lastSeq {
			t.Fatalf("record %d (%s) seq %d is not strictly greater than previous seq %d", i, types[i], seq, lastSeq)
		}
		lastSeq = seq
	}

	// single-writer-per-file: every commit the RUNNER made (i.e. every
	// commit after the browser's session-start commit) touches ONLY
	// outbox.jsonl -- never inbox.jsonl or meta.json.
	commits := commitFileLists(t, bare, branch)
	if len(commits) < 2 {
		t.Fatalf("expected at least 2 commits on %s (browser start + >=1 runner push), got %d", branch, len(commits))
	}
	browserFiles := commits[0]
	wantBrowserFiles := []string{
		"sessions/" + sessionID + "/inbox.jsonl",
		"sessions/" + sessionID + "/meta.json",
	}
	if !equalStringSets(browserFiles, wantBrowserFiles) {
		t.Fatalf("browser's session-start commit touched %v, want exactly %v", browserFiles, wantBrowserFiles)
	}
	wantOutbox := "sessions/" + sessionID + "/outbox.jsonl"
	for i, files := range commits[1:] {
		if len(files) != 1 || files[0] != wantOutbox {
			t.Fatalf("runner commit #%d touched %v, want exactly [%s] (single-writer-per-file violated)", i, files, wantOutbox)
		}
	}
}

// TestGitMailbox_ShutdownOverGit proves a control:shutdown record written by
// the browser (via git, on a separate clone) ends the runner's session with
// reason "shutdown" through the real GitMailbox, not just the plain-file
// path already covered by TestServe_ShutdownControlRecordExitsImmediately.
func TestGitMailbox_ShutdownOverGit(t *testing.T) {
	const branch = "mallcop-chat"
	const sessionID = "sess-shutdown-1"

	bare := newBareOrigin(t)
	browserDir := newSeededClone(t, bare)
	writeBrowserSession(t, browserDir, branch, sessionID, []map[string]any{
		{"type": "control", "seq": 1, "cmd": "shutdown"},
	})

	runnerDir := cloneRepo(t, bare)

	st := seedStore(t)
	srv, _ := scriptedServer(t)
	defer srv.Close()
	client := &inference.DirectClient{BaseURL: srv.URL, Model: "test-model"}

	mb, err := OpenGitMailbox(GitMailboxOptions{
		RepoPath:  runnerDir,
		Branch:    branch,
		SessionID: sessionID,
		Remote:    "origin",
	})
	if err != nil {
		t.Fatalf("OpenGitMailbox: %v", err)
	}

	opts := ServeOptions{
		Options:      Options{Client: client, Model: "test-model", Store: st},
		InboxPath:    mb.InboxPath(),
		OutboxPath:   mb.OutboxPath(),
		Mailbox:      mb,
		IdleTimeout:  time.Hour, // would hang the test if shutdown didn't short-circuit it
		PollInterval: 10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}

	records := fetchOutbox(t, bare, branch, sessionID)
	types := typesOf(t, records)
	if len(types) != 2 || types[0] != "ready" || types[1] != "exit" {
		t.Fatalf("outbox types = %v, want [ready exit]", types)
	}
	if reason, _ := records[1]["reason"].(string); reason != "shutdown" {
		t.Fatalf("exit record reason = %q, want shutdown", reason)
	}
}

// TestOpenGitMailbox_RejectsUnsafeSessionID is the mallcoppro-c32 regression
// test for boundary fix (2): SessionID flows unvalidated into
// filepath.Join(RepoPath, "sessions", SessionID) (sessionDir/relOutboxPath).
// A session id containing a path separator or ".." must be rejected by
// OpenGitMailbox itself -- before any filesystem/git operation runs -- rather
// than silently resolving outside the sessions/ tree. A real UUID-shaped id
// (what the browser actually generates per the protocol doc) must still be
// accepted.
func TestOpenGitMailbox_RejectsUnsafeSessionID(t *testing.T) {
	const branch = "mallcop-chat"
	bare := newBareOrigin(t)
	_ = newSeededClone(t, bare) // seeds "main" content on origin exactly once

	for _, bad := range []string{"../evil", "a/b", "../../etc/passwd", ""} {
		runnerDir := cloneRepo(t, bare)
		_, err := OpenGitMailbox(GitMailboxOptions{
			RepoPath:  runnerDir,
			Branch:    branch,
			SessionID: bad,
			Remote:    "origin",
		})
		if err == nil {
			t.Fatalf("OpenGitMailbox accepted unsafe SessionID %q, want an error", bad)
		}
		// Must never have escaped sessions/ onto the real filesystem.
		if _, statErr := os.Stat(filepath.Join(runnerDir, "..", "evil")); statErr == nil {
			t.Fatalf("SessionID %q escaped the repo root onto disk", bad)
		}
	}

	// A real UUID (the browser's actual session-id shape) must still work.
	runnerDir := cloneRepo(t, bare)
	const uuid = "550e8400-e29b-41d4-a716-446655440000"
	mb, err := OpenGitMailbox(GitMailboxOptions{
		RepoPath:  runnerDir,
		Branch:    branch,
		SessionID: uuid,
		Remote:    "origin",
	})
	if err != nil {
		t.Fatalf("OpenGitMailbox rejected a valid UUID SessionID: %v", err)
	}
	if info, statErr := os.Stat(mb.SessionDir()); statErr != nil || !info.IsDir() {
		t.Fatalf("session dir %s was not created for a valid UUID SessionID: %v", mb.SessionDir(), statErr)
	}
}

// TestOpenGitMailbox_CreatesBranchWhenAbsent proves protocol §2 step 3's
// "creates the chat branch if absent": a repo whose remote has no
// mallcop-chat branch at all yet still ends up with one, pushed, after Open.
func TestOpenGitMailbox_CreatesBranchWhenAbsent(t *testing.T) {
	const branch = "mallcop-chat"
	const sessionID = "sess-fresh-1"

	bare := newBareOrigin(t)
	runnerDir := newSeededClone(t, bare) // origin has only "main" so far

	mb, err := OpenGitMailbox(GitMailboxOptions{
		RepoPath:  runnerDir,
		Branch:    branch,
		SessionID: sessionID,
		Remote:    "origin",
	})
	if err != nil {
		t.Fatalf("OpenGitMailbox: %v", err)
	}
	if info, err := os.Stat(mb.SessionDir()); err != nil || !info.IsDir() {
		t.Fatalf("session dir %s was not created: %v", mb.SessionDir(), err)
	}

	// The branch must now exist on the remote -- a fresh third clone proves
	// it, rather than trusting the runner's own local ref.
	verifyDir := t.TempDir()
	mustGit(t, verifyDir, "clone", "-q", "--branch", branch, bare, verifyDir)
	if _, err := os.Stat(filepath.Join(verifyDir, ".gitkeep")); err != nil {
		t.Fatalf("expected the freshly-created chat branch to contain .gitkeep, got: %v", err)
	}
}

// TestPruneSessions_RemovesStaleSessionsOnly proves protocol §6's session-dir
// GC: two sessions older than maxAge are removed (as a real commit, pushed),
// a fresh one is kept, and PruneSessions reports exactly the pruned ids.
func TestPruneSessions_RemovesStaleSessionsOnly(t *testing.T) {
	const branch = "mallcop-chat"
	bare := newBareOrigin(t)
	browserDir := newSeededClone(t, bare)

	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	old1 := now.Add(-40 * 24 * time.Hour)
	old2 := now.Add(-31 * 24 * time.Hour)
	fresh := now.Add(-1 * time.Hour)

	mustGit(t, browserDir, "checkout", "-q", "--orphan", branch)
	mustGit(t, browserDir, "rm", "-rqf", "--ignore-unmatch", ".")
	for id, createdAt := range map[string]time.Time{
		"sess-old-1": old1,
		"sess-old-2": old2,
		"sess-fresh": fresh,
	} {
		dir := filepath.Join(browserDir, "sessions", id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		meta := map[string]any{"session_id": id, "created_at": createdAt.Format(time.RFC3339)}
		b, _ := json.Marshal(meta)
		if err := os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o644); err != nil {
			t.Fatalf("write meta.json: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "inbox.jsonl"), nil, 0o644); err != nil {
			t.Fatalf("write inbox.jsonl: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "outbox.jsonl"), nil, 0o644); err != nil {
			t.Fatalf("write outbox.jsonl: %v", err)
		}
	}
	mustGit(t, browserDir, "add", "sessions")
	mustGit(t, browserDir, "commit", "-q", "-m", "chat: seed sessions for gc test")
	mustGit(t, browserDir, "push", "-q", "-u", "origin", branch)

	runnerDir := cloneRepo(t, bare)
	mustGit(t, runnerDir, "fetch", "-q", "origin", branch)
	mustGit(t, runnerDir, "checkout", "-q", "-b", branch, "origin/"+branch)

	pruned, err := PruneSessions(runnerDir, branch, "origin", 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("PruneSessions: %v", err)
	}
	if !equalStringSets(pruned, []string{"sess-old-1", "sess-old-2"}) {
		t.Fatalf("pruned = %v, want exactly [sess-old-1 sess-old-2]", pruned)
	}

	verifyDir := t.TempDir()
	mustGit(t, verifyDir, "clone", "-q", "--branch", branch, bare, verifyDir)
	entries, err := os.ReadDir(filepath.Join(verifyDir, "sessions"))
	if err != nil {
		t.Fatalf("read sessions dir in fresh clone: %v", err)
	}
	var remaining []string
	for _, e := range entries {
		remaining = append(remaining, e.Name())
	}
	if !equalStringSets(remaining, []string{"sess-fresh"}) {
		t.Fatalf("remaining sessions after GC = %v, want exactly [sess-fresh]", remaining)
	}
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// TestRunGitIn_TimesOutInsteadOfHanging is the regression test for mallcoppro-d2d:
// a stalled git network op must NOT hang the serve job forever. With a tiny
// gitOpTimeout, a real git invocation is killed and surfaced as a timeout error
// rather than blocking indefinitely.
func TestRunGitIn_TimesOutInsteadOfHanging(t *testing.T) {
	dir := t.TempDir()
	orig := gitOpTimeout
	gitOpTimeout = time.Nanosecond
	defer func() { gitOpTimeout = orig }()

	_, err := runGitIn(dir, "version")
	if err == nil {
		t.Fatal("expected runGitIn to error under a 1ns timeout, got nil (a real git op would hang forever without the bound)")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error mentioning the bound, got: %v", err)
	}
}
