package store

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// initRepo creates a REAL git repo in a temp dir. Every persistence and
// concurrency test hits this — not an in-memory fake — so the tests prove the
// git repo ALONE reconstructs full state.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	// A repo with no commits has no HEAD; seed an empty root commit so HEAD
	// resolves from the first Append onward (matches how the CLI seeds a repo).
	seed := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "root")
	seed.Dir = dir
	seed.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	return dir
}

func gitLog(t *testing.T, repo string) []string {
	t.Helper()
	cmd := exec.Command("git", "log", "--format=%H %s")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines
}

// committedBytes reads a stream file's content from the git OBJECT STORE at
// HEAD, bypassing the store package, so the test asserts on the literal
// committed content (the store materializes records into git objects, not the
// work tree). An absent blob (stream never written) returns empty bytes.
func committedBytes(t *testing.T, repo, file string) []byte {
	t.Helper()
	cmd := exec.Command("git", "cat-file", "-p", "HEAD:"+file)
	cmd.Dir = repo
	out, err := cmd.Output()
	if err != nil {
		// Missing path → empty (no records yet).
		return nil
	}
	return out
}

func TestOpenRejectsNonGitDir(t *testing.T) {
	dir := t.TempDir() // NOT a git repo
	if _, err := Open(dir); err == nil {
		t.Fatal("Open on a non-git dir should fail, got nil error")
	}
}

func TestOpenRejectsMissingPath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("Open on a missing path should fail, got nil error")
	}
}

// TestAppendAndLoadRoundTrip proves a record appended is replayed verbatim, and
// that the git repo alone holds it (we re-Open a fresh handle).
func TestAppendAndLoadRoundTrip(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rec := map[string]any{"id": "e1", "type": "login"}
	sha, err := s.Append(KindEvents, rec)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if sha == "" {
		t.Fatal("Append returned empty sha")
	}

	// Fresh handle — reconstruct from the repo, not from in-process memory.
	s2, err := Open(repo)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	got, err := s2.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	var back map[string]any
	if err := json.Unmarshal(got[0], &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["id"] != "e1" || back["type"] != "login" {
		t.Fatalf("record round-trip mismatch: %v", back)
	}
}

// TestLoadMissingStreamIsEmpty proves a never-written stream is empty, not an
// error — a valid reconstructed state.
func TestLoadMissingStreamIsEmpty(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)
	got, err := s.Load(KindFindings)
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

// TestAppendOnlyHistoryPreserved is the APPEND-ONLY proof: every prior record
// stays byte-for-byte where it was; the file only grows; nothing is rewritten
// in place. We assert (a) each Load result is a strict prefix-extension of the
// last, and (b) every git commit's diff is pure addition (no deletions).
func TestAppendOnlyHistoryPreserved(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)

	var prevBytes []byte
	var shas []string
	for i := 0; i < 5; i++ {
		rec := map[string]any{"n": i, "msg": fmt.Sprintf("record-%d", i)}
		sha, err := s.Append(KindFindings, rec)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		shas = append(shas, sha)

		cur := committedBytes(t, repo, KindFindings.file())
		// (a) The new on-disk content must START WITH the previous content —
		// proving no in-place mutation of earlier bytes.
		if i > 0 && !strings.HasPrefix(string(cur), string(prevBytes)) {
			t.Fatalf("append %d mutated prior bytes; prev was not a prefix of current", i)
		}
		if i > 0 && len(cur) <= len(prevBytes) {
			t.Fatalf("append %d did not grow the file (%d <= %d)", i, len(cur), len(prevBytes))
		}
		prevBytes = cur
	}

	// (b) Each store commit's diff must be addition-only: no removed lines.
	for _, sha := range shas {
		cmd := exec.Command("git", "show", "--format=", "--unified=0", sha)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git show %s: %v\n%s", sha, err, out)
		}
		for _, ln := range strings.Split(string(out), "\n") {
			// A real deletion line starts with "-" but not the "---" file
			// header. Its presence would mean a prior record was rewritten.
			if strings.HasPrefix(ln, "-") && !strings.HasPrefix(ln, "---") {
				t.Fatalf("commit %s contains a deletion (not append-only): %q", sha, ln)
			}
		}
	}

	// Final reconstruction from the repo alone: 5 records, in order.
	got, err := s.Load(KindFindings)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 records, got %d", len(got))
	}
	for i, raw := range got {
		var r map[string]any
		_ = json.Unmarshal(raw, &r)
		if int(r["n"].(float64)) != i {
			t.Fatalf("record %d out of order: %v", i, r)
		}
	}
}

// TestDirectivesFirstClassCrossProcess is the keystone proof: a directive
// written via Append by ONE Open is returned by a FRESH Open().LoadDirectives()
// — i.e. the next scan would load and obey it. We make the two Opens model two
// processes by using entirely independent Store handles; the only shared state
// is the git repo on disk.
func TestDirectivesFirstClassCrossProcess(t *testing.T) {
	repo := initRepo(t)

	// "Process 1": operator writes a suppress directive.
	writer, err := Open(repo)
	if err != nil {
		t.Fatalf("writer Open: %v", err)
	}
	d := Directive{
		Op:      "suppress",
		Pattern: "detector:rate-anomaly",
		Reason:  "known batch job, false positives",
		Actor:   "operator",
	}
	if _, err := writer.Append(KindDirectives, d); err != nil {
		t.Fatalf("append directive: %v", err)
	}

	// "Process 2": a fresh scan boots, Opens the repo, loads directives.
	scanner, err := Open(repo)
	if err != nil {
		t.Fatalf("scanner Open: %v", err)
	}
	dirs, err := scanner.LoadDirectives()
	if err != nil {
		t.Fatalf("LoadDirectives: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("want 1 directive obeyed by next scan, got %d", len(dirs))
	}
	if dirs[0].Op != "suppress" || dirs[0].Pattern != "detector:rate-anomaly" {
		t.Fatalf("directive not faithfully reconstructed: %+v", dirs[0])
	}
	if dirs[0].Reason != "known batch job, false positives" {
		t.Fatalf("directive reason lost: %+v", dirs[0])
	}
}

// TestConversationFirstClassCrossProcess proves conversation is durable and
// replayed by a fresh Open — the agent loop resumes from the repo alone.
func TestConversationFirstClassCrossProcess(t *testing.T) {
	repo := initRepo(t)
	w, _ := Open(repo)
	turns := []Turn{
		{Role: "user", Content: "scan the org"},
		{Role: "assistant", Content: "running 13 detectors"},
		{Role: "tool", ToolName: "detect", ToolResult: json.RawMessage(`{"findings":3}`)},
	}
	for i, tn := range turns {
		if _, err := w.Append(KindConversation, tn); err != nil {
			t.Fatalf("append turn %d: %v", i, err)
		}
	}

	r, _ := Open(repo)
	got, err := r.LoadConversation()
	if err != nil {
		t.Fatalf("LoadConversation: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 turns, got %d", len(got))
	}
	if got[0].Role != "user" || got[0].Content != "scan the org" {
		t.Fatalf("turn 0 mismatch: %+v", got[0])
	}
	if got[2].ToolName != "detect" || string(got[2].ToolResult) != `{"findings":3}` {
		t.Fatalf("tool turn mismatch: %+v", got[2])
	}
}

// TestGitRepoAloneReconstructsState is the GROUND-SOURCE proof: write to one
// repo, then `git clone` it to a brand-new directory and Open the clone. If the
// clone reconstructs every stream, the git repo ALONE is the source of truth —
// no out-of-band state exists.
func TestGitRepoAloneReconstructsState(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)
	if _, err := s.Append(KindEvents, map[string]any{"id": "e1"}); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if _, err := s.Append(KindFindings, map[string]any{"id": "f1"}); err != nil {
		t.Fatalf("append finding: %v", err)
	}
	if _, err := s.Append(KindDirectives, Directive{Op: "focus", Pattern: "exfil"}); err != nil {
		t.Fatalf("append directive: %v", err)
	}

	clone := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "-q", repo, clone)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}

	cs, err := Open(clone)
	if err != nil {
		t.Fatalf("Open clone: %v", err)
	}
	ev, _ := cs.Load(KindEvents)
	fd, _ := cs.Load(KindFindings)
	dirs, _ := cs.LoadDirectives()
	if len(ev) != 1 || len(fd) != 1 || len(dirs) != 1 {
		t.Fatalf("clone did not reconstruct full state: events=%d findings=%d directives=%d",
			len(ev), len(fd), len(dirs))
	}
	if dirs[0].Op != "focus" || dirs[0].Pattern != "exfil" {
		t.Fatalf("clone directive mismatch: %+v", dirs[0])
	}
}

// TestConcurrentWritersNoLostWrite is the CONCURRENCY proof. Many goroutines
// append to the same stream through INDEPENDENT Store handles. Every append must
// land (no lost write), the git log must be deterministic (one commit per
// append, linear history), and reconstruction from the repo must return exactly
// N records with no duplicates.
func TestConcurrentWritersNoLostWrite(t *testing.T) {
	repo := initRepo(t)

	const writers = 12
	baseCommits := len(gitLog(t, repo)) // root commit

	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// Independent handle per goroutine — they share only the repo.
			s, err := Open(repo)
			if err != nil {
				errs[n] = err
				return
			}
			_, errs[n] = s.Append(KindEvents, map[string]any{"writer": n})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d failed: %v", i, err)
		}
	}

	// No lost write: exactly `writers` records reconstructed from the repo.
	s, _ := Open(repo)
	got, err := s.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != writers {
		t.Fatalf("lost write: want %d records, got %d", writers, len(got))
	}

	// Each writer's record present exactly once — no duplication, no drop.
	seen := map[int]int{}
	for _, raw := range got {
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("corrupt record after concurrent write: %v", err)
		}
		seen[int(r["writer"].(float64))]++
	}
	if len(seen) != writers {
		t.Fatalf("want %d distinct writers, got %d (%v)", writers, len(seen), seen)
	}
	for w, c := range seen {
		if c != 1 {
			t.Fatalf("writer %d landed %d times (want exactly 1)", w, c)
		}
	}

	// Deterministic merged log: exactly one new commit per append, linear.
	log := gitLog(t, repo)
	if got, want := len(log)-baseCommits, writers; got != want {
		t.Fatalf("want %d store commits, got %d (log has %d lines)", want, got, len(log))
	}
	for _, ln := range log[:writers] { // newest `writers` entries are ours
		if !strings.Contains(ln, "store: append events") {
			t.Fatalf("unexpected commit in merged log: %q", ln)
		}
	}
}

// noopSerializer grants the lock to everyone immediately — it provides NO
// mutual exclusion. Passing it to OpenWith strips away the in-process mutex so
// concurrent goroutines genuinely race at the git layer, the way two separate
// OS PROCESSES would. This is the real stress test for the rebase-retry: if the
// retry logic is wrong, this test loses or duplicates writes.
type noopSerializer struct{}

func (noopSerializer) Lock(string) (func(), error) { return func() {}, nil }

// TestRebaseRetryUnderTrueRace drives the cross-process race path. With no
// shared in-process lock, N goroutines append to the same stream and the only
// thing preventing a lost write is commitAppend's sync-append-commit rebase
// loop. We assert exactly N records, each exactly once, and a linear log.
func TestRebaseRetryUnderTrueRace(t *testing.T) {
	repo := initRepo(t)
	baseCommits := len(gitLog(t, repo))

	const writers = 16
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s, err := OpenWith(repo, noopSerializer{})
			if err != nil {
				errs[n] = err
				return
			}
			_, errs[n] = s.Append(KindEvents, map[string]any{"w": n})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racing writer %d failed: %v", i, err)
		}
	}

	s, _ := Open(repo)
	got, err := s.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != writers {
		t.Fatalf("true-race lost/duplicated writes: want %d records, got %d", writers, len(got))
	}
	seen := map[int]int{}
	for _, raw := range got {
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("corrupt record: %v", err)
		}
		seen[int(r["w"].(float64))]++
	}
	for w := 0; w < writers; w++ {
		if seen[w] != 1 {
			t.Fatalf("writer %d landed %d times under true race (want exactly 1); full map %v", w, seen[w], seen)
		}
	}

	// Deterministic merged log: one commit per append, all linear (each commit
	// has exactly one parent — no merge commits introduced by the retry).
	log := gitLog(t, repo)
	if got, want := len(log)-baseCommits, writers; got != want {
		t.Fatalf("want %d store commits under true race, got %d", want, got)
	}
	mp := exec.Command("git", "log", "--merges", "--format=%H")
	mp.Dir = repo
	mout, _ := mp.CombinedOutput()
	if strings.TrimSpace(string(mout)) != "" {
		t.Fatalf("rebase-retry produced merge commits (non-linear log):\n%s", mout)
	}
}

// TestSerializerHookIsUsed proves the per-tenant write-serialization HOOK is a
// real seam: a custom Serializer passed to OpenWith is invoked around every
// Append, and its release runs. This is the interface the managed (aztables)
// side implements later; here we just prove the seam exists and is honored.
func TestSerializerHookIsUsed(t *testing.T) {
	repo := initRepo(t)

	hook := &countingSerializer{inner: defaultMutex}
	s, err := OpenWith(repo, hook)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Append(KindResolutions, map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if hook.locks != 3 {
		t.Fatalf("serializer hook Lock called %d times, want 3", hook.locks)
	}
	if hook.releases != 3 {
		t.Fatalf("serializer hook release called %d times, want 3", hook.releases)
	}
}

type countingSerializer struct {
	inner    Serializer
	mu       sync.Mutex
	locks    int
	releases int
}

func (c *countingSerializer) Lock(repoPath string) (func(), error) {
	rel, err := c.inner.Lock(repoPath)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.locks++
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.releases++
		c.mu.Unlock()
		rel()
	}, nil
}

// TestBootstrapOnEmptyRepo proves the FIRST Append on a freshly `git init`'d
// repo with ZERO commits works — the store bootstraps a root commit. The
// consumer (CLI) may hand the store a repo it just inited without seeding a
// root; the store must not require a pre-existing HEAD.
func TestBootstrapOnEmptyRepo(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "t"},
		{"config", "user.email", "t@e"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	// No root commit seeded — HEAD is unborn.
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sha, err := s.Append(KindDirectives, Directive{Op: "suppress", Pattern: "x"})
	if err != nil {
		t.Fatalf("bootstrap Append: %v", err)
	}
	if sha == "" {
		t.Fatal("bootstrap Append returned empty sha")
	}
	// Fresh handle reconstructs the directive from the repo alone.
	s2, _ := Open(dir)
	dirs, err := s2.LoadDirectives()
	if err != nil {
		t.Fatalf("LoadDirectives: %v", err)
	}
	if len(dirs) != 1 || dirs[0].Op != "suppress" {
		t.Fatalf("bootstrap directive not reconstructed: %+v", dirs)
	}
}

// TestBootstrapRaceNoDoubleRoot proves that when MANY writers race to be the
// first Append on an unborn-HEAD repo, the zero-value CAS lets exactly one win
// the root and the rest rebase onto it — no forked history, no lost write.
func TestBootstrapRaceNoDoubleRoot(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.name", "t"}, {"config", "user.email", "t@e"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	const writers = 10
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s, err := OpenWith(dir, noopSerializer{})
			if err != nil {
				errs[n] = err
				return
			}
			_, errs[n] = s.Append(KindEvents, map[string]any{"w": n})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("bootstrap-race writer %d: %v", i, err)
		}
	}

	s, _ := Open(dir)
	got, err := s.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != writers {
		t.Fatalf("bootstrap race lost/dup writes: want %d, got %d", writers, len(got))
	}
	// Linear history rooted at a single root commit.
	mp := exec.Command("git", "rev-list", "--max-parents=0", "HEAD")
	mp.Dir = dir
	rout, _ := mp.CombinedOutput()
	if roots := strings.Fields(string(rout)); len(roots) != 1 {
		t.Fatalf("want exactly 1 root commit, got %d (%v)", len(roots), roots)
	}
}

func TestAppendRejectsUnknownKind(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)
	if _, err := s.Append(Kind("bogus"), map[string]any{}); err == nil {
		t.Fatal("Append with unknown kind should fail")
	}
	if _, err := s.Load(Kind("bogus")); err == nil {
		t.Fatal("Load with unknown kind should fail")
	}
}

// TestKindsCoverage guards the closed set: Kinds() returns exactly the six
// streams and every one is valid.
func TestKindsCoverage(t *testing.T) {
	ks := Kinds()
	if len(ks) != 6 {
		t.Fatalf("want 6 kinds, got %d", len(ks))
	}
	for _, k := range ks {
		if !k.valid() {
			t.Fatalf("Kinds() returned invalid kind %q", k)
		}
	}
}
