// Package store is the git-repo source of truth for mallcop's six append-only
// streams: events, findings, resolutions, baseline, conversation, and
// directives.
//
// ONE-BRAIN keystone. Every other core subsystem (the agent loop, the scan
// pipeline) CONSUMES this package; this package consumes nothing from them. The
// store has exactly one job: durably append records to a git repository such
// that the git repository ALONE can reconstruct the full state of the system.
// There is no separate database. The git history is the database.
//
// Each stream is a JSON-Lines file at the repo root (events.jsonl,
// findings.jsonl, …). Append serializes a record to one line, appends it to the
// stream file, stages, and commits. Reads replay the file. Because every write
// is a commit, `git log` is the audit trail and `git checkout <sha>` is
// time-travel.
//
// Directives and conversation are first-class streams, not afterthoughts. A
// directive written by one process (e.g. {"op":"suppress","pattern":"…"}) is
// loaded and obeyed by the next process that Opens the same repo — this is how
// an operator steers future scans. Conversation is the durable transcript that
// the agent loop appends to and replays.
//
// Concurrency model (OSS, single repo, no remote): a process-wide serialization
// hook guards the critical section, and every commit is performed on top of the
// current HEAD with a rebase-retry on the rare interleaving that still races.
// No write is ever lost; the merged log is deterministic (ordered by commit).
//
// IMPORT DISCIPLINE: this package imports NO channel, campfire, inference, or
// connect packages. It is the bottom of the dependency graph. See
// imports_test.go, which fails the build if that ever changes.
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Kind identifies one of the six append-only streams. The string value is also
// the on-disk basename (Kind+".jsonl").
type Kind string

const (
	// KindEvents is the normalized security-event stream.
	KindEvents Kind = "events"
	// KindFindings is the detector-output stream.
	KindFindings Kind = "findings"
	// KindResolutions is the actor-decision stream.
	KindResolutions Kind = "resolutions"
	// KindBaseline is the baseline-snapshot stream (append-only: each new
	// baseline is a new record; prior baselines are preserved as history).
	KindBaseline Kind = "baseline"
	// KindConversation is the durable agent-loop transcript stream.
	KindConversation Kind = "conversation"
	// KindDirectives is the operator-steering stream (suppressions, focus,
	// policy). Loaded and obeyed by the next scan.
	KindDirectives Kind = "directives"
)

// kinds is the closed set of valid streams. Append/Load reject anything else so
// a typo can never create a rogue, unreplayed file in the repo.
var kinds = map[Kind]bool{
	KindEvents:       true,
	KindFindings:     true,
	KindResolutions:  true,
	KindBaseline:     true,
	KindConversation: true,
	KindDirectives:   true,
}

// Kinds returns the six stream kinds in deterministic order. Useful for
// callers that want to enumerate or snapshot every stream.
func Kinds() []Kind {
	return []Kind{
		KindEvents, KindFindings, KindResolutions,
		KindBaseline, KindConversation, KindDirectives,
	}
}

func (k Kind) valid() bool { return kinds[k] }

func (k Kind) file() string { return string(k) + ".jsonl" }

// Serializer is the per-tenant write-serialization HOOK. The OSS store uses an
// in-process mutex (procMutex); the managed/multi-tenant side implements this
// against a durable lock (e.g. an Azure Table lease) so that writers in
// different processes — or different machines — cannot interleave commits to
// the same tenant repo.
//
// Lock must block until the caller holds exclusive write access for repoPath,
// and return a release func that the store calls (deferred) when the append's
// commit has landed. An implementation MAY ignore repoPath if its lock is
// already tenant-scoped. Lock returns an error only when the lock cannot be
// acquired at all (e.g. lease backend unreachable); a transient contention is
// the implementation's problem to retry internally.
//
// This package deliberately does NOT implement an aztables serializer. That
// belongs to the managed side, which will provide its own Serializer to
// OpenWith.
type Serializer interface {
	Lock(repoPath string) (release func(), err error)
}

// procMutex is the default OSS Serializer: a process-wide mutex keyed by
// absolute repo path. It guarantees that two *Store handles (or two goroutines)
// in the SAME process never commit concurrently to the same repo. Cross-process
// safety on a single machine is provided additionally by the rebase-retry in
// commitAppend; cross-machine safety is the managed Serializer's job.
type procMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

var defaultMutex = &procMutex{locks: map[string]*sync.Mutex{}}

func (p *procMutex) Lock(repoPath string) (func(), error) {
	p.mu.Lock()
	m, ok := p.locks[repoPath]
	if !ok {
		m = &sync.Mutex{}
		p.locks[repoPath] = m
	}
	p.mu.Unlock()
	m.Lock()
	return m.Unlock, nil
}

// Store is a handle to the git-repo source of truth at a single repo path. It
// is safe for concurrent use by multiple goroutines; appends are serialized by
// the Serializer.
type Store struct {
	repoPath   string
	serializer Serializer
	authorName string
	authorMail string
}

// Open opens (and, on a fresh repo, initializes the streams in) the git
// repository rooted at repoPath. repoPath must already be a git work tree —
// callers run `git init` first (the store does not create repos; tests and the
// CLI own that lifecycle). Open uses the default in-process Serializer.
//
// Open is cheap and side-effect-light: it verifies the repo, but does NOT read
// or rewrite any stream. State is reconstructed lazily by Load*/LoadDirectives.
func Open(repoPath string) (*Store, error) {
	return OpenWith(repoPath, defaultMutex)
}

// OpenWith is Open with an explicit Serializer. The managed side passes its
// durable, tenant-scoped lock here. A nil serializer falls back to the default
// in-process mutex.
func OpenWith(repoPath string, s Serializer) (*Store, error) {
	if s == nil {
		s = defaultMutex
	}
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("store: resolve repo path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("store: repo path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("store: repo path %q is not a directory", abs)
	}
	if _, err := os.Stat(filepath.Join(abs, ".git")); err != nil {
		return nil, fmt.Errorf("store: %q is not a git repository (run git init first): %w", abs, err)
	}
	return &Store{
		repoPath:   abs,
		serializer: s,
		authorName: "mallcop-store",
		authorMail: "store@mallcop.app",
	}, nil
}

// Path returns the absolute repo path this store writes to.
func (s *Store) Path() string { return s.repoPath }

// Append serializes record to a single JSON line and appends it to the kind's
// stream, then commits. The write is APPEND-ONLY: prior records in the file are
// never read, parsed, or rewritten — the new line is concatenated to the
// existing bytes, so history is preserved verbatim. The commit is taken under
// the Serializer lock and retried via rebase if a concurrent committer moved
// HEAD between staging and commit, so no write is ever lost.
//
// record may be any JSON-serializable value (a typed struct such as
// finding.Finding, or a map[string]any directive). Append returns the resulting
// commit SHA.
func (s *Store) Append(kind Kind, record any) (sha string, err error) {
	if !kind.valid() {
		return "", fmt.Errorf("store: unknown stream kind %q", kind)
	}
	line, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("store: marshal %s record: %w", kind, err)
	}
	if bytes.ContainsRune(line, '\n') {
		// json.Marshal never emits a bare newline, but guard the JSONL
		// invariant explicitly: one record == one line.
		return "", fmt.Errorf("store: marshaled %s record contains a newline", kind)
	}

	release, err := s.serializer.Lock(s.repoPath)
	if err != nil {
		return "", fmt.Errorf("store: acquire write lock: %w", err)
	}
	defer release()

	return s.commitAppend(kind, line)
}

// commitAppend performs the append-and-commit critical section: REBASE-RETRY on
// conflict via a git ref compare-and-swap. The caller holds the Serializer lock,
// which serializes writers in the SAME process; this function additionally
// makes the write safe against a SECOND OS PROCESS (or a managed Serializer that
// scopes per-tenant rather than per-repo) WITHOUT relying on the shared work
// tree or index at all.
//
// A naive "append to the work-tree file, then git add && git commit" is unsafe
// under true concurrency: two processes share one work tree and one index.lock,
// so their file appends and commits interleave into lost writes, duplicated
// records, or hard "File exists" failures. We sidestep the work tree entirely
// and operate on the git OBJECT STORE with plumbing:
//
//  1. Read the current HEAD (oldHead) and the committed content of the stream
//     blob at HEAD.
//  2. Append our line to that content in memory and write a NEW BLOB
//     (git hash-object -w).
//  3. Build a NEW TREE from HEAD's tree with our blob swapped in
//     (read-tree + update-index in a TEMPORARY, per-attempt index file — never
//     the shared index — then write-tree).
//  4. Create the commit (git commit-tree -p oldHead).
//  5. Atomically advance the ref: git update-ref HEAD <newCommit> <oldHead>.
//     This is a COMPARE-AND-SWAP — it fails iff HEAD moved since step 1. On
//     failure we loop (rebase onto the new tip). On success our write is the
//     unique child of oldHead.
//
// Because the CAS rejects any commit whose expected-old-value is stale, no
// concurrent writer can be overwritten: every winner advances HEAD by exactly
// one commit, every loser retries against the new HEAD. The result is a linear,
// deterministic, commit-ordered log with NO lost write and NO duplicate, proven
// by TestRebaseRetryUnderTrueRace.
func (s *Store) commitAppend(kind Kind, line []byte) (string, error) {
	const maxRetries = 128
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff(attempt)
		}

		// oldHead is the tip we rebase onto, or "" if the repo has no commits
		// yet (a freshly `git init`'d repo). The first Append bootstraps a root
		// commit; thereafter every Append builds on the prior tip.
		oldHead, _ := s.head() // err ⇒ no HEAD ⇒ oldHead == ""

		// (1) Current committed content of the stream at HEAD ("" if the blob
		// does not exist yet, or no HEAD). We read from the OBJECT STORE, not
		// the work tree, so a peer's in-flight work-tree state cannot taint us.
		var prev []byte
		if oldHead != "" {
			var err error
			prev, err = s.blobAt(oldHead, kind.file())
			if err != nil {
				lastErr = err
				continue
			}
		}

		// (2) Append our line in memory and write the new blob.
		next := make([]byte, 0, len(prev)+len(line)+1)
		next = append(next, prev...)
		next = append(next, line...)
		next = append(next, '\n')
		blobSHA, err := s.hashObject(next)
		if err != nil {
			lastErr = err
			continue
		}

		// (3) Build the new tree (off HEAD's tree, or the empty tree on
		// bootstrap) with our blob swapped in, using a per-attempt temp index
		// so we never touch the shared index.
		treeSHA, err := s.buildTree(oldHead, kind.file(), blobSHA)
		if err != nil {
			lastErr = err
			continue
		}

		// (4) Commit the tree on top of oldHead (no parent on bootstrap).
		commitSHA, err := s.commitTree(treeSHA, oldHead, fmt.Sprintf("store: append %s", kind))
		if err != nil {
			lastErr = err
			continue
		}

		// (5) CAS the ref. On bootstrap, require the ref to NOT yet exist (a
		// zero old-value) so two racing first-writers can't both create it;
		// otherwise require it to still equal oldHead. Either way a stale CAS
		// is retryable contention.
		var casArgs []string
		if oldHead == "" {
			// 40 zeros = "ref must not currently exist".
			casArgs = []string{"update-ref", "HEAD", commitSHA, strings.Repeat("0", 40)}
		} else {
			casArgs = []string{"update-ref", "HEAD", commitSHA, oldHead}
		}
		if _, err := s.git(casArgs...); err != nil {
			lastErr = err // expected under contention — rebase and retry
			continue
		}
		return commitSHA, nil
	}
	return "", fmt.Errorf("store: commit %s gave up after %d rebase retries: %w", kind, maxRetries, lastErr)
}

// blobAt returns the bytes of the file blob at the given commit, or empty bytes
// if the file does not exist in that commit's tree.
func (s *Store) blobAt(commit, file string) ([]byte, error) {
	out, err := s.gitRaw("cat-file", "-p", commit+":"+file)
	if err != nil {
		// Missing path is not an error: the stream simply has no records yet.
		if strings.Contains(err.Error(), "does not exist") ||
			strings.Contains(err.Error(), "Not a valid object name") ||
			strings.Contains(err.Error(), "exists on disk, but not in") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: read blob %s:%s: %w", commit, file, err)
	}
	return out, nil
}

// hashObject writes content as a blob into the object store and returns its sha.
func (s *Store) hashObject(content []byte) (string, error) {
	out, err := s.gitStdin(content, "hash-object", "-w", "--stdin")
	if err != nil {
		return "", fmt.Errorf("store: hash-object: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// buildTree produces a new tree identical to baseCommit's tree but with file
// pointing at blobSHA. It uses a TEMPORARY index file unique to this attempt so
// concurrent writers never contend on the repo's shared index.
func (s *Store) buildTree(baseCommit, file, blobSHA string) (string, error) {
	tmpIndex, err := os.CreateTemp("", "mallcop-store-index-*")
	if err != nil {
		return "", fmt.Errorf("store: temp index: %w", err)
	}
	idxPath := tmpIndex.Name()
	if err := tmpIndex.Close(); err != nil {
		return "", fmt.Errorf("store: close temp index: %w", err)
	}
	// Remove the empty placeholder: git rejects a 0-byte file as a corrupt
	// index ("smaller than expected"). It must create the index fresh at this
	// path. We only needed CreateTemp to reserve a collision-free name.
	if err := os.Remove(idxPath); err != nil {
		return "", fmt.Errorf("store: clear temp index: %w", err)
	}
	defer os.Remove(idxPath)

	env := append(s.gitEnv(), "GIT_INDEX_FILE="+idxPath)

	// Seed the temp index from the base commit's tree. On bootstrap (no base
	// commit) the temp index starts empty, so we skip read-tree.
	if baseCommit != "" {
		if out, err := s.gitEnvCmd(env, nil, "read-tree", baseCommit); err != nil {
			return "", fmt.Errorf("store: read-tree %s: %v: %s", baseCommit, err, out)
		}
	}
	// Swap in our blob at the stream path (regular file mode 100644).
	if out, err := s.gitEnvCmd(env, nil, "update-index", "--add", "--cacheinfo", "100644", blobSHA, file); err != nil {
		return "", fmt.Errorf("store: update-index %s: %v: %s", file, err, out)
	}
	// Write the resulting tree.
	out, err := s.gitEnvCmd(env, nil, "write-tree")
	if err != nil {
		return "", fmt.Errorf("store: write-tree: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// commitTree creates a commit object for tree and returns its sha. parent is
// the single parent, or "" to create a root (parentless) commit on bootstrap.
// No ref is moved here — that is the CAS step in commitAppend.
func (s *Store) commitTree(tree, parent, message string) (string, error) {
	args := []string{"commit-tree", tree, "-m", message}
	if parent != "" {
		args = []string{"commit-tree", tree, "-p", parent, "-m", message}
	}
	out, err := s.git(args...)
	if err != nil {
		return "", fmt.Errorf("store: commit-tree: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// Load replays the kind's stream and returns each record as a raw JSON message,
// oldest first. State is reconstructed from the git OBJECT STORE at HEAD — the
// committed blob, not the work-tree file — so a Load always reflects durable,
// committed records and never a peer's in-flight write. This is what makes the
// git repo ALONE the source of truth: `git clone` carries every record, and a
// work tree is not even required.
//
// A stream with no committed records (never appended to, or a repo with no
// commits) is not an error — it returns an empty slice, because "the system has
// emitted zero of these" is a valid reconstructed state. Blank lines are
// skipped so a partially-flushed record degrades gracefully.
func (s *Store) Load(kind Kind) ([]json.RawMessage, error) {
	if !kind.valid() {
		return nil, fmt.Errorf("store: unknown stream kind %q", kind)
	}
	head, err := s.head()
	if err != nil {
		// No HEAD (repo with zero commits) → no records yet.
		return nil, nil
	}
	content, err := s.blobAt(head, kind.file())
	if err != nil {
		return nil, fmt.Errorf("store: load %s: %w", kind, err)
	}
	if len(content) == 0 {
		return nil, nil
	}

	var out []json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(content))
	// Allow long lines (large payloads/evidence blobs).
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		// Validate it is well-formed JSON so a corrupt line surfaces here,
		// not three layers up in a consumer.
		if !json.Valid(raw) {
			return nil, fmt.Errorf("store: %s line %d is not valid JSON", kind, lineNo)
		}
		cp := make(json.RawMessage, len(raw))
		copy(cp, raw)
		out = append(out, cp)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("store: scan %s: %w", kind, err)
	}
	return out, nil
}

// --- git plumbing -----------------------------------------------------------

func (s *Store) head() (string, error) {
	out, err := s.git("rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// backoff sleeps a short, jittered interval that grows with the attempt count,
// so a contended set of writers de-synchronizes on a CAS loss instead of
// livelocking. Capped so a hot repo still drains quickly.
func backoff(attempt int) {
	base := time.Duration(attempt) * 2 * time.Millisecond
	if base > 50*time.Millisecond {
		base = 50 * time.Millisecond
	}
	jitter := time.Duration(rand.Int63n(int64(2*time.Millisecond) + 1))
	time.Sleep(base + jitter)
}

// git runs a git subcommand in the repo and returns trimmed-free stdout as a
// string. It sets a deterministic identity and disables any user/global
// hooks/config bleed so the store's commits are reproducible regardless of the
// operator's environment.
func (s *Store) git(args ...string) (string, error) {
	out, err := s.gitEnvCmd(s.gitEnv(), nil, args...)
	return string(out), err
}

// gitRaw is git but returns raw stdout bytes (no string conversion churn) for
// reading blob content verbatim.
func (s *Store) gitRaw(args ...string) ([]byte, error) {
	return s.gitEnvCmd(s.gitEnv(), nil, args...)
}

// gitStdin runs git feeding stdin from in, returning raw stdout.
func (s *Store) gitStdin(in []byte, args ...string) ([]byte, error) {
	return s.gitEnvCmd(s.gitEnv(), in, args...)
}

// gitEnvCmd is the single exec chokepoint: runs git with an explicit env and
// optional stdin, returning raw stdout. Routing every git call through one
// function keeps stderr formatting and env handling consistent.
func (s *Store) gitEnvCmd(env []string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = s.repoPath
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("git %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (s *Store) gitEnv() []string {
	env := os.Environ()
	env = append(env,
		"GIT_AUTHOR_NAME="+s.authorName,
		"GIT_AUTHOR_EMAIL="+s.authorMail,
		"GIT_COMMITTER_NAME="+s.authorName,
		"GIT_COMMITTER_EMAIL="+s.authorMail,
		// Keep the store hermetic: ignore global/system config that could
		// inject signing, hooks, or alternate identities.
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	)
	return env
}
