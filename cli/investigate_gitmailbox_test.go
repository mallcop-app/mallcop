package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func mustGitCLI(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %q: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

// TestRunInvestigate_SessionModeDrivesRealGitMailbox proves the --session/
// --chat-branch/--chat-remote/--repo flags actually wire to a real
// investigate.GitMailbox (mallcoppro-067) through the CLI entrypoint: a
// browser-side clone writes a control:shutdown record to sessions/<id>/
// inbox.jsonl on a real mallcop-chat branch behind a real bare "origin",
// runInvestigate runs --serve --session against a second (runner) clone, and
// a THIRD independent clone proves ready+exit(shutdown) landed as real
// commits on the shared remote -- the same round trip
// core/investigate/gitmailbox_test.go proves at the package level, but
// exercised here through cli flag parsing instead of calling the package API
// directly.
func TestRunInvestigate_SessionModeDrivesRealGitMailbox(t *testing.T) {
	const branch = "mallcop-chat"
	const sessionID = "sess-cli-1"

	bare := t.TempDir()
	mustGitCLI(t, bare, "init", "-q", "--bare", "-b", "main")

	browserDir := t.TempDir()
	mustGitCLI(t, browserDir, "clone", "-q", bare, browserDir)
	for _, args := range [][]string{
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		mustGitCLI(t, browserDir, args...)
	}
	if err := os.WriteFile(filepath.Join(browserDir, "README.md"), []byte("customer repo\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	mustGitCLI(t, browserDir, "add", "README.md")
	mustGitCLI(t, browserDir, "commit", "-q", "-m", "root")
	mustGitCLI(t, browserDir, "push", "-q", "-u", "origin", "main")

	mustGitCLI(t, browserDir, "checkout", "-q", "--orphan", branch)
	mustGitCLI(t, browserDir, "rm", "-rqf", "--ignore-unmatch", ".")
	sessDir := filepath.Join(browserDir, "sessions", sessionID)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir session dir: %v", err)
	}
	ctrl := map[string]any{"type": "control", "seq": 1, "cmd": "shutdown"}
	b, _ := json.Marshal(ctrl)
	if err := os.WriteFile(filepath.Join(sessDir, "inbox.jsonl"), append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write inbox.jsonl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessDir, "meta.json"), []byte(`{"session_id":"`+sessionID+`"}`), 0o644); err != nil {
		t.Fatalf("write meta.json: %v", err)
	}
	mustGitCLI(t, browserDir, "add", "sessions")
	mustGitCLI(t, browserDir, "commit", "-q", "-m", "chat: session start")
	mustGitCLI(t, browserDir, "push", "-q", "-u", "origin", branch)

	runnerDir := t.TempDir()
	mustGitCLI(t, runnerDir, "clone", "-q", bare, runnerDir)
	for _, args := range [][]string{
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		mustGitCLI(t, runnerDir, args...)
	}

	storeDir := t.TempDir()
	if _, err := openOrInitStore(storeDir); err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}

	// The inference endpoint must resolve (runInvestigate requires it before
	// Serve even starts) but must NEVER actually be called: the queued
	// record is a control:shutdown, which Serve handles before ever calling
	// Ask/askCore.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("inference endpoint was called, but the queued record is control:shutdown -- Serve should have exited first")
	}))
	defer srv.Close()
	t.Setenv(envInferenceURL, srv.URL)
	t.Setenv(envInferenceKey, "test-key")

	err := runInvestigate([]string{
		"--serve",
		"--session", sessionID,
		"--chat-branch", branch,
		"--chat-remote", "origin",
		"--repo", runnerDir,
		"--store", storeDir,
		"--idle-timeout", "5s", // would hang the test if shutdown didn't short-circuit it
	})
	if err != nil {
		t.Fatalf("runInvestigate: %v", err)
	}

	verifyDir := t.TempDir()
	mustGitCLI(t, verifyDir, "clone", "-q", "--branch", branch, bare, verifyDir)
	raw, err := os.ReadFile(filepath.Join(verifyDir, "sessions", sessionID, "outbox.jsonl"))
	if err != nil {
		t.Fatalf("read outbox.jsonl from fresh clone: %v", err)
	}
	var types []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal outbox line %q: %v", line, err)
		}
		tp, _ := rec["type"].(string)
		types = append(types, tp)
		if tp == "exit" {
			if reason, _ := rec["reason"].(string); reason != "shutdown" {
				t.Fatalf("exit record reason = %q, want shutdown", reason)
			}
		}
	}
	if len(types) != 2 || types[0] != "ready" || types[1] != "exit" {
		t.Fatalf("outbox types (from a fresh third clone of origin) = %v, want [ready exit]", types)
	}
}
