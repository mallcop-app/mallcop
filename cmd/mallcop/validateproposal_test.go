package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitProposal runs git hermetically in dir (fixed identity, no config bleed) —
// the same discipline as core/selfgate's chokepoint, duplicated locally so the
// CLI test controls its own fixture.
func gitProposal(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeProposalFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	abs := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func commitProposal(t *testing.T, dir, msg string) string {
	t.Helper()
	gitProposal(t, dir, "add", "-A")
	gitProposal(t, dir, "commit", "-q", "--no-verify", "-m", msg)
	return gitProposal(t, dir, "rev-parse", "HEAD")
}

// TestRunValidateProposal_RejectsProtectedPathEdit proves the CLI wiring
// end-to-end: a proposal touching go.mod (a protected path) yields the
// errFindings sentinel (exit 1) and a JSON report with the guard stage failed.
func TestRunValidateProposal_RejectsProtectedPathEdit(t *testing.T) {
	dir := t.TempDir()
	gitProposal(t, dir, "init", "-q")
	writeProposalFile(t, dir, "go.mod", "module example\n")
	base := commitProposal(t, dir, "base")
	writeProposalFile(t, dir, "go.mod", "module example\n// tampered\n")
	head := commitProposal(t, dir, "tamper go.mod")

	t.Chdir(dir)
	out, err := withStdio(t, "", func() error {
		return runValidateProposal([]string{"--base", base, "--head", head, "--json"})
	})

	if !isFindingsError(err) {
		t.Fatalf("expected the findings sentinel (exit 1), got %v", err)
	}
	var report proposalReport
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
		t.Fatalf("JSON report unparseable: %v\n%s", jerr, out)
	}
	if report.Pass {
		t.Fatalf("report.Pass = true for a rejected proposal:\n%s", out)
	}
	if len(report.Stages) != 1 || report.Stages[0].Name != "guard" || report.Stages[0].Pass {
		t.Fatalf("expected a single failed guard stage, got %+v", report.Stages)
	}
	if len(report.Stages[0].Findings) == 0 || report.Stages[0].Findings[0].Path != "go.mod" {
		t.Fatalf("expected a go.mod finding, got %+v", report.Stages[0].Findings)
	}
}

// TestRunValidateProposal_PassesCleanProposal proves a proposal the guard has
// no opinion on (a docs file) exits clean (nil error → exit 0), with
// --guard-only exercising the stage-pinning flag.
func TestRunValidateProposal_PassesCleanProposal(t *testing.T) {
	dir := t.TempDir()
	gitProposal(t, dir, "init", "-q")
	writeProposalFile(t, dir, "README.md", "hello\n")
	base := commitProposal(t, dir, "base")
	writeProposalFile(t, dir, "docs/notes.md", "additive docs\n")
	head := commitProposal(t, dir, "docs")

	t.Chdir(dir)
	out, err := withStdio(t, "", func() error {
		return runValidateProposal([]string{"--base", base, "--head", head, "--guard-only", "--json"})
	})
	if err != nil {
		t.Fatalf("expected a clean pass, got %v\n%s", err, out)
	}
	var report proposalReport
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
		t.Fatalf("JSON report unparseable: %v\n%s", jerr, out)
	}
	if !report.Pass {
		t.Fatalf("report.Pass = false for a clean proposal:\n%s", out)
	}
}

// TestRunValidateProposal_RequiresBase proves a missing --base is an
// operational error (exit 2), not a findings rejection.
func TestRunValidateProposal_RequiresBase(t *testing.T) {
	_, err := withStdio(t, "", func() error {
		return runValidateProposal(nil)
	})
	if err == nil || isFindingsError(err) {
		t.Fatalf("expected an operational error for missing --base, got %v", err)
	}
}
