package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/selfgate"
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
// errFindings sentinel (exit 1) and a JSON GateResult with the guard stage
// failed and NO later stage run (the short-circuit).
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
	var result selfgate.GateResult
	if jerr := json.Unmarshal([]byte(out), &result); jerr != nil {
		t.Fatalf("JSON GateResult unparseable: %v\n%s", jerr, out)
	}
	if result.Passed {
		t.Fatalf("result.Passed = true for a rejected proposal:\n%s", out)
	}
	if len(result.Stages) != 1 || result.Stages[0].Name != selfgate.StageGuard || result.Stages[0].Passed {
		t.Fatalf("expected a single failed guard stage (short-circuit), got %+v", result.Stages)
	}
	if len(result.Stages[0].Findings) == 0 || result.Stages[0].Findings[0].Path != "go.mod" {
		t.Fatalf("expected a go.mod finding, got %+v", result.Stages[0].Findings)
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
	var result selfgate.GateResult
	if jerr := json.Unmarshal([]byte(out), &result); jerr != nil {
		t.Fatalf("JSON GateResult unparseable: %v\n%s", jerr, out)
	}
	if !result.Passed {
		t.Fatalf("result.Passed = false for a clean proposal:\n%s", out)
	}
	if len(result.Stages) != 1 || result.Stages[0].Name != selfgate.StageGuard {
		t.Fatalf("--guard-only must pin the run to the guard stage, got %+v", result.Stages)
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

// TestRunValidateProposal_FullFreeTierByDefault proves the CLI runs ALL free
// stages by default (no --guard-only): over a clone of the REAL repo, a
// tuning-only widen proposal (base = tuning.yaml without the poweruser
// keyword, head = the committed state that closes PE-08) passes guard,
// structural, AND exam-detect, with coverage +1, and exits 0. Also exercises
// the --head default (HEAD, detached at the real head commit).
func TestRunValidateProposal_FullFreeTierByDefault(t *testing.T) {
	root := cliRepoUnderTest(t)
	clone := filepath.Join(t.TempDir(), "clone")
	gitProposal(t, filepath.Dir(clone), "clone", "-q", "--no-hardlinks", root, clone)
	head := gitProposal(t, clone, "rev-parse", "HEAD")

	// Fixture base: the committed tuning minus the poweruser keyword — the
	// PE-08 detection gap re-opens at base and is closed at head.
	tuningPath := filepath.Join(clone, "detectors", "tuning.yaml")
	tuning, err := os.ReadFile(tuningPath)
	if err != nil {
		t.Fatalf("read tuning.yaml: %v", err)
	}
	const anchor = "\n    - poweruser"
	if n := strings.Count(string(tuning), anchor); n != 1 {
		t.Fatalf("expected exactly 1 occurrence of %q in the real tuning.yaml, found %d — update the fixture", anchor, n)
	}
	if err := os.WriteFile(tuningPath, []byte(strings.Replace(string(tuning), anchor, "", 1)), 0o644); err != nil {
		t.Fatalf("write tuning.yaml: %v", err)
	}
	base := commitProposal(t, clone, "fixture base: reopen the PE-08 gap")
	gitProposal(t, clone, "checkout", "-q", head) // --head defaults to HEAD

	t.Chdir(clone)
	out, err := withStdio(t, "", func() error {
		return runValidateProposal([]string{"--base", base, "--json"})
	})
	if err != nil {
		t.Fatalf("expected the full free tier to pass, got %v\n%s", err, out)
	}
	var result selfgate.GateResult
	if jerr := json.Unmarshal([]byte(out), &result); jerr != nil {
		t.Fatalf("JSON GateResult unparseable: %v\n%s", jerr, out)
	}
	if !result.Passed {
		t.Fatalf("result.Passed = false for the widen proposal:\n%s", out)
	}
	if len(result.Stages) != 3 ||
		result.Stages[0].Name != selfgate.StageGuard ||
		result.Stages[1].Name != selfgate.StageStructural ||
		result.Stages[2].Name != selfgate.StageExamDetect {
		t.Fatalf("expected all three free stages to run by default, got %+v", result.Stages)
	}
	if result.CoveragePlus != 1 {
		t.Fatalf("CoveragePlus = %d, want 1 (the PE-08 close)\n%s", result.CoveragePlus, out)
	}
	if result.BaseSHA != base || result.HeadSHA != head {
		t.Fatalf("SHAs not carried: base %s (want %s), head %s (want %s)", result.BaseSHA, base, result.HeadSHA, head)
	}
}

// cliRepoUnderTest locates the real repository root by walking up from the
// test's working directory to go.mod.
func cliRepoUnderTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
}
