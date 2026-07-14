package cli

import (
	"encoding/json"
	"fmt"
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
// stages by default (no --guard-only): over a clone of the REAL repo, the
// SYNTHETIC tuning widen (base = the synthetic gap-close pair injected with the
// gap OPEN, head = the synthetic elevated keyword added) passes guard,
// structural, AND exam-detect, with coverage +1, and exits 0. Uses the synthetic
// pair (exams/synthetic/) so it depends on NO real corpus scenario (rd
// mallcoppro-a07 / S1).
func TestRunValidateProposal_FullFreeTierByDefault(t *testing.T) {
	root := cliRepoUnderTest(t)
	clone := filepath.Join(t.TempDir(), "clone")
	gitProposal(t, filepath.Dir(clone), "clone", "-q", "--no-hardlinks", root, clone)

	// BASE: inject the synthetic gap-close pair into the pinned corpus (gap OPEN
	// — SYNTH-PE-01 RED), regenerate the pin, commit.
	synthDir := filepath.Join(clone, "exams", "scenarios", "synthetic")
	if err := os.MkdirAll(synthDir, 0o755); err != nil {
		t.Fatalf("mkdir synthetic: %v", err)
	}
	for _, name := range []string{"SYNTH-PE-01-elevated-must-fire.yaml", "SYNTH-PE-02-baseline-benign-twin.yaml"} {
		data, err := os.ReadFile(filepath.Join(root, "exams", "synthetic", name))
		if err != nil {
			t.Fatalf("read synthetic fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(synthDir, name), data, 0o644); err != nil {
			t.Fatalf("inject %s: %v", name, err)
		}
	}
	count, sha := cliRecomputeCorpusPin(t, clone)
	if err := os.WriteFile(filepath.Join(clone, "exams", "scenarios", "corpus.pin"),
		[]byte(fmt.Sprintf("# fixture pin (synthetic gap-close injection)\ncount %d\nsha256 %s\n", count, sha)), 0o644); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	base := commitProposal(t, clone, "fixture base: synthetic gap-close pair injected, gap OPEN")

	// HEAD: the widen — append the synthetic elevated keyword to tuning.yaml.
	tuningPath := filepath.Join(clone, "detectors", "tuning.yaml")
	tuning, err := os.ReadFile(tuningPath)
	if err != nil {
		t.Fatalf("read tuning.yaml: %v", err)
	}
	if err := os.WriteFile(tuningPath, []byte(string(tuning)+"    - mallcopsyntheticelevated\n"), 0o644); err != nil {
		t.Fatalf("write tuning.yaml: %v", err)
	}
	head := commitProposal(t, clone, "proposal: synthetic tuning widen closes SYNTH-PE-01")

	t.Chdir(clone)
	out, err := withStdio(t, "", func() error {
		return runValidateProposal([]string{"--base", base, "--head", head, "--json"})
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
		t.Fatalf("CoveragePlus = %d, want 1 (the SYNTH-PE-01 close)\n%s", result.CoveragePlus, out)
	}
	if result.BaseSHA != base || result.HeadSHA != head {
		t.Fatalf("SHAs not carried: base %s (want %s), head %s (want %s)", result.BaseSHA, base, result.HeadSHA, head)
	}
}

// gitWorktreeAdd materializes a detached worktree of root at sha into dir —
// duplicated locally so the CLI test controls its own cleanup (mirrors
// core/selfgate's unexported addWorktree/removeWorktree, not reachable from
// this package).
func gitWorktreeAdd(t *testing.T, root, dir, sha string) {
	t.Helper()
	gitProposal(t, root, "worktree", "add", "--detach", dir, sha)
	t.Cleanup(func() {
		_, _ = exec.Command("git", "-C", root, "worktree", "remove", "--force", dir).CombinedOutput()
		_, _ = exec.Command("git", "-C", root, "worktree", "prune").CombinedOutput()
	})
}

// TestRunValidateProposal_ExamRepoFlagRoutesCustomerTreeMode proves the
// --exam-repo flag threads all the way from the CLI into
// selfgate.Options.ExamRepo and actually changes which stage-3 lane runs: the
// SAME customer-shaped (no cmd/mallcop) proposal tree that
// TestRunValidateProposal_DefaultModeFailsLoudlyOnCustomerShapedTree_ExamRepo
// below rejects in the default lane passes clean once --exam-repo names a
// real reference tree (a detached worktree of the repo under test — it still
// has cmd/mallcop and its own pinned corpus). The tree carries no
// detectors/<name>/ of its own, so customer-tree mode has "nothing to grade"
// — the discriminating signal is that this NO LONGER errors the way the
// default-mode test (same tree, no flag) does.
func TestRunValidateProposal_ExamRepoFlagRoutesCustomerTreeMode(t *testing.T) {
	root := cliRepoUnderTest(t)
	examTree := filepath.Join(t.TempDir(), "examtree")
	headSHA := gitProposal(t, root, "rev-parse", "HEAD")
	gitWorktreeAdd(t, root, examTree, headSHA)

	dir := t.TempDir()
	gitProposal(t, dir, "init", "-q")
	writeProposalFile(t, dir, "go.mod", "module example.com/customer-fixture\n\ngo 1.25.0\n")
	base := commitProposal(t, dir, "base")
	writeProposalFile(t, dir, "README.md", "customer deployment repo\n")
	head := commitProposal(t, dir, "docs-only proposal")

	t.Chdir(dir)
	out, err := withStdio(t, "", func() error {
		return runValidateProposal([]string{"--base", base, "--head", head, "--exam-repo", examTree, "--json"})
	})
	if err != nil {
		t.Fatalf("expected --exam-repo mode to pass (nothing to grade), got %v\n%s", err, out)
	}
	var result selfgate.GateResult
	if jerr := json.Unmarshal([]byte(out), &result); jerr != nil {
		t.Fatalf("JSON GateResult unparseable: %v\n%s", jerr, out)
	}
	if !result.Passed {
		t.Fatalf("result.Passed = false under --exam-repo with nothing to grade:\n%s", out)
	}
	requireCLIStageNames(t, result, selfgate.StageGuard, selfgate.StageStructural, selfgate.StageExamDetect)
	examStage := result.Stages[2]
	if !strings.Contains(examStage.Evidence, "customer-tree exam mode") {
		t.Fatalf("expected the exam-detect evidence to name customer-tree mode, got %q", examStage.Evidence)
	}
}

// TestRunValidateProposal_DefaultModeFailsLoudlyOnCustomerShapedTree_ExamRepo
// is the CLI-level counterpart to the core/selfgate proof of the same name:
// the SAME customer-shaped tree WITHOUT --exam-repo fails loudly (exit 2,
// not the findings sentinel) naming the flag, instead of surfacing a raw
// `go build ./cmd/mallcop` failure.
func TestRunValidateProposal_DefaultModeFailsLoudlyOnCustomerShapedTree_ExamRepo(t *testing.T) {
	dir := t.TempDir()
	gitProposal(t, dir, "init", "-q")
	writeProposalFile(t, dir, "go.mod", "module example.com/customer-fixture\n\ngo 1.25.0\n")
	base := commitProposal(t, dir, "base")
	writeProposalFile(t, dir, "README.md", "customer deployment repo\n")
	head := commitProposal(t, dir, "docs-only proposal")

	t.Chdir(dir)
	_, err := withStdio(t, "", func() error {
		return runValidateProposal([]string{"--base", base, "--head", head, "--json"})
	})
	if err == nil || isFindingsError(err) {
		t.Fatalf("expected a loud operational error (not the findings sentinel), got %v", err)
	}
	if !strings.Contains(err.Error(), "--exam-repo") && !strings.Contains(err.Error(), "ExamRepo") {
		t.Fatalf("error must name the --exam-repo flag, got: %v", err)
	}
}

// requireCLIStageNames is requireStageNames's CLI-package-local duplicate
// (core/selfgate's version is unexported).
func requireCLIStageNames(t *testing.T, res selfgate.GateResult, want ...string) {
	t.Helper()
	if len(res.Stages) != len(want) {
		t.Fatalf("expected stages %v to have run, got %+v", want, res.Stages)
	}
	for i, name := range want {
		if res.Stages[i].Name != name {
			t.Fatalf("stage[%d] = %q, want %q (all: %+v)", i, res.Stages[i].Name, name, res.Stages)
		}
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
