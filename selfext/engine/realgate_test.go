package engine

// realgate_test.go closes the veracity finding: every OTHER
// test in this package binds the engine to `mallcop validate-proposal` via a
// SHELL SCRIPT stub (writeValidateStub et al.) — engine.GateResult is never
// actually decoded from bytes the REAL mallcop core/selfgate.GateResult
// marshaler produced, so a wire-format drift between the two independently
// maintained struct definitions would pass every existing test silently.
//
// These tests build the REAL `mallcop` binary from the sibling OSS checkout
// (github.com/mallcop-app/mallcop, module-pinned by cmd/mallcop) and run the
// engine's exact `validate-proposal --base ... --head HEAD --json` subprocess
// contract against it — the same binary, the same argv, the same env-allowlist
// path Run() uses in production. Three tests, increasing in how much of the
// REAL gate they exercise:
//
//   - RealGate_RejectsProtectedPath (via RunValidateProposal directly): the
//     K3 guard stage short-circuits BEFORE structural/exam-detect run, so this
//     needs no full mallcop-shaped tree — fast (no `go build`).
//   - Run_RealGate_RejectsProtectedPath: the SAME real-gate REJECT, but driven
//     through the FULL Engine.Run() — spend gate, worktree jail, authoring,
//     commit, THEN the real binary — proving Outcome.Gate really is bound to
//     the real wire format end to end, not just the exported wrapper.
//   - RealGate_FullPipelineOnProductTree: runs ALL THREE stages (guard,
//     structural go build/go vet, exam-detect) against the sibling checkout's
//     OWN current HEAD (base==head, a deterministic no-op diff) — the only
//     test in the suite that proves the schema survives a full real 3-stage
//     run, not just the fast guard short-circuit.
//
// Every test here SKIPS (not fails) when the sibling checkout is absent — it
// is a real integration test, not a network mock, and has nothing to fake. It
// RUNS for real in two places: locally, whenever ~/projects/mallcop exists
// (the standard dev layout — see CLAUDE.md's Repos table), and in CI via
// .github/workflows/selfimprove-offline.yml, which checks out mallcop-app/
// mallcop as a sibling directory and points MALLCOP_SRC at it before running
// `go test ./selfext/...` (e2e/selfimprove/uc7b-selfext-tests.sh) —
// exactly the env-var convention e2e/selfimprove/lib.sh's build_mallcop()
// uses, deliberately mirrored here so this test and the offline harness agree
// on where the sibling checkout lives without any CI wiring beyond what
// selfimprove-offline.yml already does.
//
// A present-but-broken sibling checkout (exists, but `go build ./cmd/mallcop`
// fails) is a HARD failure, not a skip — that is real signal (a stale/broken
// sibling), not an absent-environment gap.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/opencode"
	"github.com/mallcop-app/mallcop/selfext/sandbox"
)

// mallcopSrcDir resolves the sibling OSS mallcop checkout the SAME way
// e2e/selfimprove/lib.sh's build_mallcop() does: the MALLCOP_SRC env var,
// defaulting to ~/projects/mallcop. Skips (loudly, with the setup hint) when
// it is absent or not a full mallcop checkout (no cmd/mallcop) — this is an
// integration test with a real dependency, not a mock with a fallback.
func mallcopSrcDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("MALLCOP_SRC")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skipf("real-gate integration test: MALLCOP_SRC unset and $HOME unavailable (%v) — skipping", err)
		}
		dir = filepath.Join(home, "projects", "mallcop")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Skipf("real-gate integration test SKIPPED: sibling mallcop checkout not found at %s "+
			"(set MALLCOP_SRC to override). This test binds engine.GateResult to the REAL "+
			"selfgate.GateResult wire format — it needs a real checkout, not a "+
			"mock, so it has nothing to fall back to. It RUNS in CI via "+
			".github/workflows/selfimprove-offline.yml, which checks out mallcop-app/mallcop as a "+
			"sibling and sets MALLCOP_SRC before `go test ./internal/selfext/...`.", dir)
	}
	if info, err := os.Stat(filepath.Join(dir, "cmd", "mallcop")); err != nil || !info.IsDir() {
		t.Skipf("real-gate integration test SKIPPED: %s has no cmd/mallcop — not a full mallcop checkout", dir)
	}
	return dir
}

// buildRealMallcop builds the REAL `mallcop` binary (the trusted gate) from
// the sibling checkout, exactly as production resolves Engine.ValidateBin from
// PATH (and exactly as e2e/selfimprove/lib.sh's build_mallcop() does for the
// offline harness). A present sibling checkout that fails to build is a hard
// failure (t.Fatalf), never a skip — a broken sibling is real signal.
func buildRealMallcop(t *testing.T) string {
	t.Helper()
	src := mallcopSrcDir(t)
	bin := filepath.Join(t.TempDir(), "mallcop")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mallcop")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/mallcop in sibling checkout %s: %v\n%s", src, err, out)
	}
	return bin
}

// gitH runs git -C repo <args> with a hermetic identity, fatal on error.
func gitH(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=selfext-realgate-test", "GIT_AUTHOR_EMAIL=selfext-realgate-test@example.com",
		"GIT_COMMITTER_NAME=selfext-realgate-test", "GIT_COMMITTER_EMAIL=selfext-realgate-test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func gitRevParse(t *testing.T, repo, ref string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "rev-parse", ref).CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse %s: %v\n%s", ref, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestRunValidateProposal_RealGate_RejectsProtectedPath proves the exported
// RunValidateProposal — the exact wrapper Engine.Run uses internally — binds
// engine.GateResult correctly to the REAL mallcop `validate-proposal`
// binary's JSON, not a shell-script stand-in. It reproduces the SAME
// protected-path fixture e2e/selfimprove/uc7a-validate-proposal.sh proves
// against the CLI directly (a diff touching core/agent/, the committee, is a
// K3 guard rejection: core/selfgate/guard.go's agent-must-never-touch set).
// Because the guard stage short-circuits BEFORE the structural/exam-detect
// stages run, this needs no full mallcop-shaped tree — a throwaway git repo
// suffices — so it stays fast (no `go build ./...` of the fixture itself,
// only the one-time `go build ./cmd/mallcop` of the real gate binary).
func TestRunValidateProposal_RealGate_RejectsProtectedPath(t *testing.T) {
	bin := buildRealMallcop(t)
	repo := initFixtureRepo(t)
	baseSHA := gitRevParse(t, repo, "HEAD")

	agentDir := filepath.Join(repo, "core", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	committee := filepath.Join(agentDir, "committee.go")
	body := "package agent\n\nfunc Vote() bool { return false /* bypass consensus */ }\n"
	if err := os.WriteFile(committee, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gitH(t, repo, "add", "-A")
	gitH(t, repo, "commit", "-q", "--no-verify", "-m", "bypass")

	gate, exitCode, rerr := RunValidateProposal(context.Background(), bin, repo, baseSHA, "")
	if rerr != nil {
		t.Fatalf("RunValidateProposal (real gate): %v", rerr)
	}

	// ---- the REAL selfgate.GateResult wire shape, round-tripped through the
	//      engine's OWN, independently-maintained struct definition
	//      (this engine deliberately does not import core/selfgate — see
	//      gate.go's package doc). This is the process-boundary contract
	//      flagged as circular/vacuous under the shell stub. ----
	if gate.SchemaVersion != expectedGateSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", gate.SchemaVersion, expectedGateSchemaVersion)
	}
	if gate.Tier != "free" {
		t.Errorf("Tier = %q, want %q", gate.Tier, "free")
	}
	if gate.Passed {
		t.Fatalf("expected the REAL gate to REJECT a consensus-bypass edit, got Passed=true: %+v", gate)
	}
	if exitCode != gateExitRejected {
		t.Errorf("exit code = %d, want %d (rejected-with-findings)", exitCode, gateExitRejected)
	}
	if gate.BaseSHA != baseSHA {
		t.Errorf("BaseSHA = %q, want %q", gate.BaseSHA, baseSHA)
	}
	if gate.HeadSHA == "" {
		t.Errorf("HeadSHA is empty")
	}
	if len(gate.Stages) != 1 {
		t.Fatalf("expected exactly 1 stage (short-circuit at guard), got %d: %+v", len(gate.Stages), gate.Stages)
	}
	stage := gate.Stages[0]
	if stage.Name != "guard" || stage.Passed {
		t.Fatalf("stage 0 = %+v, want name=guard passed=false", stage)
	}
	found := false
	for _, f := range stage.Findings {
		// "protected-path" mirrors core/selfgate.RuleProtectedPath — hardcoded
		// here (not imported) since this engine deliberately does not depend on
		// core/selfgate; this string literal IS the cross-boundary contract test.
		if f.Rule == "protected-path" && f.Path == "core/agent/committee.go" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a protected-path finding on core/agent/committee.go, got %+v", stage.Findings)
	}
}

// protectedPathAuthorer authors a change under core/agent/ — a K3
// GUARD-protected path the self-extension loop must never touch — so the REAL
// gate's guard stage rejects it. It stands in for opencode; opencode's own
// behavior (output-cap, redaction) is out of scope here — see /
// opencode/realbin_test.go for that adapter's own real-binary coverage.
type protectedPathAuthorer struct{}

func (protectedPathAuthorer) BuildTaskPrompt(opencode.TrustedGap, bool) string { return "prompt" }

func (protectedPathAuthorer) Invoke(_ context.Context, wt *sandbox.Worktree, _ string, _ string) (opencode.Result, error) {
	dir := filepath.Join(wt.Dir, "core", "agent")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return opencode.Result{}, err
	}
	body := "package agent\n\nfunc Vote() bool { return false /* bypass consensus */ }\n"
	if err := os.WriteFile(filepath.Join(dir, "committee.go"), []byte(body), 0o644); err != nil {
		return opencode.Result{}, err
	}
	return opencode.Result{TranscriptRedacted: []byte("authored a protected-path edit (real-gate test)")}, nil
}

// TestRun_RealGate_RejectsProtectedPath drives the FULL Engine.Run() — spend
// gate, worktree jail, opencode-shaped authoring, commit, THEN THE REAL
// `mallcop validate-proposal` BINARY (not writeValidateStub) — end to end. It
// proves Outcome.Gate really is populated from the actual selfgate.GateResult
// wire format: the RED verdict correctly poisons the fingerprint, and no
// reviewable artifact is emitted. Every OTHER Run() test in this package
// drives the identical code path against writeValidateStub (a shell script);
// this is the one binding to the real trusted binary end to end.
func TestRun_RealGate_RejectsProtectedPath(t *testing.T) {
	bin := buildRealMallcop(t)
	h := newHarness(t, 0.0)
	gate := &spySpendGate{}
	eng := h.engine(gate, protectedPathAuthorer{}, bin)

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Rejected {
		t.Fatalf("expected Rejected against the REAL gate, got %+v", out)
	}
	if out.Gate == nil {
		t.Fatalf("Outcome.Gate is nil")
	}
	if out.Gate.Passed {
		t.Errorf("real gate GateResult.Passed = true, want false")
	}
	if out.Gate.SchemaVersion != expectedGateSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", out.Gate.SchemaVersion, expectedGateSchemaVersion)
	}
	if len(out.Gate.Stages) == 0 || out.Gate.Stages[0].Name != "guard" {
		t.Fatalf("expected the guard stage, got %+v", out.Gate.Stages)
	}
	foundRule := false
	for _, f := range out.Gate.Stages[0].Findings {
		if f.Rule == "protected-path" {
			foundRule = true
		}
	}
	if !foundRule {
		t.Errorf("expected a protected-path finding, got %+v", out.Gate.Stages[0].Findings)
	}
	if out.ArtifactPath != "" {
		t.Errorf("RED run against the real gate must not emit a reviewable artifact, got %q", out.ArtifactPath)
	}
	if !h.rejects.Has(testGap().Fingerprint()) {
		t.Errorf("RED run against the real gate did not poison the reject set")
	}
	assertRevoked(t, h)
}

// TestRunValidateProposal_RealGate_FullPipelineOnProductTree drives ALL THREE
// gate stages (guard, structural go build/go vet, exam-detect) against the
// REAL mallcop product tree itself — the sibling checkout's OWN current HEAD,
// base==head (a no-op diff). This is the only test in the suite that exercises
// the structural and exam-detect stages against a genuinely mallcop-shaped
// tree (the tests above short-circuit at guard, deliberately, to stay fast);
// it proves the engine.GateResult schema survives a full 3-stage real run —
// every stage, every field — not just the guard stage's minimal shape.
//
// base==head is deterministic REGARDLESS of the sibling checkout's current
// content: the two exam-detect reports are byte-identical, so coverage_plus is
// always exactly 0 and the proposal is REJECTED on "exam-detect-no-coverage-
// gain" (a no-op diff closes no detection gap) — this is a property of the
// fixture construction, not of anything being broken. Guard and structural are
// both expected to PASS: the product's own trunk always builds+vets clean
// (see .github/workflows/build.yml / go-test.yml on the mallcop repo).
func TestRunValidateProposal_RealGate_FullPipelineOnProductTree(t *testing.T) {
	bin := buildRealMallcop(t)
	src := mallcopSrcDir(t)
	headSHA := gitRevParse(t, src, "HEAD")

	gate, exitCode, rerr := RunValidateProposal(context.Background(), bin, src, headSHA, "")
	if rerr != nil {
		t.Fatalf("RunValidateProposal against the real product tree (base==head): %v", rerr)
	}

	if gate.SchemaVersion != expectedGateSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", gate.SchemaVersion, expectedGateSchemaVersion)
	}
	if gate.Passed {
		t.Fatalf("expected a no-op diff to be REJECTED for zero coverage gain, got Passed=true: %+v", gate)
	}
	if exitCode != gateExitRejected {
		t.Errorf("exit code = %d, want %d", exitCode, gateExitRejected)
	}
	if gate.BaseSHA != headSHA || gate.HeadSHA != headSHA {
		t.Errorf("BaseSHA/HeadSHA = %q/%q, want both %q", gate.BaseSHA, gate.HeadSHA, headSHA)
	}
	if len(gate.Stages) != 3 {
		names := make([]string, len(gate.Stages))
		for i, s := range gate.Stages {
			names[i] = s.Name
		}
		t.Fatalf("expected all 3 stages to run (guard, structural, exam-detect), got %v", names)
	}
	if !gate.Stages[0].Passed || gate.Stages[0].Name != "guard" {
		t.Errorf("guard stage = %+v, want passed=true", gate.Stages[0])
	}
	if !gate.Stages[1].Passed || gate.Stages[1].Name != "structural" {
		t.Errorf("structural stage = %+v, want passed=true (the product's own trunk must build+vet clean)", gate.Stages[1])
	}
	exam := gate.Stages[2]
	if exam.Passed || exam.Name != "exam-detect" {
		t.Errorf("exam-detect stage = %+v, want passed=false", exam)
	}
	foundRule := false
	for _, f := range exam.Findings {
		if f.Rule == "exam-detect-no-coverage-gain" {
			foundRule = true
		}
	}
	if !foundRule {
		t.Errorf("expected exam-detect-no-coverage-gain finding, got %+v", exam.Findings)
	}
	if gate.CoveragePlus != 0 {
		t.Errorf("CoveragePlus = %d, want 0 for a no-op diff", gate.CoveragePlus)
	}

	// Ground-source: the whole test is only meaningful if the gate produced a
	// non-trivial GateResult — reconfirm via a raw JSON round-trip that nothing
	// here is a zero-value struct slipping past the field checks above.
	raw, merr := json.Marshal(gate)
	if merr != nil {
		t.Fatalf("marshal gate for ground-source check: %v", merr)
	}
	if strings.TrimSpace(string(raw)) == "{}" {
		t.Fatalf("GateResult marshaled to an empty object — the real gate's JSON was not actually decoded")
	}
}
