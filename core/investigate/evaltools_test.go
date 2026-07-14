package investigate

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// ---------------------------------------------------------------------------
// Pure unit tests: arg-building and output-parsing, no subprocess involved.
// ---------------------------------------------------------------------------

func TestEvalArgs_NoRepoRoot_NoOverride(t *testing.T) {
	args, env := evalArgs("", false)
	wantArgs := []string{"eval", "--json"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %v, want %v", args, wantArgs)
	}
	if env != nil {
		t.Errorf("extraEnv = %v, want nil", env)
	}
}

func TestEvalArgs_RepoRootWithScenarios_PinsScenariosDir(t *testing.T) {
	args, env := evalArgs("/repo", true)
	wantArgs := []string{"eval", "--json", "--scenarios-dir", filepath.Join("/repo", "scenarios")}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %v, want %v", args, wantArgs)
	}
	if env != nil {
		t.Errorf("extraEnv = %v, want nil (explicit --scenarios-dir takes precedence)", env)
	}
}

func TestEvalArgs_RepoRootWithoutScenarios_SetsEnvOverride(t *testing.T) {
	args, env := evalArgs("/repo", false)
	wantArgs := []string{"eval", "--json"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %v, want %v (no --scenarios-dir on a directory known not to exist)", args, wantArgs)
	}
	wantEnv := []string{"MALLCOP_REPO_ROOT=/repo"}
	if !reflect.DeepEqual(env, wantEnv) {
		t.Errorf("extraEnv = %v, want %v", env, wantEnv)
	}
}

func TestCaptureArgs_EventIDsMustFireReservedAndOverrides(t *testing.T) {
	in := FlagLikeThisInput{
		EventIDs: []string{"evt-1", "evt-2"},
		MustFire: []string{"sql-injection"},
		Reserved: true,
		Title:    "custom title",
		Severity: "high",
		ID:       "LOCAL-custom",
	}
	args := captureArgs("/store/dir", "/repo", in)
	want := []string{
		"scenario", "capture",
		"--store", "/store/dir",
		"--scenarios-dir", filepath.Join("/repo", "scenarios"),
		"--event-ids", "evt-1,evt-2",
		"--must-fire", "sql-injection",
		"--reserved",
		"--title", "custom title",
		"--severity", "high",
		"--id", "LOCAL-custom",
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("captureArgs = %v, want %v", args, want)
	}
}

func TestCaptureArgs_ActorWindowMustNotFire_NoRepoRootMeansNoOverride(t *testing.T) {
	in := FlagLikeThisInput{Actor: "alice", Window: "24h", MustNotFire: []string{"unusual-timing"}}
	args := captureArgs("/store", "", in)
	want := []string{
		"scenario", "capture",
		"--store", "/store",
		"--actor", "alice",
		"--window", "24h",
		"--must-not-fire", "unusual-timing",
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("captureArgs = %v, want %v", args, want)
	}
}

func TestParseCaptureOutput_ExtractsScenarioIDAndPath(t *testing.T) {
	stdout := "Captured scenario LOCAL-sql-injection-abcd1234\n" +
		"  Wrote:  /tmp/repo/scenarios/LOCAL-sql-injection-abcd1234.yaml\n" +
		"  Events: 2 (evt-1, evt-2)\n" +
		"  Must fire:     sql-injection (reserved)\n" +
		"Run 'mallcop eval' to grade this scenario locally, or 'mallcop scenario lint' to check benign-twin coverage.\n"
	id, path := parseCaptureOutput(stdout)
	if id != "LOCAL-sql-injection-abcd1234" {
		t.Errorf("scenarioID = %q, want LOCAL-sql-injection-abcd1234", id)
	}
	if path != "/tmp/repo/scenarios/LOCAL-sql-injection-abcd1234.yaml" {
		t.Errorf("path = %q, want /tmp/repo/scenarios/LOCAL-sql-injection-abcd1234.yaml", path)
	}
}

func TestParseCaptureOutput_UnparseableOutputYieldsEmpty(t *testing.T) {
	id, path := parseCaptureOutput("not the expected format at all\n")
	if id != "" || path != "" {
		t.Errorf("parseCaptureOutput of garbage = (%q, %q), want (\"\", \"\")", id, path)
	}
}

// TestRunEvalSummary_RendersSplitNotBlended is a direct proof that the chat
// summary keeps the operator's OWN numbers (n/m/IDs, false alarms) separate
// from the shipped reference corpus's numbers (x/y) — the C9 build
// requirement's exact format: "MY missed attacks: n of m (IDs); reference: x
// of y; false alarms: k". Constructed from fabricated eval.RecallReport
// values (no subprocess, no grading) so it stays a pure formatting test.
func TestRunEvalSummary_RendersSplitNotBlended(t *testing.T) {
	report := evalReportShape{
		Reference: eval.RecallReport{Recall: eval.RecallStat{MustFire: 42, Detected: 42}},
		Local: eval.RecallReport{
			Recall: eval.RecallStat{
				MustFire: 2,
				Detected: 1,
				Missed:   []eval.MissedAttack{{ScenarioID: "LOCAL-foo", Missing: []string{"foo"}, Reserved: true}},
			},
			Precision: eval.PrecisionStat{
				MustStaySilent: 3,
				CorrectSilent:  2,
				FalseAlarms:    []eval.FalseAlarm{{ScenarioID: "LOCAL-bar", Fired: []string{"bar"}}},
			},
		},
	}
	got := runEvalSummary(report)
	want := "MY missed attacks: 1 of 2 (LOCAL-foo); reference: 0 of 42; false alarms: 1"
	if got != want {
		t.Errorf("runEvalSummary = %q, want %q", got, want)
	}
}

func TestRunEvalSummary_NoMisses_OmitsParens(t *testing.T) {
	report := evalReportShape{
		Reference: eval.RecallReport{Recall: eval.RecallStat{MustFire: 10, Detected: 9}},
		Local:     eval.RecallReport{Recall: eval.RecallStat{MustFire: 0, Detected: 0}},
	}
	got := runEvalSummary(report)
	want := "MY missed attacks: 0 of 0; reference: 1 of 10; false alarms: 0"
	if got != want {
		t.Errorf("runEvalSummary = %q, want %q", got, want)
	}
}

// TestSummarizeToolResult_RunEvalAndFlagLikeThis proves the git-mailbox
// outbox trace (docs/chat-investigate-protocol.md's tool_result.summary,
// core/investigate/serve.go) renders a useful summary for the two new tools
// instead of falling through to the generic "<name> returned N bytes" case —
// the console (mallcop-pro) renders this string verbatim without knowing
// anything about individual tool names, so the summary has to carry the
// meaning here.
func TestSummarizeToolResult_RunEvalAndFlagLikeThis(t *testing.T) {
	evalOut := RunEvalOutput{Summary: "MY missed attacks: 1 of 2 (LOCAL-foo); reference: 0 of 42; false alarms: 0"}
	if got := summarizeToolResult("run-eval", evalOut, nil); got != evalOut.Summary {
		t.Errorf("summarizeToolResult(run-eval) = %q, want %q", got, evalOut.Summary)
	}

	captureOut := FlagLikeThisOutput{ScenarioID: "LOCAL-foo", Path: "/repo/scenarios/LOCAL-foo.yaml"}
	got := summarizeToolResult("flag-like-this", captureOut, nil)
	if !strings.Contains(got, captureOut.ScenarioID) || !strings.Contains(got, captureOut.Path) {
		t.Errorf("summarizeToolResult(flag-like-this) = %q, want it to name the scenario id and path", got)
	}
}

func TestToolDefs_IncludesRunEvalAndFlagLikeThis(t *testing.T) {
	names := toolNames(ToolDefs())
	var hasRunEval, hasFlagLikeThis bool
	for _, n := range names {
		switch n {
		case "run-eval":
			hasRunEval = true
		case "flag-like-this":
			hasFlagLikeThis = true
		}
	}
	if !hasRunEval {
		t.Errorf("ToolDefs() missing run-eval; got %v", names)
	}
	if !hasFlagLikeThis {
		t.Errorf("ToolDefs() missing flag-like-this; got %v", names)
	}
}

// TestExecuteTool_UnknownFlagLikeThisInputDecodeError proves ExecuteTool
// surfaces a decode error (never silently ignores) when given malformed
// input for flag-like-this — mirroring the same contract every other tool in
// this dispatch table already has.
func TestExecuteTool_FlagLikeThisInputDecodesArrayFields(t *testing.T) {
	st := seedStore(t)
	opts := Options{Store: st, MallcopBinary: "/nonexistent/should-not-be-reached-if-input-decode-fails"}
	// A non-array value for event_ids must fail JSON decode before ever
	// touching the (deliberately invalid) binary path.
	_, err := ExecuteTool(opts, "flag-like-this", map[string]any{"event_ids": "not-an-array"})
	if err == nil {
		t.Fatal("flag-like-this with malformed event_ids: want a decode error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Real, not mocked: build the actual mallcop binary and self-exec it exactly
// as run-eval/flag-like-this do in production. buildMallcopBinary is shared
// (sync.Once) across every test in this file — a full `go build` per test
// would be needlessly slow for what is otherwise a fast unit-test package.
// ---------------------------------------------------------------------------

var (
	buildMallcopOnce sync.Once
	builtMallcopBin  string
	buildMallcopErr  error
)

// evalToolsRepoRoot resolves the mallcop module root from this test file's
// own location (core/investigate/evaltools_test.go is two directories below
// the repo root), mirroring test/docdemo/demo_test.go's repoRoot() helper.
func evalToolsRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	return root
}

// buildMallcopBinary builds the REAL cmd/mallcop binary once per `go test`
// process and returns its path. Deliberately NOT built into t.TempDir(): a
// sync.Once-cached path must outlive whichever test happens to call it
// first, so it uses its own os.MkdirTemp scratch dir (small binary, cleaned
// up by the OS temp reaper — the same trade-off other shared-build test
// harnesses in this repo make).
func buildMallcopBinary(t *testing.T) string {
	t.Helper()
	buildMallcopOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mallcop-evaltools-bin-")
		if err != nil {
			buildMallcopErr = fmt.Errorf("mkdtemp: %w", err)
			return
		}
		bin := filepath.Join(dir, "mallcop")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/mallcop")
		cmd.Dir = evalToolsRepoRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildMallcopErr = fmt.Errorf("go build ./cmd/mallcop: %w\n%s", err, out)
			return
		}
		builtMallcopBin = bin
	})
	if buildMallcopErr != nil {
		t.Fatalf("build mallcop binary: %v", buildMallcopErr)
	}
	return builtMallcopBin
}

// gitInitAt runs a real `git init` + empty seed commit at an EXISTING dir
// (unlike this package's own initRepo, which allocates its own t.TempDir()) —
// needed here because a deploy-repo fixture needs TWO nested git repos at
// specific paths: the deploy repo itself, and store/ inside it (D3 SAME-REPO,
// cli/deployrepo.go's investigateWorkflowTemplate).
func gitInitAt(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v (in %s): %v\n%s", args, dir, err, out)
		}
	}
	seed := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "root")
	seed.Dir = dir
	seed.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit (in %s): %v\n%s", dir, err, out)
	}
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// newDeployRepoFixture builds a temp directory shaped like a REAL scaffolded
// mallcop deploy repo in production: a git repo (repoDir) with the mallcop
// binary installed at bin/mallcop (exactly where
// investigateWorkflowTemplate's curl+tar step puts it) and a nested git-repo
// store/ (D3 SAME-REPO). This is what makes Options.RepoRoot == "" (the
// production default — see evaltools.go's package doc) resolve correctly in
// a test: self-exec's os.Executable() walk from repoDir/bin/mallcop finds
// repoDir's own .git.
func newDeployRepoFixture(t *testing.T) (repoDir string, st *store.Store, mallcopBin string) {
	t.Helper()
	repoDir = t.TempDir()
	gitInitAt(t, repoDir)

	binDir := filepath.Join(repoDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin/: %v", err)
	}
	mallcopBin = filepath.Join(binDir, "mallcop")
	copyExecutable(t, buildMallcopBinary(t), mallcopBin)

	storeDir := filepath.Join(repoDir, "store")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatalf("mkdir store/: %v", err)
	}
	gitInitAt(t, storeDir)
	var err error
	st, err = store.Open(storeDir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return repoDir, st, mallcopBin
}

func seedFlagTestEvents(t *testing.T, st *store.Store) {
	t.Helper()
	events := []event.Event{
		{
			ID:        "evt-flag-1",
			Source:    "github",
			Type:      "push",
			Actor:     "mallory",
			Timestamp: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			Org:       "acme",
			Payload:   json.RawMessage(`{"action":"push"}`),
		},
		{
			ID:        "evt-flag-2",
			Source:    "github",
			Type:      "push",
			Actor:     "mallory",
			Timestamp: time.Date(2026, 7, 1, 0, 5, 0, 0, time.UTC),
			Org:       "acme",
			Payload:   json.RawMessage(`{"action":"push"}`),
		},
	}
	for _, ev := range events {
		if _, err := st.Append(store.KindEvents, ev); err != nil {
			t.Fatalf("seed event %s: %v", ev.ID, err)
		}
	}
}

// TestChatTools_FlagLikeThisThenRunEval_EndToEnd is the C9 acceptance test:
// a chat turn "flag things like this" must produce a schema-valid captured
// scenario internal/exam.Load parses, and a subsequent "what's my miss rate?"
// chat turn must return the recall-first split from a REAL `mallcop eval`
// run, with the just-captured scenario showing up on the LOCAL side (never
// blended into the reference corpus's own, much larger, numbers). Both tool
// calls go through the public ExecuteTool dispatch — the exact seam the
// investigate loop itself calls — driving the REAL cmd/mallcop binary via
// self-exec, not an in-process shortcut.
func TestChatTools_FlagLikeThisThenRunEval_EndToEnd(t *testing.T) {
	repoDir, st, bin := newDeployRepoFixture(t)
	seedFlagTestEvents(t, st)

	// RepoRoot is intentionally "" here: the production topology (see
	// evaltools.go's package doc) has the running binary installed INSIDE
	// the deploy repo, so self-exec's own walk resolves repoDir without any
	// override — proving the default (no --repo-root) chat session path
	// actually works end to end, not just the explicit-override path.
	opts := Options{Store: st, MallcopBinary: bin}

	// "chat-flagged-test-family" is a family with NO registered detector
	// anywhere in this process (same technique as cli/eval_test.go's
	// "beacon-c2-callback" fixture) — --reserved makes the miss a
	// deterministic TRACKED GAP, not a coin-flip on real detector matching.
	out, err := ExecuteTool(opts, "flag-like-this", map[string]any{
		"event_ids": []string{"evt-flag-1", "evt-flag-2"},
		"must_fire": []string{"chat-flagged-test-family"},
		"reserved":  true,
	})
	if err != nil {
		t.Fatalf("flag-like-this: %v", err)
	}
	capture, ok := out.(FlagLikeThisOutput)
	if !ok {
		t.Fatalf("flag-like-this returned %T, want FlagLikeThisOutput", out)
	}
	if capture.ScenarioID == "" {
		t.Fatal("flag-like-this: empty ScenarioID")
	}
	wantRepo, err := filepath.EvalSymlinks(repoDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", repoDir, err)
	}
	gotRepo, err := filepath.EvalSymlinks(capture.Repo)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", capture.Repo, err)
	}
	if gotRepo != wantRepo {
		t.Errorf("flag-like-this Repo = %q, want %q (the operator's own deploy repo)", capture.Repo, repoDir)
	}
	if !strings.Contains(capture.RuntimeImpact, "propose-safe") {
		t.Errorf("RuntimeImpact does not state propose-safety: %q", capture.RuntimeImpact)
	}
	if !strings.Contains(capture.Confirmation, capture.ScenarioID) || !strings.Contains(capture.Confirmation, capture.Path) {
		t.Errorf("Confirmation = %q, want it to name the scenario id and the written path", capture.Confirmation)
	}

	// The written file is REAL, schema-valid data — internal/exam.Load must
	// parse it (the exact C9 test requirement).
	scenario, err := exam.Load(capture.Path)
	if err != nil {
		t.Fatalf("exam.Load(%s): %v", capture.Path, err)
	}
	if scenario.ID != capture.ScenarioID {
		t.Errorf("loaded scenario id = %q, want %q", scenario.ID, capture.ScenarioID)
	}

	// Now "what's my miss rate?" — run-eval must report this exact scenario
	// as a local miss, reserved, SEPARATE from the (much larger) reference
	// corpus split.
	out, err = ExecuteTool(opts, "run-eval", map[string]any{})
	if err != nil {
		t.Fatalf("run-eval: %v", err)
	}
	report, ok := out.(RunEvalOutput)
	if !ok {
		t.Fatalf("run-eval returned %T, want RunEvalOutput", out)
	}
	if report.Local.Recall.MustFire != 1 {
		t.Fatalf("local.recall.must_fire = %d, want 1", report.Local.Recall.MustFire)
	}
	if report.Local.Recall.Detected != 0 {
		t.Fatalf("local.recall.detected = %d, want 0 (no detector registered for chat-flagged-test-family)", report.Local.Recall.Detected)
	}
	if len(report.Local.Recall.Missed) != 1 || report.Local.Recall.Missed[0].ScenarioID != capture.ScenarioID {
		t.Fatalf("local.recall.missed = %+v, want exactly one entry for %s", report.Local.Recall.Missed, capture.ScenarioID)
	}
	if !report.Local.Recall.Missed[0].Reserved {
		t.Error("local.recall.missed[0].reserved = false, want true (tracked gap)")
	}
	if report.Reference.Recall.MustFire <= 1 {
		t.Fatalf("reference.recall.must_fire = %d, want > 1 (the shipped reference corpus, not the local fixture)", report.Reference.Recall.MustFire)
	}

	wantSummaryPrefix := fmt.Sprintf("MY missed attacks: 1 of 1 (%s); reference: ", capture.ScenarioID)
	if !strings.HasPrefix(report.Summary, wantSummaryPrefix) {
		t.Errorf("Summary = %q, want prefix %q", report.Summary, wantSummaryPrefix)
	}
	if !strings.Contains(report.Summary, "false alarms: 0") {
		t.Errorf("Summary = %q, want it to report false alarms: 0 (no must_not_fire scenarios captured)", report.Summary)
	}
}

// TestChatTools_RunEval_HonestErrorWhenRepoUnresolvable proves the "no
// corpus, no repo" path is an honest, real structured error — never a
// fabricated report — when the binary cannot resolve any repo root at all
// (a bare, non-git temp dir with no go.mod/.git/exams-scenarios marker
// anywhere above it, and no explicit RepoRoot/MALLCOP_REPO_ROOT override).
func TestChatTools_RunEval_HonestErrorWhenRepoUnresolvable(t *testing.T) {
	bareDir := t.TempDir() // deliberately NOT git-inited
	dst := filepath.Join(bareDir, "mallcop")
	copyExecutable(t, buildMallcopBinary(t), dst)

	st := seedStore(t) // any real store; irrelevant to this failure mode
	opts := Options{Store: st, MallcopBinary: dst}

	_, err := ExecuteTool(opts, "run-eval", map[string]any{})
	if err == nil {
		t.Fatal("run-eval: want an honest error when the repo root cannot be resolved, got nil")
	}
	// Must be the REAL subprocess's own failure text (eval.RepoRoot's
	// "no project marker ... found" message), not a made-up placeholder.
	if !strings.Contains(err.Error(), "repo root") {
		t.Errorf("run-eval error = %q, want it to name the real repo-root resolution failure", err.Error())
	}
}

// TestChatTools_RunEval_ExplicitRepoRootOverridesSelfWalk proves the
// explicit-RepoRoot path (an operator's session pinned --repo-root on
// `mallcop investigate`) is honored even when the binary itself sits
// somewhere self-walk would never find on its own — the override, not the
// binary's location, decides which repo gets graded.
func TestChatTools_RunEval_ExplicitRepoRootOverridesSelfWalk(t *testing.T) {
	repoDir, st, bin := newDeployRepoFixture(t)
	seedFlagTestEvents(t, st)

	// Copy the binary OUT of the deploy repo into a bare dir so self-walk
	// alone could never find repoDir -- only the explicit opts.RepoRoot can.
	bareDir := t.TempDir()
	detachedBin := filepath.Join(bareDir, "mallcop")
	copyExecutable(t, bin, detachedBin)

	opts := Options{Store: st, MallcopBinary: detachedBin, RepoRoot: repoDir}

	out, err := ExecuteTool(opts, "flag-like-this", map[string]any{
		"event_ids": []string{"evt-flag-1", "evt-flag-2"},
		"must_fire": []string{"chat-flagged-test-family-2"},
		"reserved":  true,
	})
	if err != nil {
		t.Fatalf("flag-like-this: %v", err)
	}
	capture := out.(FlagLikeThisOutput)
	wantPath := filepath.Join(repoDir, "scenarios", capture.ScenarioID+".yaml")
	if capture.Path != wantPath {
		t.Fatalf("flag-like-this Path = %q, want %q (pinned by explicit RepoRoot, not the detached binary's own location)", capture.Path, wantPath)
	}
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("expected scenario file at %s: %v", wantPath, err)
	}
}

// TestFlagLikeThis_RejectsPathTraversalID_AdapterLayer pins the ADAPTER's own
// independent copy of the safe-slug check (PR #191 review, HIGH): a traversal
// id must be rejected HERE, before any subprocess spawns — the asserted
// message is the adapter's own, so this test still fails if the adapter check
// is removed even though the CLI's authoritative check would also block the
// write (MallcopBinary deliberately points at a nonexistent file: if the
// adapter check regressed, the failure mode would be "spawn failed", not the
// message asserted below).
func TestFlagLikeThis_RejectsPathTraversalID_AdapterLayer(t *testing.T) {
	st := seedStore(t)
	opts := Options{Store: st, MallcopBinary: filepath.Join(t.TempDir(), "never-spawned")}

	for _, id := range []string{"../../outside/evil-poc", "..", "a/b", "/etc/evil", "-leading-dash"} {
		_, err := ExecuteTool(opts, "flag-like-this", map[string]any{
			"event_ids": []string{"evt-ghost-001"},
			"must_fire": []string{"poc-family"},
			"id":        id,
		})
		if err == nil {
			t.Errorf("flag-like-this with id %q: expected an error, got nil", id)
			continue
		}
		if !strings.Contains(err.Error(), "invalid scenario id") {
			t.Errorf("flag-like-this with id %q: error %q is not the adapter's own validation message (did the adapter-layer check regress to relying on the CLI?)", id, err.Error())
		}
	}
}

// TestChatTools_SpawnFailureIsHonestError reaches runMallcopSelf's
// spawn-failed branch for REAL (PR #191 review, MED): a MallcopBinary that
// does not exist, with input that survives decode/validation, must surface as
// an honest structured error naming the spawn failure — never a fabricated
// report or a silent success.
func TestChatTools_SpawnFailureIsHonestError(t *testing.T) {
	st := seedStore(t)
	opts := Options{Store: st, MallcopBinary: filepath.Join(t.TempDir(), "missing-binary")}

	if _, err := ExecuteTool(opts, "run-eval", map[string]any{}); err == nil {
		t.Error("run-eval with a nonexistent binary: expected an error, got nil")
	} else if !strings.Contains(err.Error(), "spawn failed") {
		t.Errorf("run-eval spawn error = %q, want it to name the spawn failure", err.Error())
	}

	if _, err := ExecuteTool(opts, "flag-like-this", map[string]any{
		"event_ids": []string{"evt-ghost-001"},
		"must_fire": []string{"poc-family"},
	}); err == nil {
		t.Error("flag-like-this with a nonexistent binary: expected an error, got nil")
	} else if !strings.Contains(err.Error(), "spawn failed") {
		t.Errorf("flag-like-this spawn error = %q, want it to name the spawn failure", err.Error())
	}
}

// decoyShadowScenario is a reserved must-fire scenario for a family with NO
// registered detector — planted in the WALK-resolvable root of the shadowing-
// topology test below. If the subprocess ignores the explicit repo-root pin
// and self-resolves via its binary-location walk instead, this decoy shows up
// as a local recall row and the test fails.
const decoyShadowScenario = `id: DECOY-shadow-01
detector: decoy-shadow-family
provenance: operator
finding:
  id: fnd_decoy_001
  detector: decoy-shadow-family
  title: 'Decoy scenario in the walk-resolvable root'
  severity: high
  event_ids: [evt_d1]
events:
  - id: evt_d1
    timestamp: '2026-07-01T00:05:00Z'
    source: edr
    event_type: network_connection
    actor: workstation-9
    action: outbound_connect
    target: 203.0.113.9
    severity: high
expected_detection:
  must_fire: [decoy-shadow-family]
  reserved: true
`

// TestChatTools_RunEval_EnvPinBeatsWalk_ShadowingTopology is the PR #191
// review's (MED) required proof that run-eval's MALLCOP_REPO_ROOT pin is
// actually honored by the subprocess — not silently shadowed by the binary-
// location walk (eval.RepoRoot resolution order). Topology: the binary lives
// inside a marker-bearing decoy repo whose scenarios/ contains a decoy
// scenario, while Options.RepoRoot pins a DIFFERENT root with no scenarios/
// at all.
//
// Phase 1 (positive control, no pin): the walk resolves the decoy repo and
// the decoy scenario appears in the local split — proving the decoy is
// genuinely discoverable, so phase 2 cannot pass vacuously.
// Phase 2 (explicit pin): the pinned root must win — the local split must be
// EMPTY. Before the env-beats-walk precedence fix in core/eval/reporoot.go,
// the subprocess's walk won and the decoy leaked in (this phase failed).
func TestChatTools_RunEval_EnvPinBeatsWalk_ShadowingTopology(t *testing.T) {
	decoyRoot, st, bin := newDeployRepoFixture(t)
	scenariosDir := filepath.Join(decoyRoot, "scenarios")
	if err := os.MkdirAll(scenariosDir, 0o755); err != nil {
		t.Fatalf("mkdir decoy scenarios/: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenariosDir, "decoy.yaml"), []byte(decoyShadowScenario), 0o644); err != nil {
		t.Fatalf("write decoy scenario: %v", err)
	}

	// Phase 1 — positive control: with NO pin, the subprocess self-resolves
	// the decoy repo (the binary sits inside it) and the decoy is graded.
	out, err := ExecuteTool(Options{Store: st, MallcopBinary: bin}, "run-eval", map[string]any{})
	if err != nil {
		t.Fatalf("run-eval (no pin): %v", err)
	}
	unpinned := out.(RunEvalOutput)
	if unpinned.Local.Recall.MustFire != 1 {
		t.Fatalf("positive control: local.recall.must_fire = %d, want 1 (the decoy must be discoverable via the walk, or phase 2 proves nothing)", unpinned.Local.Recall.MustFire)
	}

	// Phase 2 — the explicit pin names a root with NO scenarios/ directory:
	// the local split must be EMPTY, never the decoy repo's.
	pinnedRoot := t.TempDir()
	out, err = ExecuteTool(Options{Store: st, MallcopBinary: bin, RepoRoot: pinnedRoot}, "run-eval", map[string]any{})
	if err != nil {
		t.Fatalf("run-eval (pinned): %v", err)
	}
	pinned := out.(RunEvalOutput)
	if pinned.Local.Recall.MustFire != 0 {
		t.Fatalf("local.recall.must_fire = %d, want 0 — the subprocess IGNORED the explicit repo-root pin and graded the walk-resolved decoy root instead (missed: %+v)", pinned.Local.Recall.MustFire, pinned.Local.Recall.Missed)
	}
	if pinned.Local.Precision.MustStaySilent != 0 {
		t.Errorf("local.precision.must_stay_silent = %d, want 0 (pinned root has no scenarios at all)", pinned.Local.Precision.MustStaySilent)
	}
}
