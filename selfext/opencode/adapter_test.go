package opencode

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/selfext/sandbox"
)

// initFixtureRepo creates a throwaway git repo with one commit and returns its
// path. No network, no real opencode.
func initFixtureRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "main")
	run("config", "user.email", "fixture@example.com")
	run("config", "user.name", "Fixture")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-m", "initial")
	return repo
}

func TestFingerprintStableAndFamilySensitive(t *testing.T) {
	a := TrustedGap{DetectorID: "authored-deploy-burst", EventType: "github.deployment", TargetFamily: "deploy-burst"}
	// Case/whitespace-insensitive, deterministic.
	b := TrustedGap{DetectorID: "Authored-Deploy-Burst ", EventType: " github.deployment", TargetFamily: "Deploy-Burst"}
	if a.Fingerprint() != b.Fingerprint() {
		t.Errorf("fingerprint not normalized: %s != %s", a.Fingerprint(), b.Fingerprint())
	}
	// A different family yields a different fingerprint.
	c := TrustedGap{DetectorID: "authored-deploy-burst", EventType: "github.deployment", TargetFamily: "other-family"}
	if a.Fingerprint() == c.Fingerprint() {
		t.Errorf("different family collided: %s", a.Fingerprint())
	}
	// Empty family falls back to detector id (still stable, non-empty).
	d := TrustedGap{DetectorID: "authored-x", EventType: "e"}
	if len(d.Fingerprint()) != 64 {
		t.Errorf("fingerprint not 64 hex chars: %q", d.Fingerprint())
	}
}

func TestPackageName(t *testing.T) {
	cases := map[string]string{
		"authored-deploy-burst": "deployburst",
		"authored-X Y Z":        "xyz",
		"authored":              "authored",
		"":                      "authored",
		"authored-123":          "d123",
	}
	for id, want := range cases {
		if got := (TrustedGap{DetectorID: id}).PackageName(); got != want {
			t.Errorf("PackageName(%q)=%q, want %q", id, got, want)
		}
	}
}

func TestProviderConfigShape(t *testing.T) {
	a := &Adapter{Lane: "heal", Provider: "forge"}
	cfg, err := a.ProviderConfig("mallcop-sk-secret123", "https://forge.example.com")
	if err != nil {
		t.Fatalf("ProviderConfig: %v", err)
	}
	for _, want := range []string{
		`"baseURL":"https://forge.example.com/v1"`,
		`"apiKey":"mallcop-sk-secret123"`,
		`"@ai-sdk/openai-compatible"`,
		`"heal":{"limit":{"context":128000,"output":32768}}`, // lane declared with context+output caps
		`"forge":`, // provider key
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("provider config missing %q:\n%s", want, cfg)
		}
	}

	// A custom cap is honored.
	capped, _ := (&Adapter{Lane: "heal", MaxOutputTokens: 2048}).ProviderConfig("k", "https://forge.example.com")
	if !strings.Contains(capped, `"output":2048`) {
		t.Errorf("custom MaxOutputTokens not applied:\n%s", capped)
	}

	// Empty lane and empty base URL are hard errors (no unrestricted default).
	if _, err := (&Adapter{}).ProviderConfig("k", "u"); err == nil {
		t.Errorf("empty lane: expected error")
	}
	if _, err := (&Adapter{Lane: "heal"}).ProviderConfig("k", ""); err == nil {
		t.Errorf("empty base URL: expected error")
	}
}

func TestBaseURLIdempotentV1(t *testing.T) {
	a := &Adapter{Lane: "heal"}
	cfg, _ := a.ProviderConfig("k", "https://forge.example.com/v1/")
	if !strings.Contains(cfg, `"baseURL":"https://forge.example.com/v1"`) {
		t.Errorf("baseURL should not double /v1:\n%s", cfg)
	}
}

func TestParseTolerant(t *testing.T) {
	stream := strings.Join([]string{
		`not json at all`,
		`{"type":"text","text":"Authoring "}`,
		`{"type":"tool","tool":"write","state":{"input":{"filePath":"core/detect/authored/foo/foo.go"}}}`,
		`{"type":"text","text":"the detector."}`,
		`{"type":"file","path":"exams/scenarios/authored/foo-must-fire.yaml"}`,
		`{"noise":"https://example.com/not-a-file"}`,
		``,
	}, "\n")
	files, text := Parse([]byte(stream))
	if text != "Authoring the detector." {
		t.Errorf("assistant text = %q", text)
	}
	want := map[string]bool{
		"core/detect/authored/foo/foo.go":             true,
		"exams/scenarios/authored/foo-must-fire.yaml": true,
	}
	if len(files) != len(want) {
		t.Fatalf("files = %v, want keys %v", files, want)
	}
	for _, f := range files {
		if !want[f] {
			t.Errorf("unexpected authored file %q", f)
		}
	}
}

func TestBuildTaskPromptTrustedAndComplete(t *testing.T) {
	a := &Adapter{Lane: "heal"}
	gap := TrustedGap{
		DetectorID:   "authored-deploy-burst",
		EventType:    "github.deployment",
		TargetFamily: "deploy-burst",
		Severity:     "high",
		Actor:        "ci-bot",
		Source:       "connector:github",
	}
	p := a.BuildTaskPrompt(gap, false)
	for _, want := range []string{
		"authored-deploy-burst",
		"core/detect/authored/deployburst/",
		"github.deployment",
		"deploy-burst",
		"core/detect/authored/registry.go",
		"must-fire",
		"benign-twin",
		"must_not_fire",
		"github.com/mallcop-app/mallcop/core/detect", // import allow-list exemplar
		"detect.Register",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	// The prompt must NOT invite arbitrary tool/command execution beyond authoring.
	if strings.Contains(p, "do not run any command") == false {
		t.Errorf("prompt should forbid running commands")
	}
}

// TestBuildTaskPromptCustomerShapedTargetsSidecar proves BuildTaskPrompt's
// customerShaped=true branch targets the SIDECAR shape
// (detectors/<name>/main.go, package main, detectorhost.Run) instead of the
// in-tree own-package shape, and never invites the registry-linkage step a
// customer deployment repo has no file for.
func TestBuildTaskPromptCustomerShapedTargetsSidecar(t *testing.T) {
	a := &Adapter{Lane: "heal"}
	gap := TrustedGap{
		DetectorID:   "authored-widget-leak",
		EventType:    "customer.widget-secret-exposed",
		TargetFamily: "widget-leak",
		Severity:     "high",
		Actor:        "cust-actor",
		Source:       "connector:github",
	}
	p := a.BuildTaskPrompt(gap, true)
	for _, want := range []string{
		"authored-widget-leak",
		"detectors/widgetleak/",
		"detectors/widgetleak/main.go",
		"detectors/widgetleak/main_test.go",
		"customer.widget-secret-exposed",
		"package main",
		"detectorhost.Run",
		"os.Exit",
		"func main()",
		"github.com/mallcop-app/mallcop/pkg/detectorhost",
		"github.com/mallcop-app/mallcop/pkg/baseline",
		"github.com/mallcop-app/mallcop/pkg/event",
		"github.com/mallcop-app/mallcop/pkg/finding",
		// the sidecar unit's OWN co-located efficacy scenarios
		// are now a REQUIRED file, graded via --extra-scenarios-dir.
		"detectors/widgetleak/scenarios/",
		"detectors/widgetleak/scenarios/must-fire.yaml",
		"detectors/widgetleak/scenarios/benign-twin.yaml",
		"must_fire",
		"must_not_fire",
		"MEASURED MINIMAL MUTATION",
		"expected_detection",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("sidecar prompt missing %q:\n%s", want, p)
		}
	}
	// This branch must NEVER instruct opencode to WRITE the in-tree own-package
	// shape (detect.Register, an own-package dir, in-tree scenario files) — a
	// customer deployment repo has no such tree, and the registry the old
	// unconditional step tried to restore does not exist (the exact
	// live-leg bug). It DOES explicitly forbid touching core/detect/authored/
	// by name (defense in depth), so that substring alone is expected.
	for _, mustNotContain := range []string{
		"detect.Register",
		"own-package directory",
		"exams/scenarios/authored",
	} {
		if strings.Contains(p, mustNotContain) {
			t.Errorf("sidecar prompt must not mention %q (in-tree-only concept):\n%s", mustNotContain, p)
		}
	}
	// the prompt must EXPLICITLY forbid authoring under the
	// top-level exams/scenarios/ reference-corpus path (defense in depth) —
	// the sidecar's own scenarios live ONLY under detectors/<name>/scenarios/.
	if !strings.Contains(p, "TOP-LEVEL exams/scenarios/") {
		t.Errorf("sidecar prompt should explicitly forbid the top-level exams/scenarios/ path:\n%s", p)
	}
	// It explicitly tells opencode the registry step does not apply here.
	if !strings.Contains(p, "core/detect/authored/registry.go") {
		t.Errorf("sidecar prompt should explicitly forbid the in-tree registry file:\n%s", p)
	}
	if strings.Contains(p, "do not run any command") == false {
		t.Errorf("sidecar prompt should forbid running commands")
	}
}

// TestInvokeRunsStubExtractsFilesAndRedacts drives Invoke against a FAKE
// opencode stub script. The stub deliberately leaks OPENCODE_CONFIG_CONTENT
// (which carries the run key) to stdout; the adapter MUST redact it before
// returning the transcript.
func TestInvokeRunsStubExtractsFilesAndRedacts(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	stub := writeInvokeStub(t)
	a := &Adapter{Bin: stub, Lane: "heal", Provider: "forge", ForgeBaseURL: "https://forge.example.com"}

	const subkey = "mallcop-sk-liveleaktoken999"
	res, err := a.Invoke(context.Background(), wt, subkey, "author a detector")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	// The stub wrote a file into the worktree AND announced it via JSON.
	if len(res.AuthoredFiles) == 0 {
		t.Errorf("no authored files extracted from event stream")
	}
	if _, err := os.Stat(filepath.Join(wt.Dir, "authored-by-stub.txt")); err != nil {
		t.Errorf("stub did not write into the worktree: %v", err)
	}
	// The run key (leaked to stdout by the stub) MUST be redacted.
	transcript := string(res.TranscriptRedacted)
	if strings.Contains(transcript, subkey) {
		t.Errorf("transcript leaked the raw subkey")
	}
	if strings.Contains(transcript, "mallcop-sk") {
		t.Errorf("transcript leaked a mallcop-sk token:\n%s", transcript)
	}
	if !strings.Contains(transcript, "***REDACTED***") {
		t.Errorf("expected redaction marker in transcript:\n%s", transcript)
	}
}

// TestInvokeRedactsBYOIVendorKey proves the adapter path scrubs a BYOI vendor
// key (an "sk-ant-..." key, NOT a mallcop-sk-*) that a stub leaks to BOTH stdout
// and stderr — the exact-string redaction pass catches it regardless of shape.
// It also asserts the adapter's own logger never emits the raw key.
func TestInvokeRedactsBYOIVendorKey(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	stub := writeStderrLeakStub(t)
	var logbuf strings.Builder
	a := &Adapter{
		Bin:          stub,
		Lane:         "heal",
		Provider:     "forge",
		ForgeBaseURL: "https://user.example/v1", // BYOI: the adapter endpoint is the user's URL
		Logger:       slog.New(slog.NewTextHandler(&logbuf, nil)),
	}

	const userKey = "sk-ant-api03-LEAKED-USERKEY-abcdefghijklmnop"
	res, err := a.Invoke(context.Background(), wt, userKey, "author a detector")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	transcript := string(res.TranscriptRedacted)
	if strings.Contains(transcript, userKey) || strings.Contains(transcript, "sk-ant") {
		t.Errorf("transcript leaked the BYOI vendor key:\n%s", transcript)
	}
	if !strings.Contains(transcript, "***REDACTED***") {
		t.Errorf("expected the redaction marker in the transcript:\n%s", transcript)
	}
	// The adapter's structured log must never carry the raw key.
	if strings.Contains(logbuf.String(), userKey) || strings.Contains(logbuf.String(), "sk-ant") {
		t.Errorf("a log line leaked the raw BYOI key:\n%s", logbuf.String())
	}
}

// writeStderrLeakStub writes a fake opencode that echoes its provider config
// (carrying the key) to BOTH stdout and stderr, then emits a canned event.
func writeStderrLeakStub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode-stderr-leak.sh")
	script := `#!/bin/sh
printf '%s\n' "$OPENCODE_CONFIG_CONTENT"
printf '%s\n' "$OPENCODE_CONFIG_CONTENT" 1>&2
printf '{"type":"text","text":"done"}\n'
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestInvokeSpawnFailureIsError proves a missing opencode binary surfaces as an
// error, not a silent success.
func TestInvokeSpawnFailureIsError(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	a := &Adapter{Bin: filepath.Join(t.TempDir(), "no-such-opencode"), Lane: "heal", ForgeBaseURL: "https://forge.example.com"}
	if _, err := a.Invoke(context.Background(), wt, "mallcop-sk-x", "task"); err == nil {
		t.Fatalf("expected spawn error for missing binary")
	}
}

// TestInvokeTimeoutKillsHungOpencodeAndItsProcessGroup proves :
// a hung opencode subprocess (one that never exits — the live shape that
// wedged a whole build loop for ~10h with no bound) is force-killed once
// Adapter.Timeout elapses, Invoke returns promptly (not after the stub's own
// 120s sleep) with Result.TimedOut true, and it is NEVER retried (the count
// file proves exactly one invocation despite MaxAttempts>1).
func TestInvokeTimeoutKillsHungOpencodeAndItsProcessGroup(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	stub, countFile, pgidFile := writeHangStub(t)
	a := &Adapter{
		Bin: stub, Lane: "heal", Provider: "forge", ForgeBaseURL: "https://forge.example.com",
		Timeout: 200 * time.Millisecond,
		// MaxAttempts>1 proves the "never retry a timeout" rule, not merely
		// that Invoke returns after one bounded attempt.
		MaxAttempts: 3, RetryBackoff: time.Millisecond, sleepFn: func(time.Duration) {},
	}

	start := time.Now()
	res, err := a.Invoke(context.Background(), wt, "mallcop-sk-x", "author a detector")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Invoke: %v (a bounded-timeout kill must not surface as an adapter error)", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("timeout not honored: Invoke took %s (stub sleeps 120s, Adapter.Timeout was 200ms)", elapsed)
	}
	if !res.TimedOut {
		t.Errorf("expected Result.TimedOut=true, got %+v", res)
	}
	if got := readCount(t, countFile); got != 1 {
		t.Errorf("opencode invoked %d times, want exactly 1 (a timeout must never be retried)", got)
	}
	if !strings.Contains(string(res.TranscriptRedacted), "timeout") {
		t.Errorf("transcript should note the timeout for diagnosability:\n%s", res.TranscriptRedacted)
	}

	// Prove the narrative, not just its symptoms: the WHOLE process group —
	// the direct child AND the pipe-holding grandchild — must actually be
	// dead once Invoke has returned, not merely that Invoke stopped waiting.
	assertProcessGroupDead(t, pgidFile)
}

// TestInvokeRetriesTransientFastFailThenSucceeds proves the bounded retry: a
// stub that fast-fails transiently (exit 1, authors NOTHING, 5xx transcript) on
// its first attempt and authors a detector on its second is retried once and
// ultimately succeeds. The worktree-clean gate holds because attempt 1 wrote no
// file. Backoff is neutralized via sleepFn so the test is instant.
func TestInvokeRetriesTransientFastFailThenSucceeds(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	stub, countFile := writeTransientThenSucceedStub(t)
	a := &Adapter{
		Bin: stub, Lane: "heal", Provider: "forge", ForgeBaseURL: "https://forge.example.com",
		MaxAttempts: 3, RetryBackoff: time.Millisecond, sleepFn: func(time.Duration) {},
	}

	res, err := a.Invoke(context.Background(), wt, "mallcop-sk-x", "author a detector")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("final exit code = %d, want 0 after retry", res.ExitCode)
	}
	if got := readCount(t, countFile); got != 2 {
		t.Errorf("opencode invoked %d times, want 2 (1 fast-fail + 1 success)", got)
	}
	if _, err := os.Stat(filepath.Join(wt.Dir, "authored-on-retry.txt")); err != nil {
		t.Errorf("retry did not author into the worktree: %v", err)
	}
}

// TestInvokeDoesNotRetryWhenAuthored proves the double-spend guard: a stub that
// authors a file AND exits non-zero with a transient-looking transcript is NOT
// retried, because the worktree is dirty (work already happened). The non-zero
// exit surfaces unchanged for the engine to handle.
func TestInvokeDoesNotRetryWhenAuthored(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	stub, countFile := writeAuthorThenFailStub(t)
	a := &Adapter{
		Bin: stub, Lane: "heal", Provider: "forge", ForgeBaseURL: "https://forge.example.com",
		MaxAttempts: 3, RetryBackoff: time.Millisecond, sleepFn: func(time.Duration) {},
	}

	res, err := a.Invoke(context.Background(), wt, "mallcop-sk-x", "author a detector")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.ExitCode != 1 {
		t.Errorf("exit code = %d, want the non-zero exit surfaced unchanged", res.ExitCode)
	}
	if got := readCount(t, countFile); got != 1 {
		t.Errorf("opencode invoked %d times, want 1 (a run that authored files must NOT be retried)", got)
	}
}

// TestInvokeDoesNotRetryNonTransient proves the transient gate: a stub that
// authors NOTHING and exits non-zero but with a DETERMINISTIC failure (no
// 5xx/rate-limit/timeout signal, above the empty threshold) is NOT retried — a
// retry cannot help a deterministic failure.
func TestInvokeDoesNotRetryNonTransient(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	stub, countFile := writeNonTransientFailStub(t)
	a := &Adapter{
		Bin: stub, Lane: "heal", Provider: "forge", ForgeBaseURL: "https://forge.example.com",
		MaxAttempts: 3, RetryBackoff: time.Millisecond, sleepFn: func(time.Duration) {},
	}

	res, err := a.Invoke(context.Background(), wt, "mallcop-sk-x", "author a detector")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.ExitCode != 1 {
		t.Errorf("exit code = %d, want 1", res.ExitCode)
	}
	if got := readCount(t, countFile); got != 1 {
		t.Errorf("opencode invoked %d times, want 1 (deterministic failure must NOT be retried)", got)
	}
}

// TestInvokeFailsLoudlyOnTruncation proves the truncation guard end to end: a
// stub that emits opencode's REAL 1.17.11 --format json event shape for a
// truncated tool call — tool="invalid" AND a step-finish reason="length" —
// makes Invoke fail IMMEDIATELY with a loud, diagnosed error naming the
// configured cap, and is NEVER retried even though MaxAttempts allows more.
// The two literal event lines below are copied verbatim (session/timestamp
// fields aside) from a live capture: the real opencode-ai 1.17.11 binary driven
// against a local fake server scripted to truncate a write-tool argument
// mid-string (rd mallcoppro-da5) — not a guessed schema.
func TestInvokeFailsLoudlyOnTruncation(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	stub, countFile := writeTruncationDoomLoopStub(t)
	const cap = 4096
	a := &Adapter{
		Bin: stub, Lane: "heal", Provider: "forge", ForgeBaseURL: "https://forge.example.com",
		MaxOutputTokens: cap,
		MaxAttempts:     3, RetryBackoff: time.Millisecond, sleepFn: func(time.Duration) {},
	}

	res, err := a.Invoke(context.Background(), wt, "mallcop-sk-x", "author a detector")
	if err == nil {
		t.Fatalf("Invoke: expected a loud error for a truncated generation, got nil (res=%+v)", res)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(cap)) {
		t.Errorf("error does not name the configured cap %d: %v", cap, err)
	}
	if !strings.Contains(err.Error(), "sst/opencode#18108") {
		t.Errorf("error does not cite the upstream issue for diagnosability: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "never retried") {
		t.Errorf("error does not say it was never retried: %v", err)
	}
	if !res.Truncated {
		t.Errorf("Result.Truncated = false, want true")
	}
	if res.TruncationDetail == "" {
		t.Errorf("Result.TruncationDetail is empty, want a diagnostic")
	}
	if got := readCount(t, countFile); got != 1 {
		t.Errorf("opencode invoked %d times, want exactly 1 (truncation must NEVER be retried — retrying "+
			"resends the same prompt against the same cap and reproduces opencode's own silent doom loop)", got)
	}
}

// TestInvokeFailsLoudlyOnLengthFinishAlone proves the guard fires on the
// step-finish reason="length" signal ALONE — no tool call in play at all (the
// model exhausted its output budget on invisible reasoning before ever
// emitting a tool call, the OTHER live-observed shape from rd mallcoppro-4a1's
// wire-level bisection: completion_tokens pegged at the cap, finish_reason
// length, zero visible content, zero tool calls).
func TestInvokeFailsLoudlyOnLengthFinishAlone(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	stub, countFile := stubWithCounter(t, "opencode-length-finish.sh",
		`printf '{"type":"step_finish","part":{"reason":"length","type":"step-finish","tokens":{"total":4101,"input":5,"output":4096,"reasoning":4091}}}\n'
exit 0`)
	a := &Adapter{
		Bin: stub, Lane: "heal", Provider: "forge", ForgeBaseURL: "https://forge.example.com",
		MaxOutputTokens: 4096,
		MaxAttempts:     3, RetryBackoff: time.Millisecond, sleepFn: func(time.Duration) {},
	}

	res, err := a.Invoke(context.Background(), wt, "mallcop-sk-x", "author a detector")
	if err == nil {
		t.Fatalf("Invoke: expected a loud error, got nil (res=%+v)", res)
	}
	if !res.Truncated {
		t.Errorf("Result.Truncated = false, want true")
	}
	if !strings.Contains(res.TruncationDetail, "finish_reason=length") {
		t.Errorf("TruncationDetail missing the length-finish diagnostic: %q", res.TruncationDetail)
	}
	if got := readCount(t, countFile); got != 1 {
		t.Errorf("opencode invoked %d times, want exactly 1 (never retried)", got)
	}
}

// writeTruncationDoomLoopStub writes a fake opencode that authors NOTHING and
// emits opencode's real tool="invalid" + step-finish reason="length" event pair
// (see TestInvokeFailsLoudlyOnTruncation), then exits 0 — mirroring the LIVE
// observation that opencode does not fail the session over this, it just does
// nothing useful.
func writeTruncationDoomLoopStub(t *testing.T) (bin, countFile string) {
	body := `printf '{"type":"tool_use","part":{"type":"tool","tool":"invalid","callID":"call_trunc","state":{"status":"completed","input":{"tool":"write","error":"Invalid input for tool write: JSON parsing failed: Text: {\"filePath\":\"detector.go\",\"content\":\"package foo truncated mid strin.\nError message: JSON Parse error: Unterminated string"},"title":"Invalid Tool"}}}\n'
printf '{"type":"step_finish","part":{"reason":"length","type":"step-finish","tokens":{"total":4101,"input":5,"output":4096,"reasoning":0}}}\n'
exit 0`
	return stubWithCounter(t, "opencode-truncation-doomloop.sh", body)
}

// TestScanTruncation proves scanTruncation's schema-tolerant classification
// directly: the real invalid-tool event, the real length-finish event, both
// together, and negative cases (a normal write-tool event, unparseable lines,
// and empty input) that must NOT flag truncation.
func TestScanTruncation(t *testing.T) {
	const invalidToolLine = `{"type":"tool_use","part":{"type":"tool","tool":"invalid","callID":"call_trunc","state":{"status":"completed","input":{"tool":"write","error":"Invalid input for tool write: JSON parsing failed: Unterminated string"}}}}`
	const lengthFinishLine = `{"type":"step_finish","part":{"reason":"length","type":"step-finish","tokens":{"total":4101,"input":5,"output":4096,"reasoning":0}}}`
	const normalWriteLine = `{"type":"tool","tool":"write","state":{"input":{"filePath":"authored.go"}}}`
	const normalStopFinishLine = `{"type":"step_finish","part":{"reason":"stop","type":"step-finish","tokens":{"total":50,"input":5,"output":45}}}`

	cases := []struct {
		name          string
		stdout        string
		wantTruncated bool
		wantDetail    []string // substrings that must all appear in detail when wantTruncated
	}{
		{"invalid tool alone", invalidToolLine, true, []string{"1 tool call(s) relabeled \"invalid\"", "write"}},
		{"length finish alone", lengthFinishLine, true, []string{"finish_reason=length", "output_tokens=4096", "cap=4096"}},
		{"both signals", invalidToolLine + "\n" + lengthFinishLine, true,
			[]string{"relabeled \"invalid\"", "finish_reason=length"}},
		{"repeated invalid tool counts each occurrence",
			invalidToolLine + "\n" + invalidToolLine + "\n" + invalidToolLine, true, []string{"3 tool call(s)"}},
		{"normal write event: not truncated", normalWriteLine, false, nil},
		{"normal stop finish: not truncated", normalStopFinishLine, false, nil},
		{"garbage lines: not truncated", "not json at all\n{broken", false, nil},
		{"empty input: not truncated", "", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			truncated, detail := scanTruncation([]byte(tc.stdout), 4096)
			if truncated != tc.wantTruncated {
				t.Fatalf("scanTruncation truncated=%v, want %v (detail=%q)", truncated, tc.wantTruncated, detail)
			}
			if !tc.wantTruncated && detail != "" {
				t.Errorf("expected empty detail when not truncated, got %q", detail)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(detail, want) {
					t.Errorf("detail %q missing substring %q", detail, want)
				}
			}
		})
	}
}

func TestLooksTransient(t *testing.T) {
	pad := strings.Repeat("x", transientEmptyThreshold+100)
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", true},
		{"near-empty 519B fast-fail", strings.Repeat("e", 519), true},
		{"503 in a large transcript", pad + " upstream 503 service unavailable", true},
		{"429 rate limit", pad + " HTTP 429 too many requests", true},
		{"timeout", pad + " context deadline exceeded", true},
		{"overloaded", pad + " model overloaded, please try again", true},
		{"deterministic error above threshold", pad + " invalid model name: forge/nope", false},
	}
	for _, c := range cases {
		if got := looksTransient([]byte(c.in)); got != c.want {
			t.Errorf("looksTransient(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// ---- stateful stubs (attempt counter persisted in the jail's $TMPDIR) --------

// counterPreamble finds --dir, then increments a per-run counter kept in the
// jail's throwaway $TMPDIR (stable across attempts within one Invoke, and NOT
// shared with the caller). The counter path is echoed to a returned host file so
// the test can read the invocation count.
func stubWithCounter(t *testing.T, name, body string) (bin, countFile string) {
	t.Helper()
	dir := t.TempDir()
	countFile = filepath.Join(dir, "count.txt")
	// The stub increments a host-side counter file (the test's view of how many
	// times opencode was invoked) on every attempt.
	script := "#!/bin/sh\n" +
		"d=\"\"; prev=\"\"\n" +
		"for a in \"$@\"; do if [ \"$prev\" = \"--dir\" ]; then d=\"$a\"; fi; prev=\"$a\"; done\n" +
		"cf=\"" + countFile + "\"\n" +
		"n=$(cat \"$cf\" 2>/dev/null || echo 0); n=$((n+1)); echo \"$n\" > \"$cf\"\n" +
		body + "\n"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, countFile
}

func writeTransientThenSucceedStub(t *testing.T) (bin, countFile string) {
	// Attempt 1: author nothing, emit a 5xx to stderr, exit 1 (transient).
	// Attempt 2+: author a file, exit 0.
	body := `if [ "$n" -lt 2 ]; then
  printf 'upstream returned 503 service unavailable\n' 1>&2
  exit 1
fi
echo authored > "$d/authored-on-retry.txt"
printf '{"type":"text","text":"authored the detector"}\n'
exit 0`
	return stubWithCounter(t, "opencode-transient.sh", body)
}

func writeAuthorThenFailStub(t *testing.T) (bin, countFile string) {
	// Authors a file AND fails transiently: the dirty worktree must veto a retry.
	body := `echo authored > "$d/authored-by-stub.txt"
printf 'upstream 503 service unavailable\n' 1>&2
exit 1`
	return stubWithCounter(t, "opencode-author-then-fail.sh", body)
}

// writeHangStub writes a fake opencode that records its own PID to pgidFile
// (its PID doubles as the process GROUP id, since Adapter's setProcessGroup
// applies Setpgid — see procgroup_unix.go), forks a grandchild that inherits
// the RAW stdout/stderr pipes (no /dev/null redirect: this is the exact
// "shell wrapper forks a pipe-holding grandchild" shape the group kill exists
// to close, not merely a detached process outside the pipe), and hangs both
// the parent and the grandchild forever on `sleep`, authoring nothing. It
// never exits on its own — proving Adapter.Timeout is what ends the
// invocation, not a well-behaved exit. pgidFile lets the
// caller assert the WHOLE GROUP — parent and pipe-holding grandchild alike —
// is actually gone after the timeout fires, not merely that Invoke returned.
func writeHangStub(t *testing.T) (bin, countFile, pgidFile string) {
	t.Helper()
	dir := t.TempDir()
	countFile = filepath.Join(dir, "count.txt")
	pgidFile = filepath.Join(dir, "pgid.txt")
	script := "#!/bin/sh\n" +
		"echo $$ > \"" + pgidFile + "\"\n" +
		"n=$(cat \"" + countFile + "\" 2>/dev/null || echo 0); n=$((n+1)); echo \"$n\" > \"" + countFile + "\"\n" +
		"(sleep 120) &\n" +
		"sleep 120\n"
	bin = filepath.Join(dir, "opencode-hang.sh")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, countFile, pgidFile
}

// assertProcessGroupDead polls until kill(-pgid, 0) reports ESRCH (no member
// of the group is alive — including a reaped, reparented former grandchild)
// or the deadline passes. Polling (not a single check) tolerates the small,
// expected lag between Invoke returning and the OS finishing reaping a
// grandchild that was reparented away from this test process on the parent's
// death — a single immediate check would be flaky, not a proof.
func assertProcessGroupDead(t *testing.T, pgidFile string) {
	t.Helper()
	raw, err := os.ReadFile(pgidFile)
	if err != nil {
		t.Fatalf("read pgid file: %v", err)
	}
	pgid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("parse pgid %q: %v", raw, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = syscall.Kill(-pgid, 0)
		if errors.Is(lastErr, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("process group %d still has a live member 5s after the timeout kill (kill(-pgid,0) = %v) — the group kill did not reach the pipe-holding grandchild", pgid, lastErr)
}

func writeNonTransientFailStub(t *testing.T) (bin, countFile string) {
	// Authors nothing but fails DETERMINISTICALLY (no transient signal, padded
	// past the empty threshold): must NOT be retried.
	pad := strings.Repeat("x", transientEmptyThreshold+50)
	body := `printf '` + pad + ` invalid model configuration\n' 1>&2
exit 1`
	return stubWithCounter(t, "opencode-nontransient.sh", body)
}

func readCount(t *testing.T, countFile string) int {
	t.Helper()
	raw, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatalf("read count file: %v", err)
	}
	n := 0
	for _, f := range strings.Fields(string(raw)) {
		// The last non-empty token is the final count.
		v := 0
		for _, c := range f {
			if c < '0' || c > '9' {
				v = -1
				break
			}
			v = v*10 + int(c-'0')
		}
		if v >= 0 {
			n = v
		}
	}
	return n
}

// writeInvokeStub writes a fake opencode that finds --dir, writes one file into
// the worktree, echoes its own OPENCODE_CONFIG_CONTENT (leaking the run key to
// stdout on purpose), emits canned JSON events, and exits 0.
func writeInvokeStub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode-stub.sh")
	script := `#!/bin/sh
d=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--dir" ]; then d="$a"; fi
  prev="$a"
done
echo "authored" > "$d/authored-by-stub.txt"
# Leak the provider config (which contains the subkey) to stdout on purpose —
# the adapter must redact it.
printf '%s\n' "$OPENCODE_CONFIG_CONTENT"
printf '{"type":"text","text":"authored the file"}\n'
printf '{"type":"tool","tool":"write","state":{"input":{"filePath":"authored-by-stub.txt"}}}\n'
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestWriteToolFilesExcludesReads proves the bc1 fix: the honest authored-file
// counter (WriteToolFiles) counts ONLY write/edit tool calls, never a read
// tool's filePath or a bare file-reference event. Before the fix, the
// "opencode invocation complete ... authored_files=N" log used len(Parse(...)),
// which counts every path the transcript referenced — so a zero-write run that
// READ 27 files logged authored_files=27 (a false positive).
func TestWriteToolFilesExcludesReads(t *testing.T) {
	stream := strings.Join([]string{
		`{"type":"text","text":"surveying the repo"}`,
		// READ tool calls — must NOT count as authored.
		`{"type":"tool","tool":"read","state":{"input":{"filePath":"core/detect/authored/foo/existing.go"}}}`,
		`{"type":"tool","tool":"read","state":{"input":{"filePath":"exams/scenarios/behavioral/VA-01.yaml"}}}`,
		// A bare file-reference event (Parse extracts it too) — must NOT count.
		`{"type":"file","path":"go.mod"}`,
		// WRITE + EDIT tool calls — the only authored files.
		`{"type":"tool","tool":"write","state":{"input":{"filePath":"core/detect/authored/foo/foo.go"}}}`,
		`{"type":"tool","tool":"edit","state":{"input":{"filePath":"exams/scenarios/authored/foo-must-fire.yaml"}}}`,
	}, "\n")

	// Parse (the old counter) sees every path reference — reads included.
	allRefs, _ := Parse([]byte(stream))
	if len(allRefs) < 4 {
		t.Fatalf("Parse should see all 5 path refs (reads+writes+file event), got %d: %v", len(allRefs), allRefs)
	}

	// WriteToolFiles (the honest counter) sees only the write/edit tool files.
	authored := WriteToolFiles([]byte(stream))
	if len(authored) != 2 {
		t.Fatalf("WriteToolFiles = %v, want exactly the 2 write/edit files", authored)
	}
	got := map[string]bool{}
	for _, f := range authored {
		got[f] = true
	}
	for _, want := range []string{
		"core/detect/authored/foo/foo.go",
		"exams/scenarios/authored/foo-must-fire.yaml",
	} {
		if !got[want] {
			t.Errorf("WriteToolFiles missing authored file %q; got %v", want, authored)
		}
	}
	for _, unwanted := range []string{
		"core/detect/authored/foo/existing.go",
		"exams/scenarios/behavioral/VA-01.yaml",
		"go.mod",
	} {
		if got[unwanted] {
			t.Errorf("WriteToolFiles counted a non-authored (read/reference) path %q", unwanted)
		}
	}

	// A zero-write run that only READ files reports zero authored (the bc1 case).
	readsOnly := strings.Join([]string{
		`{"type":"tool","tool":"read","state":{"input":{"filePath":"a.go"}}}`,
		`{"type":"tool","tool":"read","state":{"input":{"filePath":"b.go"}}}`,
	}, "\n")
	if n := len(WriteToolFiles([]byte(readsOnly))); n != 0 {
		t.Errorf("a reads-only transcript reported %d authored files, want 0", n)
	}
}
