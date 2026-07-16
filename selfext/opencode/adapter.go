// Package opencode is the headless code-authoring adapter for mallcop's
// self-extension loop. It drives the opencode CLI (MIT,
// github.com/sst/opencode) HEADLESS to author a net-new security-monitoring
// DETECTOR inside a sandboxed git worktree, on metered inference routed through
// the configured OpenAI-compatible inference endpoint.
//
// # Provider wiring
//
// opencode talks to the inference endpoint as an OpenAI-compatible provider.
// The provider config is delivered ONLY through the OPENCODE_CONFIG_CONTENT
// subprocess env var (never a file committed to the worktree), and carries the
// short-lived run key as the provider apiKey. The authoring model is referenced
// as "<provider>/<lane>": opencode sends model="<lane>" to the endpoint, which
// resolves the lane to a concrete backing model — a raw catalog id may 404, so
// the request sends a lane name. On the metered rail the run key's
// allowed_models is scoped to that one lane's catalog ids (see engine).
//
// # Code-authoring model override
//
// LIVE evidence: sending the bare "heal" lane resolves to a flash-tier model.
// That model authored a correctly-STRUCTURED customer-tree sidecar detector but
// HALLUCINATED the pkg/event API (called Payload as a method instead of reading
// the json.RawMessage FIELD), failing go build/go vet at the sound gate.
// Adapter.Model (below) lets the CALLER override the model string opencode
// requests, independent of Lane, so the CODE-authoring path sends the OPAQUE
// alias CodeAuthoringModel ("coding") — which the inference endpoint resolves
// server-side to a stronger Go-capable coder through the account's "coding"
// alias (the raw model id never leaves the server, so it never ships in the
// public binary). Lane still scopes the run-key mint (the aliased request
// spends against a lane grant that already covers the stronger coder, so no
// extra grant is needed); the caller resolves the alias locally and verifies
// that grant BEFORE setting Model — never overrides silently if the pool does
// not actually carry it. The model the alias resolves to must NEVER be a Fable
// model (it refuses security-adjacent authoring like detector code); that
// choice lives in the endpoint's lane configuration, not here. The override
// must never be forced onto the BYOI rail: a user's own arbitrary inference
// endpoint may not recognize the alias, so BYOI leaves Model empty and keeps
// sending the bare lane string (Lane). This invariant does NOT touch the
// customer-facing lane routing customers actually get inference through.
//
// # Secret hygiene
//
// The run key is embedded only inside the in-memory provider config (never a
// bare env var, never logged). Every transcript is run through redact.Redact
// BEFORE it is returned for persistence, scrubbing the exact run key and any
// mallcop-sk-* token to a fixed marker.
//
// # Trusted signals only
//
// BuildTaskPrompt constructs the authoring instruction from STRUCTURAL signals
// only (detector id, event type, finding family/severity/actor/source) — never
// raw untrusted sample text (mallcop core/agent/untrusted.go tags untrusted
// zones; the gap builder excludes them). The prompt cannot carry an injected
// instruction from a scanned artifact.
package opencode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/selfext/jail"
	"github.com/mallcop-app/mallcop/selfext/redact"
	"github.com/mallcop-app/mallcop/selfext/sandbox"
)

// defaultProvider is the opencode provider key when Adapter.Provider is empty.
// It mirrors sandbox.ProviderName so the "<provider>/<lane>" model reference and
// the OPENCODE_CONFIG_CONTENT provider block agree.
const defaultProvider = sandbox.ProviderName

// CodeAuthoringModel is the OPAQUE lane alias the CODE-authoring path sends as
// the model string when the caller overrides the bare lane-name routing via
// Adapter.Model (see the package doc's
// "Code-authoring model override" section). It is NOT a raw catalog id: the
// inference endpoint resolves this alias to the real, stronger Go-capable coder
// through the calling account's model alias, exactly the way the scan lanes
// resolve. Keeping the raw model id server-side is deliberate: this constant
// ships in the PUBLIC self-extension binary, so it must name only the opaque
// alias — never the model the product exists to obscure.
//
// The alias name IS the lane name by construction; it is declared here as its
// own const to avoid layering this low-level adapter on a higher-level routing
// package.
//
// The model it resolves to MUST NEVER be a Fable model (Fable models refuse
// security-adjacent authoring tasks like detector code) and MUST NOT be the
// "heal" default (a flash-tier model that plans a detector but fails to execute
// the file writes — observed live); that choice lives in the endpoint's
// coding-lane configuration, not here.
const CodeAuthoringModel = "coding"

// defaultBin is the opencode executable resolved from PATH when Adapter.Bin is
// empty.
const defaultBin = "opencode"

// defaultMaxAttempts is the total opencode invocations for one authoring run
// when Adapter.MaxAttempts is unset: the initial run plus up to two retries of a
// TRANSIENT, no-op fast-fail (opencode exiting non-zero having authored nothing).
const defaultMaxAttempts = 3

// defaultRetryBackoff is the pause between transient retry attempts when
// Adapter.RetryBackoff is unset.
const defaultRetryBackoff = 2 * time.Second

// defaultInvokeTimeout bounds ONE opencode subprocess invocation when
// Adapter.Timeout is unset: headless opencode can hang
// alive well past authoring with no output — a live run wedged the whole
// build loop for ~10h with nothing bounding it. 15 minutes is generous for a
// single detector-authoring turn (the live fast-fail this package already
// retries around exits in seconds) while still guaranteeing the loop always
// makes forward progress instead of wedging indefinitely.
const defaultInvokeTimeout = 15 * time.Minute

// invokeWaitDelay bounds how long runOnce waits for the killed process's I/O
// pipes to close after a timeout fires, mirroring mallcop connect/exec's
// ExecConnector (cmd.WaitDelay) — a grandchild holding the stdout/stderr pipe
// open past the SIGKILL must not itself re-introduce an unbounded hang.
const invokeWaitDelay = 5 * time.Second

// TrustedGap is the ONLY input to an authoring run: the structural description
// of a detection gap. It deliberately carries NO raw untrusted sample text —
// only fields the gap-builder derived from trusted, structural signals — so a
// scanned artifact cannot inject an instruction into the authoring prompt.
type TrustedGap struct {
	// DetectorID is the proposed authored detector's stable name (e.g.
	// "authored-deploy-burst"). It becomes the own-package name and the emitted
	// finding.Type.
	DetectorID string
	// EventType is the connector event type the detector keys on.
	EventType string
	// TargetFamily is the finding family the detector emits — normalized into
	// the fingerprint. Empty falls back to DetectorID.
	TargetFamily string
	// Severity is the structural severity of the gap's exemplar finding
	// (low/medium/high/critical). Structural, not free text.
	Severity string
	// Actor is the structural actor field of the exemplar finding.
	Actor string
	// Source is the structural source field of the exemplar finding.
	Source string
}

// Fingerprint is the stable anti-thrash key: sha256 over the normalized
// (detector id, event type, target family) triple. Two gaps that would author
// the same detector against the same family collapse to one fingerprint, so a
// known-reject is skipped without re-spending inference.
func (g TrustedGap) Fingerprint() string {
	family := g.TargetFamily
	if strings.TrimSpace(family) == "" {
		family = g.DetectorID
	}
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	sum := sha256.Sum256([]byte(norm(g.DetectorID) + "\x00" + norm(g.EventType) + "\x00" + norm(family)))
	return hex.EncodeToString(sum[:])
}

// pkgNamePattern strips a detector id down to a legal, lowercase Go package name
// token. Anything not [a-z0-9] collapses; a leading digit is prefixed.
var pkgNamePattern = regexp.MustCompile(`[^a-z0-9]+`)

// PackageName derives the own-package directory/name for the authored detector
// from the gap's DetectorID (e.g. "authored-Deploy Burst" -> "deployburst").
func (g TrustedGap) PackageName() string {
	name := pkgNamePattern.ReplaceAllString(strings.ToLower(g.DetectorID), "")
	name = strings.TrimPrefix(name, "authored")
	if name == "" {
		name = "authored"
	}
	if name[0] >= '0' && name[0] <= '9' {
		name = "d" + name
	}
	return name
}

// Adapter drives one headless opencode authoring invocation.
type Adapter struct {
	// Bin is the opencode executable path. Empty → "opencode" on PATH.
	Bin string
	// Lane is the authoring lane (the opencode model key AND, when Model is
	// empty, the model string the inference endpoint receives), e.g. "heal".
	// Required. Lane ALSO still scopes the run-key mint on the metered rail even
	// when Model overrides what literal model string is requested — see Model.
	Lane string
	// Model, when non-empty, is the model string opencode requests INSTEAD of the
	// bare Lane string (see the package doc's
	// "Code-authoring model override" section). It is normally an OPAQUE lane
	// alias (CodeAuthoringModel, "coding") that the inference endpoint resolves
	// server-side to the real coder; on a BYOI endpoint that recognizes a literal
	// catalog id, the caller may pass that id verbatim instead. Empty preserves
	// the base behavior: send Lane itself as the model and let the endpoint's
	// own lane resolution pick a model. The caller is responsible for only ever
	// setting this to an alias/model the run key's allowed_models for Lane
	// actually grants after server-side resolution — this package has no endpoint
	// catalog visibility to verify that itself.
	Model string
	// Provider is the opencode provider key. Empty → sandbox.ProviderName.
	Provider string
	// ForgeBaseURL is the inference endpoint base URL; the OpenAI-compatible "/v1"
	// suffix is appended when building the provider config. Required.
	ForgeBaseURL string
	// MaxAttempts caps opencode invocations for one authoring run: the initial
	// run plus retries of a TRANSIENT, no-op fast-fail (opencode exiting non-zero
	// having authored NOTHING and left a transcript that indicates an upstream
	// 5xx/rate-limit/timeout/empty response). ≤0 → defaultMaxAttempts (3). A run
	// that authored files or failed non-transiently is NEVER retried (avoids
	// double-spend on work that already happened).
	MaxAttempts int
	// RetryBackoff is the pause between transient retry attempts. ≤0 →
	// defaultRetryBackoff.
	RetryBackoff time.Duration
	// Timeout bounds ONE opencode subprocess invocation.
	// ≤0 → defaultInvokeTimeout (15m). Applied fresh to EACH attempt (a retry
	// gets its own full budget, not a shared remainder) via
	// context.WithTimeout layered on top of the caller's ctx, so a hung
	// opencode process is force-killed — whole process GROUP, mirroring
	// mallcop connect/exec's procgroup pattern (see procgroup_unix.go) — even
	// though the caller's own ctx (e.g. context.Background() at the CLI) never
	// times out on its own.
	Timeout time.Duration
	// Confine, when true, runs the opencode child under OS-enforced Landlock
	// confinement (the jail package): no filesystem writes outside the
	// worktree's authoring/scratch tree, and no TCP egress except the port of the
	// configured inference endpoint. It is FAIL-CLOSED — if the kernel cannot
	// establish the jail, Invoke returns an error and authors nothing. The
	// production runner sets it; adapter unit tests leave it off (the re-exec
	// launcher needs the real operator binary as /proc/self/exe).
	Confine bool
	// MaxOutputTokens caps the authoring model's output tokens in the opencode
	// provider config. opencode has no registry metadata for our custom
	// openai-compatible provider, so without an explicit limit it defaults its
	// max_tokens ABOVE the lane model's hard cap, and every authoring request
	// 400s ("max_tokens must not exceed 4096"). opencode then transient-fast-fails
	// (0 files authored) on every attempt. ≤0 → defaultMaxOutputTokens.
	MaxOutputTokens int
	// MaxContextTokens is the context-window size declared alongside MaxOutputTokens
	// in the opencode model config. opencode REQUIRES context when output is set (it
	// fails config validation otherwise). ≤0 → defaultMaxContextTokens.
	MaxContextTokens int
	// Logger receives non-secret adapter events. Nil → discard.
	Logger *slog.Logger

	// sleepFn is the backoff sleeper, injectable for deterministic tests. Nil →
	// time.Sleep.
	sleepFn func(time.Duration)

	// extraRunArgs, when set, are appended to the `opencode run` argv AFTER the
	// fixed flags. TEST-ONLY: the real-opencode integration
	// tests (realbin_test.go) set this to []string{"--pure"} — skip loading
	// external opencode plugins — for hermetic determinism against a LOCAL fake
	// inference server. Plugin loading is a real, unrelated network dependency
	// (observed live to occasionally stall a cold invocation for 30s+) that has
	// nothing to do with what those tests verify (the output-cap wire contract,
	// event-stream file/text extraction, key redaction); nil in production
	// leaves argv, and therefore behavior, completely unchanged. Same
	// test-injection pattern as sleepFn above.
	extraRunArgs []string
}

// defaultMaxOutputTokens is the output-token ceiling declared in the opencode
// model config when Adapter.MaxOutputTokens is unset. It must not exceed the
// inference endpoint's per-request acceptance cap, or every authoring request
// 400s ("max_tokens must not exceed N") and opencode transient-fast-fails.
// 32768 (was 4096): reasoning authoring models bill thinking tokens against
// max_tokens, so an authoring turn (reasoning + a whole detector file in one
// write tool call) cannot fit in 4096 — measured live, failing turns pegged
// completion_tokens=4096 / finish_reason=length / empty content (rd 4a1). The
// endpoint acceptance cap was raised in lockstep (forge#122). A BYOK endpoint
// that caps lower will reject loudly; pass a smaller Adapter.MaxOutputTokens
// (cli: --max-output-tokens) for such endpoints.
const defaultMaxOutputTokens = 32768

// defaultMaxContextTokens is the context-window size declared alongside the output cap.
// opencode's config schema REJECTS a model whose limit block sets output without context
// ("Missing key provider.<p>.models.<m>.limit.context"), so both must be present or
// opencode fails config validation before it ever calls inference. 128k is safe for the
// lane models the inference endpoint routes to. Overridable via Adapter.MaxContextTokens.
const defaultMaxContextTokens = 128000

func (a *Adapter) bin() string {
	if a.Bin != "" {
		return a.Bin
	}
	return defaultBin
}

func (a *Adapter) maxOutputTokens() int {
	if a.MaxOutputTokens > 0 {
		return a.MaxOutputTokens
	}
	return defaultMaxOutputTokens
}

func (a *Adapter) maxContextTokens() int {
	if a.MaxContextTokens > 0 {
		return a.MaxContextTokens
	}
	return defaultMaxContextTokens
}

func (a *Adapter) provider() string {
	if a.Provider != "" {
		return a.Provider
	}
	return defaultProvider
}

// model returns the literal model string opencode requests: Model when set,
// else Lane (see the Model field doc).
func (a *Adapter) model() string {
	if a.Model != "" {
		return a.Model
	}
	return a.Lane
}

// RequestedModel is model, exported for callers outside this package (the
// engine's provenance writer) that need to record the
// literal model actually requested/billed, not just the lane it was requested
// under. overridden is true when Adapter.Model (the
// code-authoring override) is in effect, so the caller can distinguish "the
// resolved literal catalog id" from "the bare lane, the inference endpoint resolves it".
func (a *Adapter) RequestedModel() (model string, overridden bool) {
	if a.Model != "" {
		return a.Model, true
	}
	return a.Lane, false
}

func (a *Adapter) logger() *slog.Logger {
	if a.Logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return a.Logger
}

func (a *Adapter) maxAttempts() int {
	if a.MaxAttempts > 0 {
		return a.MaxAttempts
	}
	return defaultMaxAttempts
}

func (a *Adapter) retryBackoff() time.Duration {
	if a.RetryBackoff > 0 {
		return a.RetryBackoff
	}
	return defaultRetryBackoff
}

func (a *Adapter) timeout() time.Duration {
	if a.Timeout > 0 {
		return a.Timeout
	}
	return defaultInvokeTimeout
}

func (a *Adapter) sleep(d time.Duration) {
	if a.sleepFn != nil {
		a.sleepFn(d)
		return
	}
	time.Sleep(d)
}

// Result is the outcome of one opencode invocation. AuthoredFiles is a
// best-effort extraction from the event stream; git (the worktree diff) is the
// authoritative record of what changed and is what the gate diffs.
type Result struct {
	AuthoredFiles      []string
	AssistantText      string
	TranscriptRedacted []byte
	ExitCode           int
	// TimedOut is true when THIS attempt was killed because it exceeded
	// Adapter.Timeout. Invoke never retries a timed-out
	// attempt (see Invoke) — a hang is not the "transient, no-op fast-fail"
	// the retry heuristic targets, and retrying a bounded hang just risks
	// stacking several bounded hangs back to back instead of failing fast.
	TimedOut bool
}

// ProviderConfig marshals the opencode OpenAI-compatible provider config as a
// STRING for OPENCODE_CONFIG_CONTENT. It declares the authoring lane under the
// provider's models map so opencode will accept "-m <provider>/<lane>", and
// embeds the run key as the provider apiKey. It is never written to a file.
func (a *Adapter) ProviderConfig(apiKey, forgeBaseURL string) (string, error) {
	if a.Lane == "" {
		return "", errors.New("opencode: Adapter.Lane is empty")
	}
	if forgeBaseURL == "" {
		return "", errors.New("opencode: forgeBaseURL is empty")
	}
	cfg := map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"provider": map[string]any{
			a.provider(): map[string]any{
				"npm":  "@ai-sdk/openai-compatible",
				"name": "Forge",
				"options": map[string]any{
					"baseURL": openAIBaseURL(forgeBaseURL),
					"apiKey":  apiKey,
				},
				"models": map[string]any{
					// Declare the lane model's output cap so opencode never requests
					// max_tokens above the model's hard limit (the endpoint 400s
					// otherwise, and opencode then fast-fails having authored nothing).
					a.model(): map[string]any{
						// opencode requires BOTH context and output in a limit block
						// (it fails config validation on output-without-context), and
						// output must not exceed the lane model's hard cap or the endpoint 400s.
						"limit": map[string]any{
							"context": a.maxContextTokens(),
							"output":  a.maxOutputTokens(),
						},
					},
				},
			},
		},
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("opencode: marshal provider config: %w", err)
	}
	return string(blob), nil
}

// Invoke runs opencode HEADLESS against the worktree jail:
//
//	opencode run <task> -m <provider>/<lane> --format json \
//	  --dangerously-skip-permissions --dir <wt.Dir>
//
// The subprocess env is the sandbox's credential-scrubbed allowlist with
// OPENCODE_CONFIG_CONTENT overridden by this adapter's lane-aware provider
// config (the sandbox default omits the models map). The captured stdout+stderr
// are REDACTED before being returned for persistence.
//
// A non-zero opencode exit is NOT an error — it is recorded in Result.ExitCode
// so the engine can decide (git remains the source of truth for what, if
// anything, was authored). A spawn failure or a canceled context IS an error.
//
// # Bounded transient retry
//
// Live runs sometimes fast-fail: opencode exits non-zero within a few seconds
// on a transient upstream error (a 5xx, a rate-limit, an empty response) having
// authored NOTHING. Invoke retries that case up to MaxAttempts-1 times with a
// backoff, so a flaky upstream does not burn the whole build. The retry is
// gated by TWO hard conditions to avoid double-spend:
//
//   - the worktree is still CLEAN (git status --porcelain empty) — proof
//     nothing was authored; a run that wrote any file is never retried, and
//   - the redacted transcript matches a TRANSIENT signal (see looksTransient) —
//     a deterministic failure (bad model, config error, compile-time refusal)
//     is not retried because a retry cannot help it.
//
// A canceled context or a spawn failure surfaces immediately (never retried).
func (a *Adapter) Invoke(ctx context.Context, wt *sandbox.Worktree, apiKey, task string) (Result, error) {
	if wt == nil {
		return Result{}, errors.New("opencode: worktree is nil")
	}
	if a.Lane == "" {
		return Result{}, errors.New("opencode: Adapter.Lane is empty")
	}

	cfg, err := a.ProviderConfig(apiKey, a.ForgeBaseURL)
	if err != nil {
		return Result{}, err
	}
	env := withConfigContent(wt.ScrubbedEnv(apiKey, a.ForgeBaseURL), cfg)

	maxAttempts := a.maxAttempts()
	var res Result
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var runErr error
		res, runErr = a.runOnce(ctx, wt, env, apiKey, task)
		if runErr != nil {
			// Spawn failure / context cancellation: surface it, never retry.
			return res, runErr
		}
		if res.ExitCode == 0 || attempt == maxAttempts {
			return res, nil
		}

		// A timed-out attempt is NEVER retried: a hang is
		// not the "transient, no-op fast-fail" this heuristic targets, so
		// retrying would only risk stacking multiple bounded hangs instead of
		// failing fast for the operator.
		if res.TimedOut {
			a.logger().Warn("opencode invocation timed out; not retried (fail fast on a hang)",
				"attempt", attempt, "timeout", a.timeout())
			return res, nil
		}

		// Non-zero exit with attempts remaining. Retry ONLY a transient, no-op
		// fast-fail — and only when the worktree proves nothing was authored, so
		// we never re-run over work that already spent inference.
		clean, cerr := worktreeClean(ctx, wt.Dir)
		if cerr != nil || !clean {
			a.logger().Info("opencode non-zero exit; not retried (authored files or indeterminate worktree)",
				"exit_code", res.ExitCode, "attempt", attempt, "worktree_clean_err", cerr)
			return res, nil
		}
		if !looksTransient(res.TranscriptRedacted) {
			a.logger().Info("opencode non-zero exit; not retried (non-transient failure)",
				"exit_code", res.ExitCode, "attempt", attempt, "transcript_bytes", len(res.TranscriptRedacted))
			return res, nil
		}
		a.logger().Warn("opencode transient fast-fail; retrying",
			"exit_code", res.ExitCode, "attempt", attempt, "next_attempt", attempt+1,
			"max_attempts", maxAttempts, "transcript_bytes", len(res.TranscriptRedacted))
		a.sleep(a.retryBackoff())
	}
	return res, nil
}

// runOnce performs a SINGLE headless opencode invocation and captures its
// redacted transcript, extracted files, and exit code. It is the retry unit for
// Invoke. A spawn failure / canceled (by the CALLER, not our own timeout)
// context is returned as an error (with the redacted transcript captured so
// far); a non-zero process exit is recorded in Result.ExitCode, not returned
// as an error.
//
// # Bounded wall-clock
//
// Every attempt gets its OWN context.WithTimeout(ctx, a.timeout()) layered on
// top of the caller's ctx — a live run has wedged the whole build loop for
// ~10h with nothing bounding it, since the caller's own ctx (context.Background()
// at the CLI) never times out on its own. On expiry the WHOLE PROCESS GROUP is
// killed (setProcessGroup — mirroring mallcop connect/exec's procgroup
// pattern: a headless opencode may fork tool subprocesses that inherit the
// stdout/stderr pipes, so killing only the direct child could leave Wait
// blocked on a pipe a grandchild still holds open) and cmd.WaitDelay bounds
// how long Wait can then take to observe that. A timeout is recorded in
// Result.TimedOut, NOT returned as an error — same shape as any other
// non-zero-exit run — so it flows through the engine's existing
// failWithTranscript diagnostics path.
func (a *Adapter) runOnce(ctx context.Context, wt *sandbox.Worktree, env []string, apiKey, task string) (Result, error) {
	runCtx, cancel := context.WithTimeout(ctx, a.timeout())
	defer cancel()

	model := a.provider() + "/" + a.model()
	args := []string{
		"run", task,
		"-m", model,
		"--format", "json",
		"--dangerously-skip-permissions",
		"--dir", wt.Dir,
	}
	args = append(args, a.extraRunArgs...)

	// Build the command. When Confine is set, spawn opencode under OS-enforced
	// Landlock confinement via the operator binary's re-exec launcher
	// (jail.WrapCommand runs /proc/self/exe, whose main() calls jail.MaybeReexec
	// to apply the jail and then exec opencode). FAIL-CLOSED: if the kernel cannot establish the
	// jail, refuse to author rather than spawn opencode unconfined.
	var cmd *exec.Cmd
	if a.Confine {
		if serr := jail.Supported(); serr != nil {
			return Result{}, fmt.Errorf("opencode: OS-enforced authoring jail required but unavailable: %w", serr)
		}
		pol, perr := jailPolicy(wt, a.ForgeBaseURL)
		if perr != nil {
			return Result{}, perr
		}
		penv, perr := jail.PolicyEnv(pol)
		if perr != nil {
			return Result{}, perr
		}
		cmd = jail.WrapCommand(runCtx, "/proc/self/exe", a.bin(), args...)
		env = append(env, penv)
	} else {
		cmd = exec.CommandContext(runCtx, a.bin(), args...)
	}
	cmd.Env = env
	cmd.Dir = wt.Dir
	setProcessGroup(cmd)
	cmd.WaitDelay = invokeWaitDelay

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	timedOut := errors.Is(runCtx.Err(), context.DeadlineExceeded)

	// Redact BEFORE anything is returned for persistence.
	raw := stdout.String()
	if stderr.Len() > 0 {
		raw += "\n--- stderr ---\n" + stderr.String()
	}
	if timedOut {
		raw += fmt.Sprintf("\n--- opencode killed: exceeded timeout %s ---\n", a.timeout())
	}
	redacted := redact.Redact(raw, apiKey)

	files, text := Parse(stdout.Bytes())

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			// The process ran and exited non-zero (including signal-killed by
			// our own timeout): not an adapter error.
			exitCode = exitErr.ExitCode()
		} else if timedOut {
			// The kill raced Wait in a way that didn't surface as a plain
			// *exec.ExitError (e.g. WaitDelay force-closed the pipes) — still
			// OUR OWN bound firing, not a spawn failure. Record it, don't error.
			exitCode = -1
		} else {
			// Spawn failure / context cancellation the CALLER initiated: surface it.
			return Result{
				TranscriptRedacted: []byte(redacted),
				ExitCode:           -1,
			}, fmt.Errorf("opencode: run %s: %w", a.bin(), runErr)
		}
	}

	a.logger().Info("opencode invocation complete",
		"exit_code", exitCode,
		"authored_files", len(files),
		"transcript_bytes", len(redacted),
		"timed_out", timedOut,
	)

	return Result{
		AuthoredFiles:      files,
		AssistantText:      text,
		TranscriptRedacted: []byte(redacted),
		ExitCode:           exitCode,
		TimedOut:           timedOut,
	}, nil
}

// transientEmptyThreshold is the transcript size (bytes, trimmed) below which a
// non-zero-exit run is treated as an empty/near-empty upstream fast-fail. The
// observed live fast-fail is a ~519-byte transcript, so this covers the
// "opencode produced almost nothing and gave up" shape even absent an explicit
// status code.
const transientEmptyThreshold = 800

// transientPatterns match a transcript that indicates a TRANSIENT upstream
// failure (a 5xx status, a rate-limit, a timeout, a dropped connection, or an
// explicit "overloaded / try again" signal) — the fast-fail worth retrying.
// They are deliberately conservative: none match a substantive authoring
// failure (a compile error, a policy refusal, a tool error), so a run that did
// real work is not retried.
var transientPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(50[0-9]|429)\b`),
	regexp.MustCompile(`(?i)rate.?limit|too many requests`),
	regexp.MustCompile(`(?i)timeout|timed out|deadline exceeded`),
	regexp.MustCompile(`(?i)connection (reset|refused|closed)|unexpected eof|no response|empty response`),
	regexp.MustCompile(`(?i)temporarily unavailable|service unavailable|overloaded|please try again`),
}

// looksTransient reports whether a non-zero-exit transcript indicates a
// transient upstream hiccup worth one more attempt. An empty/near-empty
// transcript is itself a transient signal (opencode produced no usable event
// stream before giving up).
func looksTransient(transcript []byte) bool {
	if len(bytes.TrimSpace(transcript)) < transientEmptyThreshold {
		return true
	}
	for _, re := range transientPatterns {
		if re.Match(transcript) {
			return true
		}
	}
	return false
}

// worktreeClean reports whether the worktree has NO staged/unstaged changes —
// the authoritative "authored nothing" signal that gates a retry. Any error
// determining cleanliness returns (false, err): when in doubt, do NOT retry.
func worktreeClean(ctx context.Context, dir string) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "status", "--porcelain")
	// Scrub the env to the bare minimum: git needs none of the operator
	// credentials, and this call must not depend on the caller's config.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0"}
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("opencode: git status: %w", err)
	}
	return len(bytes.TrimSpace(out)) == 0, nil
}

// withConfigContent returns env with the OPENCODE_CONFIG_CONTENT entry replaced
// (or appended) with cfg. Every other entry — the sandbox's credential-scrubbed
// allowlist — is preserved verbatim, so this override cannot widen the env.
func withConfigContent(env []string, cfg string) []string {
	const key = "OPENCODE_CONFIG_CONTENT="
	// Capacity len(env) (not len(env)+1): the one possible extra append (the
	// !replaced case) grows the slice on demand — avoids a size-computation the
	// allocation-overflow analysis flags, with no behavioral change.
	out := make([]string, 0, len(env))
	replaced := false
	for _, kv := range env {
		if strings.HasPrefix(kv, key) {
			out = append(out, key+cfg)
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, key+cfg)
	}
	return out
}

// jailPolicy derives the OS-enforced confinement for the opencode child from the
// worktree and the configured inference endpoint. The child may:
//
//   - read+write ONLY the worktree's authoring/scratch tree and the git metadata
//     dir it writes through (sandbox.Worktree.JailWritePaths), read-only elsewhere; and
//   - connect(2) ONLY to the TCP port of the inference endpoint (the loopback
//     stream-shim port on the metered rail, or 443 for a direct BYOI endpoint).
//
// A missing write tree or an unparseable endpoint is a fail-closed error: the
// caller refuses to author rather than run under a meaningless jail.
func jailPolicy(wt *sandbox.Worktree, forgeBaseURL string) (jail.Policy, error) {
	writes := wt.JailWritePaths()
	if len(writes) == 0 {
		return jail.Policy{}, errors.New("opencode: cannot confine — worktree exposes no writable authoring tree")
	}
	port, err := inferencePort(forgeBaseURL)
	if err != nil {
		return jail.Policy{}, fmt.Errorf("opencode: cannot confine — %w", err)
	}
	// opencode is a Bun/Node process that (under --dangerously-skip-permissions)
	// spawns shell tools which constantly redirect to /dev/null and read
	// /dev/urandom etc. A strictly read-only rootfs would deny those writes and
	// break authoring, so /dev is granted read+write. This does NOT widen the
	// meaningful blast radius: the device nodes are DAC-protected (the unprivileged
	// runner user cannot write raw disks), and the protection that matters — no
	// writes to the target repo's working tree, the operator's HOME, or any system
	// binary/config outside the authoring scratch tree — is fully preserved because
	// everything except WritePaths (worktree scratch + git metadata + /dev) stays
	// read-only.
	if fi, statErr := os.Stat("/dev"); statErr == nil && fi.IsDir() {
		writes = append(writes, "/dev")
	}
	return jail.Policy{
		WritePaths:    writes,
		ReadPaths:     []string{"/"},
		AllowTCPPorts: []uint16{port},
	}, nil
}

// inferencePort extracts the TCP port the opencode child must be allowed to
// reach from the configured inference base URL. An explicit port wins; otherwise
// it defaults by scheme (https→443, http→80). It is the ONLY egress the jail
// permits, so an endpoint we cannot resolve to a port is a fail-closed error.
func inferencePort(forgeBaseURL string) (uint16, error) {
	if strings.TrimSpace(forgeBaseURL) == "" {
		return 0, errors.New("inference base URL is empty")
	}
	u, err := url.Parse(forgeBaseURL)
	if err != nil {
		return 0, fmt.Errorf("parse inference base URL %q: %w", forgeBaseURL, err)
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.ParseUint(p, 10, 16)
		if perr != nil || n == 0 {
			return 0, fmt.Errorf("invalid inference port %q", p)
		}
		return uint16(n), nil
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return 443, nil
	case "http":
		return 80, nil
	default:
		return 0, fmt.Errorf("cannot derive port from inference base URL %q (scheme %q)", forgeBaseURL, u.Scheme)
	}
}

// fileKeyPattern matches an event-object key that names an authored file path.
var fileKeyPattern = regexp.MustCompile(`(?i)(filepath|file_path|filename|file|path)$`)

// Parse extracts authored file paths and concatenated assistant text from
// opencode's line-delimited --format json event stream. It is deliberately
// SCHEMA-TOLERANT: it decodes each line as a generic JSON object and walks it
// recursively, collecting string values under file/path-shaped keys and under
// "text" keys. If the schema drifts and nothing is recognized, files come back
// empty — git (the worktree diff) remains the authoritative record of what the
// run actually changed.
func Parse(stdout []byte) (files []string, text string) {
	seen := map[string]struct{}{}
	var textParts []string
	for _, line := range bytes.Split(stdout, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var obj any
		if err := json.Unmarshal(line, &obj); err != nil {
			continue
		}
		walkEvent(obj, seen, &files, &textParts)
	}
	return files, strings.Join(textParts, "")
}

// walkEvent recursively collects file paths and text from a decoded JSON value.
func walkEvent(v any, seen map[string]struct{}, files *[]string, textParts *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && s != "" {
				if fileKeyPattern.MatchString(k) && looksLikePath(s) {
					if _, dup := seen[s]; !dup {
						seen[s] = struct{}{}
						*files = append(*files, s)
					}
				}
				if strings.EqualFold(k, "text") {
					*textParts = append(*textParts, s)
				}
			}
			walkEvent(val, seen, files, textParts)
		}
	case []any:
		for _, val := range t {
			walkEvent(val, seen, files, textParts)
		}
	}
}

// looksLikePath rejects obvious non-paths (URLs, bare tokens) so a stray "file"
// key carrying a non-path string does not pollute AuthoredFiles.
func looksLikePath(s string) bool {
	if strings.Contains(s, "://") {
		return false
	}
	return strings.Contains(s, "/") || strings.Contains(s, ".")
}

// openAIBaseURL derives the OpenAI-compatible base URL (the inference endpoint
// serves POST /v1/chat/completions) from the endpoint base URL, appending /v1
// unless already present. Mirrors sandbox.openAIBaseURL (kept local to avoid
// coupling the packages on an unexported helper).
func openAIBaseURL(forgeBaseURL string) string {
	b := strings.TrimRight(forgeBaseURL, "/")
	if strings.HasSuffix(b, "/v1") {
		return b
	}
	return b + "/v1"
}
