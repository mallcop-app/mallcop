// evaltools.go — the "run-eval" and "flag-like-this" chat tools (mallcoppro-
// a2f / C9): the recall-first eval and its corpus-growth twin, reachable
// conversationally.
//
// Both tools are THIN ADAPTERS over the real CLI, never a parallel
// implementation of eval grading or scenario authoring. Neither computes a
// single recall/precision number or scenario id itself; each shells out to
// the mallcop binary this process IS (resolveMallcopBinary self-execs
// os.Executable(), or Options.MallcopBinary in tests) and runs the identical
// subcommand an operator would type at a shell:
//
//	run-eval        -> `mallcop eval --json`
//	flag-like-this  -> `mallcop scenario capture ...`
//
// This keeps the dual-audience contract (README.md's "Chat-driven
// reconfiguration" — chat and CLI are the SAME code path, never two) exactly
// as true for the recall-first eval and scenario capture as it already is
// for `mallcop config set`.
//
// # Repo-root resolution
//
// Neither tool passes --repo-root/--scenarios-dir at all when Options.RepoRoot
// is "". That is the PRODUCTION default: the scaffolded
// .github/workflows/mallcop-investigate.yml launches `mallcop investigate
// --serve` with no --repo-root, and the mallcop binary it runs is always
// installed inside the checked-out deploy repo (cli/deployrepo.go's
// investigateWorkflowTemplate: curl+tar into $PWD/bin, which IS the deploy
// repo's own working tree). Self-exec re-runs that EXACT SAME binary file, so
// the subprocess's own eval.RepoRoot()/os.Executable() walk resolves the
// IDENTICAL root the parent process would — no override needed, and none is
// added, so the chat answer is byte-for-byte what the operator would get
// typing the command themselves.
//
// When Options.RepoRoot IS set (an operator passed --repo-root to `mallcop
// investigate` explicitly, matching lookup_rules' own scoping), that pinned
// root is honored explicitly instead of trusting a second, independent walk
// inside the subprocess — see evalArgs and captureArgs.
package investigate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/eval"
)

// selfExecTimeout bounds run-eval / flag-like-this subprocess calls. Both
// paths are entirely local/offline — no network call, no inference client
// (cli/eval.go's and cli/scenariocapture.go's own package docs) — so this is
// a runaway-loop guard, not a tuning knob operators are expected to touch.
const selfExecTimeout = 2 * time.Minute

// resolveMallcopBinary returns the executable run-eval/flag-like-this
// self-exec: Options.MallcopBinary when set (the test seam), else
// os.Executable() — the production path, since core/investigate only ever
// runs as part of the `mallcop investigate` subcommand of SOME mallcop
// binary.
func resolveMallcopBinary(opts Options) (string, error) {
	if opts.MallcopBinary != "" {
		return opts.MallcopBinary, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve the running mallcop binary: %w", err)
	}
	return exe, nil
}

// selfExecResult is the raw outcome of shelling out to the mallcop binary
// this process IS.
type selfExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runMallcopSelf shells out to resolveMallcopBinary(opts) with args, in dir
// (parent's CWD unchanged when dir == ""), with extraEnv appended to the
// inherited environment. It is the ONLY place run-eval/flag-like-this touch
// os/exec — everything else in this file is pure Go string/arg building,
// independently unit-testable without a subprocess. The returned error is
// for SPAWN/timeout failures only; a started process that exits non-zero
// reports through ExitCode with a nil error, exactly like
// core/selfgate/validate.go's runToolCtx (the established pattern for a
// bounded, output-capturing subprocess elsewhere in this repo).
func runMallcopSelf(opts Options, dir string, extraEnv []string, args ...string) (selfExecResult, error) {
	bin, err := resolveMallcopBinary(opts)
	if err != nil {
		return selfExecResult{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), selfExecTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	res := selfExecResult{Stdout: outBuf.String(), Stderr: errBuf.String()}
	if runErr == nil {
		return res, nil
	}
	if ctxErr := ctx.Err(); errors.Is(ctxErr, context.DeadlineExceeded) {
		return res, fmt.Errorf("mallcop %s: exceeded its %s wall-clock timeout: %w", strings.Join(args, " "), selfExecTimeout, ctxErr)
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("mallcop %s: spawn failed: %w", strings.Join(args, " "), runErr)
}

// isDir reports whether path exists and is a directory. It is the one piece
// of real filesystem I/O evalArgs' caller performs, kept OUT of evalArgs
// itself so the arg-building logic stays a pure, unit-testable function.
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// --- run-eval ---------------------------------------------------------------

// evalArgs builds the argv + extra-env for a `mallcop eval --json` self-exec,
// given the session's repoRoot (Options.RepoRoot) and whether
// <repoRoot>/scenarios currently exists (scenariosDirExists — a plain stat
// result the caller supplies, so this function itself does no I/O and is
// directly unit-testable).
//
//   - repoRoot == "": no override — see this file's package doc for why the
//     production default is to let the subprocess self-resolve exactly like
//     the parent process would.
//   - repoRoot != "" and the scenarios/ dir exists: pin --scenarios-dir
//     explicitly rather than trusting a second walk inside the subprocess.
//   - repoRoot != "" and the scenarios/ dir does NOT exist yet: an explicit
//     --scenarios-dir pointing at a missing directory is a LOUD error by
//     cli/eval.go's own contract ("the operator pointed somewhere on
//     purpose") — so instead this sets MALLCOP_REPO_ROOT, the CLI's own
//     last-resort env override, keeping the "no scenarios/ yet is an empty
//     union, not an error" default path intact and pinned to the right root.
func evalArgs(repoRoot string, scenariosDirExists bool) (args, extraEnv []string) {
	args = []string{"eval", "--json"}
	repoRoot = strings.TrimSpace(repoRoot)
	if repoRoot == "" {
		return args, nil
	}
	if scenariosDirExists {
		return append(args, "--scenarios-dir", filepath.Join(repoRoot, "scenarios")), nil
	}
	return args, []string{"MALLCOP_REPO_ROOT=" + repoRoot}
}

// evalReportShape mirrors cli/eval.go's private evalJSONReport wire shape —
// {"reference": eval.RecallReport, "local": eval.RecallReport} — so `mallcop
// eval --json`'s real output decodes straight into the SAME typed report the
// CLI itself computed. No recall/precision math happens in this package.
type evalReportShape struct {
	Reference eval.RecallReport `json:"reference"`
	Local     eval.RecallReport `json:"local"`
}

// RunEvalOutput is run-eval's tool_result payload: the decoded reference +
// local split, plus a one-line Summary the chat answer can render verbatim.
type RunEvalOutput struct {
	// Summary is formatted "MY missed attacks: n of m (IDs); reference: x of
	// y; false alarms: k" — n/m/IDs are the operator's OWN scenarios/ corpus
	// (never blended with the reference corpus); x/y is the shipped
	// reference corpus's own miss count, reported the SAME way (missed of
	// total) so the two are directly comparable; k is the operator's own
	// false-alarm count.
	Summary   string            `json:"summary"`
	Reference eval.RecallReport `json:"reference"`
	Local     eval.RecallReport `json:"local"`
}

// runEvalSummary renders RunEvalOutput.Summary from an already-decoded
// report. Pure string formatting — no grading logic.
func runEvalSummary(report evalReportShape) string {
	local := report.Local.Recall
	ids := make([]string, 0, len(local.Missed))
	for _, m := range local.Missed {
		ids = append(ids, m.ScenarioID)
	}
	idsPart := ""
	if len(ids) > 0 {
		idsPart = " (" + strings.Join(ids, ", ") + ")"
	}
	refMissed := report.Reference.Recall.MustFire - report.Reference.Recall.Detected
	falseAlarms := len(report.Local.Precision.FalseAlarms)
	return fmt.Sprintf("MY missed attacks: %d of %d%s; reference: %d of %d; false alarms: %d",
		len(local.Missed), local.MustFire, idsPart, refMissed, report.Reference.Recall.MustFire, falseAlarms)
}

// runEvalTool implements the "run-eval" chat tool. See this file's package
// doc for the repo-root resolution contract.
func runEvalTool(opts Options) (any, error) {
	repoRoot := strings.TrimSpace(opts.RepoRoot)
	scenariosExists := repoRoot != "" && isDir(filepath.Join(repoRoot, "scenarios"))
	args, extraEnv := evalArgs(repoRoot, scenariosExists)

	res, err := runMallcopSelf(opts, repoRoot, extraEnv, args...)
	if err != nil {
		return nil, fmt.Errorf("run-eval: %w", err)
	}
	// exit 0 = every labeled row passed; exit 1 = errFindings (labeled
	// misses present) — BOTH are a legitimate, gradeable report, never a
	// command failure (cli/eval.go's own exit-code contract, mirrored from
	// exam-detect). Any other code is a REAL failure — corpus/repo-root
	// resolution error, malformed --scenarios-dir, etc. — surfaced verbatim
	// as an honest error, never papered over or turned into a fabricated
	// zero-miss report.
	if res.ExitCode != 0 && res.ExitCode != 1 {
		detail := strings.TrimSpace(res.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(res.Stdout)
		}
		return nil, fmt.Errorf("run-eval: mallcop eval exited %d: %s", res.ExitCode, detail)
	}

	var report evalReportShape
	if err := json.Unmarshal([]byte(res.Stdout), &report); err != nil {
		return nil, fmt.Errorf("run-eval: mallcop eval --json produced unparseable output: %w", err)
	}

	return RunEvalOutput{
		Summary:   runEvalSummary(report),
		Reference: report.Reference,
		Local:     report.Local,
	}, nil
}

// --- flag-like-this ----------------------------------------------------------

// FlagLikeThisInput is the "flag-like-this" tool_use input: an event
// selector (event_ids, or actor+window) plus the operator's stated ground
// truth (must_fire XOR must_not_fire, optionally reserved). Every field
// passes straight through to `mallcop scenario capture`'s own flags — ALL
// validation (mutually-exclusive selectors/labels, required combinations) is
// the real command's own; nothing here duplicates it.
type FlagLikeThisInput struct {
	EventIDs    []string `json:"event_ids,omitempty"`
	Actor       string   `json:"actor,omitempty"`
	Window      string   `json:"window,omitempty"`
	MustFire    []string `json:"must_fire,omitempty"`
	MustNotFire []string `json:"must_not_fire,omitempty"`
	Reserved    bool     `json:"reserved,omitempty"`
	Title       string   `json:"title,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	ID          string   `json:"id,omitempty"`
}

// flagLikeThisRuntimeImpact is surfaced verbatim in every successful
// FlagLikeThisOutput so the chat answer always states the propose-safety
// rationale explicitly, per this tool's own ToolDefs() description (R4 dual-
// audience / autonomy-dial contract, mallcoppro-a2f).
const flagLikeThisRuntimeImpact = "Wrote a local scenario YAML file into your own repo's scenarios/ directory. " +
	"This changes no runtime detection behavior: it is only graded the next time `mallcop eval` runs (by you " +
	"or CI), never applied automatically. That makes it propose-safe at every autonomy dial setting, including " +
	"the most conservative ('non') — there is nothing here that needs escalation or approval."

// FlagLikeThisOutput confirms exactly what `mallcop scenario capture` wrote
// and where, parsed from ITS real stdout — the scenario id default is a
// content hash cli/scenariocapture.go owns and is never recomputed here.
type FlagLikeThisOutput struct {
	Confirmation  string `json:"confirmation"`
	ScenarioID    string `json:"scenario_id"`
	Repo          string `json:"repo"`
	Path          string `json:"path"`
	RuntimeImpact string `json:"runtime_impact"`
}

// captureArgs builds the argv for a `mallcop scenario capture` self-exec from
// storePath (Options.Store.Path() — the store already open in this session)
// and the operator's FlagLikeThisInput. --scenarios-dir is pinned to
// <repoRoot>/scenarios whenever repoRoot is known: unlike eval, capture
// always os.MkdirAll's its target directory (cli/scenariocapture.go), so
// there is no "loud error on a missing dir" hazard to dodge the way evalArgs
// must — repoRoot == "" simply lets the subprocess self-resolve (this file's
// package doc explains why that reproduces the parent's own resolution).
func captureArgs(storePath, repoRoot string, in FlagLikeThisInput) []string {
	args := []string{"scenario", "capture", "--store", storePath}
	if repoRoot = strings.TrimSpace(repoRoot); repoRoot != "" {
		args = append(args, "--scenarios-dir", filepath.Join(repoRoot, "scenarios"))
	}
	if len(in.EventIDs) > 0 {
		args = append(args, "--event-ids", strings.Join(in.EventIDs, ","))
	}
	if in.Actor != "" {
		args = append(args, "--actor", in.Actor)
	}
	if in.Window != "" {
		args = append(args, "--window", in.Window)
	}
	if len(in.MustFire) > 0 {
		args = append(args, "--must-fire", strings.Join(in.MustFire, ","))
	}
	if len(in.MustNotFire) > 0 {
		args = append(args, "--must-not-fire", strings.Join(in.MustNotFire, ","))
	}
	if in.Reserved {
		args = append(args, "--reserved")
	}
	if in.Title != "" {
		args = append(args, "--title", in.Title)
	}
	if in.Severity != "" {
		args = append(args, "--severity", in.Severity)
	}
	if in.ID != "" {
		args = append(args, "--id", in.ID)
	}
	return args
}

// captureOutputPrefix/captureOutputWrotePrefix match runScenarioCapture's own
// fmt.Printf lines verbatim (cli/scenariocapture.go's "Captured scenario
// %s\n" and "  Wrote:  %s\n") — parseCaptureOutput reads the real command's
// confirmation text rather than recomputing the scenario id or output path.
const (
	captureOutputPrefix      = "Captured scenario "
	captureOutputWrotePrefix = "Wrote:"
)

// parseCaptureOutput extracts the scenario id and the absolute file path
// `mallcop scenario capture` reports having written, from its real stdout.
func parseCaptureOutput(stdout string) (scenarioID, path string) {
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, captureOutputPrefix):
			scenarioID = strings.TrimSpace(strings.TrimPrefix(line, captureOutputPrefix))
		case strings.HasPrefix(trimmed, captureOutputWrotePrefix):
			path = strings.TrimSpace(strings.TrimPrefix(trimmed, captureOutputWrotePrefix))
		}
	}
	return scenarioID, path
}

// flagLikeThisTool implements the "flag-like-this" chat tool. See this
// file's package doc for the repo-root resolution contract.
func flagLikeThisTool(opts Options, in FlagLikeThisInput) (any, error) {
	if opts.Store == nil {
		return nil, errors.New("flag-like-this: nil Store")
	}
	args := captureArgs(opts.Store.Path(), opts.RepoRoot, in)

	res, err := runMallcopSelf(opts, strings.TrimSpace(opts.RepoRoot), nil, args...)
	if err != nil {
		return nil, fmt.Errorf("flag-like-this: %w", err)
	}
	if res.ExitCode != 0 {
		detail := strings.TrimSpace(res.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(res.Stdout)
		}
		return nil, fmt.Errorf("flag-like-this: mallcop scenario capture exited %d: %s", res.ExitCode, detail)
	}

	scenarioID, path := parseCaptureOutput(res.Stdout)
	if scenarioID == "" || path == "" {
		return nil, fmt.Errorf("flag-like-this: mallcop scenario capture reported success but its confirmation output was unparseable:\n%s", res.Stdout)
	}
	repo := filepath.Dir(filepath.Dir(path)) // path == <repo>/scenarios/<id>.yaml

	return FlagLikeThisOutput{
		Confirmation:  fmt.Sprintf("Captured scenario %s. Wrote %s in %s.", scenarioID, path, repo),
		ScenarioID:    scenarioID,
		Repo:          repo,
		Path:          path,
		RuntimeImpact: flagLikeThisRuntimeImpact,
	}, nil
}
