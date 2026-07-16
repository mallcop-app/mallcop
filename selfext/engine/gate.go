package engine

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
)

// GateResult mirrors mallcop core/selfgate.GateResult over the PROCESS
// BOUNDARY. mallcop-pro does not import the mallcop module: the free-tier gate
// is a separate trusted binary, and its versioned JSON is the seam (exactly as
// selfgate itself decodes exam-detect's JSON locally rather than importing
// core/eval). SchemaVersion lets us reject a report shape we do not understand.
type GateResult struct {
	SchemaVersion int         `json:"schema_version"`
	Tier          string      `json:"tier"`
	Passed        bool        `json:"passed"`
	BaseSHA       string      `json:"base_sha"`
	HeadSHA       string      `json:"head_sha"`
	Stages        []GateStage `json:"stages"`
	CoveragePlus  int         `json:"coverage_plus"`
	NewFirings    []string    `json:"new_firings"`
	// NovelGap mirrors selfgate.GateResult.NovelGap (BOTH
	// ruling, part B): CUSTOMER-TREE MODE ONLY — true when at least one family
	// the customer detector's own scenarios declare has ZERO labeled must_fire
	// rows anywhere in the reference corpus. The held-out-corpus new-firing
	// control (part A) has no independent ground truth for such a family — it
	// can prove the detector does not fire WRONGLY elsewhere, but cannot prove
	// its claimed detection is itself sound. A GREEN gate with NovelGap==true
	// is NOT a weaker verdict (every stage still passed) but BOTH the router
	// (DATA lane) and the engine (CODE lane, below) treat it as a
	// dial-independent forced-human-review signal — mirroring the existing
	// dial-independent hard line already applied to OSS contribute-back (see
	// package autonomy's doc). Omitted/false for the in-tree lane and for any
	// run that never reaches customer-tree mode.
	NovelGap bool `json:"novel_gap,omitempty"`
	// NovelGapFamilies mirrors selfgate.GateResult.NovelGapFamilies —
	// informational detail only, never consulted to compute NovelGap.
	NovelGapFamilies []string `json:"novel_gap_families,omitempty"`
}

// GateStage mirrors selfgate.StageResult.
type GateStage struct {
	Name     string        `json:"name"`
	Passed   bool          `json:"passed"`
	Evidence string        `json:"evidence"`
	Findings []GateFinding `json:"findings"`
}

// GateFinding mirrors selfgate.GuardFinding.
type GateFinding struct {
	Path   string `json:"path"`
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

// expectedGateSchemaVersion is the selfgate.GateSchemaVersion this engine was
// written against. A report with a higher version is refused rather than
// misread.
const expectedGateSchemaVersion = 1

// Gate exit codes, mirroring `mallcop validate-proposal`
// (cmd/mallcop/validateproposal.go): 0 clean, 1 rejected-with-findings,
// 2 operational failure.
const (
	gateExitClean       = 0
	gateExitRejected    = 1
	gateExitOperational = 2
)

// RunValidateProposal is the exported entrypoint the operator K8
// propose→gate→route pipeline uses to gate an already-applied add-only overlay
// change: it execs the SAME trusted `mallcop validate-proposal` the engine's Run
// uses internally, over base..HEAD in workdir, and returns the parsed
// GateResult. The router then decides where the gate-GREEN proposal goes.
//
// examRepo is the path to a REFERENCE mallcop tree (has its
// own cmd/mallcop + pinned exam corpus) — the engine's own pinned checkout,
// caller-supplied, NEVER derived from workdir's own contents. It is only
// EVER USED when workdir itself has no cmd/mallcop (a customer-shaped
// THIN-EMBED target repo): see hasCmdMallcop below. Pass "" to preserve the
// prior behavior byte-for-byte (the flag is simply omitted from argv) — the
// existing mallcop-repo-as-TargetRepo lane is completely untouched.
//
// CUSTOMER-TREE MODE (orchestrator ruling, resolving the
// 72d/97b collision): on the mallcop side, `--exam-repo` is not just stage
// 3's reference-tree path — core/selfgate.ValidateProposal now ALSO derives
// its stage-1 guard's customerTreeMode strictly as `opts.ExamRepo != ""`
// (see selfgate/validate.go's Options.ExamRepo doc). There is deliberately NO
// separate `--customer-tree` flag on either side of this process boundary:
// customer-tree mode and --exam-repo are THE SAME SIGNAL, so they cannot
// travel apart by construction (a caller cannot pass one without the other,
// unlike two independent flags that could drift out of sync). That signal
// still originates ONLY here — the trusted engine's own hasCmdMallcop gate on
// workdir, never anything the untrusted proposal content could set — so the
// "never inferred from the target tree" invariant holds end to end.
func RunValidateProposal(ctx context.Context, bin, workdir, baseSHA, examRepo string) (GateResult, int, error) {
	return runValidateProposal(ctx, bin, workdir, baseSHA, examRepo)
}

// hasCmdMallcop reports whether dir has its own cmd/mallcop package
// directory — the discriminator between a full mallcop checkout (the gate's
// default in-tree lane builds its own binary from it) and a customer-shaped
// THIN-EMBED target repo (go.mod pins mallcop; no cmd/mallcop of its own).
// Mirrors core/selfgate.hasCmdMallcop on the mallcop side of the process
// boundary — mallcop-pro does not import that package, so the check is
// duplicated here rather than shared.
func hasCmdMallcop(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "cmd", "mallcop"))
	return err == nil && info.IsDir()
}

// runValidateProposal execs `<bin> validate-proposal --base <baseSHA> --head
// HEAD --json` with cwd = workdir (the head worktree). When workdir is
// customer-shaped (hasCmdMallcop is false) and examRepo is non-empty, it also
// passes `--exam-repo <examRepo>` so the trusted gate routes stage 3 through
// RunCustomerTreeExam against the reference tree instead of trying (and
// failing) to build workdir's own nonexistent cmd/mallcop. It returns the
// parsed GateResult for exit 0 (clean) and exit 1 (rejected-with-findings) —
// both emit the versioned JSON on stdout. Any other exit (2 = operational, or
// a spawn failure) returns an error.
//
// The gate is TRUSTED human-written code (the mallcop binary), not the authored
// code it evaluates, and it needs the Go toolchain — so it runs with an
// EXPLICIT env ALLOWLIST (gateAllowlistedEnv), not the parent environment
// minus a denylist: the same posture as sandbox.Worktree.ScrubbedEnv for the
// opencode subprocess (defense-in-depth). A denylist only strips credential
// shapes it already knows about; an allowlist admits nothing but the handful
// of vars the gate actually needs, so a credential a future operator env
// grows (a new token, a new cloud provider's *_KEY) is excluded by default
// instead of leaking until someone remembers to deny it. (The stage-3
// subprocess execs authored code, which the shape gate already forbids from
// touching env/os, but we drop the credentials regardless.)
func runValidateProposal(ctx context.Context, bin, workdir, baseSHA, examRepo string) (GateResult, int, error) {
	args := []string{"validate-proposal", "--base", baseSHA, "--head", "HEAD", "--json"}
	if examRepo != "" && !hasCmdMallcop(workdir) {
		args = append(args, "--exam-repo", examRepo)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = workdir
	cmd.Env = gateAllowlistedEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	exitCode := gateExitClean
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return GateResult{}, -1, fmt.Errorf("selfext: exec gate %q: %w: %s", bin, runErr, truncate(stderr.String(), 800))
		}
	}

	switch exitCode {
	case gateExitClean, gateExitRejected:
		var gr GateResult
		if err := json.Unmarshal(stdout.Bytes(), &gr); err != nil {
			return GateResult{}, exitCode, fmt.Errorf("selfext: gate exit %d but unparseable GateResult JSON: %w: %s",
				exitCode, err, truncate(stdout.String()+stderr.String(), 800))
		}
		if gr.SchemaVersion > expectedGateSchemaVersion {
			return GateResult{}, exitCode, fmt.Errorf("selfext: gate GateResult schema_version %d newer than supported %d",
				gr.SchemaVersion, expectedGateSchemaVersion)
		}
		// Cross-check: exit code and Passed must agree, or one of them is lying.
		if (exitCode == gateExitClean) != gr.Passed {
			return GateResult{}, exitCode, fmt.Errorf("selfext: gate exit %d disagrees with GateResult.Passed=%v",
				exitCode, gr.Passed)
		}
		return gr, exitCode, nil
	default:
		return GateResult{}, exitCode, fmt.Errorf("selfext: gate operational failure (exit %d): %s",
			exitCode, truncate(stderr.String()+stdout.String(), 800))
	}
}

// validateBinProbeArg is a subcommand name reserved by mallcop-pro — never a
// real mallcop CLI verb (see cli/main.go's Commands: list) — used solely to
// elicit the Go CLI's deterministic "unknown command" usage-error shape as a
// version-probe fingerprint (see probeGoMallcopBinary).
const validateBinProbeArg = "__selfext_validate_bin_probe__"

// validateBinProbeMarker is the literal, version-independent text
// cli/main.go's unknown-command path writes for ANY unrecognized subcommand:
//
//	fmt.Fprintf(os.Stderr, "mallcop: unknown command %q\n\n", cmd)
//
// It is present in every mallcop Go CLI build regardless of version, and
// absent from anything else that might also answer to the name "mallcop" on
// an operator's PATH (a stale python-legacy shim crashes with
// ModuleNotFoundError before it ever gets this far; an unrelated tool won't
// match either).
const validateBinProbeMarker = "mallcop: unknown command"

// probeGoMallcopBinary verifies bin behaves like the mallcop Go CLI before the
// engine trusts it to gate a self-extension proposal. It execs bin with
// validateBinProbeArg (a subcommand no real mallcop verb will ever match) and
// checks the combined output for validateBinProbeMarker. A binary that does
// not produce this shape — a stale/wrong "mallcop" resolved from PATH, or
// nothing at all — fails the probe loudly instead of being silently invoked
// as the trusted gate.
func probeGoMallcopBinary(ctx context.Context, bin string) error {
	cmd := exec.CommandContext(ctx, bin, validateBinProbeArg)
	cmd.Env = gateAllowlistedEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	runErr := cmd.Run()
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return fmt.Errorf("selfext: validate-bin probe: exec %q: %w", bin, runErr)
	}
	if !strings.Contains(out.String(), validateBinProbeMarker) {
		return fmt.Errorf(
			"selfext: resolved validate-bin %q does not look like the mallcop Go CLI "+
				"(expected %q in its response to an unrecognized subcommand); got: %s — "+
				"pass -validate-bin to point explicitly at the mallcop Go binary this build validates against",
			bin, validateBinProbeMarker, truncate(out.String(), 300))
	}
	return nil
}

// gateEnvAllowlist is the exact set of env var keys the trusted gate
// subprocess (`mallcop validate-proposal`) is permitted to inherit. Only vars
// in this set (case-sensitive, no prefix matching) survive into the
// subprocess environment — everything else in the parent process's env
// (Forge admin key, 1Password session, AWS_*, GitHub tokens, CF_HOME, ...) is
// dropped by construction, not by name. It is deliberately the standard Go
// toolchain env (the gate builds the proposal trees it evaluates) plus PATH
// and locale/temp-dir plumbing — nothing credential-shaped.
var gateEnvAllowlist = map[string]bool{
	"PATH":         true,
	"HOME":         true,
	"TMPDIR":       true,
	"TMP":          true,
	"TEMP":         true,
	"LANG":         true,
	"LC_ALL":       true,
	"GOCACHE":      true,
	"GOMODCACHE":   true,
	"GOPATH":       true,
	"GOROOT":       true,
	"GOFLAGS":      true,
	"GOPROXY":      true,
	"GOSUMDB":      true,
	"GOPRIVATE":    true,
	"GONOSUMCHECK": true,
	"GOTOOLCHAIN":  true,
}

// gateAllowlistedEnv returns the subset of os.Environ() whose keys are in
// gateEnvAllowlist. See runValidateProposal's doc comment for why this is an
// allowlist rather than a denylist.
func gateAllowlistedEnv() []string {
	src := os.Environ()
	out := make([]string, 0, len(gateEnvAllowlist))
	for _, kv := range src {
		key, _, _ := strings.Cut(kv, "=")
		if gateEnvAllowlist[key] {
			out = append(out, kv)
		}
	}
	return out
}

// truncate caps s at n bytes for error details.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + " …(truncated)"
}
