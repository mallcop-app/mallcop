// validate.go — the FREE-TIER unified validate_proposal gate (K4, rd
// mallcoppro-bae).
//
// ValidateProposal runs a self-extension proposal (base..head in a git repo)
// through the ORDERED free stages, SHORT-CIRCUITING on the first failing
// stage (a failed stage is the last entry in GateResult.Stages — later stages
// never run):
//
//  1. guard       — the K3 static invariant guard (diff-level widen-only
//     rules over the base..head name-status + blobs).
//  2. structural  — materialize the head tree as a DETACHED git worktree,
//     `go build ./...` it, and run the K2a authored-detector import
//     allow-list (core/lint.CheckAuthoredDetectorTree) over it.
//  3. exam-detect — materialize the base tree too, build each tree's OWN
//     binary, and exec `<tree>/mallcop exam-detect --json` per tree
//     (SUBPROCESS ISOLATION: detector tuning applies via package vars in
//     core/detect, so an in-process double-run would contaminate the second
//     report; two hermetic binaries cannot). The two reports must satisfy the
//     MONOTONIC-WIDEN contract:
//     (a) NO REGRESSION — every labeled row passing at base still passes;
//     (b) COVERAGE +1  — at least one labeled must_fire row that was failing
//     (or absent) at base passes at head, unless
//     Options.AllowNoCoverageGain waives it (plumbing diffs);
//     (c) NO NEW FIRINGS — for every scenario present in both reports,
//     emittedFamilies(head) ⊆ emittedFamilies(base) ∪ declaredTargets,
//     where declaredTargets are the must_fire families of rows newly
//     labeled / newly passing in this proposal.
//
// $0 BY CONSTRUCTION: nothing on this path constructs an inference client or
// talks to the network — the free tier is git + the Go toolchain + the repo's
// own OFFLINE exam binary (exam-detect is LLM-free by design). This package
// deliberately does not import core/inference, core/agent, core/eval, or any
// network package; validate_test.go enforces that with a parsed-imports
// assertion. The METERED tier (committee re-vote, the $25 cap) lives on the
// other side of a process boundary in mallcop-pro, which consumes the
// JSON-serialized GateResult this package emits — GateResult is versioned
// (SchemaVersion) and carries everything the pro side needs (SHAs, per-stage
// evidence and findings, coverage delta, new firings).
package selfgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mallcop-app/mallcop/core/lint"
)

// GateSchemaVersion is the GateResult wire-format version. Bump it on any
// field change so the mallcop-pro consumer can reject reports it does not
// understand instead of misreading them.
const GateSchemaVersion = 1

// TierFree identifies the $0 gate tier this package implements.
const TierFree = "free"

// Stage names, in run order.
const (
	StageGuard      = "guard"
	StageStructural = "structural"
	StageExamDetect = "exam-detect"
)

// Stable rule identifiers for stage-2/3 findings (stage 1 uses the K3
// Rule* constants in guard.go).
const (
	// RuleStructuralBuild — `go build ./...` failed in the head tree.
	RuleStructuralBuild = "structural-build"
	// RuleStructuralAllowlist — an authored-detector import allow-list
	// violation (or an unverifiable authored tree — fail closed).
	RuleStructuralAllowlist = "structural-import-allowlist"
	// RuleExamExecution — the head tree's own exam-detect run failed
	// operationally (e.g. the proposal drifted the corpus off its pin).
	RuleExamExecution = "exam-detect-execution"
	// RuleExamRegression — a labeled row passing at base fails (or vanished)
	// at head.
	RuleExamRegression = "exam-detect-regression"
	// RuleExamNoCoverageGain — the proposal closes no detection gap and
	// Options.AllowNoCoverageGain was not set.
	RuleExamNoCoverageGain = "exam-detect-no-coverage-gain"
	// RuleExamNewFiring — a detector family fired at head on a scenario where
	// it did not fire at base and is not a declared target of the proposal.
	RuleExamNewFiring = "exam-detect-new-firing"
)

// Options tunes a ValidateProposal run.
type Options struct {
	// GuardOnly pins the run to stage 1 (the static invariant guard),
	// regardless of what later stages exist.
	GuardOnly bool
	// AllowNoCoverageGain waives the COVERAGE-+1 requirement for
	// plumbing/no-op diffs that legitimately close no detection gap. The
	// no-regression and no-new-firings requirements are NEVER waivable.
	AllowNoCoverageGain bool
}

// StageResult is one gate stage's outcome.
type StageResult struct {
	Name     string         `json:"name"`
	Passed   bool           `json:"passed"`
	Evidence string         `json:"evidence"`
	Findings []GuardFinding `json:"findings"`
}

// GateResult is the JSON-serializable free-tier verdict. Stages contains ONLY
// the stages that actually ran: a rejected proposal's failing stage is the
// last entry, and the absence of later entries is the short-circuit evidence.
type GateResult struct {
	SchemaVersion int           `json:"schema_version"`
	Tier          string        `json:"tier"`
	Passed        bool          `json:"passed"`
	BaseSHA       string        `json:"base_sha"`
	HeadSHA       string        `json:"head_sha"`
	Stages        []StageResult `json:"stages"`
	// CoveragePlus is the number of labeled must_fire rows that pass at head
	// while failing (or not existing) at base — the detection gaps this
	// proposal closes.
	CoveragePlus int `json:"coverage_plus"`
	// NewFirings lists undeclared new emissions ("<scenario_id>: <family>")
	// found by the no-new-firings check. Empty on a passing run.
	NewFirings []string `json:"new_firings"`
}

func (r *GateResult) addStage(name, evidence string, findings []GuardFinding) {
	passed := len(findings) == 0
	if findings == nil {
		findings = []GuardFinding{} // JSON: [] not null
	}
	r.Stages = append(r.Stages, StageResult{Name: name, Passed: passed, Evidence: evidence, Findings: findings})
	r.Passed = r.Passed && passed
}

// ValidateProposal runs the ordered free-tier stages over baseRef..headRef in
// the git repository containing repoRoot. It returns a GateResult describing
// every stage that ran (short-circuiting on the first failure) and an error
// only for OPERATIONAL failures (unresolvable refs, git/go unavailable, a
// base tree that does not build — a broken trunk is not a property of the
// proposal). A rejected proposal is Passed=false with findings, never an
// error.
func ValidateProposal(repoRoot, baseRef, headRef string, opts Options) (GateResult, error) {
	res := GateResult{
		SchemaVersion: GateSchemaVersion,
		Tier:          TierFree,
		Passed:        true,
		NewFirings:    []string{},
	}

	baseSHA, err := resolveCommit(repoRoot, baseRef)
	if err != nil {
		return GateResult{}, err
	}
	headSHA, err := resolveCommit(repoRoot, headRef)
	if err != nil {
		return GateResult{}, err
	}
	res.BaseSHA, res.HeadSHA = baseSHA, headSHA

	// ---- stage 1: the static invariant guard (K3) ---------------------------
	guardFindings, err := Guard(repoRoot, baseSHA, headSHA)
	if err != nil {
		return GateResult{}, err
	}
	res.addStage(StageGuard,
		fmt.Sprintf("static invariant guard over %.12s..%.12s: %d finding(s)", baseSHA, headSHA, len(guardFindings)),
		guardFindings)
	if !res.Passed || opts.GuardOnly {
		return res, nil
	}

	// ---- worktree scratch space ---------------------------------------------
	scratch, err := os.MkdirTemp("", "mallcop-selfgate-")
	if err != nil {
		return GateResult{}, fmt.Errorf("selfgate: scratch dir: %w", err)
	}
	defer os.RemoveAll(scratch)

	headTree := filepath.Join(scratch, "head")
	if err := addWorktree(repoRoot, headTree, headSHA); err != nil {
		return GateResult{}, err
	}
	defer removeWorktree(repoRoot, headTree)

	// ---- stage 2: structural (head builds + import allow-list) --------------
	structFindings, structEvidence, err := structuralStage(headTree)
	if err != nil {
		return GateResult{}, err
	}
	res.addStage(StageStructural, structEvidence, structFindings)
	if !res.Passed {
		return res, nil
	}

	// ---- stage 3: exam-detect diff (monotonic-widen contract) ---------------
	baseTree := filepath.Join(scratch, "base")
	if err := addWorktree(repoRoot, baseTree, baseSHA); err != nil {
		return GateResult{}, err
	}
	defer removeWorktree(repoRoot, baseTree)

	baseReport, _, baseErr := runTreeExam(baseTree)
	if baseErr != nil {
		// The base ref is the accepted trunk: if ITS OWN exam binary cannot
		// produce a report, the gate has no ground truth to diff against —
		// operational, not a property of the proposal.
		return GateResult{}, fmt.Errorf("selfgate: base tree %.12s exam-detect: %w", baseSHA, baseErr)
	}

	var examFindings []GuardFinding
	headReport, headDetail, headErr := runTreeExam(headTree)
	if headErr != nil {
		// The HEAD tree failing to produce a report is a proposal defect
		// (e.g. scenario added without a corpus.pin regen drifts the corpus
		// off its pin and exam-detect hard-fails). Fail closed as a finding.
		examFindings = append(examFindings, GuardFinding{
			Path:   StageExamDetect,
			Rule:   RuleExamExecution,
			Detail: fmt.Sprintf("head tree exam-detect produced no report (%v) — fail closed. %s", headErr, headDetail),
		})
		res.addStage(StageExamDetect,
			fmt.Sprintf("base: %d labeled (%d passed); head: no report", baseReport.Totals.Labeled, baseReport.Totals.Passed),
			examFindings)
		return res, nil
	}

	diffFindings, coveragePlus, newFirings := diffExamReports(baseReport, headReport, opts.AllowNoCoverageGain)
	res.CoveragePlus = coveragePlus
	if len(newFirings) > 0 {
		res.NewFirings = newFirings
	}
	evidence := fmt.Sprintf("base: %d labeled (%d passed); head: %d labeled (%d passed); coverage +%d; %d undeclared new firing(s)",
		baseReport.Totals.Labeled, baseReport.Totals.Passed,
		headReport.Totals.Labeled, headReport.Totals.Passed,
		coveragePlus, len(newFirings))
	if opts.AllowNoCoverageGain {
		evidence += "; coverage-gain requirement waived by options"
	}
	res.addStage(StageExamDetect, evidence, diffFindings)
	return res, nil
}

// ---- stage 2: structural -----------------------------------------------------

// structuralStage builds the head tree and runs the authored-detector import
// allow-list over it. Findings are proposal defects; the error return is
// operational only.
func structuralStage(headTree string) ([]GuardFinding, string, error) {
	var findings []GuardFinding

	// `go build ./...` — the proposal must compile as a whole tree.
	buildOK := true
	stdout, stderr, code, err := runTool(headTree, nil, "go", "build", "./...")
	if err != nil {
		return nil, "", fmt.Errorf("selfgate: running `go build` in the head tree: %w", err)
	}
	if code != 0 {
		buildOK = false
		findings = append(findings, GuardFinding{
			Path:   "./...",
			Rule:   RuleStructuralBuild,
			Detail: fmt.Sprintf("`go build ./...` failed in the head tree (exit %d): %s", code, truncate(stderr+stdout, 1500)),
		})
	}

	// K2a authored-detector import allow-list over the head tree.
	modulePath, err := lint.ModulePath(headTree)
	if err != nil {
		// go.mod is a protected file the proposal cannot change; an unreadable
		// module identity means the repo itself is broken — operational.
		return nil, "", fmt.Errorf("selfgate: head tree module path: %w", err)
	}
	allowlistNote := "authored-detector import allow-list clean"
	violations, err := lint.CheckAuthoredDetectorTree(headTree, modulePath, "detectors")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// No authored tree at head — trivially green.
		allowlistNote = "no authored detector tree (trivially clean)"
	case err != nil:
		// An authored tree that cannot be verified (e.g. an unparseable
		// authored file) is a proposal defect — fail closed.
		findings = append(findings, GuardFinding{
			Path:   "detectors",
			Rule:   RuleStructuralAllowlist,
			Detail: fmt.Sprintf("authored detector tree cannot be verified (%v) — fail closed", err),
		})
		allowlistNote = "authored-detector tree unverifiable"
	default:
		for _, v := range violations {
			detail := fmt.Sprintf("illegal import %q: %s", v.Import, v.Reason)
			if len(v.Via) > 0 {
				detail += fmt.Sprintf(" (via %s)", strings.Join(v.Via, " -> "))
			}
			findings = append(findings, GuardFinding{Path: v.File, Rule: RuleStructuralAllowlist, Detail: detail})
		}
		if len(violations) > 0 {
			allowlistNote = fmt.Sprintf("%d authored-detector import violation(s)", len(violations))
		}
	}

	buildNote := "`go build ./...` OK in head tree"
	if !buildOK {
		buildNote = "`go build ./...` FAILED in head tree"
	}
	return findings, buildNote + "; " + allowlistNote, nil
}

// ---- stage 3: exam-detect ------------------------------------------------------

// examRow / examReport mirror the JSON `mallcop exam-detect --json` emits
// (core/eval.ExamDetectReport). Decoded locally so this package never imports
// core/eval — the exam binary is a subprocess and JSON is the seam, exactly
// like the mallcop-pro process boundary above this one.
type examRow struct {
	ScenarioID  string   `json:"scenario_id"`
	MustFire    []string `json:"must_fire"`
	MustNotFire []string `json:"must_not_fire"`
	Emitted     []string `json:"emitted"`
	Pass        bool     `json:"pass"`
}

type examReport struct {
	Rows   []examRow `json:"rows"`
	Totals struct {
		Labeled   int `json:"labeled"`
		Unlabeled int `json:"unlabeled"`
		Passed    int `json:"passed"`
		Failed    int `json:"failed"`
	} `json:"totals"`
}

// runTreeExam builds tree's OWN mallcop binary and execs its exam-detect over
// tree's OWN corpus (MALLCOP_REPO_ROOT pins the root; --tuning is passed iff
// the tree carries detectors/tuning.yaml). Exit 0 (all green) and exit 1
// (gaps present) both yield a report; anything else is an error, with detail
// carrying the subprocess output for the caller's finding/error message.
func runTreeExam(tree string) (examReport, string, error) {
	bin := filepath.Join(tree, "mallcop")
	stdout, stderr, code, err := runTool(tree, nil, "go", "build", "-o", bin, "./cmd/mallcop")
	if err != nil {
		return examReport{}, "", fmt.Errorf("running `go build` for the tree binary: %w", err)
	}
	if code != 0 {
		return examReport{}, truncate(stderr+stdout, 1500), fmt.Errorf("building the tree's own binary failed (exit %d)", code)
	}

	args := []string{"exam-detect", "--json"}
	tuning := filepath.Join(tree, "detectors", "tuning.yaml")
	if _, err := os.Stat(tuning); err == nil {
		args = append(args, "--tuning", tuning)
	}
	stdout, stderr, code, err = runTool(tree, []string{"MALLCOP_REPO_ROOT=" + tree}, bin, args...)
	if err != nil {
		return examReport{}, "", fmt.Errorf("exec %s: %w", bin, err)
	}
	if code != 0 && code != 1 {
		// exit 1 = labeled gaps present (a report was still produced);
		// anything else (2 = corpus integrity mismatch, ...) is a failure.
		return examReport{}, truncate(stderr, 1500), fmt.Errorf("exam-detect exit %d", code)
	}
	var report examReport
	if jerr := json.Unmarshal([]byte(stdout), &report); jerr != nil {
		return examReport{}, truncate(stdout+stderr, 1500), fmt.Errorf("exam-detect report unparseable: %w", jerr)
	}
	return report, "", nil
}

// diffExamReports enforces the monotonic-widen contract between the base and
// head exam reports. ALL violated requirements are reported (the stage itself
// is what short-circuits, not the rules within it).
func diffExamReports(base, head examReport, allowNoCoverageGain bool) (findings []GuardFinding, coveragePlus int, newFirings []string) {
	baseByID := make(map[string]examRow, len(base.Rows))
	for _, r := range base.Rows {
		baseByID[r.ScenarioID] = r
	}
	headByID := make(map[string]examRow, len(head.Rows))
	for _, r := range head.Rows {
		headByID[r.ScenarioID] = r
	}

	// declaredTargets: the must_fire families of rows newly labeled (absent at
	// base) or newly passing (failing at base) — the detection the proposal
	// EXPLICITLY set out to add. Only rows that actually PASS at head declare
	// targets: an unproven label excuses nothing (fail closed). This is also
	// the COVERAGE-+1 count.
	declared := map[string]bool{}
	for _, h := range head.Rows {
		if !h.Pass || len(h.MustFire) == 0 {
			continue
		}
		b, inBase := baseByID[h.ScenarioID]
		if !inBase || !b.Pass {
			coveragePlus++
			for _, fam := range h.MustFire {
				declared[normalizeFamily(fam)] = true
			}
		}
	}

	// (a) NO REGRESSION: every labeled row passing at base still passes at
	// head. A passing base row MISSING from the head report is equally a
	// regression (fail closed) — layers above should make it unreachable
	// (scenario files are frozen), but the contract does not depend on them.
	for _, b := range base.Rows {
		if !b.Pass {
			continue
		}
		h, inHead := headByID[b.ScenarioID]
		switch {
		case !inHead:
			findings = append(findings, GuardFinding{
				Path:   b.ScenarioID,
				Rule:   RuleExamRegression,
				Detail: "labeled row passing at base is missing from the head report — fail closed",
			})
		case !h.Pass:
			findings = append(findings, GuardFinding{
				Path: b.ScenarioID,
				Rule: RuleExamRegression,
				Detail: fmt.Sprintf("labeled row passing at base FAILS at head (must_fire=%v must_not_fire=%v; emitted base=%v head=%v)",
					h.MustFire, h.MustNotFire, b.Emitted, h.Emitted),
			})
		}
	}

	// (b) COVERAGE +1: the proposal must close at least one labeled detection
	// gap, unless explicitly waived for plumbing/no-op diffs.
	if coveragePlus == 0 && !allowNoCoverageGain {
		findings = append(findings, GuardFinding{
			Path:   StageExamDetect,
			Rule:   RuleExamNoCoverageGain,
			Detail: "no labeled must_fire row that was failing (or absent) at base passes at head — a widen proposal must close a detection gap (waivable via AllowNoCoverageGain for plumbing diffs)",
		})
	}

	// (c) NO NEW FIRINGS: for every scenario present in both reports, head may
	// only emit families base emitted plus the proposal's declared targets —
	// the monotonic-widen contract. An undeclared new firing is scope creep
	// even when no label bans it.
	for _, h := range head.Rows {
		b, inBase := baseByID[h.ScenarioID]
		if !inBase {
			continue
		}
		baseFams := map[string]bool{}
		for _, e := range b.Emitted {
			baseFams[normalizeFamily(e)] = true
		}
		seen := map[string]bool{}
		for _, e := range h.Emitted {
			fam := normalizeFamily(e)
			if seen[fam] || baseFams[fam] || declared[fam] {
				seen[fam] = true
				continue
			}
			seen[fam] = true
			findings = append(findings, GuardFinding{
				Path: h.ScenarioID,
				Rule: RuleExamNewFiring,
				Detail: fmt.Sprintf("family %q fires at head but not at base and is not a declared target of this proposal (declared: %v) — widens must be monotonic and intentional",
					fam, sortedKeys(declared)),
			})
			newFirings = append(newFirings, h.ScenarioID+": "+fam)
		}
	}

	return findings, coveragePlus, newFirings
}

// normalizeFamily canonicalizes a family token the same way the exam grader
// does (lowercase, trimmed).
func normalizeFamily(tok string) string {
	return strings.ToLower(strings.TrimSpace(tok))
}

// ---- subprocess plumbing -------------------------------------------------------

// resolveCommit resolves ref to a full commit SHA in the repo at repoRoot.
func resolveCommit(repoRoot, ref string) (string, error) {
	out, err := runGit(repoRoot, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("selfgate: resolving %q: %v: %s", ref, err, out)
	}
	return strings.TrimSpace(out), nil
}

// addWorktree materializes sha as a detached git worktree at dir.
func addWorktree(repoRoot, dir, sha string) error {
	out, err := runGit(repoRoot, "worktree", "add", "--detach", dir, sha)
	if err != nil {
		return fmt.Errorf("selfgate: git worktree add %s @ %.12s: %v: %s", dir, sha, err, out)
	}
	return nil
}

// removeWorktree tears the worktree down (--force: the tree holds untracked
// build artifacts). Best-effort — the scratch dir is removed regardless, and
// a stale registration is pruned.
func removeWorktree(repoRoot, dir string) {
	if _, err := runGit(repoRoot, "worktree", "remove", "--force", dir); err != nil {
		_, _ = runGit(repoRoot, "worktree", "prune")
	}
}

// runTool executes a subprocess with Dir=dir and the parent environment plus
// extraEnv (later entries win), capturing stdout/stderr separately. The error
// return is for SPAWN failures only; a started process that exits non-zero
// reports through code. GOWORK=off keeps a stray workspace file above the
// scratch dir from leaking into tree builds.
func runTool(dir string, extraEnv []string, name string, args ...string) (stdout, stderr string, code int, err error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOWORK=off"), extraEnv...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	runErr := cmd.Run()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return outBuf.String(), errBuf.String(), exitErr.ExitCode(), nil
		}
		return outBuf.String(), errBuf.String(), -1, runErr
	}
	return outBuf.String(), errBuf.String(), 0, nil
}

// truncate caps s at n bytes for finding/error details.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + " …(truncated)"
}
