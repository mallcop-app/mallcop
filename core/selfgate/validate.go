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
// CUSTOMER-TREE EXAM MODE (mallcoppro-cc3e): ValidateProposal above grades an
// authored detector that lives IN this repo's own core/detect/authored/ tree,
// compiled straight into the tree's own cmd/mallcop binary. RunCustomerTreeExam
// (customerexam.go) is the sibling entry point for grading a detector that does
// NOT — a customer's own detector source, anywhere on disk, built to a wasip1
// .wasm module and graded through the exact same subprocess/wazero path a real
// deployment uses. See customerexam.go's doc comment for the ground-truth
// invariant this preserves.
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/lint"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// GateSchemaVersion is the GateResult wire-format version. Bump it on any
// field change so the mallcop-pro consumer can reject reports it does not
// understand instead of misreading them.
const GateSchemaVersion = 1

// TierFree identifies the $0 gate tier this package implements.
const TierFree = "free"

// authoredDetectorRel is the repo-relative root of the AUTHORED detector tree,
// the own-package location the self-extension loop writes new detectors into
// (K7 L1: core/detect/authored/<name>/). Both the K2a import allow-list and the
// K7 L3 shape AST gate police exactly this tree, and the invariant guard opens
// its additive lane here — so they must all name the same root.
const authoredDetectorRel = "core/detect/authored"

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
	// RuleStructuralVet — `go vet ./...` failed in the head tree. `go build
	// ./...` alone SKIPS _test.go files; a sidecar's authored main_test.go can
	// fail to even compile (an unused import, a struct-value call written as a
	// function call, ...) and still sail through structuralStage undetected
	// (mallcoppro-f95, round 5's non-compiling detectors/forcepushprotected
	// branch/main_test.go). `go vet` compiles every _test.go in the tree as
	// part of its analysis, so a non-compiling test file fails HERE, closed —
	// before the customer detector's quality is ever graded.
	RuleStructuralVet = "structural-vet"
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
	// it did not fire at base and is not a declared target of the proposal FOR
	// THAT SCENARIO.
	RuleExamNewFiring = "exam-detect-new-firing"
	// RuleExamNewScenarioFails — a labeled scenario this proposal ADDS (present
	// at head, absent at base) does not pass at head. The base-row regression
	// check cannot see it, so without this a newly-added benign twin the rule
	// wrongly fires on (or a must_fire the new detector misses) would fail
	// silently. An added label the head does not satisfy is a hard rejection.
	RuleExamNewScenarioFails = "exam-detect-new-scenario-fails"
	// RuleExamMissingMustFire — a proposal ADDED an authored detector package but
	// no PASSING must_fire scenario in the head corpus labels its family: the
	// detector ships no proof it detects what it claims to. Fires only when the
	// proposal adds an authored detector.
	RuleExamMissingMustFire = "exam-detect-missing-must-fire"
	// RuleExamMissingBenignTwin — a proposal ADDED an authored detector package
	// but no PASSING must_not_fire BENIGN TWIN in the head corpus labels its
	// family: the detector ships no proof it correctly stays silent on a benign
	// look-alike. This is the consensus-not-rules false-positive floor — a new
	// detector must demonstrate BOTH a true-positive (must_fire) and a
	// true-negative (must_not_fire benign twin) before it merges. Fires only
	// when the proposal adds an authored detector.
	RuleExamMissingBenignTwin = "exam-detect-missing-benign-twin"
	// RuleCustomerExamFail — CUSTOMER-TREE MODE ONLY (Options.ExamRepo set): a
	// labeled scenario in the reference tree's corpus fails its must_fire /
	// must_not_fire contract with this customer detector loaded (including a
	// detector that fires on its own benign twin — the false-positive floor,
	// same substance as RuleExamMissingBenignTwin but for a detector graded in
	// isolation against a fixed reference corpus rather than diffed against a
	// sibling base report). ALSO fires (mallcoppro-f95 round 2) when a
	// detector's own must_fire + must_not_fire pair both pass individually but
	// the benign twin is not a MEASURED MINIMAL MUTATION of the must-fire
	// scenario (checkMinimalMutationCoverage) — see that function's doc for the
	// veracity-reproduced bypass this closes.
	RuleCustomerExamFail = "customer-tree-exam-fail"
	// RuleCustomerExamVacuous — CUSTOMER-TREE MODE ONLY: RunCustomerTreeExam
	// graded zero labeled scenarios from the reference tree's corpus — a
	// vacuous grade proves nothing about the detector, fail closed.
	RuleCustomerExamVacuous = "customer-tree-exam-vacuous"
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
	// ExamRepo, when set, is the path to a REFERENCE mallcop tree (one that
	// has its own cmd/mallcop and its own pinned exams/scenarios corpus) used
	// to grade a CUSTOMER-SHAPED proposal tree — one with no cmd/mallcop of
	// its own (the THIN-EMBED shape: go.mod pins mallcop, detectors/<name>/
	// carries the authored detector source). When set, stage 3 routes through
	// RunCustomerTreeExam(ExamRepo, detectorDir) for every detectors/<name>/
	// directory found in the head tree, INSTEAD OF building and execing the
	// head tree's own (nonexistent) cmd/mallcop binary. Guard and structural
	// (stages 1-2) are UNCHANGED by this option — they run identically either
	// way. ExamRepo is a caller-supplied path (the engine/operator's own
	// pinned mallcop checkout): it is NEVER derived from the untrusted
	// proposal tree's own contents (core/selfgate is security-critical — see
	// the package doc's $0-purity note; the reference tree is a trust
	// boundary the CALLER owns, not something the proposal can point at
	// itself). When ExamRepo == "" (the default), behavior is EXACTLY the
	// prior in-tree lane, byte-for-byte — this option is purely additive.
	ExamRepo string
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
	// customerTreeMode is opts.ExamRepo != "" — the SAME trusted-caller signal
	// stage 3 uses (see the Options.ExamRepo doc above), threaded here too
	// (mallcoppro-97b orchestrator ruling) so a customer-shaped proposal's
	// legitimate detectors/<name>/main.go sidecar Add routes through the
	// sidecar-shape AST gate (sidecarshape.go) instead of the blanket
	// RuleCodeFrozen deny. It is never derived from the head/base tree
	// contents — only from this caller's own opts, exactly like ExamRepo.
	guardFindings, err := Guard(repoRoot, baseSHA, headSHA, opts.ExamRepo != "")
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
	// customerTreeMode reuses the SAME opts.ExamRepo != "" signal stage 3 uses
	// (and stage 1's Guard call above) — never derived from tree contents.
	structFindings, structEvidence, err := structuralStage(headTree, opts.ExamRepo != "")
	if err != nil {
		return GateResult{}, err
	}
	res.addStage(StageStructural, structEvidence, structFindings)
	if !res.Passed {
		return res, nil
	}

	// ---- stage 3: exam-detect ------------------------------------------------
	// CUSTOMER-TREE MODE (mallcoppro-97b): a caller-supplied reference tree
	// routes stage 3 through RunCustomerTreeExam instead of building the head
	// tree's own (possibly nonexistent) cmd/mallcop binary. This is the ONLY
	// place Options.ExamRepo affects the run — guard and structural above are
	// identical in both modes.
	if opts.ExamRepo != "" {
		examFindings, examEvidence, err := customerTreeExamStage(opts.ExamRepo, headTree)
		if err != nil {
			return GateResult{}, err
		}
		res.addStage(StageExamDetect, examEvidence, examFindings)
		return res, nil
	}

	// DEFAULT (in-tree) MODE: the head tree must build its own cmd/mallcop.
	// Fail loudly and NAME THE FLAG when it can't, rather than surfacing the
	// raw `go build ./cmd/mallcop: no such file or directory` failure a
	// customer-shaped tree (no cmd/mallcop by design) would otherwise produce
	// deep inside runTreeExam — this is the empirically-proven gap (rd 7ee7)
	// this option closes.
	if !hasCmdMallcop(headTree) {
		return GateResult{}, fmt.Errorf(
			"selfgate: head tree %.12s has no cmd/mallcop — this looks like a customer-shaped (THIN-EMBED) tree, not a full mallcop checkout; pass Options.ExamRepo (mallcop validate-proposal --exam-repo <reference-mallcop-tree>) to grade it via RunCustomerTreeExam instead",
			headSHA)
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

	// MANDATORY BENIGN TWIN (L4c). If this proposal ADDED a detector in the
	// AUTHORED lane (core/detect/authored/: head authored names \ base authored
	// names), the head corpus must prove BOTH a passing must_fire scenario AND a
	// passing must_not_fire benign twin for its family. Pure data/tuning widens
	// add no family, so this stays a no-op for them. baseTree / headTree are the
	// same worktrees the exam ran over.
	addedFamilies, aerr := addedAuthoredFamilies(baseTree, headTree)
	if aerr != nil {
		return GateResult{}, fmt.Errorf("selfgate: collecting added authored detectors: %w", aerr)
	}
	diffFindings = append(diffFindings, checkAuthoredBenignTwins(addedFamilies, headReport)...)

	evidence := fmt.Sprintf("base: %d labeled (%d passed); head: %d labeled (%d passed); coverage +%d; %d undeclared new firing(s)",
		baseReport.Totals.Labeled, baseReport.Totals.Passed,
		headReport.Totals.Labeled, headReport.Totals.Passed,
		coveragePlus, len(newFirings))
	if len(addedFamilies) > 0 {
		evidence += fmt.Sprintf("; %d added authored detector(s) benign-twin checked: %v", len(addedFamilies), addedFamilies)
	}
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
//
// customerTreeMode (mallcoppro-a08) mirrors the GOFLAGS=-mod=mod convention
// buildAndRegisterSourceSidecar already uses for stage 3 (see the doc comment
// on that function, cli/sidecars.go) and cli/deployrepo.go's generated
// scan.yml CI applies for the same reason: a customer-shaped (THIN-EMBED)
// tree's go.mod pins this module, but nothing may have imported the framework
// packages (pkg/event, pkg/finding, pkg/baseline, pkg/detectorhost, ...)
// before the authored sidecar under test did — go.sum can legitimately be
// missing entries for them, and plain `go build` hard-fails on that
// (`missing go.sum entry`) before this proposal's detector quality is ever
// graded. -mod=mod lets `go build` compute the missing sums itself (from the
// local module cache, else GOPROXY) instead of failing closed on a gap that
// is not a property of the proposal.
//
// In the DEFAULT (in-tree) lane — validating mallcop's own repo, including
// for contribute-back — go.sum is expected to already be complete, so this
// stays OFF (strict -mod=readonly, the go default): -mod=mod there would
// silently compute and mask real dependency drift (or a supply-chain
// manipulation) in the OSS repo's own build, which is exactly the invariant
// this stage exists to enforce. GOFLAGS is scoped to this one `go build`
// invocation's env via runTool's extraEnv (a copy of os.Environ(), never the
// process env) — it is never set process-wide and never applied in-tree.
func structuralStage(headTree string, customerTreeMode bool) ([]GuardFinding, string, error) {
	var findings []GuardFinding

	// `go build ./...` — the proposal must compile as a whole tree.
	var buildEnv []string
	if customerTreeMode {
		buildEnv = []string{"GOFLAGS=-mod=mod"}
	}
	buildOK := true
	stdout, stderr, code, err := runTool(headTree, buildEnv, "go", "build", "./...")
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

	// `go vet ./...` — DEFENSE-IN-DEPTH beside `go build ./...` above:
	// `go build` never compiles _test.go files, so a sidecar's authored
	// main_test.go that does not even COMPILE (mallcoppro-f95: round 5's
	// forcepushprotectedbranch/main_test.go called a struct value as a
	// function and carried an unused import) sails through the build check
	// untouched. `go vet` DOES compile every _test.go in the tree as part of
	// its own analysis pass, so a non-compiling test file fails here, fail
	// closed, before the detector's efficacy is ever graded. Same GOFLAGS
	// convention as the build above (customer-tree mode only).
	//
	// GUARD: `go vet ./...` (unlike `go build ./...`) exits 1 with "no
	// packages to vet" on a tree with ZERO .go files anywhere (a bare
	// THIN-EMBED scaffold before any detector is authored) — `go build`
	// silently no-ops (exit 0) on the exact same tree. Skip the vet call
	// entirely when the tree has no .go files at all, so an empty/no-op
	// proposal is trivially clean under vet exactly as it already is under
	// build, instead of failing on Go's own "nothing here" plumbing message.
	vetOK := true
	if treeHasGoFiles(headTree) {
		vstdout, vstderr, vcode, verr := runTool(headTree, buildEnv, "go", "vet", "./...")
		if verr != nil {
			return nil, "", fmt.Errorf("selfgate: running `go vet` in the head tree: %w", verr)
		}
		if vcode != 0 {
			vetOK = false
			findings = append(findings, GuardFinding{
				Path:   "./...",
				Rule:   RuleStructuralVet,
				Detail: fmt.Sprintf("`go vet ./...` failed in the head tree (exit %d): %s", vcode, truncate(vstderr+vstdout, 1500)),
			})
		}
	}

	// K2a authored-detector import allow-list over the head tree.
	modulePath, err := lint.ModulePath(headTree)
	if err != nil {
		// go.mod is a protected file the proposal cannot change; an unreadable
		// module identity means the repo itself is broken — operational.
		return nil, "", fmt.Errorf("selfgate: head tree module path: %w", err)
	}
	allowlistNote := "authored-detector import allow-list clean"
	violations, err := lint.CheckAuthoredDetectorTree(headTree, modulePath, authoredDetectorRel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// No authored tree at head — trivially green.
		allowlistNote = "no authored detector tree (trivially clean)"
	case err != nil:
		// An authored tree that cannot be verified (e.g. an unparseable
		// authored file) is a proposal defect — fail closed.
		findings = append(findings, GuardFinding{
			Path:   authoredDetectorRel,
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

	// K7 L3 additive-shape AST gate over the same authored tree the allow-list
	// polices. Where the allow-list constrains what authored code may LINK,
	// this constrains its SHAPE (pure, self-registering leaf; no build tags,
	// cgo, compiler directives, non-local writes, non-literal Names, or
	// duplicate Names). An unverifiable tree fails closed.
	shapeNote := "authored-detector shape gate clean"
	authoredRoot := filepath.Join(headTree, filepath.FromSlash(authoredDetectorRel))
	shapeViolations, serr := CheckAuthoredDetectorTreeShape(authoredRoot)
	switch {
	case errors.Is(serr, fs.ErrNotExist):
		shapeNote = "no authored detector tree (shape gate trivially clean)"
	case serr != nil:
		findings = append(findings, GuardFinding{
			Path:   authoredDetectorRel,
			Rule:   RuleAuthoredShape,
			Detail: fmt.Sprintf("authored detector tree cannot be shape-verified (%v) — fail closed", serr),
		})
		shapeNote = "authored-detector shape gate unverifiable"
	default:
		for _, v := range shapeViolations {
			findings = append(findings, GuardFinding{
				Path:   repoRelativeHead(headTree, v.File),
				Rule:   RuleAuthoredShape,
				Detail: v.Rule + ": " + v.Detail,
			})
		}
		if len(shapeViolations) > 0 {
			shapeNote = fmt.Sprintf("%d authored-detector shape violation(s)", len(shapeViolations))
		}
	}

	buildNote := "`go build ./...` OK in head tree"
	if !buildOK {
		buildNote = "`go build ./...` FAILED in head tree"
	}
	vetNote := "`go vet ./...` OK in head tree"
	if !vetOK {
		vetNote = "`go vet ./...` FAILED in head tree"
	}
	return findings, buildNote + "; " + vetNote + "; " + allowlistNote + "; " + shapeNote, nil
}

// repoRelativeHead makes a shape-violation file path (which is absolute, rooted
// in the head worktree) repo-relative and slash-separated, so GateResult
// findings carry stable paths the mallcop-pro consumer can render.
func repoRelativeHead(headTree, file string) string {
	rel, err := filepath.Rel(headTree, file)
	if err != nil {
		return filepath.ToSlash(file)
	}
	return filepath.ToSlash(rel)
}

// ---- stage 3: exam-detect (customer-tree mode) -------------------------------

// hasCmdMallcop reports whether tree has its own cmd/mallcop package
// directory — the discriminator between a full mallcop checkout (the
// in-tree lane builds `<tree>/mallcop` from it) and a customer-shaped
// THIN-EMBED tree (go.mod pins mallcop; no cmd/mallcop of its own).
func hasCmdMallcop(tree string) bool {
	info, err := os.Stat(filepath.Join(tree, "cmd", "mallcop"))
	return err == nil && info.IsDir()
}

// discoverCustomerDetectorDirs returns the sorted list of detectors/<name>/
// directories under tree that carry a main.go — the THIN-EMBED shape
// deployrepo.go scaffolds (see scanWorkflowTemplate's own `for d in
// detectors/*/; do [ -f "${d}main.go" ] ...` discovery, mirrored here in Go).
// A missing detectors/ dir is the empty set, not an error — a proposal that
// touches nothing under detectors/ (e.g. a config-only change) is valid and
// simply has nothing for customer-tree exam mode to grade.
func discoverCustomerDetectorDirs(tree string) ([]string, error) {
	root := filepath.Join(tree, "detectors")
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		candidate := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(candidate, "main.go")); err == nil {
			dirs = append(dirs, candidate)
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

// dirExists reports whether path exists and is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// treeHasGoFiles reports whether tree contains at least one .go file at any
// depth (skipping .git). Used to skip `go vet ./...` on a tree with nothing
// to vet — Go's own "no packages to vet" plumbing message on such a tree is
// not a detector defect (see structuralStage).
func treeHasGoFiles(tree string) bool {
	found := false
	_ = filepath.WalkDir(tree, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// customerScenariosSubdir is the co-located efficacy-scenarios directory
// every customer-tree detector sidecar unit ships (mallcoppro-f95 RULING,
// Approach A): detectors/<name>/{main.go, main_test.go, scenarios/*.yaml}.
// Its absence is not an error — a detector that ships none simply declares
// zero families (checkCustomerEfficacy fails it closed for that).
const customerScenariosSubdir = "scenarios"

// customerTreeExamStage is stage 3 under Options.ExamRepo: it grades every
// detectors/<name>/ source directory found in headTree against the UNION of
// (a) examRepoTree's OWN pinned reference corpus and (b) the detector's OWN
// co-located detectors/<name>/scenarios/*.yaml efficacy scenarios (mallcoppro-
// f95), via RunCustomerTreeExamExtra (customerexam.go) — the real
// wasip1/wazero host path, never an in-process link. The detector's own
// scenarios are UNPINNED (never touch examRepoTree's corpus.pin).
//
// EPHEMERAL SCRATCH COPY (mallcoppro-f95 ruling): examRepoTree is a
// caller-supplied REAL reference tree, potentially the operator's own
// long-lived checkout reused across many gate runs — not a disposable
// worktree like headTree. Grading builds a `mallcop` binary straight into
// whatever tree it's pointed at (runTreeExamWithSidecarSrc); pointing that at
// examRepoTree directly would leave a stray binary in the operator's real
// checkout on every run. This stage therefore makes an ephemeral, throwaway
// COPY of examRepoTree first (scratchCopyExamRepo) and grades against the
// copy exclusively — examRepoTree itself is only ever READ (to make the
// copy), never built into, never written to, and its corpus.pin is never
// touched.
//
// A REAL reference tree's corpus can legitimately carry PRE-EXISTING labeled
// gaps (documented, accepted red rows unrelated to any customer proposal —
// e.g. a known false-negative tracked as a backlog item); RunCustomerTreeExam
// itself has no base-tree diff (see its package doc), so grading the
// candidate report in isolation would wrongly reject every customer detector
// over gaps it didn't cause. This stage therefore diffs TWO exam runs of the
// SAME scratch copy: a BASELINE (runTreeExam, no sidecar, no extra scenarios —
// whatever the reference tree already scores on its own) and the CANDIDATE
// (the customer detector + its own scenarios loaded via
// RunCustomerTreeExamExtra). Only a REFERENCE-CORPUS scenario (row.Extra ==
// false) that PASSED at baseline and FAILS at candidate is a regression THIS
// detector introduced against the shared corpus — including a detector that
// fires on some unrelated reference scenario it should stay silent on. A
// pre-existing baseline failure is never blamed on the candidate.
//
// EFFICACY (the K1 hole this fix closes, mallcoppro-f95): a detector proven
// ONLY against the reference corpus can pass vacuously for a NOVEL gap (an
// event type with zero reference-corpus scenarios) without ever being shown
// an event of its own target type. checkCustomerEfficacy generalizes the
// in-tree lane's checkAuthoredBenignTwins into this lane: for every family
// the detector's OWN scenarios declare as a must_fire target
// (customerDeclaredFamilies, sourced from Extra==true rows only), the UNION
// report must carry a PASSING must_fire row AND a PASSING must_not_fire
// benign-twin row for it — zero declared families (no scenarios/ shipped, or
// none labeled) fails closed trivially. This is a REAL rejection finding,
// never folded into the operational-error path. The error return here is
// operational only: a detector source that doesn't build, the scratch copy
// failing to materialize, or the reference tree's own corpus failing to
// resolve (either pass).
func customerTreeExamStage(examRepoTree, headTree string) ([]GuardFinding, string, error) {
	detectorDirs, err := discoverCustomerDetectorDirs(headTree)
	if err != nil {
		return nil, "", fmt.Errorf("selfgate: discovering customer detector source under %s: %w", headTree, err)
	}
	if len(detectorDirs) == 0 {
		return nil, fmt.Sprintf("customer-tree exam mode: no detectors/<name>/main.go found under %s (nothing to grade)", headTree), nil
	}

	scratchExamRepo, cleanup, err := scratchCopyExamRepo(examRepoTree)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()

	baselineReport, _, baseErr := runTreeExam(scratchExamRepo)
	if baseErr != nil {
		// The reference tree is the caller-supplied ground truth: if it cannot
		// even grade itself (no detector loaded), the gate has nothing to diff
		// against — operational, not a property of the customer proposal.
		return nil, "", fmt.Errorf("selfgate: reference tree %s baseline exam-detect (no customer detector loaded): %w", examRepoTree, baseErr)
	}
	baselinePass := make(map[string]bool, len(baselineReport.Rows))
	for _, r := range baselineReport.Rows {
		baselinePass[r.ScenarioID] = r.Pass
	}

	var findings []GuardFinding
	var parts []string
	for _, dir := range detectorDirs {
		name := filepath.Base(dir)
		relPath := "detectors/" + name

		extraScenariosDir := ""
		if candidate := filepath.Join(dir, customerScenariosSubdir); dirExists(candidate) {
			extraScenariosDir = candidate
		}

		report, err := RunCustomerTreeExamExtra(scratchExamRepo, dir, extraScenariosDir)
		if err != nil {
			return nil, "", fmt.Errorf("selfgate: customer-tree exam for %s: %w", relPath, err)
		}

		if report.Totals.Labeled == 0 {
			findings = append(findings, GuardFinding{
				Path:   relPath,
				Rule:   RuleCustomerExamVacuous,
				Detail: fmt.Sprintf("customer-tree exam graded zero labeled scenarios against %s's corpus — fail closed (a vacuous grade proves nothing)", examRepoTree),
			})
			parts = append(parts, fmt.Sprintf("%s: 0 labeled (vacuous)", name))
			continue
		}

		// EFFICACY (mallcoppro-f95): the detector's OWN scenarios must prove it
		// fires on its declared target(s) and stays silent on a benign twin.
		// Zero declared families (no scenarios/ shipped, or none labeled) fails
		// closed here — this is what stops a novel-gap detector from passing
		// on reference-corpus silence alone (it is never even shown its target
		// event type by the reference corpus).
		efficacyFindings, effErr := checkCustomerEfficacy(name, relPath, report.Rows, extraScenariosDir)
		if effErr != nil {
			return nil, "", fmt.Errorf("selfgate: customer-tree efficacy check for %s: %w", relPath, effErr)
		}
		findings = append(findings, efficacyFindings...)

		// REGRESSION (unchanged in substance): only REFERENCE-CORPUS rows
		// (Extra == false) are diffed against the baseline — the detector's
		// OWN scenario rows are graded above by checkCustomerEfficacy instead,
		// which gives them a more precise per-family verdict than a bare
		// "regressed since it was never at baseline" message would.
		regressions := 0
		for _, row := range report.Rows {
			if row.Extra {
				continue
			}
			if row.Pass {
				continue
			}
			if wasPassing, seenAtBaseline := baselinePass[row.ScenarioID]; seenAtBaseline && !wasPassing {
				// Pre-existing gap in the reference tree's own corpus — not
				// introduced by this detector, not this proposal's fault.
				continue
			}
			regressions++
			findings = append(findings, GuardFinding{
				Path: relPath,
				Rule: RuleCustomerExamFail,
				Detail: fmt.Sprintf("scenario %q regresses from passing (without this detector) to failing (with it loaded) against %s's reference corpus (must_fire=%v must_not_fire=%v emitted=%v)",
					row.ScenarioID, examRepoTree, row.MustFire, row.MustNotFire, row.Emitted),
			})
		}
		parts = append(parts, fmt.Sprintf("%s: %d labeled (%d passed, %d failed, %d regression(s) vs. the reference tree's own baseline)",
			name, report.Totals.Labeled, report.Totals.Passed, report.Totals.Failed, regressions))
	}

	evidence := fmt.Sprintf("customer-tree exam via reference tree %s (graded against an ephemeral scratch copy) — %s", examRepoTree, strings.Join(parts, "; "))
	return findings, evidence, nil
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
	// Extra mirrors core/eval.ExamDetectRow.Extra (mallcoppro-f95): true when
	// this row came from an --extra-scenarios-dir union rather than the
	// pinned reference corpus. Always false/omitted for the in-tree lane
	// (which never passes an extra dir) — decoded here only so
	// customerTreeExamStage can tell a customer detector's OWN efficacy
	// scenarios apart from reference-corpus rows in the SAME report.
	Extra bool `json:"extra,omitempty"`
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

// examExecWallClock bounds a single tree's exam-detect exec (stage 3). It is
// generous — the exam is an offline pass over a small corpus and finishes in
// seconds — but finite: it exists so a hang in an authored detector cannot stall
// the gate indefinitely. It is a var (not const) ONLY so tests can shorten it;
// production never mutates it.
var examExecWallClock = 3 * time.Minute

// runTreeExam builds tree's OWN mallcop binary and execs its exam-detect over
// tree's OWN corpus (MALLCOP_REPO_ROOT pins the root; --tuning is passed iff
// the tree carries detectors/tuning.yaml). Exit 0 (all green) and exit 1
// (gaps present) both yield a report; anything else is an error, with detail
// carrying the subprocess output for the caller's finding/error message.
func runTreeExam(tree string) (examReport, string, error) {
	return runTreeExamWithSidecarSrc(tree, "")
}

// runTreeExamWithSidecarSrc is runTreeExam, optionally grading an AD HOC
// detector built from sidecarSrcDir IN ADDITION to whatever the tree builds
// in-process — the CUSTOMER-TREE exam mode (mallcoppro-cc3e; see
// RunCustomerTreeExam). sidecarSrcDir == "" reproduces runTreeExam's exact
// prior behavior byte-for-byte (the flag is simply omitted from argv), which
// is what keeps the existing in-tree stage-3 lane unchanged.
//
// GROUND-TRUTH INVARIANT: this package never imports core/eval or detecthost
// (see the package doc and TestSelfgateImportsNoInferenceOrCommittee) — the
// $0 purity constraint on selfgate. Grading a wasm sidecar therefore ALWAYS
// happens on the far side of this same subprocess/JSON seam runTreeExam
// already uses for the in-tree lane: `mallcop exam-detect --sidecar-src <dir>
// --json` builds sidecarSrcDir to a wasip1 .wasm module and loads it through
// the REAL detecthost host (cli/sidecars.go's
// buildAndRegisterSourceSidecar) before grading — never links the detector's
// Go source into the tree's own binary. selfgate cannot even construct an
// in-process shortcut for this: it has no way to reach core/detect's registry
// or detecthost directly.
func runTreeExamWithSidecarSrc(tree, sidecarSrcDir string) (examReport, string, error) {
	return runTreeExamWithSidecarSrcAndScenarios(tree, sidecarSrcDir, "")
}

// runTreeExamWithSidecarSrcAndScenarios is runTreeExamWithSidecarSrc,
// additionally passing --extra-scenarios-dir extraScenariosDir when non-empty
// (mallcoppro-f95) — unions a customer detector's OWN co-located efficacy
// scenarios into the SAME exam-detect run, UNPINNED (see
// RunCustomerTreeExamExtra). extraScenariosDir == "" reproduces
// runTreeExamWithSidecarSrc's exact prior behavior byte-for-byte (the flag is
// simply omitted from argv), which is what keeps every existing caller
// (runTreeExam, the in-tree lane, RunCustomerTreeExam) unchanged.
func runTreeExamWithSidecarSrcAndScenarios(tree, sidecarSrcDir, extraScenariosDir string) (examReport, string, error) {
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
	if sidecarSrcDir != "" {
		args = append(args, "--sidecar-src", sidecarSrcDir)
	}
	if extraScenariosDir != "" {
		args = append(args, "--extra-scenarios-dir", extraScenariosDir)
	}
	// Defense-in-depth behind the L3 shape gate: an authored detector that slips
	// an unbounded loop or blocking call past the AST check would otherwise let
	// stage-3 "pass" by running forever/long instead of crashing. Wall-clock-box
	// the exam-detect exec — a timeout kills it and (for the head tree) surfaces
	// as a RuleExamExecution fail-closed rejection upstream.
	ctx, cancel := context.WithTimeout(context.Background(), examExecWallClock)
	defer cancel()
	stdout, stderr, code, err = runToolCtx(ctx, tree, []string{"MALLCOP_REPO_ROOT=" + tree}, bin, args...)
	if err != nil {
		return examReport{}, truncate(stderr, 1500), fmt.Errorf("exec %s: %w", bin, err)
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

	// declaredOn maps a family to the SET OF SCENARIOS that declare it as a
	// passing must_fire target — the must_fire families of rows newly labeled
	// (absent at base) or newly passing (failing at base), the detection the
	// proposal EXPLICITLY set out to add, tracked PER SCENARIO. Scoping the
	// no-new-firings excusal to the declaring scenario (not a blanket family
	// excusal) is what stops an over-broad NEW rule from firing on UNRELATED
	// existing benign scenarios under cover of "its family is declared somewhere".
	// Only rows that actually PASS at head declare a target: an unproven label
	// excuses nothing (fail closed). This is also the COVERAGE-+1 count.
	declaredOn := map[string]map[string]bool{}
	for _, h := range head.Rows {
		if !h.Pass || len(h.MustFire) == 0 {
			continue
		}
		b, inBase := baseByID[h.ScenarioID]
		if !inBase || !b.Pass {
			coveragePlus++
			for _, fam := range h.MustFire {
				f := normalizeFamily(fam)
				if declaredOn[f] == nil {
					declaredOn[f] = map[string]bool{}
				}
				declaredOn[f][h.ScenarioID] = true
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
			// A declared family is excused ONLY on the scenario that declared it
			// (declaredOn[fam][h.ScenarioID]); firing on any OTHER scenario is a new
			// firing even for a declared family.
			if seen[fam] || baseFams[fam] || declaredOn[fam][h.ScenarioID] {
				seen[fam] = true
				continue
			}
			seen[fam] = true
			findings = append(findings, GuardFinding{
				Path: h.ScenarioID,
				Rule: RuleExamNewFiring,
				Detail: fmt.Sprintf("family %q fires at head but not at base and is not a declared target of this proposal FOR THIS scenario (families declared: %v) — widens must be monotonic and intentional",
					fam, sortedKeys(declaredOn)),
			})
			newFirings = append(newFirings, h.ScenarioID+": "+fam)
		}
	}

	// (d) NEW LABELED SCENARIO MUST PASS. The regression check (a) only covers
	// rows present at BASE, and (a)'s "missing from head" arm cannot see a row
	// that never existed at base, so a scenario this proposal ADDS (present at
	// head, absent at base) that carries a label but does NOT pass at head would
	// otherwise be invisible — the exact hole a benign-twin must_not_fire the new
	// rule wrongly fires on falls through. An added label the head does not
	// satisfy is unproven detection: fail closed.
	for _, h := range head.Rows {
		if _, inBase := baseByID[h.ScenarioID]; inBase {
			continue
		}
		if (len(h.MustFire) > 0 || len(h.MustNotFire) > 0) && !h.Pass {
			findings = append(findings, GuardFinding{
				Path: h.ScenarioID,
				Rule: RuleExamNewScenarioFails,
				Detail: fmt.Sprintf("labeled scenario added by this proposal does not pass at head (must_fire=%v must_not_fire=%v emitted=%v) — an added label the head does not satisfy is unproven detection, fail closed",
					h.MustFire, h.MustNotFire, h.Emitted),
			})
		}
	}

	return findings, coveragePlus, newFirings
}

// addedAuthoredFamilies returns the normalized families of the authored
// detectors a proposal ADDS: the registered Names present under
// core/detect/authored/ in the HEAD tree but not in the BASE tree, normalized to
// their emitted family token (an authored detector emits finding.Type == its
// Name). A missing authored tree at either ref (fs.ErrNotExist) is treated as the
// empty set — a base with no authored tree means every head authored detector is
// new. The result is sorted for deterministic finding order. An error is returned
// only for a non-NotExist I/O failure reading a tree.
func addedAuthoredFamilies(baseTree, headTree string) ([]string, error) {
	authoredRel := filepath.FromSlash(authoredDetectorRel)

	collect := func(tree string) (map[string]bool, error) {
		names, err := collectAuthoredDetectorNames(filepath.Join(tree, authoredRel))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return map[string]bool{}, nil
			}
			return nil, err
		}
		return names, nil
	}

	base, err := collect(baseTree)
	if err != nil {
		return nil, err
	}
	head, err := collect(headTree)
	if err != nil {
		return nil, err
	}

	added := map[string]bool{}
	for name := range head {
		if !base[name] {
			added[normalizeFamily(name)] = true
		}
	}
	return sortedKeys(added), nil
}

// checkAuthoredBenignTwins enforces, for every detector a proposal ADDS in the
// authored lane (addedFamilies — the normalized authored-detector Names present
// at head but not at base), that the head exam corpus proves BOTH halves of the
// consensus-not-rules contract for it:
//
//   - a MUST-FIRE scenario labeled for the family that PASSES (a true positive:
//     the detector actually fires where it should — the detection gain), and
//   - a MUST-NOT-FIRE BENIGN TWIN labeled for the family that PASSES (a true
//     negative: the detector correctly stays silent on a benign look-alike).
//
// Requiring the benign twin ties "X detects its target" to "X does NOT fire on
// its benign neighbor", both present and passing, before a detector merges — so
// the loop cannot grow a trigger-happy detector proven only on its happy path.
// It runs ONLY when the proposal adds a family (addedFamilies non-empty); pure
// data/tuning widens pass through untouched. Pure function over the head
// report — no I/O; findings are emitted in sorted family order (addedFamilies
// is pre-sorted) for determinism.
func checkAuthoredBenignTwins(addedFamilies []string, head examReport) []GuardFinding {
	if len(addedFamilies) == 0 {
		return nil
	}
	// Families that appear in a PASSING must_fire row and in a PASSING
	// must_not_fire row of the head corpus.
	firesPassing := map[string]bool{}
	twinPassing := map[string]bool{}
	for _, r := range head.Rows {
		if !r.Pass {
			continue
		}
		for _, fam := range r.MustFire {
			firesPassing[normalizeFamily(fam)] = true
		}
		for _, fam := range r.MustNotFire {
			twinPassing[normalizeFamily(fam)] = true
		}
	}

	var findings []GuardFinding
	for _, fam := range addedFamilies {
		if !firesPassing[fam] {
			findings = append(findings, GuardFinding{
				Path:   StageExamDetect,
				Rule:   RuleExamMissingMustFire,
				Detail: fmt.Sprintf("detector family %q was added but no passing must_fire scenario labels it — an added authored detector must ship a labeled scenario proving it fires on its target", fam),
			})
		}
		if !twinPassing[fam] {
			findings = append(findings, GuardFinding{
				Path:   StageExamDetect,
				Rule:   RuleExamMissingBenignTwin,
				Detail: fmt.Sprintf("detector family %q was added without a passing must_not_fire benign twin — every added authored detector must ship a benign look-alike scenario it correctly does NOT fire on (consensus-not-rules false-positive floor)", fam),
			})
		}
	}
	return findings
}

// normalizeFamily canonicalizes a family token the same way the exam grader
// does (lowercase, trimmed).
func normalizeFamily(tok string) string {
	return strings.ToLower(strings.TrimSpace(tok))
}

// customerDeclaredFamilies returns the sorted, de-duplicated set of detector
// families a customer detector's OWN scenarios/*.yaml sidecar (rows marked
// Extra) declares as a must_fire target — the customer-tree analogue of
// addedAuthoredFamilies for the in-tree lane. There is no base/head package
// diff in customer-tree mode (a single detector is graded in isolation, not
// diffed against a sibling proposal); the detector's own must_fire
// declarations under its own scenarios/ ARE the claim it must prove.
// Reference-corpus rows (Extra == false) never contribute here — a detector
// cannot borrow proof of its own novel-gap efficacy from scenarios it did not
// ship.
func customerDeclaredFamilies(rows []CustomerExamRow) []string {
	set := map[string]bool{}
	for _, r := range rows {
		if !r.Extra {
			continue
		}
		for _, fam := range r.MustFire {
			set[normalizeFamily(fam)] = true
		}
	}
	return sortedKeys(set)
}

// checkCustomerEfficacy is the customer-tree generalization of
// checkAuthoredBenignTwins (mallcoppro-f95): for every family the detector's
// OWN scenarios/*.yaml declares (customerDeclaredFamilies), the UNION report
// (reference corpus + the detector's own scenarios, graded through the SAME
// real .wasm run) must carry a PASSING must_fire row AND a PASSING
// must_not_fire benign-twin row for it.
//
// Zero declared families — no scenarios/ subdirectory shipped at all, or one
// that ships no labeled must_fire scenario — fails closed trivially: a
// detector graded ONLY against the reference corpus proves nothing about a
// novel gap it targets (the reference corpus, by definition, may have zero
// scenarios of that event type). This is the K1 hole mallcoppro-f95 closes:
// before this check, RuleCustomerExamVacuous only ever looked at the WHOLE
// union's Totals.Labeled, which is never zero once a non-trivial reference
// corpus is in play — a detector with zero of its own scenarios sailed
// through untouched.
//
// firesPassing/twinPassing are computed over ALL rows (reference and extra)
// so a family's proof can legitimately live in either — a family a detector
// declares that HAPPENS to already have reference-corpus coverage is not
// penalized for it — but a declared family with NO passing proof anywhere in
// the union fails on both the must-fire and (independently) the benign-twin
// arm. All findings use RuleCustomerExamFail (the single customer-tree
// rejection rule; RuleCustomerExamVacuous stays reserved for the whole-corpus
// backstop).
func checkCustomerEfficacy(name, relPath string, rows []CustomerExamRow, extraScenariosDir string) ([]GuardFinding, error) {
	declared := customerDeclaredFamilies(rows)
	if len(declared) == 0 {
		return []GuardFinding{{
			Path: relPath,
			Rule: RuleCustomerExamFail,
			Detail: fmt.Sprintf(
				"detector %q ships zero efficacy scenarios — expected %s/%s/*.yaml with at least one must_fire scenario proving it fires on its target and a benign-twin must_not_fire scenario proving it stays silent on a look-alike; a detector graded ONLY against the reference corpus proves nothing about a novel gap it targets, fail closed",
				name, relPath, customerScenariosSubdir),
		}}, nil
	}

	firesPassing := map[string]bool{}
	twinPassing := map[string]bool{}
	// extraFireIDs / extraTwinIDs collect, PER FAMILY, the scenario IDs of the
	// detector's OWN (Extra == true) PASSING must_fire / must_not_fire rows —
	// exactly the candidate pairs checkMinimalMutationCoverage below diffs.
	// Reference-corpus rows (Extra == false) never enter these maps: see that
	// function's doc for why the minimal-mutation check is scoped to the
	// detector's own scenario pair, not the reference corpus.
	extraFireIDs := map[string][]string{}
	extraTwinIDs := map[string][]string{}
	for _, r := range rows {
		if !r.Pass {
			continue
		}
		for _, fam := range r.MustFire {
			f := normalizeFamily(fam)
			firesPassing[f] = true
			if r.Extra {
				extraFireIDs[f] = append(extraFireIDs[f], r.ScenarioID)
			}
		}
		for _, fam := range r.MustNotFire {
			f := normalizeFamily(fam)
			twinPassing[f] = true
			if r.Extra {
				extraTwinIDs[f] = append(extraTwinIDs[f], r.ScenarioID)
			}
		}
	}

	var findings []GuardFinding
	// scenarios is loaded lazily (at most once) from extraScenariosDir — most
	// proposals declare one family, and many families that DO have reference-
	// corpus coverage on both arms never need it at all (see the skip below).
	var scenarios map[string]*exam.Scenario
	for _, fam := range declared {
		if !firesPassing[fam] {
			findings = append(findings, GuardFinding{
				Path: relPath,
				Rule: RuleCustomerExamFail,
				Detail: fmt.Sprintf(
					"detector %q family %q: no passing must_fire scenario proves it fires on its target — the detector's own %s/%s/*.yaml must-fire scenario did not clear the real .wasm run",
					name, fam, relPath, customerScenariosSubdir),
			})
		}
		if !twinPassing[fam] {
			findings = append(findings, GuardFinding{
				Path: relPath,
				Rule: RuleCustomerExamFail,
				Detail: fmt.Sprintf(
					"detector %q family %q: no passing must_not_fire benign-twin scenario proves it stays silent on a look-alike — missing benign twin, or the twin fires (the false-positive floor)",
					name, fam),
			})
			continue // no twin at all for this family — nothing to diff below
		}

		// MEASURED MINIMAL MUTATION (mallcoppro-f95 round 2, veracity-reproduced
		// bypass): a passing must_fire row AND a passing must_not_fire row is
		// NOT enough on its own — see checkMinimalMutationCoverage's doc for the
		// reproduced attack this closes (a detector that fires on every event
		// except one hand-picked, structurally-unrelated event_type ships a
		// compliant must-fire + twin pair and passed under the OLD check).
		// Scoped to families whose proof for BOTH arms is entirely the
		// detector's OWN scenarios (Extra rows): a family already proven via
		// the reference corpus needs no re-derivation here — that corpus is
		// the gate's own trusted ground truth, not the untrusted proposal
		// content this check exists to police.
		if len(extraFireIDs[fam]) == 0 || len(extraTwinIDs[fam]) == 0 {
			continue
		}
		if scenarios == nil {
			loaded, lerr := loadCustomerScenarioFiles(extraScenariosDir)
			if lerr != nil {
				return nil, fmt.Errorf("loading %s's own scenarios (%s) for the minimal-mutation check: %w", relPath, extraScenariosDir, lerr)
			}
			scenarios = loaded
		}
		if f := checkMinimalMutationCoverage(name, relPath, fam, extraFireIDs[fam], extraTwinIDs[fam], scenarios); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

// loadCustomerScenarioFiles parses every scenario YAML under dir (a customer
// detector's own co-located scenarios/ directory) into a map keyed by the
// scenario's own `id:` field — the SAME key CustomerExamRow.ScenarioID
// carries for these rows, since both are derived from the identical file set
// RunCustomerTreeExamExtra's --extra-scenarios-dir union already graded
// through the real .wasm pass. CustomerExamRow itself carries no event data
// (see customerexam.go's wire shape); this is the only way
// checkMinimalMutationCoverage can recover the raw event sequence a passing
// row's verdict was computed over. A parse failure here is OPERATIONAL, never
// silently skipped: the same directory just built and graded successfully
// through RunCustomerTreeExamExtra, so a YAML this loader rejects means
// something is wrong with the gate's own re-read, not the proposal.
func loadCustomerScenarioFiles(dir string) (map[string]*exam.Scenario, error) {
	out := map[string]*exam.Scenario{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != dir && strings.HasPrefix(d.Name(), "_") {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), "_") {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yaml") && !strings.HasSuffix(d.Name(), ".yml") {
			return nil
		}
		sc, lerr := exam.Load(path)
		if lerr != nil {
			return fmt.Errorf("parsing %s: %w", path, lerr)
		}
		out[sc.ID] = sc
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// maxDiscriminatingFields bounds how many event fields a benign-twin scenario
// may differ on from its must-fire sibling and still count as a MEASURED
// MINIMAL MUTATION rather than an arbitrary carve-out.
//
// Derived from the reference corpus's OWN benign-twin convention
// (exams/scenarios/privilege/PE-08-aws-poweruser-grant.yaml and
// PE-09-aws-readonly-grant-benign.yaml — PE-09's own trap_description names
// itself "the benign twin of PE-08"): the discriminating event in that pair
// shares event_type (role_assignment) and source (aws) and differs ONLY in
// the SUBSTANTIVE payload that actually separates escalation from routine —
// there, the policy attached (metadata.role / metadata.policy_arn:
// PowerUserAccess vs ReadOnlyAccess, plus the principal fields that go with
// it). It never differs in event TYPE itself. A customer-tree twin that
// instead differs in event type (or actor, source, or event count) is not
// narrowing on a substantive value at all — it is pointing at a
// structurally different event and calling it a "near miss", which is
// exactly the reproduced attack shape: a detector that fires on every event
// except one hand-picked, structurally-unrelated event_type. Forcing the
// twin to share the must-fire event's type/actor/source means that same
// "if type == X, stay silent" logic which let the twin pass would ALSO
// silence the must-fire event itself (same type) — so the must-fire arm
// fails instead, and the detector is forced into genuine discrimination on
// the bounded, substantive difference.
//
// 3 is small enough that a twin differing across essentially its entire
// metadata block is still rejected (that is a different narrative wearing a
// twin's clothes, not a bounded discrimination) while comfortably covering a
// real near-miss that changes one semantic value (e.g. a policy ARN) plus
// one or two correlated fields that legitimately change WITH it (e.g. a
// severity or action string derived from that same underlying value, as
// PE-08/PE-09's own action/severity fields do alongside the policy).
//
// This bound applies ONLY to the customer's own minimal single/few-event
// scenario pair (detectors/<name>/scenarios/*.yaml) — the reference corpus's
// own richer, multi-event scenarios (like PE-09's two-event onboarding
// sequence) are a DIFFERENT, unconstrained authoring convention this check
// does not police; see checkMinimalMutationCoverage's doc for the scope
// boundary.
const maxDiscriminatingFields = 3

// checkMinimalMutationCoverage reports whether AT LEAST ONE (must-fire,
// benign-twin) scenario ID pair drawn from fireIDs × twinIDs is a MEASURED
// MINIMAL MUTATION of each other (minimalMutationPairOK) — proof that the
// detector's discrimination is genuine, not an arbitrary carve-out. Returns
// nil (no finding) the moment one qualifying pair is found; a detector may
// ship extra, broader scenarios beyond the required minimal pair without
// penalty. Returns a RuleCustomerExamFail finding, listing every attempted
// pair and why it failed, only if NONE of the passing pairs qualify.
//
// THE REPRODUCED BYPASS this closes (opus veracity, independently
// reproduced): checkCustomerEfficacy previously verified only that a family
// had SOME passing must_fire row and SOME passing must_not_fire row — never
// that the benign twin was a minimal mutation of the must-fire scenario. A
// detector for a novel family (zero reference-corpus rows, so the regression
// arm is an empty backstop) that fires on every event EXCEPT its own
// hand-picked twin event_type shipped a compliant must-fire + twin pair and
// PASSED. minimalMutationPairOK's structural-identity requirement
// (event_type/actor/source must match, see maxDiscriminatingFields's doc)
// closes this: the twin can no longer be "some other event the detector
// happens to ignore" — it must share the must-fire event's type/actor/source
// and differ only on a bounded, non-zero set of substantive fields.
func checkMinimalMutationCoverage(name, relPath, fam string, fireIDs, twinIDs []string, scenarios map[string]*exam.Scenario) *GuardFinding {
	var attemptDetails []string
	foundAny := false
	for _, fireID := range fireIDs {
		fireScenario := scenarios[fireID]
		if fireScenario == nil {
			continue
		}
		for _, twinID := range twinIDs {
			twinScenario := scenarios[twinID]
			if twinScenario == nil {
				continue
			}
			foundAny = true
			ok, reason := minimalMutationPairOK(fireScenario, twinScenario)
			if ok {
				return nil
			}
			attemptDetails = append(attemptDetails, fmt.Sprintf("%s vs %s: %s", fireID, twinID, reason))
		}
	}
	if !foundAny {
		// Every declared must_fire/must_not_fire ID for this family came from
		// files this loader could not locate under the detector's own
		// scenarios directory — should not happen (the same directory just
		// graded successfully through the real exam-detect pass) — fail
		// closed rather than silently accept an unverifiable pair.
		return &GuardFinding{
			Path: relPath,
			Rule: RuleCustomerExamFail,
			Detail: fmt.Sprintf(
				"detector %q family %q: could not locate its own must_fire/must_not_fire scenario files under %s to verify the benign twin is a measured minimal mutation of the must-fire scenario — fail closed",
				name, fam, customerScenariosSubdir),
		}
	}
	return &GuardFinding{
		Path: relPath,
		Rule: RuleCustomerExamFail,
		Detail: fmt.Sprintf(
			"detector %q family %q: no passing must_fire/must_not_fire pair proves the benign twin is a MEASURED MINIMAL MUTATION of the must-fire scenario (same event count and order, matching event_type/actor/source, a bounded 1..%d discriminating field difference on action/target/severity/metadata) — a twin that is byte-identical, that differs in event type/count/actor/source, or that differs too broadly is an arbitrary carve-out, not a genuine near-miss (%s)",
			name, fam, maxDiscriminatingFields, strings.Join(attemptDetails, "; ")),
	}
}

// minimalMutationPairOK reports whether twin's Events are a MEASURED MINIMAL
// MUTATION of fire's Events: same count and order, matching structural
// identity per event (event_type/actor/source — see maxDiscriminatingFields's
// doc for why), and a bounded, NON-ZERO total count of discriminating field
// differences (action/target/severity/metadata) across the whole sequence.
// reason is empty iff ok is true.
func minimalMutationPairOK(fire, twin *exam.Scenario) (ok bool, reason string) {
	if len(fire.Events) != len(twin.Events) {
		return false, fmt.Sprintf(
			"event count differs (must-fire has %d, twin has %d) — a twin must mirror the must-fire scenario's event sequence, not add or drop events",
			len(fire.Events), len(twin.Events))
	}
	if len(fire.Events) == 0 {
		return false, "must-fire scenario has zero events — nothing to mutate"
	}
	total := 0
	for i := range fire.Events {
		if r := structuralIdentityMismatch(fire.Events[i], twin.Events[i], i); r != "" {
			return false, r
		}
		total += eventDiscriminatingDiff(fire.Events[i], twin.Events[i])
	}
	if total == 0 {
		return false, "twin is byte-identical to the must-fire scenario on every discriminating field (action/target/severity/metadata) — zero discrimination proves nothing"
	}
	if total > maxDiscriminatingFields {
		return false, fmt.Sprintf(
			"twin differs from the must-fire scenario on %d discriminating field(s), exceeding the bound of %d — too broad a difference to be a genuine near-miss",
			total, maxDiscriminatingFields)
	}
	return true, ""
}

// structuralIdentityMismatch returns a non-empty reason if fire and twin (at
// event position idx) do not share the SAME structural identity — event_type,
// actor, and source. See maxDiscriminatingFields's doc for why these three
// fields must match rather than count as bounded discriminators: allowing any
// of them to differ reopens the exact reproduced bypass (a twin that is
// simply a different, hand-picked event the detector special-cases around,
// rather than a substantive near-miss of the SAME event).
func structuralIdentityMismatch(fire, twin exam.Event, idx int) string {
	switch {
	case fire.EventType != twin.EventType:
		return fmt.Sprintf(
			"event[%d]: event_type differs (%q vs %q) — the twin targets a different event type entirely, an arbitrary carve-out rather than a near-miss of the SAME event type",
			idx, fire.EventType, twin.EventType)
	case fire.Actor != twin.Actor:
		return fmt.Sprintf(
			"event[%d]: actor differs (%q vs %q) — structural identity (event_type/actor/source) must match; only a bounded number of payload/value fields may discriminate",
			idx, fire.Actor, twin.Actor)
	case fire.Source != twin.Source:
		return fmt.Sprintf(
			"event[%d]: source differs (%q vs %q) — structural identity (event_type/actor/source) must match; only a bounded number of payload/value fields may discriminate",
			idx, fire.Source, twin.Source)
	}
	return ""
}

// eventDiscriminatingDiff counts the DISCRIMINATING field differences between
// two events already known to share structural identity (event_type/actor/
// source — the caller checks that first). id, timestamp, and ingested_at are
// EXEMPT: they always differ between two scenario files (an event id must be
// unique; a twin is authored at a different, later timestamp) and carry no
// information about whether the detector genuinely discriminates on the
// attack's substance. action, target, severity, and each metadata key ARE
// counted; raw is intentionally ignored (a free-form escape hatch scenario
// authors are not required to keep parallel).
func eventDiscriminatingDiff(fire, twin exam.Event) int {
	n := 0
	if fire.Action != twin.Action {
		n++
	}
	if fire.Target != twin.Target {
		n++
	}
	if fire.Severity != twin.Severity {
		n++
	}
	n += metadataDiffCount(fire.Metadata, twin.Metadata)
	return n
}

// metadataDiffCount counts keys that differ (by value) or are present in one
// metadata map but absent from the other — each such key is one
// discriminating field.
func metadataDiffCount(a, b exam.EventMetadata) int {
	n := 0
	for k, av := range a {
		if bv, ok := b[k]; !ok || !reflect.DeepEqual(av, bv) {
			n++
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			n++
		}
	}
	return n
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

// scratchCopyExamRepo makes an EPHEMERAL, THROWAWAY copy of a caller-supplied
// REAL reference tree (Options.ExamRepo) into a fresh temp dir, so grading a
// customer detector against it can never mutate the operator's actual
// checkout (mallcoppro-f95). Grading builds a `mallcop` binary straight into
// whatever tree it's pointed at (runTreeExamWithSidecarSrc has always done
// this in place — correct for the in-tree lane's OWN throwaway worktrees, but
// wrong for a caller-supplied PERSISTENT reference tree reused across many
// gate runs). The copy excludes .git (build/grading needs no VCS metadata,
// and a real checkout's .git can be large) — everything else, including
// exams/scenarios/corpus.pin, is byte-copied. Returns the copy's root and a
// cleanup func that removes the whole scratch dir; cleanup is always safe to
// call even if an error already occurred.
func scratchCopyExamRepo(examRepoTree string) (copyDir string, cleanup func(), err error) {
	scratch, err := os.MkdirTemp("", "mallcop-examrepo-")
	if err != nil {
		return "", func() {}, fmt.Errorf("selfgate: exam-repo scratch dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(scratch) }
	dst := filepath.Join(scratch, "examrepo")
	if cerr := copyTree(examRepoTree, dst); cerr != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("selfgate: copying reference tree %s to an ephemeral scratch copy: %w", examRepoTree, cerr)
	}
	return dst, cleanup, nil
}

// copyTree recursively byte-copies src to dst (creating dst), skipping .git
// directories at any depth. File permissions are preserved; symlinks are
// recreated as symlinks (never followed) so the copy cannot escape src via a
// malicious link target it did not itself resolve.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}
		if d.IsDir() && d.Name() == ".git" {
			return fs.SkipDir
		}
		target := filepath.Join(dst, rel)
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, lerr := os.Readlink(path)
			if lerr != nil {
				return lerr
			}
			return os.Symlink(linkTarget, target)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

// runTool executes a subprocess with Dir=dir and the parent environment plus
// extraEnv (later entries win), capturing stdout/stderr separately. The error
// return is for SPAWN failures only; a started process that exits non-zero
// reports through code. GOWORK=off keeps a stray workspace file above the
// scratch dir from leaking into tree builds. It runs with no wall-clock bound —
// use runToolCtx for a subprocess that must be time-boxed.
func runTool(dir string, extraEnv []string, name string, args ...string) (stdout, stderr string, code int, err error) {
	return runToolCtx(context.Background(), dir, extraEnv, name, args...)
}

// runToolCtx is runTool bounded by ctx: if ctx's deadline fires, the process
// (and its children) are killed and the call returns a NON-nil error wrapping
// context.DeadlineExceeded with code -1 — a hang is surfaced as a hard failure,
// never mistaken for a clean exit. Spawn failures likewise return err with code
// -1; a started process that exits non-zero reports through code with a nil err.
func runToolCtx(ctx context.Context, dir string, extraEnv []string, name string, args ...string) (stdout, stderr string, code int, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOWORK=off"), extraEnv...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	runErr := cmd.Run()
	if runErr != nil {
		// A wall-clock timeout is a HANG, not a spawn error nor a clean exit.
		// Surface it explicitly so the stage-3 caller fails the proposal closed.
		if ctxErr := ctx.Err(); errors.Is(ctxErr, context.DeadlineExceeded) {
			return outBuf.String(), errBuf.String(), -1,
				fmt.Errorf("subprocess %q exceeded its wall-clock timeout: %w", name, ctxErr)
		}
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
