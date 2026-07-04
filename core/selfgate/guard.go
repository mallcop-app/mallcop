// Package selfgate is the STATIC INVARIANT GUARD for the self-extension loop
// (K3, rd mallcoppro-154). It is a diff-checker: given a base ref and a head
// ref in a git repo, it enumerates every changed path and rejects any change
// that could NARROW what the detection committee sees.
//
// THE INVARIANT (consensus-not-rules, the #1 project invariant): the
// self-extension loop may only ever WIDEN what the committee sees. The loop
// authors DATA (tuning knobs, escalate routes, exam scenarios); it never
// touches the human-written interpreters, the committee mechanics, the grader,
// or the guard itself. This package is the enforcement point — a proposal diff
// that violates any rule below is rejected before anything merges.
//
// Enforcement layers (this guard is layer one, purely static):
//
//   - PROTECTED PATHS — any Add/Modify/Delete under the committee, pipeline,
//     lint, tools, eval (the grader is out of the agent's reach), inference,
//     the stable pkg contracts, cmd, CI config, the module files, and this
//     package itself (the guard protects the guard) is rejected outright.
//   - GO SOURCE DEFAULT-DENY (the catch-all safety floor) — ANY .go path not
//     terminally handled above is rejected: Modify/Delete of any existing .go
//     file, and Add of a .go file anywhere EXCEPT the single sanctioned
//     additive detector lane (a NEW own-package file under
//     core/detect/authored/<name>/). This floor does NOT depend on the
//     enumerated protected prefixes, so a decision-path package the list never
//     named (core/observe's force-escalate predicates, core/toolrun's cascade
//     wiring, core/store, core/connect, internal/**, non-contract pkg/**) is
//     frozen ANYWAY — the loop authors DATA, never code, so a Go change always
//     needs a human.
//   - FROZEN-BUT-EXTENSIBLE trees — existing exam scenarios are frozen (M/D
//     rejected) while purely additive new scenario files pass THIS layer. The
//     AUTHORED-DETECTOR CODE LANE (K7 L1) is the OWN-PACKAGE tree
//     core/detect/authored/<name>/: a NEW file there passes this layer (gated
//     downstream by the K2a import allow-list and the K7 L3 shape AST gate),
//     while an existing authored detector is frozen. A NEW file DIRECTLY under
//     core/detect/ is `package detect`, the SHARED framework package — its
//     init() could mutate a sibling detector's unexported state (the §5 L1
//     hazard), so it is FROZEN (human-only), NOT the lane. The registration
//     aggregator core/detect/authored/registry.go accepts only append-only
//     blank imports of packages under core/detect/authored/; every other change
//     to it fails closed.
//   - SEMANTIC WIDEN RULES — detectors/*.yaml tuning data and
//     agents/rules/operator-decisions.yaml may be MODIFIED, but the contents
//     are parsed (base and head) and only pure widens pass. Anything
//     unrecognized — including an unknown top-level section or field — fails
//     closed.
//
// DESIGN DECISION (no mechanical-pair exception): a proposal that widens
// agents/rules/operator-decisions.yaml is ADDITIVE at this layer (new routes /
// alias additions only; the widen-only rules above are the always-on floor).
// As DEFENCE-IN-DEPTH, core/tools/lookup_rules.go pins the sha256 of that
// corpus in the Go constant expectedOperatorRulesSHA256, and core/tools/** is a
// protected path the proposal cannot touch. WHEN sha256 enforcement is enabled
// in the deployment env — MALLCOP_RULES_SHA256_ENFORCE set truthy, or an
// explicit MALLCOP_RULES_SHA256 digest (the check is OPT-IN and OFF by default,
// see core/tools/lookup_rules.go verifyOperatorRulesChecksum) — the unchanged
// pin makes the runtime corpus SHA check fire, so the widened corpus only takes
// effect after a HUMAN reviews the widen and re-pins. There is deliberately no
// "the pair moved together mechanically, wave it through" exception. This pin
// coupling is a deployment-conditional defence, not an unconditional guarantee.
package selfgate

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
)

// GuardFinding is one rejected change. Path is the repo-relative path that
// tripped the rule, Rule is the stable rule identifier, Detail is the
// human-readable explanation.
type GuardFinding struct {
	Path   string `json:"path"`
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

// Stable rule identifiers carried on GuardFinding.Rule.
const (
	// RuleProtectedPath — any A/M/D under a protected path (committee,
	// pipeline, grader, tools, guard, contracts, cmd, CI, module files).
	RuleProtectedPath = "protected-path"
	// RuleDetectCodeFrozen — M/D on an existing core/detect/*.go file.
	RuleDetectCodeFrozen = "detect-code-frozen"
	// RuleCodeFrozen — the Go source DEFAULT-DENY catch-all: Modify/Delete of
	// ANY existing .go file, or Add of a .go file OUTSIDE the sanctioned
	// additive detector lane (a new file directly under core/detect/). The
	// self-extension loop authors DATA, not code; any other Go change requires
	// human review. This is the safety floor that does NOT depend on the
	// enumerated protectedPrefixes, so a decision-path package the list forgot
	// (core/observe, core/toolrun, core/store, core/connect, …) is frozen anyway.
	RuleCodeFrozen = "code-frozen"
	// RuleScenarioFrozen — M/D on an existing exam scenario file.
	RuleScenarioFrozen = "scenario-frozen"
	// RuleCorpusPinPairing — corpus.pin changed without the required
	// additive-only scenario accompaniment (or added/deleted outright).
	RuleCorpusPinPairing = "corpus-pin-pairing"
	// RuleDetectorDataWidenOnly — detectors/** data change that is not a pure
	// widen (deletion, non-YAML modification, removed/changed element, or an
	// unrecognized structure — fail closed).
	RuleDetectorDataWidenOnly = "detector-data-widen-only"
	// RuleOperatorDecisionsWidenOnly — agents/rules/operator-decisions.yaml
	// change that is not a pure widen (route removal/mutation, metadata_match
	// narrowing, any rules: change, or an unrecognized shape — fail closed).
	RuleOperatorDecisionsWidenOnly = "operator-decisions-widen-only"
	// RuleDiffUnrecognized — a diff entry the guard does not understand
	// (typechange, unmerged, ...). Fail closed: unknown means rejected.
	RuleDiffUnrecognized = "diff-unrecognized"
	// RuleAuthoredRegistry — a change to the authored-detector registration
	// aggregator (core/detect/authored/registry.go) that is not an append-only
	// blank import of a package under core/detect/authored/. The registry is
	// human-bootstrapped once (A/D rejected); thereafter only append-only
	// blank-import growth is allowed.
	RuleAuthoredRegistry = "authored-registry-append-only"
)

// Paths with special (non-prefix) handling.
const (
	operatorDecisionsPath = "agents/rules/operator-decisions.yaml"
	corpusPinPath         = "exams/scenarios/corpus.pin"
	scenariosPrefix       = "exams/scenarios/"
	detectorsPrefix       = "detectors/"
	detectGoDir           = "core/detect"
	// authoredPrefix is the OWN-PACKAGE authored-detector code lane: a NEW .go
	// file under core/detect/authored/<name>/ is the sanctioned additive lane
	// (gated downstream by K2a import allow-list + K7 shape AST). Its own
	// package makes the §5 L1 same-package-mutation hazard structurally
	// impossible.
	authoredPrefix = "core/detect/authored/"
	// authoredRegistryPath is the human-bootstrapped registration aggregator;
	// the ONLY file allowed to sit directly in the authored/ package, and only
	// append-only blank-import modifications to it pass.
	authoredRegistryPath = "core/detect/authored/registry.go"
)

// protectedPrefixes deny ANY Add/Modify/Delete beneath them. This is the
// agent-must-never-touch set: the committee and its knobs (core/agent — incl.
// DefaultConsensusRuns and the consensus temperature), the pipeline, the lint
// gates, this guard, the human-written tool interpreters (core/tools — incl.
// lookup_rules.go and its expectedOperatorRulesSHA256 pin), the grader
// (core/eval — out of the agent's reach, rd 71c), inference, the stable event/
// finding/baseline contracts, every binary entrypoint, and CI.
//
// mallcoppro-519 moved the runX command logic out of cmd/mallcop into the
// importable cli/ package. cli/ is deliberately NOT enumerated here: it does
// not need to be — the RuleCodeFrozen default-deny floor below (Go source
// outside the additive core/detect/ detector lane) already freezes every
// existing cli/*.go file and rejects any new one, independent of this list.
var protectedPrefixes = []string{
	"core/agent/",
	"core/pipeline/",
	"core/lint/",
	"core/selfgate/",
	"core/tools/",
	"core/eval/",
	"core/inference/",
	"pkg/event/",
	"pkg/finding/",
	"pkg/baseline/",
	"cmd/",
	".github/",
}

// protectedFiles are exact repo-relative paths denied for ANY change.
var protectedFiles = map[string]bool{
	"go.mod": true,
	"go.sum": true,
}

// change is one parsed `git diff --name-status` entry.
type change struct {
	status byte // 'A', 'M' or 'D' (anything else fails closed upstream)
	path   string
}

// Guard statically checks the diff between baseRef and headRef in the git
// repository containing repoRoot (any directory inside the work tree works —
// git resolves the tree, and both name-status output and <ref>:<path> blob
// addressing are repo-root-relative). It returns one GuardFinding per rejected
// change and an error only for operational failures (git unavailable, refs
// unresolvable). An unparseable or unrecognized proposal is a FINDING, not an
// error: the guard fails closed.
//
// customerTreeMode (mallcoppro-97b, orchestrator ruling) switches the .go
// arm under detectors/<name>/ from the RuleCodeFrozen blanket deny to the
// sidecar-shape AST gate (sidecarshape.go). It is set by ValidateProposal as
// opts.ExamRepo != "" — i.e. by the TRUSTED CALLER's own invocation (the
// engine/operator passing --exam-repo / --customer-tree), NEVER inferred from
// the proposal tree's own contents; an untrusted tree cannot opt itself into
// the looser rules merely by looking customer-shaped. false reproduces the
// prior (mallcoppro-72d) behavior byte-for-byte — the two 72d regression
// tests (TestGuard_RejectsNewGoFileAddedUnderDetectors,
// TestGuard_RejectsModifiedGoFileUnderDetectors) call Guard through the
// fixture's f.guard() helper, which passes false and is unchanged by this
// option.
func Guard(repoRoot, baseRef, headRef string, customerTreeMode bool) ([]GuardFinding, error) {
	changes, err := listChanges(repoRoot, baseRef, headRef)
	if err != nil {
		return nil, err
	}

	var findings []GuardFinding

	// The corpus.pin repin-pairing rule needs whole-changeset context: a pin
	// modification is legitimate ONLY when accompanied by additive-only
	// scenario changes (new scenario files added, nothing existing touched).
	scenarioAdds := 0
	scenarioMutations := 0
	for _, c := range changes {
		if c.path == corpusPinPath || !strings.HasPrefix(c.path, scenariosPrefix) {
			continue
		}
		if c.status == 'A' {
			scenarioAdds++
		} else {
			scenarioMutations++
		}
	}

	// CUSTOMER-TREE MODE pre-scan: collect every detectors/ subdirectory
	// touched by a .go change in this diff. Shape-checking is a WHOLE-PACKAGE
	// property (imports, the one func main(), no init() — ACROSS every file
	// in the directory), so it cannot be judged file-by-file inside the
	// per-change loop below; that loop SKIPS .go files under detectors/
	// entirely when customerTreeMode is set (see the detectorsPrefix case),
	// and the pass after the loop evaluates each touched directory exactly
	// once against its HEAD state.
	var sidecarDirs []string
	if customerTreeMode {
		seen := map[string]bool{}
		for _, c := range changes {
			if !strings.HasPrefix(c.path, detectorsPrefix) || !strings.HasSuffix(c.path, ".go") {
				continue
			}
			dir := path.Dir(c.path)
			if !seen[dir] {
				seen[dir] = true
				sidecarDirs = append(sidecarDirs, dir)
			}
		}
		sort.Strings(sidecarDirs)
	}

	for _, c := range changes {
		switch {
		case c.status != 'A' && c.status != 'M' && c.status != 'D':
			findings = append(findings, GuardFinding{
				Path:   c.path,
				Rule:   RuleDiffUnrecognized,
				Detail: fmt.Sprintf("diff status %q is not one of A/M/D — fail closed", string(c.status)),
			})

		case isProtected(c.path):
			findings = append(findings, GuardFinding{
				Path:   c.path,
				Rule:   RuleProtectedPath,
				Detail: fmt.Sprintf("%s on a protected path: the self-extension loop may not touch the committee, pipeline, lint, tools, grader, inference, contracts, cmd, CI, module files, or the guard itself", statusWord(c.status)),
			})

		case c.path == operatorDecisionsPath:
			if c.status != 'M' {
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleOperatorDecisionsWidenOnly,
					Detail: fmt.Sprintf("%s of the operator-decision corpus is not a widen — only in-place pure widens (new routes, alias additions) are expressible", statusWord(c.status)),
				})
				continue
			}
			base, head, err := readBlobs(repoRoot, baseRef, headRef, c.path)
			if err != nil {
				return nil, err
			}
			findings = append(findings, checkOperatorDecisions(c.path, base, head)...)

		case c.path == corpusPinPath:
			switch {
			case c.status != 'M':
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleCorpusPinPairing,
					Detail: fmt.Sprintf("%s of the corpus integrity pin is never a valid proposal — only a repin paired with additive-only scenario changes", statusWord(c.status)),
				})
			case scenarioMutations > 0:
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleCorpusPinPairing,
					Detail: "corpus.pin repin accompanied by modifications/deletions of existing scenarios — the pairing rule requires additive-only scenario changes",
				})
			case scenarioAdds == 0:
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleCorpusPinPairing,
					Detail: "bare corpus.pin modification with no added scenario files — a repin must accompany additive scenario changes, never stand alone",
				})
			}

		case strings.HasPrefix(c.path, scenariosPrefix):
			if c.status != 'A' {
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleScenarioFrozen,
					Detail: fmt.Sprintf("%s of an existing exam scenario: the labeled corpus is frozen; only additive new scenario files are allowed", statusWord(c.status)),
				})
			}

		case strings.HasPrefix(c.path, detectorsPrefix):
			switch {
			case strings.HasSuffix(c.path, ".go") && customerTreeMode:
				// CUSTOMER-TREE MODE (mallcoppro-97b, orchestrator ruling): handled
				// by the aggregated per-directory sidecarDirs pass AFTER this loop,
				// not here -- a single changed file cannot be judged in isolation
				// (the shape gate needs every file in the directory: the whole
				// import surface, the one func main(), etc). This arm exists only
				// to prevent the default-deny arm below from ALSO firing for the
				// same path.
			case strings.HasSuffix(c.path, ".go"):
				// mallcoppro-72d (the 7ee7 live-leg probe HOLE): a .go path
				// under detectors/ is NOT tuning DATA -- it is customer-tree
				// wasm-sidecar detector CODE (cli/deployrepo.go scaffolds
				// detectors/<name>/main.go, built GOOS=wasip1 GOARCH=wasm and
				// loaded by detecthost). Before this arm existed, EVERY status
				// (A/M/D) of a .go path here fell through the A/M/D switch
				// below untouched -- an Add matched none of its arms and
				// PASSED UNCHECKED, contradicting the package doc's claim
				// (line ~19) that any non-authored .go Add is default-denied.
				// detectors/ has no sanctioned Go code lane of its own: the
				// ONLY additive authored-detector lane this guard recognizes
				// is the own-package tree core/detect/authored/<name>/, whose
				// shape is init()+detect.Register -- structurally
				// incompatible with a wasip1 sidecar's `package main` +
				// detectorhost.Run(T{}) shape, so the K7 L3 AST shape gate
				// cannot be reused here (it would hard-reject every
				// legitimate sidecar for having zero init()s). Rather than
				// either silently pass (the hole) or force a mismatched
				// check that always fails legitimate code, this fails closed
				// exactly like the GO SOURCE DEFAULT-DENY floor below: ANY
				// A/M/D of a .go file under detectors/ requires human review.
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleCodeFrozen,
					Detail: fmt.Sprintf("%s of a .go file under detectors/: detectors/ has no sanctioned Go code lane (the only additive authored-detector lane is core/detect/authored/<name>/, whose init()+detect.Register shape does not fit a wasip1-sidecar main.go); Go source here requires human review", statusWord(c.status)),
				})
			case c.status == 'D':
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleDetectorDataWidenOnly,
					Detail: "deleting detector tuning data removes everything it widened — narrowing",
				})
			case c.status == 'M' && !isYAMLPath(c.path):
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleDetectorDataWidenOnly,
					Detail: "only YAML tuning data under detectors/ has a widen rule; modification of anything else fails closed",
				})
			case c.status == 'M':
				base, head, err := readBlobs(repoRoot, baseRef, headRef, c.path)
				if err != nil {
					return nil, err
				}
				// The widen SEMANTICS differ by data file shape, so dispatch on
				// the filename. tuning.yaml (and any unknown data file, which
				// checkWidenOnlyYAML still fails closed on) is section→field→list
				// widen. learned_mappings.yaml is source→action→SCALAR, which does
				// not fit that contract. Each gets its own checker; the default
				// still fails closed on unknown sections.
				switch path.Base(c.path) {
				case "learned_mappings.yaml":
					findings = append(findings, checkMappingWidenOnly(c.path, base, head)...)
				default:
					findings = append(findings, checkWidenOnlyYAML(c.path, base, head)...)
				}
			}
			// 'A' of a non-.go path passes: a brand-new data file widens by
			// definition at this layer (its loader strictly rejects
			// non-additive fields). 'A' of a .go path is handled by the
			// dedicated arm above, NOT here.

		case c.path == authoredRegistryPath:
			// The authored-detector registration aggregator. Bootstrapped once
			// by a human (A/D rejected); thereafter ONLY append-only blank
			// imports of packages under core/detect/authored/ pass. Anything
			// else — a func, a non-blank import, a removed/rewritten import, a
			// changed package clause — fails closed.
			if c.status != 'M' {
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleAuthoredRegistry,
					Detail: fmt.Sprintf("%s of the authored-detector registry: it is human-bootstrapped once and thereafter only append-only blank imports are allowed", statusWord(c.status)),
				})
				continue
			}
			base, head, err := readBlobs(repoRoot, baseRef, headRef, c.path)
			if err != nil {
				return nil, err
			}
			findings = append(findings, checkAuthoredRegistryAppendOnly(c.path, base, head)...)

		case strings.HasPrefix(c.path, authoredPrefix) && strings.HasSuffix(c.path, ".go"):
			// The OWN-PACKAGE authored-detector code lane. rel is the path
			// beneath core/detect/authored/.
			rel := strings.TrimPrefix(c.path, authoredPrefix)
			// The sanctioned own-package lane is EXACTLY one path segment before
			// the filename: rel of the form "<name>/<file>.go" (one slash). This
			// mirrors the registry's isAuthoredDetectorImportPath one-segment rule
			// AND the shape gate's documented one-level design — the guard-allowed
			// change surface and the shape-checked surface must not diverge.
			switch strings.Count(rel, "/") {
			case 0:
				// A .go file sitting DIRECTLY in the aggregator package (only
				// registry.go is allowed there, handled above) — not a detector
				// package. Freeze it.
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleCodeFrozen,
					Detail: fmt.Sprintf("%s of a .go file directly in the authored aggregator package: only registry.go and per-detector own-package subdirectories are allowed under core/detect/authored/", statusWord(c.status)),
				})
				continue
			case 1:
				// rel is <name>/<file>.go — an own-package authored detector,
				// handled below.
			default:
				// rel is <name>/<sub>/.../<file>.go — a NESTED authored package.
				// It compiles into cmd/mallcop through the aggregator's transitive
				// import graph yet lies OUTSIDE the one-level own-package lane the
				// shape gate and import allow-list are designed around. Freeze it:
				// the guard's allowed surface must never exceed what the downstream
				// gates shape-check.
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleCodeFrozen,
					Detail: fmt.Sprintf("%s of a .go file nested below core/detect/authored/<name>/: authored detectors are single-level own packages (core/detect/authored/<name>/<file>.go); deeper packages are not a sanctioned lane", statusWord(c.status)),
				})
				continue
			}
			// rel is <name>/<file>.go — an own-package authored detector. A NEW
			// file is the sanctioned additive lane (gated downstream by the
			// K2a import allow-list and the K7 shape AST gate). An existing
			// authored detector is FROZEN once merged.
			if c.status != 'A' {
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleDetectCodeFrozen,
					Detail: fmt.Sprintf("%s of an existing authored detector: once merged, core/detect/authored/<name>/ code is frozen; only NEW own-package detector files are the additive lane", statusWord(c.status)),
				})
			}

		case path.Dir(c.path) == detectGoDir && strings.HasSuffix(c.path, ".go"):
			// A .go file DIRECTLY under core/detect/ is `package detect` — the
			// SHARED framework package. THE §5 L1 BREAK: a new file here runs
			// its init() alongside every sibling detector and could mutate their
			// unexported state. It is human-only now. Add/Modify/Delete are ALL
			// frozen — the sanctioned additive lane is the own-package
			// core/detect/authored/<name>/ tree handled above, not this package.
			findings = append(findings, GuardFinding{
				Path:   c.path,
				Rule:   RuleDetectCodeFrozen,
				Detail: fmt.Sprintf("%s of core/detect/*.go: the shared framework `detect` package is frozen (a new file here is package detect and its init() could mutate sibling detectors' state — the §5 L1 hazard); the additive lane is core/detect/authored/<name>/", statusWord(c.status)),
			})

		case strings.HasSuffix(c.path, ".go"):
			// GO SOURCE DEFAULT-DENY (the catch-all safety floor). Any .go path
			// that reaches here was NOT terminally handled above: it is neither
			// a protected package nor the sanctioned additive detector lane
			// (a new file directly under core/detect/, handled by the case
			// above). Modify/Delete of an existing .go file and Add of a .go
			// file anywhere else is a FINDING — the loop authors DATA, not
			// code. Critically this does NOT rely on protectedPrefixes, so a
			// decision-path package the prefix list never enumerated
			// (core/observe's force-escalate predicates, core/toolrun's cascade
			// wiring, core/store, core/connect, internal/**, non-contract
			// pkg/**) is frozen ANYWAY, and a NEW .go file in a SUBDIRECTORY
			// under core/detect (core/detect/evil/…) is code — not the lane.
			findings = append(findings, GuardFinding{
				Path:   c.path,
				Rule:   RuleCodeFrozen,
				Detail: fmt.Sprintf("%s of Go source outside the additive core/detect/ detector lane: the self-extension loop authors DATA, not code; modification/addition of Go source requires human review", statusWord(c.status)),
			})
		}
		// Anything else passes THIS layer: the guard enforces the enumerated
		// invariants; unlisted non-.go paths (docs, README, ...) are gated
		// elsewhere.
	}

	// CUSTOMER-TREE MODE: shape-check every touched detectors/ directory
	// collected in the pre-scan above, against its HEAD state. A directory
	// with zero production .go files left at head (the whole detector was
	// deleted, or every change was itself a delete leaving nothing) is
	// SKIPPED, not rejected — deleting a detector is data-loss-free and
	// human-reviewable at PR time (ORCHESTRATOR RULING mallcoppro-97b); a
	// PARTIAL delete (some files removed, others remain) still re-derives and
	// shape-checks the SURVIVING files, since removing one file of a
	// multi-file package can itself break the shape (e.g. orphaning the
	// detector impl from main()).
	for _, dir := range sidecarDirs {
		findings = append(findings, checkSidecarDetectorDir(repoRoot, headRef, dir)...)
	}

	return findings, nil
}

// checkSidecarDetectorDir shape-checks ONE detectors/<name>/ directory's
// production .go files as they exist at headRef, converting each
// sidecarshape.go Violation into a GuardFinding under the single dedicated
// RuleSidecarShape rule id (the sub-rule is folded into Detail, mirroring
// exactly how validate.go folds authoredast.go's shape Violations into
// RuleAuthoredShape findings).
func checkSidecarDetectorDir(repoRoot, headRef, dir string) []GuardFinding {
	paths, err := listDirGoFiles(repoRoot, headRef, dir)
	if err != nil {
		return []GuardFinding{{
			Path:   dir,
			Rule:   RuleSidecarShape,
			Detail: fmt.Sprintf("cannot list %s at %.12s (%v) — fail closed", dir, headRef, err),
		}}
	}
	if len(paths) == 0 {
		// Nothing left at head under this directory: the whole detector was
		// removed. Allow (see the call site's comment).
		return nil
	}

	sources := make([][]byte, len(paths))
	for i, p := range paths {
		blob, err := readBlob(repoRoot, headRef, p)
		if err != nil {
			return []GuardFinding{{
				Path:   p,
				Rule:   RuleSidecarShape,
				Detail: fmt.Sprintf("cannot read %s at %.12s (%v) — fail closed", p, headRef, err),
			}}
		}
		sources[i] = blob
	}

	violations := CheckSidecarDetectorShape(paths, sources)
	findings := make([]GuardFinding, 0, len(violations))
	for _, v := range violations {
		findings = append(findings, GuardFinding{
			Path:   v.File,
			Rule:   RuleSidecarShape,
			Detail: v.Rule + ": " + v.Detail,
		})
	}
	return findings
}

// listDirGoFiles returns the sorted, repo-relative paths of every production
// .go file (isProductionGoFile — no _test.go) directly under dir at ref,
// via `git ls-tree` (NON-recursive: dir is a flat "one package dir per
// detector" leaf per the sidecar shape contract — a nested subdirectory is
// simply never discovered as part of THIS directory's package, and any .go
// file a proposal adds under such a nested path is itself a SEPARATE change
// matching detectorsPrefix, so it gets its OWN sidecarDirs entry and its OWN
// shape check, which a real nested helper package fails on the package-clause
// rule (it would have to be a non-`main` package to be importable, and this
// gate demands `package main`) or on the import allow-list (a customer-module
// import path for the nested package is not on it) — see sidecarshape.go's
// file doc for the fuller nested-package threat-model note. A ref with no
// such path returns an empty, non-error result (git ls-tree exits 0 with
// empty output) — the "whole detector deleted" case the caller treats as
// allow.
func listDirGoFiles(repoRoot, ref, dir string) ([]string, error) {
	out, err := runGit(repoRoot, "ls-tree", "--name-only", "-z", ref, "--", dir+"/")
	if err != nil {
		return nil, fmt.Errorf("git ls-tree %s %s: %w: %s", ref, dir, err, out)
	}
	// `git ls-tree --name-only <ref> -- <dir>/` (no -r) already prints each
	// matching entry's path relative to the REPO ROOT (the normal
	// `git ls-tree <tree-ish> <path>/` one-level-listing behavior), not
	// relative to dir — do not re-prefix with dir.
	var files []string
	for _, name := range strings.Split(out, "\x00") {
		if name == "" {
			continue
		}
		if isProductionGoFile(name) {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

// readBlob reads ref's content of repo-relative path p via `git show
// <ref>:<path>` — the single-ref half of readBlobs, used where only the head
// state matters (shape-checking has no base/head diff; it is a HEAD-state
// property).
func readBlob(repoRoot, ref, p string) ([]byte, error) {
	out, err := runGit(repoRoot, "show", ref+":"+p)
	if err != nil {
		return nil, fmt.Errorf("selfgate: git show %s:%s: %w: %s", ref, p, err, out)
	}
	return []byte(out), nil
}

// isProtected reports whether p is under a protected prefix or is a protected
// exact file.
func isProtected(p string) bool {
	if protectedFiles[p] {
		return true
	}
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func isYAMLPath(p string) bool {
	return strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")
}

func statusWord(s byte) string {
	switch s {
	case 'A':
		return "addition"
	case 'M':
		return "modification"
	case 'D':
		return "deletion"
	}
	return fmt.Sprintf("status %q", string(s))
}

// listChanges enumerates base→head changes via
// `git diff --name-status --no-renames -z` (NUL-separated, so exotic file
// names cannot corrupt parsing). No unified-diff parsing anywhere: the guard
// works from name-status plus whole-blob reads only.
func listChanges(repoRoot, baseRef, headRef string) ([]change, error) {
	out, err := runGit(repoRoot, "diff", "--name-status", "--no-renames", "-z", baseRef, headRef)
	if err != nil {
		return nil, fmt.Errorf("selfgate: git diff %s..%s: %v: %s", baseRef, headRef, err, out)
	}
	fields := strings.Split(out, "\x00")
	var changes []change
	for i := 0; i+1 < len(fields); i += 2 {
		status := fields[i]
		p := fields[i+1]
		if status == "" || p == "" {
			return nil, fmt.Errorf("selfgate: malformed name-status entry %q/%q", status, p)
		}
		changes = append(changes, change{status: status[0], path: p})
	}
	return changes, nil
}

// readBlobs reads the base and head contents of a repo-relative path via
// `git show <ref>:<path>`. Both blobs must exist — callers only reach here for
// 'M' entries.
func readBlobs(repoRoot, baseRef, headRef, p string) (base, head []byte, err error) {
	baseOut, err := runGit(repoRoot, "show", baseRef+":"+p)
	if err != nil {
		return nil, nil, fmt.Errorf("selfgate: git show %s:%s: %v: %s", baseRef, p, err, baseOut)
	}
	headOut, err := runGit(repoRoot, "show", headRef+":"+p)
	if err != nil {
		return nil, nil, fmt.Errorf("selfgate: git show %s:%s: %v: %s", headRef, p, err, headOut)
	}
	return []byte(baseOut), []byte(headOut), nil
}

// checkAuthoredRegistryAppendOnly is the narrow structured allow for a
// modification of core/detect/authored/registry.go. It parses BOTH the base and
// head blobs and passes ONLY when: both are `package authored`; the head file
// contains nothing but import declarations (no funcs/vars/types/consts); every
// base import survives verbatim into head (no removals or rewrites); and every
// import ADDED at head is a BLANK import (`_`) of a package under
// core/detect/authored/. Anything else — including an unparseable file — fails
// closed with RuleAuthoredRegistry.
func checkAuthoredRegistryAppendOnly(p string, base, head []byte) []GuardFinding {
	fail := func(detail string) []GuardFinding {
		return []GuardFinding{{Path: p, Rule: RuleAuthoredRegistry, Detail: detail}}
	}

	fset := token.NewFileSet()
	bf, berr := parser.ParseFile(fset, "base/registry.go", base, parser.ParseComments)
	hf, herr := parser.ParseFile(fset, "head/registry.go", head, parser.ParseComments)
	if berr != nil || herr != nil {
		return fail(fmt.Sprintf("authored registry unparseable (base: %v; head: %v) — fail closed", berr, herr))
	}
	if bf.Name.Name != "authored" || hf.Name.Name != "authored" {
		return fail(fmt.Sprintf("authored registry package clause changed or unexpected (base %q, head %q) — must remain package authored", bf.Name.Name, hf.Name.Name))
	}
	if bad := nonImportDecl(hf); bad != "" {
		return fail("authored registry may contain only import declarations, found " + bad)
	}

	baseSet := importSpecKeys(bf)
	for _, spec := range importSpecs(hf) {
		if baseSet[spec.key] {
			delete(baseSet, spec.key) // matched a surviving base import
			continue
		}
		// An import present at head but not base: it must be an append-only
		// blank import of an authored detector package.
		if !spec.blank {
			return fail(fmt.Sprintf("added registry import %q is not a blank import — appends must be `_ \".../core/detect/authored/<name>\"`", spec.path))
		}
		if !isAuthoredDetectorImportPath(spec.path) {
			return fail(fmt.Sprintf("added blank import %q is not a package under core/detect/authored/", spec.path))
		}
	}
	if len(baseSet) > 0 {
		return fail("an existing registry import was removed or rewritten — the aggregator is append-only")
	}
	return nil
}

// importSpec is one parsed import: its normalized identity key (alias+path),
// its path, and whether it is a blank (`_`) import.
type importSpec struct {
	key   string
	path  string
	blank bool
}

// importSpecs returns every import in f as an importSpec.
func importSpecs(f *ast.File) []importSpec {
	var specs []importSpec
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		}
		specs = append(specs, importSpec{
			key:   name + "|" + path,
			path:  path,
			blank: name == "_",
		})
	}
	return specs
}

// importSpecKeys returns the set of import identity keys in f.
func importSpecKeys(f *ast.File) map[string]bool {
	set := map[string]bool{}
	for _, s := range importSpecs(f) {
		set[s.key] = true
	}
	return set
}

// nonImportDecl returns a human description of the first top-level declaration
// in f that is NOT an import, or "" if every declaration is an import.
func nonImportDecl(f *ast.File) string {
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok != token.IMPORT {
				return "a " + d.Tok.String() + " declaration"
			}
		case *ast.FuncDecl:
			return "a func declaration"
		default:
			return "a non-import declaration"
		}
	}
	return ""
}

// isAuthoredDetectorImportPath reports whether p addresses a package directly
// under core/detect/authored/ (exactly one path segment after the marker, i.e.
// .../core/detect/authored/<name>). Module-prefix agnostic — the K2a import
// allow-list independently constrains the concrete import graph.
func isAuthoredDetectorImportPath(p string) bool {
	const marker = "/core/detect/authored/"
	i := strings.Index(p, marker)
	if i < 0 {
		return false
	}
	rest := p[i+len(marker):]
	return rest != "" && !strings.Contains(rest, "/")
}

// runGit is the hermetic git exec chokepoint — the SAME discipline as
// core/eval's scenario seeding and core/store: fixed identity, no global or
// system config bleed, no terminal prompts. Every git invocation in this
// package goes through here, so the guard's view of the diff cannot be skewed
// by an operator's (or an attacker's) git configuration.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=mallcop-selfgate",
		"GIT_AUTHOR_EMAIL=selfgate@mallcop.app",
		"GIT_COMMITTER_NAME=mallcop-selfgate",
		"GIT_COMMITTER_EMAIL=selfgate@mallcop.app",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}
