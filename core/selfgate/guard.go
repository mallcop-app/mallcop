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
//     additive detector lane (a NEW file directly under core/detect/). This
//     floor does NOT depend on the enumerated protected prefixes, so a
//     decision-path package the list never named (core/observe's
//     force-escalate predicates, core/toolrun's cascade wiring, core/store,
//     core/connect, internal/**, non-contract pkg/**) is frozen ANYWAY — the
//     loop authors DATA, never code, so a Go change always needs a human.
//   - FROZEN-BUT-EXTENSIBLE trees — existing exam scenarios are frozen (M/D
//     rejected) while purely additive new scenario files pass THIS layer, and
//     a NEW detector file DIRECTLY under core/detect/ passes this layer (the
//     additive code lane, gated by other layers). A .go file in a SUBDIRECTORY
//     under core/detect is NOT the lane — it is code-frozen by the floor above.
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
	"os"
	"os/exec"
	"path"
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
)

// Paths with special (non-prefix) handling.
const (
	operatorDecisionsPath = "agents/rules/operator-decisions.yaml"
	corpusPinPath         = "exams/scenarios/corpus.pin"
	scenariosPrefix       = "exams/scenarios/"
	detectorsPrefix       = "detectors/"
	detectGoDir           = "core/detect"
)

// protectedPrefixes deny ANY Add/Modify/Delete beneath them. This is the
// agent-must-never-touch set: the committee and its knobs (core/agent — incl.
// DefaultConsensusRuns and the consensus temperature), the pipeline, the lint
// gates, this guard, the human-written tool interpreters (core/tools — incl.
// lookup_rules.go and its expectedOperatorRulesSHA256 pin), the grader
// (core/eval — out of the agent's reach, rd 71c), inference, the stable event/
// finding/baseline contracts, every binary entrypoint, and CI.
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
func Guard(repoRoot, baseRef, headRef string) ([]GuardFinding, error) {
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
				findings = append(findings, checkWidenOnlyYAML(c.path, base, head)...)
			}
			// 'A' passes: a brand-new data file widens by definition at this
			// layer (its loader strictly rejects non-additive fields).

		case path.Dir(c.path) == detectGoDir && strings.HasSuffix(c.path, ".go"):
			if c.status != 'A' {
				findings = append(findings, GuardFinding{
					Path:   c.path,
					Rule:   RuleDetectCodeFrozen,
					Detail: fmt.Sprintf("%s of existing detector code: core/detect/*.go is frozen; new additive detector files are the gated code lane", statusWord(c.status)),
				})
			}

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

	return findings, nil
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
