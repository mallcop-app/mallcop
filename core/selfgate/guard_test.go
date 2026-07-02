// guard_test.go — PROOF tests for the K3 static invariant guard.
//
// Invariant 10 (ground-source testing): the rejection proofs run against REAL
// repo content, not synthetic strawmen. Every fixture repo is seeded by
// COPYING THE REAL FILES from the repository under test (located by walking up
// to go.mod), then the "proposal" mutates that real content the way a
// compromised or drifting self-extension loop would. If the real files change
// shape, replaceOnce fails loudly and the proof mutation must be updated — the
// proofs never silently degrade into testing fabricated content.
package selfgate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- fixture: temp git repos seeded from the real repo ----------------------

// repoUnderTest locates the real repository root by walking up from the test's
// working directory to go.mod.
func repoUnderTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
}

// fixture is a temp git repo the tests seed (from real files), commit, mutate,
// and run Guard over.
type fixture struct {
	t    *testing.T
	dir  string // temp git repo
	root string // real repo root (source of the copied files)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "init", "-q")
	return &fixture{t: t, dir: dir, root: repoUnderTest(t)}
}

// copyReal copies the REAL file at rel from the repo under test into the
// fixture repo at the same path and returns its content for mutation.
func (f *fixture) copyReal(rel string) string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(rel)))
	if err != nil {
		f.t.Fatalf("copy real %s: %v", rel, err)
	}
	f.write(rel, string(data))
	return string(data)
}

func (f *fixture) write(rel, content string) {
	f.t.Helper()
	abs := filepath.Join(f.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		f.t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		f.t.Fatalf("write %s: %v", rel, err)
	}
}

func (f *fixture) remove(rel string) {
	f.t.Helper()
	if err := os.Remove(filepath.Join(f.dir, filepath.FromSlash(rel))); err != nil {
		f.t.Fatalf("remove %s: %v", rel, err)
	}
}

// commit stages everything and commits, returning the commit hash.
func (f *fixture) commit(msg string) string {
	f.t.Helper()
	mustGit(f.t, f.dir, "add", "-A")
	mustGit(f.t, f.dir, "commit", "-q", "--no-verify", "-m", msg)
	return strings.TrimSpace(mustGit(f.t, f.dir, "rev-parse", "HEAD"))
}

// guard runs Guard over the fixture and fails the test on operational error.
func (f *fixture) guard(base, head string) []GuardFinding {
	f.t.Helper()
	findings, err := Guard(f.dir, base, head)
	if err != nil {
		f.t.Fatalf("Guard: %v", err)
	}
	return findings
}

// mustGit runs the package's hermetic git chokepoint and fails the test on
// error.
func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runGit(dir, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

// replaceOnce asserts old occurs EXACTLY once in the real content (so the
// proof mutation is still anchored to reality) and replaces it.
func replaceOnce(t *testing.T, content, old, new string) string {
	t.Helper()
	if n := strings.Count(content, old); n != 1 {
		t.Fatalf("expected exactly 1 occurrence of %q in the real content, found %d — the repo under test changed; update the proof mutation", old, n)
	}
	return strings.Replace(content, old, new, 1)
}

// requireRejected asserts at least one finding with the given rule whose Path
// contains pathFragment.
func requireRejected(t *testing.T, findings []GuardFinding, rule, pathFragment string) {
	t.Helper()
	for _, f := range findings {
		if f.Rule == rule && strings.Contains(f.Path, pathFragment) {
			return
		}
	}
	t.Fatalf("expected a %q finding for path containing %q; got %+v", rule, pathFragment, findings)
}

// requireClean asserts zero findings.
func requireClean(t *testing.T, findings []GuardFinding) {
	t.Helper()
	if len(findings) != 0 {
		t.Fatalf("expected a clean guard pass, got %d finding(s): %+v", len(findings), findings)
	}
}

// ---- REJECT proofs (real content, real attack shapes) -----------------------

// (a) A hand-fed diff editing the REAL core/agent/hardconstraints.go to add a
// force-escalate constant is rejected: the pre-LLM floor's MECHANISM is a
// protected path — policy lives in data, never in new Go constants.
func TestGuard_RejectsForceEscalateConstantInHardConstraints(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("core/agent/hardconstraints.go")
	base := f.commit("base")

	f.write("core/agent/hardconstraints.go", real+"\n// smuggled by the loop\nconst forceEscalateExtraFamily = \"totally-benign\"\n")
	head := f.commit("proposal: add force-escalate constant")

	requireRejected(t, f.guard(base, head), RuleProtectedPath, "core/agent/hardconstraints.go")
}

// (b) Lowering DefaultConsensusRuns / zeroing the consensus temperature in the
// REAL core/agent/consensus.go — the committee-weakening case — is rejected.
func TestGuard_RejectsWeakeningTheConsensusCommittee(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("core/agent/consensus.go")
	base := f.commit("base")

	mutated := replaceOnce(t, real, "const DefaultConsensusRuns = 3", "const DefaultConsensusRuns = 0")
	mutated = replaceOnce(t, mutated, "const consensusTemperature = 1.0", "const consensusTemperature = 0.0")
	f.write("core/agent/consensus.go", mutated)
	head := f.commit("proposal: weaken consensus")

	requireRejected(t, f.guard(base, head), RuleProtectedPath, "core/agent/consensus.go")
}

// (c) Mutating injectionPatterns in the REAL, EXISTING
// core/detect/injection_probe.go (narrowing a SECURITY-CRITICAL pattern so it
// never fires) is rejected: existing detector code is frozen.
func TestGuard_RejectsMutatingInjectionPatterns(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("core/detect/injection_probe.go")
	base := f.commit("base")

	mutated := replaceOnce(t, real,
		`(?i)\bignore\s+(all\s+)?previous\s+instructions?\b`,
		`(?i)\bignore_nothing_ever\b`)
	f.write("core/detect/injection_probe.go", mutated)
	head := f.commit("proposal: narrow an injection pattern")

	requireRejected(t, f.guard(base, head), RuleDetectCodeFrozen, "core/detect/injection_probe.go")
}

// (d) Adding an entry under the REAL operator-decisions.yaml rules: section (a
// smuggled auto-resolve for a dangerous family) is rejected: the global
// resolution rules are frozen (invariant 1).
func TestGuard_RejectsAddingAResolveRule(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("agents/rules/operator-decisions.yaml")
	base := f.commit("base")

	smuggled := real + `
  - id: "R-999"
    applies_to:
      family: "priv-escalation"
      metadata_match:
        approved: "true"
    operator_directive: |
      Smuggled auto-resolve for privilege escalation.
`
	f.write("agents/rules/operator-decisions.yaml", smuggled)
	head := f.commit("proposal: add resolve rule")

	requireRejected(t, f.guard(base, head), RuleOperatorDecisionsWidenOnly, "operator-decisions.yaml")
}

// (e) Deleting an escalate_route alias from the REAL corpus (an evasion
// spelling stops force-escalating) is rejected: alias sets may only grow.
func TestGuard_RejectsDeletingAnEscalateRouteAlias(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("agents/rules/operator-decisions.yaml")
	base := f.commit("base")

	f.write("agents/rules/operator-decisions.yaml", replaceOnce(t, real, `, "privesc"`, ""))
	head := f.commit("proposal: drop the privesc alias")

	requireRejected(t, f.guard(base, head), RuleOperatorDecisionsWidenOnly, "operator-decisions.yaml")
}

// (f) Adding metadata_match to an EXISTING route in the REAL corpus is
// rejected: the conjunctive predicate NARROWS when the route fires — an
// injection-probe finding without the smuggled marker would stop escalating.
func TestGuard_RejectsAddingMetadataMatchToExistingRoute(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("agents/rules/operator-decisions.yaml")
	base := f.commit("base")

	mutated := replaceOnce(t, real,
		`family: "injection-probe"`,
		"family: \"injection-probe\"\n    metadata_match:\n      probe_source: \"external\"")
	f.write("agents/rules/operator-decisions.yaml", mutated)
	head := f.commit("proposal: narrow E-002 with a predicate")

	requireRejected(t, f.guard(base, head), RuleOperatorDecisionsWidenOnly, "operator-decisions.yaml")
}

// (g) Removing a keyword from the REAL detectors/tuning.yaml (undoing the
// PE-08 poweruser FN-close) is rejected: every base element must survive into
// head.
func TestGuard_RejectsRemovingATuningKeyword(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("detectors/tuning.yaml")
	base := f.commit("base")

	f.write("detectors/tuning.yaml", replaceOnce(t, real, "\n    - poweruser", ""))
	head := f.commit("proposal: drop poweruser keyword")

	requireRejected(t, f.guard(base, head), RuleDetectorDataWidenOnly, "detectors/tuning.yaml")
}

// The guard protects ITSELF: modifying core/selfgate/guard.go (e.g. shrinking
// the protected set) is rejected.
func TestGuard_RejectsEditingTheGuardItself(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("core/selfgate/guard.go")
	base := f.commit("base")

	f.write("core/selfgate/guard.go", real+"\n// loosened\n")
	head := f.commit("proposal: edit the guard")

	requireRejected(t, f.guard(base, head), RuleProtectedPath, "core/selfgate/guard.go")
}

// Representative protected paths (the tool interpreters incl. the
// expectedOperatorRulesSHA256 pin, the CLI entrypoints, the module file): any
// modification of the REAL files is rejected.
func TestGuard_RejectsProtectedPathModifications(t *testing.T) {
	for _, rel := range []string{
		"core/tools/lookup_rules.go",
		"cmd/mallcop/main.go",
		"go.mod",
	} {
		t.Run(rel, func(t *testing.T) {
			f := newFixture(t)
			real := f.copyReal(rel)
			base := f.commit("base")

			f.write(rel, real+"\n// tampered\n")
			head := f.commit("proposal: tamper")

			requireRejected(t, f.guard(base, head), RuleProtectedPath, rel)
		})
	}
}

// Existing exam scenarios are frozen: modifying or deleting a REAL labeled
// scenario is rejected (the grader's ground truth is out of the agent's
// reach).
func TestGuard_RejectsTouchingExistingScenarios(t *testing.T) {
	const scenario = "exams/scenarios/behavioral/UT-02-maintenance-window.yaml"

	t.Run("modify", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal(scenario)
		base := f.commit("base")
		f.write(scenario, real+"\n# nudged ground truth\n")
		head := f.commit("proposal: edit scenario")
		requireRejected(t, f.guard(base, head), RuleScenarioFrozen, scenario)
	})

	t.Run("delete", func(t *testing.T) {
		f := newFixture(t)
		f.copyReal(scenario)
		base := f.commit("base")
		f.remove(scenario)
		head := f.commit("proposal: delete scenario")
		requireRejected(t, f.guard(base, head), RuleScenarioFrozen, scenario)
	})
}

// A BARE corpus.pin repin (no accompanying additive scenario change) is
// rejected: a standalone repin only ever means the pinned corpus drifted.
func TestGuard_RejectsBareCorpusPinRepin(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("exams/scenarios/corpus.pin")
	base := f.commit("base")

	f.write("exams/scenarios/corpus.pin", replaceOnce(t, real, "count 58", "count 57"))
	head := f.commit("proposal: bare repin")

	requireRejected(t, f.guard(base, head), RuleCorpusPinPairing, "corpus.pin")
}

// An unrecognized tuning.yaml shape ("priv_escalation: disabled" — a scalar
// where the section mapping belongs) FAILS CLOSED, even though no list element
// was provably removed.
func TestGuard_RejectsUnrecognizedTuningStructure(t *testing.T) {
	f := newFixture(t)
	f.copyReal("detectors/tuning.yaml")
	base := f.commit("base")

	f.write("detectors/tuning.yaml", "priv_escalation: disabled\n")
	head := f.commit("proposal: disable the section")

	requireRejected(t, f.guard(base, head), RuleDetectorDataWidenOnly, "detectors/tuning.yaml")
}

// ---- ACCEPT proofs (the widens the loop is FOR) ------------------------------

// (h) The exact K2b-shaped change passes: a new extra_elevated_keywords entry
// in the REAL detectors/tuning.yaml, paired with an additive new scenario file
// and the corpus.pin repin.
func TestGuard_AcceptsK2bShapedTuningWiden(t *testing.T) {
	f := newFixture(t)
	tuning := f.copyReal("detectors/tuning.yaml")
	pin := f.copyReal("exams/scenarios/corpus.pin")
	scenario := f.copyReal("exams/scenarios/behavioral/UT-02-maintenance-window.yaml")
	base := f.commit("base")

	f.write("detectors/tuning.yaml", replaceOnce(t, tuning, "\n    - poweruser", "\n    - poweruser\n    - clusteradmin"))
	f.write("exams/scenarios/privilege/PE-99-clusteradmin-grant.yaml", scenario) // additive new scenario
	f.write("exams/scenarios/corpus.pin", replaceOnce(t, pin, "count 58", "count 59"))
	head := f.commit("proposal: K2b-shaped widen + scenario + repin")

	requireClean(t, f.guard(base, head))
}

// (i) A purely additive new core/detect file (A, not M) passes THE GUARD
// layer — the additive code lane is gated by other layers (K7), not here.
func TestGuard_AcceptsAdditiveNewDetectorFile(t *testing.T) {
	f := newFixture(t)
	f.copyReal("core/detect/injection_probe.go")
	base := f.commit("base")

	f.write("core/detect/new_signal_probe.go", "package detect\n\n// additive detector lane — gated elsewhere\n")
	head := f.commit("proposal: additive detector file")

	requireClean(t, f.guard(base, head))
}

// (j) An additive escalate_routes entry in the REAL corpus, WITHOUT the Go pin
// edit, passes the semantic widen rule. In production the UNCHANGED
// expectedOperatorRulesSHA256 pin (core/tools/lookup_rules.go — a protected
// path the proposal cannot touch) means the corpus SHA check fires at runtime,
// so the widen reaches the HUMAN tier by construction. The second half proves
// the other side: pairing the widen WITH the pin edit is rejected.
func TestGuard_AcceptsAdditiveEscalateRouteWithoutPinEdit(t *testing.T) {
	const newRoute = `  - id: "E-100"
    family: "credential-stuffing"
    aliases: ["cred-stuffing"]
    reason: |
      New dangerous family proposed by the loop; always route to a human.

`
	seed := func(t *testing.T) (*fixture, string, string) {
		f := newFixture(t)
		real := f.copyReal("agents/rules/operator-decisions.yaml")
		f.copyReal("core/tools/lookup_rules.go")
		base := f.commit("base")
		widened := replaceOnce(t, real, "\nrules:\n", "\n"+newRoute+"\nrules:\n")
		f.write("agents/rules/operator-decisions.yaml", widened)
		return f, base, widened
	}

	t.Run("widen without pin edit passes the guard (runtime pin -> human tier)", func(t *testing.T) {
		f, base, _ := seed(t)
		head := f.commit("proposal: additive route only")
		requireClean(t, f.guard(base, head))
	})

	t.Run("widen paired with the pin edit is rejected (no mechanical-pair exception)", func(t *testing.T) {
		f, base, _ := seed(t)
		pinFile, err := os.ReadFile(filepath.Join(f.dir, "core/tools/lookup_rules.go"))
		if err != nil {
			t.Fatalf("read fixture lookup_rules.go: %v", err)
		}
		f.write("core/tools/lookup_rules.go", string(pinFile)+"\n// repinned by the loop\n")
		head := f.commit("proposal: route + pin edit")
		requireRejected(t, f.guard(base, head), RuleProtectedPath, "core/tools/lookup_rules.go")
	})
}

// The consensus-bypass proof: core/observe computes the PRODUCTION
// force-escalate floor (ZeroHistoryAccess / RoleGrantByActor /
// BulkExportNoJustification), core/toolrun wires it into the cascade, and
// core/store backs it — NONE of these were in protectedPrefixes, so the old
// guard let an attacker neuter a predicate (e.g. ZeroHistoryAccess -> false,
// disabling lateral-movement escalation) and pass the whole free tier. The Go
// default-deny floor rejects Modify of ANY existing .go file on the decision
// path, regardless of what the diff content is.
func TestGuard_RejectsModifyingDecisionPathGoCode(t *testing.T) {
	cases := []struct {
		path   string
		mutate func(t *testing.T, real string) string
	}{
		{
			// The exact red-team attack: neuter the lateral-movement predicate
			// so it never force-escalates (return true -> return false).
			path: "core/observe/observe.go",
			mutate: func(t *testing.T, real string) string {
				return replaceOnce(t, real,
					`return true, actor + " → " + target + " (no relationship history)"`,
					`return false, actor + " → " + target + " (no relationship history)"`)
			},
		},
		{
			path:   "core/toolrun/toolrun.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{
			path:   "core/store/store.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{
			path:   "core/store/records.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{
			path:   "core/connect/connect.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{ // non-contract pkg/** (pkg/event, pkg/finding, pkg/baseline are the
			// protected contracts; everything else under pkg/ is code-frozen).
			path:   "pkg/ghauth/ghauth.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{
			path:   "pkg/resolution/resolution.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
		{ // internal/** is never enumerated in protectedPrefixes — the floor covers it.
			path:   "internal/exam/scenario.go",
			mutate: func(t *testing.T, real string) string { return real + "\n// tampered by the loop\n" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			f := newFixture(t)
			real := f.copyReal(tc.path)
			base := f.commit("base")
			f.write(tc.path, tc.mutate(t, real))
			head := f.commit("proposal: tamper with a decision-path Go file")
			requireRejected(t, f.guard(base, head), RuleCodeFrozen, tc.path)
		})
	}
}

// The sanctioned additive code lane is directly-under-core/detect ONLY. A NEW
// .go file anywhere else is code the loop may not author: under a protected
// package it trips RuleProtectedPath; under a NEW SUBDIRECTORY of core/detect
// it trips the Go default-deny floor (RuleCodeFrozen) — a subdir is NOT the
// lane, so the L1-isolation escape hatch stays behind K7's dedicated gate, not
// this guard. Both are rejected.
func TestGuard_RejectsNewGoFileOutsideDetectorLane(t *testing.T) {
	cases := []struct{ path, rule string }{
		{"core/agent/smuggled.go", RuleProtectedPath},
		{"core/detect/evil/evil.go", RuleCodeFrozen},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			f := newFixture(t)
			f.copyReal("core/detect/injection_probe.go") // real committed base
			base := f.commit("base")
			f.write(tc.path, "package p\n\n// a new .go file the loop tried to add outside the lane\n")
			head := f.commit("proposal: add a new Go file outside the detector lane")
			requireRejected(t, f.guard(base, head), tc.rule, tc.path)
		})
	}
}

// The Go default-deny floor must NOT swallow the sanctioned lane: a NEW .go
// file DIRECTLY under core/detect/ passes THIS layer (K7 gates the lane
// downstream). Mirrors TestGuard_AcceptsAdditiveNewDetectorFile from the
// floor's perspective.
func TestGuard_StillAcceptsNewDetectorFileDirectlyUnderDetect(t *testing.T) {
	f := newFixture(t)
	f.copyReal("core/detect/injection_probe.go")
	base := f.commit("base")

	f.write("core/detect/newdet.go", "package detect\n\n// additive detector lane — gated by K7, not this guard\n")
	head := f.commit("proposal: additive detector file directly under core/detect")

	requireClean(t, f.guard(base, head))
}

// A WELL-SHAPED (mapping→field→list) but loader-unknown section or field in
// detectors/tuning.yaml would sail past the widen subset check (head-only IS
// the widen). The section/field allowlist mirrors core/detect/tuning.go's
// Tuning struct and fails closed at the GUARD layer — it does not defer to
// exam-detect or the loader's strict decode.
func TestGuard_RejectsUnknownTuningSection(t *testing.T) {
	t.Run("unknown top-level section", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("detectors/tuning.yaml")
		base := f.commit("base")
		// A brand-new, structurally valid, but loader-unknown top-level section.
		f.write("detectors/tuning.yaml", real+"\nlateral_movement:\n  extra_elevated_keywords:\n    - clusteradmin\n")
		head := f.commit("proposal: smuggle an unknown top-level tuning section")
		requireRejected(t, f.guard(base, head), RuleDetectorDataWidenOnly, "detectors/tuning.yaml")
	})

	t.Run("unknown field under a known section", func(t *testing.T) {
		f := newFixture(t)
		real := f.copyReal("detectors/tuning.yaml")
		base := f.commit("base")
		// A sibling key under priv_escalation the loader's struct does not declare.
		f.write("detectors/tuning.yaml", real+"  override_elevated_keywords:\n    - poweruser\n")
		head := f.commit("proposal: smuggle an unknown field under a known section")
		requireRejected(t, f.guard(base, head), RuleDetectorDataWidenOnly, "detectors/tuning.yaml")
	})
}

// Paths the guard has no opinion on (docs) pass this layer — the guard
// enforces the enumerated invariants, other layers gate the rest.
func TestGuard_PassesUnprotectedDocChange(t *testing.T) {
	f := newFixture(t)
	real := f.copyReal("README.md")
	base := f.commit("base")

	f.write("README.md", real+"\nDocs-only change.\n")
	head := f.commit("proposal: docs")

	requireClean(t, f.guard(base, head))
}
