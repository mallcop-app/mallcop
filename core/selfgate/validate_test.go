// validate_test.go — PROOF tests for the K4 free-tier validate_proposal gate.
//
// Invariant 10 (ground-source testing): the accept AND rejection proofs run
// against the REAL repository — each end-to-end test clones the repo under
// test into a temp dir, manufactures the proposal as real git commits over
// real files, and runs the full gate (real worktrees, real `go build`, real
// exam-detect subprocesses over the real labeled corpus). No stage is mocked.
//
// $0 proof: EVERY end-to-end test in this file runs with the inference
// environment stripped (clearInferenceEnv) — the free tier accepting and
// rejecting under a no-inference-env process proves no stage constructs an
// inference client; TestSelfgateImportsNoInferenceOrCommittee additionally
// proves the package cannot even link one.
package selfgate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---- fixture: temp clones of the REAL repo ----------------------------------

// cloneRepo clones the repository under test (committed state at its current
// HEAD) into a temp dir and returns the clone path.
func cloneRepo(t *testing.T) string {
	t.Helper()
	root := repoUnderTest(t)
	parent := t.TempDir()
	clone := filepath.Join(parent, "clone")
	mustGit(t, parent, "clone", "-q", "--no-hardlinks", root, clone)
	return clone
}

// commitAll stages everything in dir and commits, returning the commit SHA.
func commitAll(t *testing.T, dir, msg string) string {
	t.Helper()
	mustGit(t, dir, "add", "-A")
	mustGit(t, dir, "commit", "-q", "--no-verify", "-m", msg)
	return strings.TrimSpace(mustGit(t, dir, "rev-parse", "HEAD"))
}

func headOf(t *testing.T, dir string) string {
	t.Helper()
	return strings.TrimSpace(mustGit(t, dir, "rev-parse", "HEAD"))
}

func readRepoFile(t *testing.T, dir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func writeRepoFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// clearInferenceEnv strips every inference-related variable from the test
// process (children inherit the stripped environment), registering restoration
// via t.Setenv. The free tier must accept and reject identically without them.
func clearInferenceEnv(t *testing.T) {
	t.Helper()
	keys := []string{"MALLCOP_INFERENCE_URL", "MALLCOP_API_KEY"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "FORGE_") {
			keys = append(keys, strings.SplitN(kv, "=", 2)[0])
		}
	}
	for _, k := range keys {
		t.Setenv(k, "") // registers restoration of the original value
		os.Unsetenv(k)
	}
}

// recomputeCorpusPin replicates the canonical corpus manifest digest the
// loader (core/eval/corpus.go — the documented SOURCE OF TRUTH for the
// format) verifies: one "<relpath><two spaces><sha256(file)>\n" line per
// included scenario (.yaml/.yml, leading-underscore components excluded at
// any depth), sorted by relpath; the pin sha is sha256 of that manifest.
// TestValidateProposal_AcceptsK2bShapedWidenProposal anchors this replication
// against the COMMITTED corpus.pin before trusting it — drift fails loudly.
func recomputeCorpusPin(t *testing.T, root string) (count int, sha string) {
	t.Helper()
	scenRoot := filepath.Join(root, "exams", "scenarios")
	type entry struct{ rel, fileSHA string }
	var entries []entry
	err := filepath.WalkDir(scenRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(scenRoot, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		for _, part := range strings.Split(rel, "/") {
			if strings.HasPrefix(part, "_") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() || (!strings.HasSuffix(d.Name(), ".yaml") && !strings.HasSuffix(d.Name(), ".yml")) {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(data)
		entries = append(entries, entry{rel: rel, fileSHA: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		t.Fatalf("recompute corpus pin: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	var manifest strings.Builder
	for _, e := range entries {
		manifest.WriteString(e.rel)
		manifest.WriteString("  ")
		manifest.WriteString(e.fileSHA)
		manifest.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(manifest.String()))
	return len(entries), hex.EncodeToString(sum[:])
}

// requireStageNames asserts the exact set of stages that RAN, in order — the
// short-circuit evidence lives in what is absent.
func requireStageNames(t *testing.T, res GateResult, want ...string) {
	t.Helper()
	if len(res.Stages) != len(want) {
		t.Fatalf("expected stages %v to have run, got %+v", want, res.Stages)
	}
	for i, name := range want {
		if res.Stages[i].Name != name {
			t.Fatalf("stage[%d] = %q, want %q (all: %+v)", i, res.Stages[i].Name, name, res.Stages)
		}
	}
}

// ---- (a) end-to-end ACCEPT: the K2b-shaped widen proposal -------------------

// The exact proposal shape the self-extension loop exists to produce: two new
// labeled scenario files (a must_fire target + its benign twin), the paired
// corpus.pin regen, and the widen-only tuning entry that closes the gap. The
// fixture manufactures the BASE by removing the committed K2b widen from a
// clone of the real repo (delete PE-08/PE-09, delete tuning.yaml, repin), so
// base→head IS the real, committed K2b widen — coverage +1 (PE-08 absent at
// base, passing at head), no regressions, no undeclared new firings.
func TestValidateProposal_AcceptsK2bShapedWidenProposal(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)
	head := headOf(t, clone)

	// Anchor the pin replication to reality BEFORE trusting it: over the
	// pristine clone it must reproduce the committed corpus.pin exactly.
	count, sha := recomputeCorpusPin(t, clone)
	committedPin := readRepoFile(t, clone, "exams/scenarios/corpus.pin")
	if !strings.Contains(committedPin, fmt.Sprintf("count %d", count)) || !strings.Contains(committedPin, "sha256 "+sha) {
		t.Fatalf("pin replication drifted from core/eval/corpus.go: recomputed count=%d sha=%s, committed pin:\n%s", count, sha, committedPin)
	}

	// Manufacture the base: the repo as it was BEFORE the K2b widen.
	for _, rel := range []string{
		"exams/scenarios/privilege/PE-08-aws-poweruser-grant.yaml",
		"exams/scenarios/privilege/PE-09-aws-readonly-grant-benign.yaml",
		"detectors/tuning.yaml",
	} {
		if err := os.Remove(filepath.Join(clone, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("remove %s: %v", rel, err)
		}
	}
	baseCount, baseSHA := recomputeCorpusPin(t, clone)
	writeRepoFile(t, clone, "exams/scenarios/corpus.pin",
		fmt.Sprintf("# fixture pin (K4 validate proof)\ncount %d\nsha256 %s\n", baseCount, baseSHA))
	base := commitAll(t, clone, "fixture base: repo before the K2b widen")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}

	// The FULL GateResult, field by field.
	if !res.Passed {
		t.Fatalf("the K2b-shaped widen must pass the free tier, got %+v", res)
	}
	if res.SchemaVersion != GateSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", res.SchemaVersion, GateSchemaVersion)
	}
	if res.Tier != TierFree {
		t.Fatalf("Tier = %q, want %q", res.Tier, TierFree)
	}
	if res.BaseSHA != base || res.HeadSHA != head {
		t.Fatalf("SHAs: base %s (want %s), head %s (want %s)", res.BaseSHA, base, res.HeadSHA, head)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	for _, stage := range res.Stages {
		if !stage.Passed || len(stage.Findings) != 0 {
			t.Fatalf("stage %q not clean: %+v", stage.Name, stage)
		}
		if stage.Evidence == "" {
			t.Fatalf("stage %q carries no evidence", stage.Name)
		}
	}
	if res.CoveragePlus != 1 {
		t.Fatalf("CoveragePlus = %d, want 1 (PE-08 newly labeled and passing)", res.CoveragePlus)
	}
	if len(res.NewFirings) != 0 {
		t.Fatalf("NewFirings = %v, want none", res.NewFirings)
	}
}

// ---- (b) end-to-end REJECT at stage 1: the force-escalate diff --------------

// The canonical forbidden shape (consensus-not-rules, invariant 1): patching a
// missed attack by smuggling a force-escalate constant into the REAL
// core/agent/hardconstraints.go. The guard rejects it and — the short-circuit
// proof — stages 2 and 3 NEVER RUN: the guard stage is the only entry in the
// result.
func TestValidateProposal_ShortCircuitsAtGuardOnForceEscalateDiff(t *testing.T) {
	clearInferenceEnv(t)
	f := newFixture(t)
	real := f.copyReal("core/agent/hardconstraints.go")
	base := f.commit("base")

	f.write("core/agent/hardconstraints.go", real+"\n// smuggled by the loop\nconst forceEscalateExtraFamily = \"totally-benign\"\n")
	head := f.commit("proposal: add force-escalate constant")

	res, err := ValidateProposal(f.dir, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	if res.Passed {
		t.Fatalf("the force-escalate diff must be rejected, got %+v", res)
	}
	// Short-circuit evidence: ONLY the guard stage ran.
	requireStageNames(t, res, StageGuard)
	if res.Stages[0].Passed {
		t.Fatalf("guard stage reported passing on a rejected proposal: %+v", res.Stages[0])
	}
	requireRejected(t, res.Stages[0].Findings, RuleProtectedPath, "core/agent/hardconstraints.go")
	if res.CoveragePlus != 0 || len(res.NewFirings) != 0 {
		t.Fatalf("exam-derived fields must be zero when exam-detect never ran: %+v", res)
	}
}

// ---- (c) end-to-end REJECT at exam-detect: benign twin starts firing --------

// A tuning add the STATIC guard cannot fault (adding a keyword is a pure
// widen at the data layer) but that makes a must_not_fire row fire: the
// "readonly" keyword substring-matches PE-09's ReadOnlyAccess role, so the
// benign twin starts emitting priv-escalation at head. The exam-detect stage
// catches it: an undeclared NEW FIRING on PE-09 (and the same flip is a
// regression — PE-09 passed at base). This is exactly why the free tier ends
// in a behavioral diff, not static rules.
func TestValidateProposal_RejectsTuningThatFiresOnBenignTwin(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)
	base := headOf(t, clone)

	tuning := readRepoFile(t, clone, "detectors/tuning.yaml")
	// Anchor on the indented list entry — the bare string also appears in a
	// file comment.
	widened := replaceOnce(t, tuning, "\n    - poweruser", "\n    - poweruser\n    - readonly")
	writeRepoFile(t, clone, "detectors/tuning.yaml", widened)
	head := commitAll(t, clone, "proposal: add the readonly keyword (fires on the benign twin)")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	if res.Passed {
		t.Fatalf("a tuning add that fires on a benign twin must be rejected, got %+v", res)
	}
	// Stages 1 and 2 pass (the static layers CANNOT see this defect); the
	// exam-detect diff is where it must die.
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	if !res.Stages[0].Passed || !res.Stages[1].Passed || res.Stages[2].Passed {
		t.Fatalf("expected guard+structural PASS and exam-detect FAIL, got %+v", res.Stages)
	}
	examFindings := res.Stages[2].Findings
	requireRejected(t, examFindings, RuleExamNewFiring, "PE-09")
	requireRejected(t, examFindings, RuleExamRegression, "PE-09")
	requireRejected(t, examFindings, RuleExamNoCoverageGain, StageExamDetect)

	wantFiring := "PE-09-aws-readonly-grant-benign: priv-escalation"
	found := false
	for _, nf := range res.NewFirings {
		if nf == wantFiring {
			found = true
		}
	}
	if !found {
		t.Fatalf("NewFirings = %v, want it to contain %q", res.NewFirings, wantFiring)
	}
	if res.CoveragePlus != 0 {
		t.Fatalf("CoveragePlus = %d, want 0 (the proposal closes nothing)", res.CoveragePlus)
	}
}

// ---- (d) $0 proof: the whole free tier runs with NO inference env -----------

// A tuning-only widen (base = the committed tuning minus the poweruser
// keyword, head = the committed state) validated end-to-end with
// MALLCOP_INFERENCE_URL, MALLCOP_API_KEY, and every FORGE_* variable stripped
// from the process (and therefore from every subprocess the gate spawns).
// All three stages run and the proposal is judged on the merits — the free
// tier needs no inference identity by construction. This shape also proves
// the NEWLY-PASSING coverage path and the declared-target excusal: PE-08
// exists at base (failing), passes at head, and its priv-escalation firing at
// head is excused because the row's must_fire declares it.
func TestValidateProposal_FreeTierIsZeroDollar(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)
	head := headOf(t, clone)

	tuning := readRepoFile(t, clone, "detectors/tuning.yaml")
	writeRepoFile(t, clone, "detectors/tuning.yaml", replaceOnce(t, tuning, "\n    - poweruser", ""))
	base := commitAll(t, clone, "fixture base: reopen the PE-08 gap")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal with no inference env: %v", err)
	}
	if !res.Passed {
		t.Fatalf("the tuning widen must pass the free tier without inference env, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	if res.CoveragePlus != 1 {
		t.Fatalf("CoveragePlus = %d, want 1 (PE-08 newly passing)", res.CoveragePlus)
	}
	if len(res.NewFirings) != 0 {
		t.Fatalf("NewFirings = %v, want none (PE-08's firing is a declared target)", res.NewFirings)
	}
}

// TestSelfgateImportsNoInferenceOrCommittee is the grep-level half of the $0
// proof: parse every production file in core/selfgate and assert the package
// imports neither the inference client, nor the network, nor the committee
// (core/agent), nor the eval harness that links the committee (core/eval —
// the exam binary is a SUBPROCESS and JSON is the seam). selfgate must not
// even be able to construct the thing it is forbidden to call.
func TestSelfgateImportsNoInferenceOrCommittee(t *testing.T) {
	dir := filepath.Join(repoUnderTest(t), "core", "selfgate")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	banned := func(p string) bool {
		return p == "net/http" ||
			strings.Contains(p, "core/inference") ||
			strings.Contains(p, "core/agent") ||
			strings.Contains(p, "core/eval")
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		checked++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if banned(p) {
				t.Errorf("%s imports %q — the free tier must not link inference, the network, or the committee", e.Name(), p)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no production files checked — the gate walked the wrong directory")
	}
}

// ---- GuardOnly option --------------------------------------------------------

// Options.GuardOnly pins a clean run to stage 1: later stages do not run even
// though the guard passed.
func TestValidateProposal_GuardOnlyPinsToStageOne(t *testing.T) {
	clearInferenceEnv(t)
	f := newFixture(t)
	real := f.copyReal("README.md")
	base := f.commit("base")
	f.write("README.md", real+"\nDocs-only change.\n")
	head := f.commit("proposal: docs")

	res, err := ValidateProposal(f.dir, base, head, Options{GuardOnly: true})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	if !res.Passed {
		t.Fatalf("docs change must pass the guard, got %+v", res)
	}
	requireStageNames(t, res, StageGuard)
}

// ---- diffExamReports unit proofs (fail-closed edges the e2e paths cannot
// reach because earlier layers block them) -------------------------------------

// A labeled row passing at base that VANISHES from the head report is a
// regression finding — fail closed, even though the frozen-scenario guard rule
// makes this unreachable end-to-end.
func TestDiffExamReports_DisappearedRowFailsClosed(t *testing.T) {
	base := examReport{Rows: []examRow{
		{ScenarioID: "S-1", MustFire: []string{"fam-a"}, Emitted: []string{"fam-a"}, Pass: true},
	}}
	head := examReport{}

	findings, coverage, newFirings := diffExamReports(base, head, true)
	requireRejected(t, findings, RuleExamRegression, "S-1")
	if coverage != 0 || len(newFirings) != 0 {
		t.Fatalf("coverage=%d newFirings=%v, want 0/none", coverage, newFirings)
	}
}

// AllowNoCoverageGain waives ONLY the coverage requirement: a no-op diff
// passes with it, but an undeclared new firing is still rejected.
func TestDiffExamReports_AllowNoCoverageGainWaivesOnlyCoverage(t *testing.T) {
	row := examRow{ScenarioID: "S-1", MustFire: []string{"fam-a"}, Emitted: []string{"fam-a"}, Pass: true}
	base := examReport{Rows: []examRow{row}}

	t.Run("no-op diff: rejected without the waiver, clean with it", func(t *testing.T) {
		findings, _, _ := diffExamReports(base, base, false)
		requireRejected(t, findings, RuleExamNoCoverageGain, StageExamDetect)
		findings, _, _ = diffExamReports(base, base, true)
		requireClean(t, findings)
	})

	t.Run("undeclared new firing rejected even with the waiver", func(t *testing.T) {
		crept := row
		crept.Emitted = []string{"fam-a", "fam-b"} // fam-b: nobody declared it
		head := examReport{Rows: []examRow{crept}}
		findings, _, newFirings := diffExamReports(base, head, true)
		requireRejected(t, findings, RuleExamNewFiring, "S-1")
		if len(newFirings) != 1 || newFirings[0] != "S-1: fam-b" {
			t.Fatalf("newFirings = %v, want [\"S-1: fam-b\"]", newFirings)
		}
	})
}
