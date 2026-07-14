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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
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

// ---- fixture: the SYNTHETIC gap-close pair (rd mallcoppro-a07 / S1) ----------
//
// The gate's tuning gap-close is demonstrated on a PURPOSE-BUILT synthetic pair
// (exams/synthetic/SYNTH-PE-01 must-fire + SYNTH-PE-02 benign twin) injected
// into a throwaway clone's PINNED corpus, NOT on any real corpus scenario. The
// synthetic elevated role carries none of priv-escalation's built-in vocabulary,
// so the gap is unclosable without the synthetic tuning knob
// (core/detect/synthdemo_invariant_test.go guards that permanently) — which is
// what frees every real scenario (PE-08, IP-01, ...) from being held RED-able
// just to prove a gap-close.
const (
	synthSrcMustFire         = "exams/synthetic/SYNTH-PE-01-elevated-must-fire.yaml"
	synthSrcTwin             = "exams/synthetic/SYNTH-PE-02-baseline-benign-twin.yaml"
	synthDstMustFire         = "exams/scenarios/synthetic/SYNTH-PE-01-elevated-must-fire.yaml"
	synthDstTwin             = "exams/scenarios/synthetic/SYNTH-PE-02-baseline-benign-twin.yaml"
	syntheticElevatedKeyword = "mallcopsyntheticelevated"
	// syntheticTwinID is the benign twin's scenario id (its filename stem's id:
	// field), the NewFiring/regression key the over-broad-widen reject asserts.
	syntheticTwinID = "SYNTH-PE-02-baseline-benign-twin"
)

// injectSyntheticGapPair copies the committed synthetic gap-close pair
// (exams/synthetic/) into the clone's PINNED corpus (exams/scenarios/synthetic/)
// and regenerates corpus.pin so the injected corpus verifies. It does NOT touch
// detectors/tuning.yaml — callers stage base (untuned: SYNTH-PE-01 RED) and head
// (synthetic keyword added: SYNTH-PE-01 GREEN) around it.
func injectSyntheticGapPair(t *testing.T, clone string) {
	t.Helper()
	root := repoUnderTest(t)
	if err := os.MkdirAll(filepath.Join(clone, "exams", "scenarios", "synthetic"), 0o755); err != nil {
		t.Fatalf("mkdir synthetic corpus dir: %v", err)
	}
	for _, p := range [][2]string{{synthSrcMustFire, synthDstMustFire}, {synthSrcTwin, synthDstTwin}} {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p[0])))
		if err != nil {
			t.Fatalf("read synthetic fixture %s: %v", p[0], err)
		}
		writeRepoFile(t, clone, p[1], string(data))
	}
	count, sha := recomputeCorpusPin(t, clone)
	writeRepoFile(t, clone, "exams/scenarios/corpus.pin",
		fmt.Sprintf("# fixture pin (synthetic gap-close injection)\ncount %d\nsha256 %s\n", count, sha))
}

// appendTuningKeyword appends one extra_elevated_keywords list entry to the
// clone's committed detectors/tuning.yaml (a pure widen the guard accepts).
func appendTuningKeyword(t *testing.T, clone, keyword string) {
	t.Helper()
	tuning := readRepoFile(t, clone, "detectors/tuning.yaml")
	writeRepoFile(t, clone, "detectors/tuning.yaml", tuning+"    - "+keyword+"\n")
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

// ---- (a) end-to-end ACCEPT: the SYNTHETIC tuning-widen proposal -------------
//
// The exact proposal shape the self-extension loop exists to produce, on the
// synthetic gap-close pair (exams/synthetic/): BASE has the synthetic
// must-fire/benign-twin scenarios injected into the pinned corpus with the gap
// OPEN (SYNTH-PE-01 RED); HEAD is the widen-only tuning entry that adds the
// synthetic elevated keyword, closing SYNTH-PE-01 while the benign twin stays
// silent. base..head is a pure tuning widen: coverage +1, no regressions, no
// undeclared new firings, and it depends on NO real corpus scenario, so PE-08 /
// IP-01 / etc. are free to be fixed (see injectSyntheticGapPair).
func TestValidateProposal_AcceptsSyntheticWidenProposal(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)

	// Anchor the pin replication to reality BEFORE trusting it: over the
	// pristine clone it must reproduce the committed corpus.pin exactly.
	count, sha := recomputeCorpusPin(t, clone)
	committedPin := readRepoFile(t, clone, "exams/scenarios/corpus.pin")
	if !strings.Contains(committedPin, fmt.Sprintf("count %d", count)) || !strings.Contains(committedPin, "sha256 "+sha) {
		t.Fatalf("pin replication drifted from core/eval/corpus.go: recomputed count=%d sha=%s, committed pin:\n%s", count, sha, committedPin)
	}

	// BASE: inject the synthetic pair into the pinned corpus, gap OPEN
	// (SYNTH-PE-01 is RED — its role carries no built-in elevation keyword).
	injectSyntheticGapPair(t, clone)
	base := commitAll(t, clone, "fixture base: synthetic gap-close pair injected, gap OPEN")

	// HEAD: the widen — add the synthetic elevated keyword to tuning.yaml,
	// closing SYNTH-PE-01 while the benign twin stays silent.
	appendTuningKeyword(t, clone, syntheticElevatedKeyword)
	head := commitAll(t, clone, "proposal: synthetic tuning widen closes SYNTH-PE-01")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}

	// The FULL GateResult, field by field.
	if !res.Passed {
		t.Fatalf("the synthetic widen must pass the free tier, got %+v", res)
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
		t.Fatalf("CoveragePlus = %d, want 1 (SYNTH-PE-01 newly passing)", res.CoveragePlus)
	}
	if len(res.NewFirings) != 0 {
		t.Fatalf("NewFirings = %v, want none", res.NewFirings)
	}

	// C6: the recall/precision deltas ride on the same GateResult and name the
	// exact unit this widen adds — SYNTH-PE-01's priv-escalation, newly detected,
	// with no recall regression and no new precision violation.
	if res.RecallDelta == nil || res.PrecisionDelta == nil {
		t.Fatalf("RecallDelta/PrecisionDelta must be populated in the in-tree lane, got %+v / %+v", res.RecallDelta, res.PrecisionDelta)
	}
	if len(res.RecallDelta.NewlyMissed) != 0 {
		t.Fatalf("NewlyMissed = %v, want none (no recall regression)", res.RecallDelta.NewlyMissed)
	}
	if len(res.PrecisionDelta.NewlyViolated) != 0 {
		t.Fatalf("NewlyViolated = %v, want none (benign twin stays silent)", res.PrecisionDelta.NewlyViolated)
	}
	foundSynth := false
	for _, u := range res.RecallDelta.NewlyDetected {
		if u.ScenarioID == "SYNTH-PE-01-elevated-must-fire" && u.Family == "priv-escalation" {
			foundSynth = true
		}
	}
	if !foundSynth {
		t.Fatalf("RecallDelta.NewlyDetected = %v, want it to name SYNTH-PE-01/priv-escalation", res.RecallDelta.NewlyDetected)
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

// A tuning add the STATIC guard cannot fault (adding a keyword is a pure widen
// at the data layer) but that makes a must_not_fire row fire: BASE already
// closes SYNTH-PE-01 with the exact synthetic keyword; HEAD adds an OVER-BROAD
// keyword ("mallcopsynthetic") that also substring-matches SYNTH-PE-02's benign
// role, so the twin starts emitting priv-escalation at head. The exam-detect
// stage catches it: an undeclared NEW FIRING on the twin (and the same flip is a
// regression - the twin passed at base), while closing no new gap (SYNTH-PE-01
// was already green at base). This is exactly why the free tier ends in a
// behavioral diff, not static rules - proven now on the synthetic pair.
func TestValidateProposal_RejectsTuningThatFiresOnBenignTwin(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)

	// BASE: synthetic pair injected AND the exact synthetic keyword applied -
	// SYNTH-PE-01 green, the benign twin silent.
	injectSyntheticGapPair(t, clone)
	appendTuningKeyword(t, clone, syntheticElevatedKeyword)
	base := commitAll(t, clone, "fixture base: synthetic gap closed, twin silent")

	// HEAD: an over-broad keyword that also fires on the benign twin.
	appendTuningKeyword(t, clone, "mallcopsynthetic")
	head := commitAll(t, clone, "proposal: over-broad keyword fires on the benign twin")

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
	requireRejected(t, examFindings, RuleExamNewFiring, syntheticTwinID)
	requireRejected(t, examFindings, RuleExamRegression, syntheticTwinID)
	requireRejected(t, examFindings, RuleExamNoCoverageGain, StageExamDetect)

	wantFiring := syntheticTwinID + ": priv-escalation"
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
		t.Fatalf("CoveragePlus = %d, want 0 (the proposal closes nothing new)", res.CoveragePlus)
	}
}

// ---- (d) $0 proof: the whole free tier runs with NO inference env -----------

// The synthetic tuning widen (base = the synthetic pair injected with the gap
// OPEN, head = the same plus the synthetic elevated keyword) validated
// end-to-end with MALLCOP_INFERENCE_URL, MALLCOP_API_KEY, and every FORGE_*
// variable stripped from the process (and therefore from every subprocess the
// gate spawns). All three stages run and the proposal is judged on the merits -
// the free tier needs no inference identity by construction. This shape also
// proves the NEWLY-PASSING coverage path and the declared-target excusal:
// SYNTH-PE-01 exists at base (failing), passes at head, and its priv-escalation
// firing at head is excused because the row's must_fire declares it.
func TestValidateProposal_FreeTierIsZeroDollar(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)

	injectSyntheticGapPair(t, clone)
	base := commitAll(t, clone, "fixture base: synthetic gap OPEN")

	appendTuningKeyword(t, clone, syntheticElevatedKeyword)
	head := commitAll(t, clone, "proposal: synthetic tuning widen closes SYNTH-PE-01")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal with no inference env: %v", err)
	}
	if !res.Passed {
		t.Fatalf("the tuning widen must pass the free tier without inference env, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	if res.CoveragePlus != 1 {
		t.Fatalf("CoveragePlus = %d, want 1 (SYNTH-PE-01 newly passing)", res.CoveragePlus)
	}
	if len(res.NewFirings) != 0 {
		t.Fatalf("NewFirings = %v, want none (SYNTH-PE-01's firing is a declared target)", res.NewFirings)
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

// TestAdversK6_NoNewFiringsExcusesDeclaredFamilyOnBenign is the Fix #5 red-team
// regression: the no-new-firings excusal must be SCENARIO-SCOPED. An over-broad
// NEW decl family, declared as a passing must_fire target on ITS OWN scenario, is
// legitimately excused THERE — but if it ALSO fires on an unrelated existing
// benign corpus scenario, that firing must NOT be excused just because the family
// is "declared somewhere". Before the fix, a blanket family excusal let such a
// trigger-happy rule sail through with zero new-firing findings.
func TestAdversK6_NoNewFiringsExcusesDeclaredFamilyOnBenign(t *testing.T) {
	base := examReport{Rows: []examRow{
		// The rule's own target: failing at base (family does not fire yet).
		{ScenarioID: "OWN-TARGET", MustFire: []string{"decl:overbroad"}, Emitted: []string{}, Pass: false},
		// An unrelated existing benign scenario: decl:overbroad is absent at base.
		{ScenarioID: "EXISTING-BENIGN", Emitted: []string{"config-drift"}, Pass: true},
	}}
	head := examReport{Rows: []examRow{
		// OWN-TARGET now fires and passes → declares decl:overbroad ON OWN-TARGET.
		{ScenarioID: "OWN-TARGET", MustFire: []string{"decl:overbroad"}, Emitted: []string{"decl:overbroad"}, Pass: true},
		// The over-broad rule ALSO fires on the unrelated benign scenario.
		{ScenarioID: "EXISTING-BENIGN", Emitted: []string{"config-drift", "decl:overbroad"}, Pass: true},
	}}

	findings, coverage, newFirings := diffExamReports(base, head, false)

	// The unrelated benign firing is flagged.
	requireRejected(t, findings, RuleExamNewFiring, "EXISTING-BENIGN")
	foundBenign := false
	for _, nf := range newFirings {
		if nf == "EXISTING-BENIGN: decl:overbroad" {
			foundBenign = true
		}
		if nf == "OWN-TARGET: decl:overbroad" {
			t.Fatalf("decl:overbroad firing on its OWN declared scenario must be excused, got new firing %q", nf)
		}
	}
	if !foundBenign {
		t.Fatalf("newFirings = %v, want it to contain \"EXISTING-BENIGN: decl:overbroad\"", newFirings)
	}
	// The real gain on the declared target still counts.
	if coverage != 1 {
		t.Fatalf("coverage = %d, want 1 (OWN-TARGET newly passing)", coverage)
	}
}

// TestDiffExamReports_NewLabeledScenarioFailingIsRejected is the Fix #4 proof: a
// labeled scenario the proposal ADDS (absent at base) that does NOT pass at head
// is a hard rejection — the exact hole a benign-twin must_not_fire the new rule
// wrongly fires on would otherwise fall through, since the regression check only
// covers base rows.
func TestDiffExamReports_NewLabeledScenarioFailingIsRejected(t *testing.T) {
	base := examReport{Rows: []examRow{
		{ScenarioID: "S-1", MustFire: []string{"fam-a"}, Emitted: []string{"fam-a"}, Pass: true},
	}}

	t.Run("new benign twin the rule wrongly fires on is rejected", func(t *testing.T) {
		head := examReport{Rows: []examRow{
			{ScenarioID: "S-1", MustFire: []string{"fam-a"}, Emitted: []string{"fam-a"}, Pass: true},
			// New benign twin: must_not_fire decl:x, but the rule fired → fails at head.
			{ScenarioID: "NEW-BENIGN", MustNotFire: []string{"decl:x"}, Emitted: []string{"decl:x"}, Pass: false},
		}}
		findings, _, _ := diffExamReports(base, head, true)
		requireRejected(t, findings, RuleExamNewScenarioFails, "NEW-BENIGN")
	})

	t.Run("new labeled scenario that passes is clean", func(t *testing.T) {
		head := examReport{Rows: []examRow{
			{ScenarioID: "S-1", MustFire: []string{"fam-a"}, Emitted: []string{"fam-a"}, Pass: true},
			{ScenarioID: "NEW-BENIGN", MustNotFire: []string{"decl:x"}, Emitted: []string{}, Pass: true},
		}}
		findings, _, _ := diffExamReports(base, head, true)
		for _, f := range findings {
			if f.Rule == RuleExamNewScenarioFails {
				t.Fatalf("a passing new labeled scenario must not be flagged: %+v", f)
			}
		}
	})
}

// TestRunToolCtx_WallClockTimeoutKillsHang is the K7 re-red-team regression for
// the stage-3 defense-in-depth timeout (Fix #3). An authored detector that slips
// an unbounded loop / blocking call past the L3 shape gate would otherwise let
// the exam-detect subprocess run forever and "pass" stage-3 by never crashing.
// runTreeExam now runs that exec through runToolCtx bounded by examExecWallClock,
// so a hang is KILLED at the wall clock and surfaced as a NON-nil error wrapping
// context.DeadlineExceeded (code -1). For the head tree that error becomes a
// RuleExamExecution fail-closed rejection upstream. This proves the mechanism:
// a subprocess that runs past the deadline is terminated promptly, not awaited.
func TestRunToolCtx_WallClockTimeoutKillsHang(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	// `sleep 60` stands in for a detector that hangs the exam exec.
	_, _, code, err := runToolCtx(ctx, t.TempDir(), nil, "sleep", "60")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a wall-clock timeout error, got nil — the hang was NOT killed")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected an error wrapping context.DeadlineExceeded, got %v", err)
	}
	if code != -1 {
		t.Fatalf("expected code -1 on a timeout, got %d", code)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("the subprocess was not killed promptly at the deadline: took %s", elapsed)
	}
}
