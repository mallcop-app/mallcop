package eval

// harness_test.go — the end-to-end test of the PORTABLE eval harness
// (portable-agent-architecture.md §4). It proves, against the REAL shipped
// corpus driven through the in-process core with cannedbackend golden responses:
//
//   - the corpus loads with the EXACT pinned count + SHA (the integrity gate);
//   - leading-underscore paths (_schema.yaml, _test/) are SKIPPED;
//   - the harness runs end-to-end, grades deterministically, and the merge-gate
//     is GREEN (golden responses → 100% chain_action);
//   - result JSON + transcripts + a classifier summary + a median over N=3 are
//     produced;
//   - the SHA/count integrity gate HARD-FAILS on a tampered corpus (tested on a
//     temp copy so the shipped tree is untouched);
//   - real-model mode is WIRED but refuses to run without creds.
//
// Determinism: every test pins the repo root via SetRepoRootForTest (NOT the
// MALLCOP_REPO_ROOT env var — process-global mutable state, incompatible with
// t.Parallel). The suite is built to survive -count=10 + -race:
// the recording client is mutex-guarded, the canned backends bind ephemeral
// ports, and no global state leaks between tests (the override is set+cleared per
// test under a shared lock).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
)

// repoRoot walks up from the test's working dir (the package dir) to the repo
// root that holds exams/scenarios — the deterministic anchor every test pins.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, scenariosRelPath)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding exams/scenarios")
		}
		dir = parent
	}
}

// pinShippedRoot pins the harness AND the agent floor at the REAL shipped corpus
// for one test and clears both overrides on cleanup.
//
// TWO roots must be pinned, deterministically:
//   - the EVAL root (SetRepoRootForTest) — locates exams/scenarios for the loader.
//   - the AGENT FLOOR root (agent.SetRepoRootForTest) — locates the
//     escalate-route corpus the PRE-LLM floor reads INSIDE ResolveFindingWith.
//
// The floor walks up from os.Executable(); under `go test` that binary lives in a
// /tmp build dir with NO corpus marker above it, so the floor would FAIL-SAFE and
// force-escalate every finding (the corpus-not-found path). Pinning the floor's
// EXPORTED test seam removes that — exactly the determinism §4 / the flake-fix
// discipline prescribe. Not parallel-safe across goroutines sharing the override;
// no test below runs parallel.
func pinShippedRoot(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	SetRepoRootForTest(root)
	agent.SetRepoRootForTest(root) // pin the floor's escalate-route corpus too
	t.Cleanup(func() {
		SetRepoRootForTest("")
		agent.SetRepoRootForTest("")
	})
	return root
}

// --- 1. CORPUS LOADER: pinned count + SHA gate. --------------------------------

func TestCorpus_LoadsPinnedCountAndSHA(t *testing.T) {
	root := pinShippedRoot(t)

	c, err := Load(root)
	if err != nil {
		t.Fatalf("Load shipped corpus: %v", err)
	}

	pin, err := readPin(os.DirFS(root), pinRelPath)
	if err != nil {
		t.Fatalf("read pin: %v", err)
	}
	if c.Count != pin.Count {
		t.Fatalf("loaded count %d != pinned %d", c.Count, pin.Count)
	}
	if c.SHA != pin.SHA {
		t.Fatalf("loaded sha %s != pinned %s", c.SHA, pin.SHA)
	}
	if c.Count == 0 {
		t.Fatal("corpus loaded 0 scenarios; layout changed?")
	}
	// Re-scanning yields the identical digest (deterministic manifest).
	c2, err := scanCorpus(os.DirFS(root), scenariosRelPath)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if c2.SHA != c.SHA || c2.Count != c.Count {
		t.Fatalf("non-deterministic scan: (%d,%s) vs (%d,%s)", c.Count, c.SHA, c2.Count, c2.SHA)
	}
}

// --- 2. LEADING-UNDERSCORE PATHS ARE SKIPPED. ----------------------------------

func TestCorpus_SkipsLeadingUnderscorePaths(t *testing.T) {
	root := pinShippedRoot(t)
	c, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The shipped tree contains _schema.yaml (a FILE) and _test/ (a DIRECTORY).
	// Neither may appear in the loaded set, and the count must exclude both.
	scenariosRoot := filepath.Join(root, scenariosRelPath)
	if _, err := os.Stat(filepath.Join(scenariosRoot, "_schema.yaml")); err != nil {
		t.Fatalf("precondition: expected _schema.yaml to exist in the corpus tree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(scenariosRoot, "_test")); err != nil {
		t.Fatalf("precondition: expected _test/ dir to exist in the corpus tree: %v", err)
	}
	for _, s := range c.Scenarios {
		if hasUnderscoreComponent(s.RelPath) {
			t.Fatalf("underscore path leaked into corpus: %s", s.RelPath)
		}
		if strings.Contains(s.RelPath, "_schema") || strings.HasPrefix(s.RelPath, "_test/") {
			t.Fatalf("forbidden underscore path included: %s", s.RelPath)
		}
	}
	// The directory-skip footgun: prove the walker, scanning the SAME tree with the
	// skip removed, WOULD have included more — by counting raw .yaml files.
	rawYAML := 0
	_ = filepath.Walk(scenariosRoot, func(path string, fi os.FileInfo, _ error) error {
		if fi != nil && !fi.IsDir() && strings.HasSuffix(path, ".yaml") {
			rawYAML++
		}
		return nil
	})
	if rawYAML <= c.Count {
		t.Fatalf("expected raw .yaml count (%d) to EXCEED skipped count (%d) — "+
			"the underscore corpus files must exist to make this assertion meaningful", rawYAML, c.Count)
	}
}

// floorForcedBenignHard is the EXACT set of corpus scenarios authored
// chain_action=resolved that a pre-LLM family floor force-escalates to a human.
//
// COMMITTEE-CONSENSUS REALIGNMENT (work/parity-consensus): this set is now EMPTY.
// The three scenarios that used to live here — AC-04 (vendor-onboarding), AC-05
// (contractor-first-day), URA-04 (sibling-rotation) — were force-escalated by the
// E-007 / E-008 detector-family floor routes, which were CUT. Those families now
// reach the model + the 4-voter consensus gate and resolve via their golden
// responses, so under golden scoring the merge-gate is fully green (pass rate 1.0)
// with NO floor-forced benign-hard misses. The map is kept (empty) so the gate's
// arithmetic — wantPass = corpus - len(floorForcedBenignHard) — stays self-
// updating, and so that re-introducing ANY family floor that over-escalates a
// benign-hard scenario must be reflected here explicitly or the gate fails loudly.
var floorForcedBenignHard = map[string]bool{}

// --- 3. END-TO-END MERGE-GATE: golden responses, median over N=3. The gate
// scores HONESTLY. After the E-007 / E-008 family-floor cut (work/parity-consensus)
// the floorForcedBenignHard set is empty, so every scenario passes under golden
// responses and the median pass rate is 1.0. The full production cascade — now
// including the 4-voter consensus gate on every resolve — runs here end-to-end. --

func TestHarness_MergeGate_GreenWithMedianOfN(t *testing.T) {
	pinShippedRoot(t)

	report, err := Run(context.Background(), RunConfig{Mode: ModeCanned, N: 3})
	if err != nil {
		t.Fatalf("Run merge-gate: %v", err)
	}

	if report.CorpusCount == 0 {
		t.Fatal("report has 0 scenarios")
	}
	if len(report.Runs) != 3 {
		t.Fatalf("median-of-N must run N=3 passes; got %d", len(report.Runs))
	}

	// HONEST MERGE-GATE: with the force-escalate auto-pass removed, exactly the
	// floor-forced benign-hard scenarios fail on chain_action. The expected median
	// pass rate is therefore (corpus - benignHard) / corpus — NOT 1.0. Computing it
	// from the pinned set (rather than hardcoding 0.9464) keeps the assertion exact
	// AND self-updating if the corpus count changes, while still catching any EXTRA
	// failure.
	wantPass := report.CorpusCount - len(floorForcedBenignHard)
	wantRate := float64(wantPass) / float64(report.CorpusCount)
	if report.MedianPassRate != wantRate {
		t.Fatalf("merge-gate median pass rate must be %.4f (%d/%d: corpus minus the %d floor-forced "+
			"benign-hard scenarios); got %.4f", wantRate, wantPass, report.CorpusCount,
			len(floorForcedBenignHard), report.MedianPassRate)
	}

	// Every run must fail on EXACTLY the pinned floor-forced benign-hard set — no
	// more, no fewer. A miss on any OTHER scenario is a real regression and fails.
	for _, rr := range report.Runs {
		if rr.Passed != wantPass {
			for _, res := range rr.Results {
				if !res.Pass && !floorForcedBenignHard[res.ScenarioID] {
					t.Errorf("merge-gate UNEXPECTED FAIL run %d: scenario %s expected=%s terminal=%s reason=%q calls=%d",
						rr.Index, res.ScenarioID, res.ExpectedAction, res.TerminalAction, res.TerminalReason, res.ModelCalls)
				}
			}
			t.Fatalf("merge-gate run %d: %d/%d passed, want %d (the pinned benign-hard set must be the ONLY misses)",
				rr.Index, rr.Passed, rr.Total, wantPass)
		}
		for _, res := range rr.Results {
			if floorForcedBenignHard[res.ScenarioID] {
				// The honest cost: an expected-resolved scenario the floor force-escalated.
				if res.Pass {
					t.Errorf("run %d: floor-forced benign-hard scenario %s must FAIL honestly (no auto-pass); got pass",
						rr.Index, res.ScenarioID)
				}
				if !res.ForceEscalated || res.ExpectedAction != "resolved" || res.TerminalAction != "escalated" {
					t.Errorf("run %d: scenario %s expected the floor-forced shape (forceEsc, expected=resolved, terminal=escalated); got forceEsc=%v expected=%s terminal=%s",
						rr.Index, res.ScenarioID, res.ForceEscalated, res.ExpectedAction, res.TerminalAction)
				}
			} else if !res.Pass {
				t.Errorf("run %d: non-floor scenario %s must pass; got expected=%s terminal=%s reason=%q",
					rr.Index, res.ScenarioID, res.ExpectedAction, res.TerminalAction, res.TerminalReason)
			}
		}
	}
	// Golden responses are deterministic → zero variance → within the 8pp band.
	if !report.WithinBand {
		t.Fatalf("golden-response runs must be within the 8pp band (zero variance expected)")
	}
	// The report must STATE it is not the accuracy number.
	if !strings.Contains(report.Note, "NOT") {
		t.Fatalf("merge-gate report must say it is NOT the accuracy number; note=%q", report.Note)
	}
	// The report must STATE median_pass_rate is blended (mallcoppro C2).
	if !strings.Contains(report.Note, "BLENDED") {
		t.Fatalf("merge-gate report must say median_pass_rate is BLENDED; note=%q", report.Note)
	}

	// RECALL/PRECISION SPLIT (mallcoppro C2): the shipped corpus is 40 attacks
	// (expected chain_action demands escalate) / 18 benigns (expected resolved).
	// With floorForcedBenignHard empty, EVERY scenario passes under golden
	// responses, so both recall and precision must be a clean 1.0 — the split
	// must never silently collapse the two into one number.
	const wantAttacks, wantBenigns = 40, 18
	if wantAttacks+wantBenigns != report.CorpusCount {
		t.Fatalf("test assumption stale: wantAttacks(%d)+wantBenigns(%d) != corpus count %d — corpus composition changed",
			wantAttacks, wantBenigns, report.CorpusCount)
	}
	for _, rr := range report.Runs {
		if rr.Attacks != wantAttacks || rr.Benigns != wantBenigns {
			t.Fatalf("run %d: attacks/benigns split = %d/%d, want %d/%d", rr.Index, rr.Attacks, rr.Benigns, wantAttacks, wantBenigns)
		}
		if rr.Attacks+rr.Benigns != rr.Total {
			t.Fatalf("run %d: attacks(%d)+benigns(%d) != total(%d) — every scenario must land in exactly one bucket", rr.Index, rr.Attacks, rr.Benigns, rr.Total)
		}
		if rr.AttacksPassed != wantAttacks {
			t.Fatalf("run %d: attacks_passed = %d, want %d (no floor-forced attack misses)", rr.Index, rr.AttacksPassed, wantAttacks)
		}
		if rr.RecallRate != 1.0 {
			t.Fatalf("run %d: recall_rate = %.4f, want 1.0 (golden responses catch every attack)", rr.Index, rr.RecallRate)
		}
		wantBenignsPassed := wantBenigns - len(floorForcedBenignHard)
		if rr.BenignsPassed != wantBenignsPassed {
			t.Fatalf("run %d: benigns_passed = %d, want %d (floor-forced benign-hard set is the only precision cost)", rr.Index, rr.BenignsPassed, wantBenignsPassed)
		}
		wantPrecisionRate := float64(wantBenignsPassed) / float64(wantBenigns)
		if rr.PrecisionRate != wantPrecisionRate {
			t.Fatalf("run %d: precision_rate = %.4f, want %.4f", rr.Index, rr.PrecisionRate, wantPrecisionRate)
		}
	}
	if report.MedianRecallRate != 1.0 {
		t.Fatalf("median_recall_rate = %.4f, want 1.0", report.MedianRecallRate)
	}
	wantMedianPrecision := float64(wantBenigns-len(floorForcedBenignHard)) / float64(wantBenigns)
	if report.MedianPrecisionRate != wantMedianPrecision {
		t.Fatalf("median_precision_rate = %.4f, want %.4f", report.MedianPrecisionRate, wantMedianPrecision)
	}

	// CLASSIFIER: under golden responses every NON-floor scenario passes the GATING
	// axis (chain_action) and bins as PASS or R_rubric_axis_fail (a NON-GATING
	// provenance bin). The 3 floor-forced benign-hard scenarios bin as
	// A1_invest_should_resolve_but_escalated — the HONEST over-escalation cost. No
	// scenario may land in the DANGEROUS under-escalation bin or an infra-failure
	// bin under golden responses.
	pass := report.Classifier.Counts[BinPass]
	rubric := report.Classifier.Counts[BinRubricAxisFail]
	shouldResolve := report.Classifier.Counts[BinShouldResolve]
	if shouldResolve != len(floorForcedBenignHard) {
		t.Fatalf("classifier: exactly %d scenarios must bin as %s (the floor-forced benign-hard cost); got %d (counts=%v)",
			len(floorForcedBenignHard), BinShouldResolve, shouldResolve, report.Classifier.Counts)
	}
	if pass+rubric+shouldResolve != report.CorpusCount {
		t.Fatalf("classifier: PASS(%d)+R_rubric_axis_fail(%d)+A1_should_resolve(%d) must equal corpus %d under golden responses; counts=%v",
			pass, rubric, shouldResolve, report.CorpusCount, report.Classifier.Counts)
	}
	for _, bad := range []FailBin{BinNoInference, BinChainDrop, BinShouldEscalate} {
		if n := report.Classifier.Counts[bad]; n != 0 {
			t.Fatalf("classifier: golden responses must produce ZERO %s (no under-escalation, no infra failure); got %d (counts=%v)", bad, n, report.Classifier.Counts)
		}
	}
	// The A1_invest_should_resolve_but_escalated scenarios must be EXACTLY the
	// pinned floor-forced benign-hard set.
	for id, bin := range report.Classifier.PerScenario {
		switch bin {
		case BinShouldResolve:
			if !floorForcedBenignHard[id] {
				t.Fatalf("classifier: scenario %s binned %s but is not in the pinned floor-forced benign-hard set", id, BinShouldResolve)
			}
		case BinRubricAxisFail:
			// Every R_rubric_axis_fail scenario must be one whose chain_action still
			// passed (the bin is provenance, never a harness failure).
			if r := findResult(report.Runs, id); r == nil || r.Structural.ChainAction != AxisPass {
				t.Fatalf("R_rubric_axis_fail scenario %s must have chain_action=pass (non-gating bin)", id)
			}
		}
	}

	// TRANSCRIPTS + RESULT JSON + CLASSIFIER persisted (§4.4/§4.7).
	out := t.TempDir()
	written, err := WriteArtifacts(out, report)
	if err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}
	if written != report.CorpusCount*len(report.Runs) {
		t.Fatalf("expected %d transcript files (count*runs); wrote %d", report.CorpusCount*len(report.Runs), written)
	}
	mustExist(t, filepath.Join(out, "report.json"))
	mustExist(t, filepath.Join(out, "classifier.json"))
	// Spot-check one scenario's result JSON + transcript carries real chain data.
	// Pick a scenario that actually REACHED the model: a force-escalated finding
	// (e.g. an E-001..E-005 hard-constraint route) is escalated pre-LLM and correctly
	// has NO model exchange — an empty transcript is the right behavior there, not a
	// capture regression. The §4.7 "every model exchange captured" invariant is
	// meaningful only for a finding that made model calls.
	var sample string
	for _, res := range report.Runs[0].Results {
		if !res.ForceEscalated && res.ModelCalls > 0 {
			sample = res.ScenarioID
			break
		}
	}
	if sample == "" {
		t.Fatal("no non-force-escalated scenario with model calls to spot-check transcript capture")
	}
	mustExist(t, filepath.Join(out, "run-0", sample+".json"))
	trPath := filepath.Join(out, "run-0", sample+".transcript.json")
	mustExist(t, trPath)
	data, _ := os.ReadFile(trPath)
	if len(strings.TrimSpace(string(data))) < 3 {
		t.Fatalf("transcript %s is empty; §4.7 requires every model exchange captured", trPath)
	}
}

// --- 4. TRANSCRIPT capture is non-negotiable: escalate path has the full chain. -

func TestHarness_TranscriptCapturesFullChain(t *testing.T) {
	pinShippedRoot(t)
	report, err := Run(context.Background(), RunConfig{Mode: ModeCanned, N: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rr := report.Runs[0]

	// A non-force-escalated ESCALATED scenario drives triage→investigate→escalate
	// = 3 model calls, each captured. AF-02 (distributed-spray) is such a case.
	var found bool
	for _, res := range rr.Results {
		if res.ScenarioID == "AF-02-distributed-spray" {
			found = true
			if res.ForceEscalated {
				t.Fatalf("AF-02 should not be force-escalated (auth-failure-burst is not a hard-constraint route)")
			}
			if res.ModelCalls != 3 {
				t.Fatalf("AF-02 escalate chain should be 3 model calls (triage→investigate→escalate); got %d", res.ModelCalls)
			}
			tr := rr.Transcripts[res.ScenarioID]
			if len(tr) != 3 {
				t.Fatalf("AF-02 transcript should have 3 entries; got %d", len(tr))
			}
			// Every entry carries the system prompt + boxed user prompt (audit value).
			for _, e := range tr {
				if e.System == "" || e.UserPrompt == "" {
					t.Fatalf("transcript entry seq %d missing system/user prompt: %+v", e.Seq, e)
				}
				if !strings.Contains(e.UserPrompt, "USER_DATA") {
					t.Fatalf("transcript entry seq %d user prompt not boxed in USER_DATA markers", e.Seq)
				}
			}
		}
		// A force-escalated PE-* scenario makes ZERO model calls (pre-model floor).
		if res.ScenarioID == "PE-02-self-elevation" {
			if !res.ForceEscalated {
				t.Fatalf("PE-02 (priv-escalation) must be force-escalated pre-model")
			}
			if res.ModelCalls != 0 {
				t.Fatalf("force-escalated PE-02 must make 0 model calls; got %d", res.ModelCalls)
			}
			if res.TerminalAction != "escalated" {
				t.Fatalf("PE-02 terminal must be escalated; got %s", res.TerminalAction)
			}
		}
	}
	if !found {
		t.Fatal("AF-02-distributed-spray not in corpus; the transcript assertion needs it")
	}
}

// --- 5. INTEGRITY GATE HARD-FAILS on a tampered corpus (temp copy). ------------

func TestCorpus_IntegrityGate_HardFailsOnTamper(t *testing.T) {
	src := repoRoot(t)

	// Build a temp corpus tree that PASSES, then tamper it.
	tmp := t.TempDir()
	copyTree(t, filepath.Join(src, scenariosRelPath), filepath.Join(tmp, scenariosRelPath))
	// A go.mod marker so RepoRoot-style resolution is consistent (not strictly
	// needed — Load takes an explicit root).
	mustWrite(t, filepath.Join(tmp, "go.mod"), "module tmp\n\ngo 1.25\n")

	// Sanity: the untampered copy loads clean against its own pin.
	if _, err := Load(tmp); err != nil {
		t.Fatalf("untampered temp copy should load clean: %v", err)
	}

	// TAMPER A: edit a scenario's bytes → SHA mismatch → HARD FAIL.
	victim := pickAnyScenario(t, filepath.Join(tmp, scenariosRelPath))
	appendBytes(t, victim, "\n# tamper: an attacker edited this scenario\n")
	_, err := Load(tmp)
	if err == nil {
		t.Fatal("edited scenario must HARD-FAIL the SHA gate; Load returned no error")
	}
	if !strings.Contains(err.Error(), "sha256") && !strings.Contains(err.Error(), "INTEGRITY") {
		t.Fatalf("tamper error should name the SHA integrity gate; got %v", err)
	}

	// Restore by re-copying, then TAMPER B: add a scenario → COUNT mismatch.
	copyTree(t, filepath.Join(src, scenariosRelPath), filepath.Join(tmp, scenariosRelPath))
	if _, err := Load(tmp); err != nil {
		t.Fatalf("re-copied temp corpus should load clean: %v", err)
	}
	mustWrite(t, filepath.Join(tmp, scenariosRelPath, "behavioral", "ZZ-99-injected.yaml"),
		"id: ZZ-99-injected\nfinding:\n  id: fnd_zz\n  detector: unusual-timing\n  title: injected\n")
	_, err = Load(tmp)
	if err == nil {
		t.Fatal("added scenario must HARD-FAIL the COUNT gate; Load returned no error")
	}
	if !strings.Contains(err.Error(), "count") && !strings.Contains(err.Error(), "INTEGRITY") {
		t.Fatalf("count tamper error should name the count integrity gate; got %v", err)
	}
}

// --- 6. REAL-MODEL MODE is WIRED but refuses to run without creds. -------------

func TestRealMode_WiredButRefusesWithoutCreds(t *testing.T) {
	// Ensure the creds are unset for this assertion (restore after).
	for _, k := range []string{"MALLCOP_INFERENCE_URL", "MALLCOP_API_KEY"} {
		old, had := os.LookupEnv(k)
		_ = os.Unsetenv(k)
		if had {
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		}
	}
	if _, err := RealClientFromEnv(); err == nil {
		t.Fatal("RealClientFromEnv must error without MALLCOP_INFERENCE_URL/MALLCOP_API_KEY")
	}

	// The harness ModeReal also refuses a nil client (no creds → no run).
	pinShippedRoot(t)
	_, err := Run(context.Background(), RunConfig{Mode: ModeReal, N: 1, RealClient: nil})
	if err == nil {
		t.Fatal("ModeReal with a nil client must refuse to run (no creds)")
	}
}

// --- 7. splitRecallPrecision: the recall/precision partition is a pure function
// of ExpectedAction + Pass, independent of any real run (mallcoppro C2). --------

func TestSplitRecallPrecision(t *testing.T) {
	results := []ScenarioResult{
		{ScenarioID: "attack-caught", ExpectedAction: "escalated", Pass: true},
		{ScenarioID: "attack-missed", ExpectedAction: "escalated", Pass: false},
		{ScenarioID: "attack-or-stronger-caught", ExpectedAction: "escalate-or-stronger", Pass: true},
		{ScenarioID: "benign-correct", ExpectedAction: "resolved", Pass: true},
		{ScenarioID: "benign-false-alarm", ExpectedAction: "resolved", Pass: false},
	}
	attacks, attacksPassed, benigns, benignsPassed := splitRecallPrecision(results)
	if attacks != 3 {
		t.Fatalf("attacks = %d, want 3 (2 escalated + 1 escalate-or-stronger)", attacks)
	}
	if attacksPassed != 2 {
		t.Fatalf("attacksPassed = %d, want 2 (attack-caught + attack-or-stronger-caught)", attacksPassed)
	}
	if benigns != 2 {
		t.Fatalf("benigns = %d, want 2", benigns)
	}
	if benignsPassed != 1 {
		t.Fatalf("benignsPassed = %d, want 1 (benign-correct only)", benignsPassed)
	}

	// Empty input: both denominators zero, no division-by-zero panic.
	a, ap, b, bp := splitRecallPrecision(nil)
	if a != 0 || ap != 0 || b != 0 || bp != 0 {
		t.Fatalf("splitRecallPrecision(nil) = (%d,%d,%d,%d), want all zero", a, ap, b, bp)
	}
	if rate(ap, a) != 0 {
		t.Fatalf("rate(0,0) = %v, want 0 (no NaN/panic on empty attack set)", rate(ap, a))
	}
}

// --- helpers -------------------------------------------------------------------

// findResult returns the ScenarioResult for id in the first run that has it.
func findResult(runs []RunResult, id string) *ScenarioResult {
	for i := range runs {
		for j := range runs[i].Results {
			if runs[i].Results[j].ScenarioID == id {
				return &runs[i].Results[j]
			}
		}
	}
	return nil
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected artifact %s: %v", path, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func appendBytes(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open append %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}

// copyTree mirrors src into dst (files + dirs), overwriting dst. Used to build a
// tamperable temp corpus from the shipped one.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	_ = os.RemoveAll(dst)
	err := filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copyTree %s→%s: %v", src, dst, err)
	}
}

// pickAnyScenario returns the path of one included scenario under root (skips
// underscore paths and the pin file).
func pickAnyScenario(t *testing.T, root string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(root, func(path string, fi os.FileInfo, _ error) error {
		if found != "" || fi == nil || fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if hasUnderscoreComponent(filepath.ToSlash(rel)) {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatal("no scenario found to tamper")
	}
	return found
}
