// infra_subversion_exam_regression_test.go — the CI regression for
// mallcoppro-192 (the security-vs-ops crux): proves, through the REAL
// exam-detect grader over the REAL pinned corpus (exams/scenarios/
// infra_subversion/), that each new infra-subversion class fires config-drift
// (or, for the priv-escalation gap, is correctly documented as NOT firing) and
// that its routine-authorized counterpart stays quiet — in BOTH directions,
// which is the "enforcement bundles its proof" requirement the item asks for.
//
// This lives in the EXTERNAL detect_test package (mirrors
// tuning_exam_regression_test.go): it imports core/eval to run the offline,
// deterministic, LLM-free exam-detect grader (RunExamDetect) over the on-disk
// corpus — no inference client anywhere on this path. The committee/consensus
// LLM layer (core/agent) is a SEPARATE, live-model-only proof (the corpus'
// full expected.chain_action / trap_description / ground_truth fields feed
// THAT proof on the next live e2e corpus run, per the project's established
// practice of not spending metered inference in a unit-test CI gate) — this
// test pins what IS mechanically provable here and now: the real detector
// layer over the real corpus separates the dangerous direction/shape from the
// routine one, for every class this item adds.
package detect_test

import (
	"testing"

	"github.com/mallcop-app/mallcop/core/eval"
)

// infraSubversionPair names one subversion-class scenario ID and its
// routine-authorized twin's ID, plus the families each is graded on.
type infraSubversionPair struct {
	class           string
	subversionID    string
	subversionFire  []string // families that MUST fire on the subversion scenario
	subversionQuiet []string // families that MUST NOT fire on the subversion scenario
	routineID       string
	routineQuiet    []string // families that MUST NOT fire on the routine twin
}

// infraSubversionPairs enumerates every class-vs-routine pair mallcoppro-192
// adds to the pinned reference corpus (exams/scenarios/infra_subversion/).
var infraSubversionPairs = []infraSubversionPair{
	{
		class:          "disable-local-auth-weakening",
		subversionID:   "IS-01-disable-local-auth-weakened",
		subversionFire: []string{"config-drift"},
		routineID:      "IS-02-disable-local-auth-hardened-benign",
	},
	{
		class:          "diagnostic-settings-delete-audit-blinding",
		subversionID:   "IS-03-diagnostic-settings-delete",
		subversionFire: []string{"config-drift"},
		routineID:      "IS-04-diagnostic-settings-update-benign",
	},
	{
		class:          "dns-zone-delete-domain-hijack",
		subversionID:   "IS-05-dns-zone-delete",
		subversionFire: []string{"config-drift"},
		routineID:      "IS-06-dns-record-change-benign",
	},
	{
		class:          "cosmos-container-delete-store-destruction",
		subversionID:   "IS-07-cosmos-container-delete",
		subversionFire: []string{"config-drift"},
		routineID:      "IS-08-cosmos-container-create-benign",
	},
	{
		class:          "consistency-level-weakening",
		subversionID:   "IS-09-consistency-level-weakened",
		subversionFire: []string{"config-drift"},
		routineID:      "IS-10-consistency-level-strengthened-benign",
	},
	{
		class:           "relay-write-allowlist-grant-to-unexpected-principal",
		subversionID:    "IS-11-relay-allowlist-grant-unexpected-pubkey",
		subversionFire:  []string{"config-drift"},
		subversionQuiet: []string{"priv-escalation"}, // tracked gap, mallcoppro-956
		routineID:       "IS-12-relay-allowlist-grant-onboarding-benign",
		routineQuiet:    []string{"config-drift", "priv-escalation"},
	},
}

// TestExamDetect_InfraSubversionCorpus is the corpus-level, both-directions
// proof: for every class above, the subversion scenario's must_fire/
// must_not_fire families grade PASS, and the routine twin's must_not_fire
// families grade PASS — over the REAL exam-detect grader run against the REAL
// pinned corpus (no synthetic/extra-dir scaffolding: these are committed
// reference-corpus scenarios).
func TestExamDetect_InfraSubversionCorpus(t *testing.T) {
	root := repoRootFromHere(t)
	eval.SetRepoRootForTest(root)
	t.Cleanup(func() { eval.SetRepoRootForTest("") })

	report, err := eval.RunExamDetect(root)
	if err != nil {
		t.Fatalf("RunExamDetect: %v", err)
	}

	for _, p := range infraSubversionPairs {
		t.Run(p.class, func(t *testing.T) {
			sub := examRow(t, report, p.subversionID)
			if !sub.Pass {
				t.Fatalf("%s (subversion) FAILED grading: must_fire=%v must_not_fire=%v emitted=%v",
					p.subversionID, sub.MustFire, sub.MustNotFire, sub.Emitted)
			}
			for _, fam := range p.subversionFire {
				if !emittedHas(sub, fam) {
					t.Errorf("%s: expected %q to FIRE (escalate via the detector layer), emitted=%v", p.subversionID, fam, sub.Emitted)
				}
			}
			for _, fam := range p.subversionQuiet {
				if emittedHas(sub, fam) {
					t.Errorf("%s: expected %q to stay quiet, emitted=%v", p.subversionID, fam, sub.Emitted)
				}
			}

			routine := examRow(t, report, p.routineID)
			if !routine.Pass {
				t.Fatalf("%s (routine twin) FAILED grading: must_fire=%v must_not_fire=%v emitted=%v",
					p.routineID, routine.MustFire, routine.MustNotFire, routine.Emitted)
			}
			for _, fam := range p.routineQuiet {
				if emittedHas(routine, fam) {
					t.Errorf("%s: expected %q to stay QUIET (routine authorized change), emitted=%v", p.routineID, fam, routine.Emitted)
				}
			}
		})
	}

	// Corpus-wide sanity: the code this item touches (config_drift.go's
	// readConfigPayload/applies plumbing, and the new_external_access.go
	// refactor onto the shared hasApprovalSignal helper) must not change
	// EITHER family's verdict on any PRE-EXISTING scenario.
	//
	// This deliberately checks only the two families this item's code
	// touches — config-drift and new-external-access — rather than each
	// row's overall Pass state: the reference corpus already carries 10
	// pre-existing RED rows on origin/main (unusual-timing / priv-escalation
	// / volume-anomaly / injection-probe gaps — verified via a clean
	// origin/main worktree run before this item's changes; e.g.
	// UT-01-competing-signals, CO-01-newest-first, PI-01-metadata-instruction)
	// that are pre-existing, tracked gaps wholly unrelated to config-drift and
	// not this item's responsibility to fix. Asserting whole-row Pass here
	// would either false-fail on those unrelated gaps or require silently
	// allowlisting them, which would hide a REAL regression in the same row.
	// Checking the two touched families directly is the precise, correct
	// regression guard.
	for _, row := range report.Rows {
		isNew := false
		for _, p := range infraSubversionPairs {
			if row.ScenarioID == p.subversionID || row.ScenarioID == p.routineID {
				isNew = true
				break
			}
		}
		if isNew {
			continue
		}
		for _, fam := range []string{"config-drift", "new-external-access"} {
			wantFire := false
			for _, want := range row.MustFire {
				if want == fam {
					wantFire = true
				}
			}
			wantQuiet := false
			for _, banned := range row.MustNotFire {
				if banned == fam {
					wantQuiet = true
				}
			}
			has := emittedHas(row, fam)
			if wantFire && !has {
				t.Errorf("REGRESSION: pre-existing scenario %s expected %q to fire but it did not (emitted: %v)", row.ScenarioID, fam, row.Emitted)
			}
			if wantQuiet && has {
				t.Errorf("REGRESSION: pre-existing scenario %s expected %q to stay quiet but it fired (emitted: %v)", row.ScenarioID, fam, row.Emitted)
			}
		}
	}
}
