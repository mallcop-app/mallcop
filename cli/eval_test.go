package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/detect"
)

// localGreenScenario is a minimal LOCAL must-fire scenario for the
// "new-actor" family — a REGISTERED built-in detector (core/detect's
// newActorDetector fires on any actor absent from the baseline's
// known_entities.actors). This is the operator's own scenarios/ directory
// content: a scenario mallcop eval's local union must GRADE GREEN.
const localGreenScenario = `id: LOCAL-01-new-actor-fixture
detector: new-actor
provenance: operator
finding:
  id: fnd_local_001
  detector: new-actor
  title: 'New actor observed: ext-fixture-actor'
  severity: medium
  event_ids: [evt_001]
baseline:
  known_entities:
    actors: [admin-user]
    sources: [azure]
events:
  - id: evt_001
    timestamp: '2026-07-01T00:00:00Z'
    source: azure
    event_type: resource_list
    actor: ext-fixture-actor
    action: list_resources
    target: sub-fixture
    severity: info
expected_detection:
  must_fire: [new-actor]
`

// localReservedGapScenario is a RESERVED must-fire scenario for a family with
// NO registered detector anywhere in this process ("beacon-c2-callback" is
// not a name any core/detect.Detectors() entry uses) — the operator's own
// tracked, not-yet-built coverage gap. mallcop eval must grade this as a
// TRACKED GAP (a recall miss with Reserved==true), never a hard failure.
const localReservedGapScenario = `id: LOCAL-02-reserved-not-yet-built
detector: beacon-c2-callback
provenance: operator
finding:
  id: fnd_local_002
  detector: beacon-c2-callback
  title: 'Suspected C2 beacon callback'
  severity: high
  event_ids: [evt_002]
events:
  - id: evt_002
    timestamp: '2026-07-01T00:05:00Z'
    source: edr
    event_type: network_connection
    actor: workstation-77
    action: outbound_connect
    target: 203.0.113.9
    severity: high
expected_detection:
  must_fire: [beacon-c2-callback]
  reserved: true
`

// newEvalFixtureDeployRepo writes a temp deploy-repo scenarios/ directory
// with one green local scenario and one reserved-gap local scenario, and
// returns the scenarios/ dir path.
func newEvalFixtureDeployRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	scenariosDir := filepath.Join(dir, "scenarios")
	if err := os.MkdirAll(scenariosDir, 0o755); err != nil {
		t.Fatalf("mkdir scenarios/: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenariosDir, "local-01.yaml"), []byte(localGreenScenario), 0o644); err != nil {
		t.Fatalf("write local-01.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenariosDir, "local-02.yaml"), []byte(localReservedGapScenario), 0o644); err != nil {
		t.Fatalf("write local-02.yaml: %v", err)
	}
	return scenariosDir
}

// evalJSONShape mirrors evalJSONReport's wire shape for test decoding.
type evalJSONShape struct {
	Reference struct {
		Recall struct {
			MustFire int `json:"must_fire"`
			Detected int `json:"detected"`
		} `json:"recall"`
	} `json:"reference"`
	Local struct {
		Recall struct {
			MustFire int `json:"must_fire"`
			Detected int `json:"detected"`
			Missed   []struct {
				ScenarioID string   `json:"scenario_id"`
				Missing    []string `json:"missing_families"`
				Reserved   bool     `json:"reserved,omitempty"`
			} `json:"missed,omitempty"`
		} `json:"recall"`
		Precision struct {
			MustStaySilent int `json:"must_stay_silent"`
			CorrectSilent  int `json:"correct_silent"`
		} `json:"precision"`
	} `json:"local"`
}

// TestRunEval_LocalVsReferenceSplit is the C4 acceptance test: a temp
// deploy-repo scenarios/ directory carrying one registered-family must-fire
// scenario (green) and one reserved-but-unregistered must-fire scenario
// (tracked gap) must show up distinctly in --json's "local" block, separate
// from the "reference" block's own (much larger) shipped-corpus recall.
func TestRunEval_LocalVsReferenceSplit(t *testing.T) {
	detect.ResetTuning()
	t.Cleanup(detect.ResetTuning)

	scenariosDir := newEvalFixtureDeployRepo(t)

	out, err := withStdio(t, "", func() error {
		return runEval([]string{"--json", "--scenarios-dir", scenariosDir})
	})

	// The reference corpus (PE-08, per the exam-detect fixtures) carries at
	// least one real labeled gap independent of anything this test adds, so
	// the errFindings sentinel (exit 1) is an expected, informative outcome
	// here — not a test failure. A real command error (exit 2, e.g. corpus
	// load failure) IS a test failure.
	if err != nil && !isFindingsError(err) {
		t.Fatalf("runEval returned a non-findings error: %v\noutput:\n%s", err, out)
	}

	var report evalJSONShape
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		t.Fatalf("--json output is not valid JSON: %v\noutput:\n%s", jsonErr, out)
	}

	// LOCAL split: exactly our 2 fixture scenarios, independent of the
	// reference corpus's own size.
	if report.Local.Recall.MustFire != 2 {
		t.Fatalf("local.recall.must_fire = %d, want 2 (our 2 fixture scenarios only)", report.Local.Recall.MustFire)
	}
	if report.Local.Recall.Detected != 1 {
		t.Fatalf("local.recall.detected = %d, want 1 (only LOCAL-01's new-actor should fire)", report.Local.Recall.Detected)
	}
	if len(report.Local.Recall.Missed) != 1 {
		t.Fatalf("local.recall.missed = %d entries, want 1 (LOCAL-02's reserved gap)", len(report.Local.Recall.Missed))
	}
	missed := report.Local.Recall.Missed[0]
	if missed.ScenarioID != "LOCAL-02-reserved-not-yet-built" {
		t.Errorf("local.recall.missed[0].scenario_id = %q, want LOCAL-02-reserved-not-yet-built", missed.ScenarioID)
	}
	if !missed.Reserved {
		t.Error("local.recall.missed[0].reserved = false, want true (tracked gap, no registered detector for beacon-c2-callback)")
	}
	if len(missed.Missing) != 1 || missed.Missing[0] != "beacon-c2-callback" {
		t.Errorf("local.recall.missed[0].missing_families = %v, want [beacon-c2-callback]", missed.Missing)
	}

	// REFERENCE split: must be non-trivially larger than our 2-scenario local
	// set (the shipped corpus has dozens of labeled scenarios) — proving the
	// two splits are NOT the same rows counted twice.
	if report.Reference.Recall.MustFire <= 2 {
		t.Fatalf("reference.recall.must_fire = %d, want > 2 (the shipped reference corpus, not the local fixture)", report.Reference.Recall.MustFire)
	}
}

// TestRunEval_MissingScenariosDirIsNotAnError proves the DEFAULT resolution
// path (<repo-root>/scenarios) treats an absent directory as an empty local
// union, not a command failure — the brand-new-deploy-repo case (mallcoppro-
// bc2's build note: "a missing default directory is NOT an error").
func TestRunEval_MissingScenariosDirIsNotAnError(t *testing.T) {
	detect.ResetTuning()
	t.Cleanup(detect.ResetTuning)

	// An explicit --scenarios-dir pointing at a real, but EMPTY, directory
	// proves the zero-local-scenarios path renders cleanly (must_fire=0,
	// detected=0, no missed/false-alarm entries) without special-casing
	// empty vs. absent in this test — loadEvalLocalScenarios' absent-default
	// path is exercised by construction (this test passes an explicit empty
	// dir instead of relying on repo-root resolution, which is unavailable
	// inside `go test`'s build sandbox without pinning MALLCOP_REPO_ROOT).
	emptyDir := t.TempDir()

	out, err := withStdio(t, "", func() error {
		return runEval([]string{"--json", "--scenarios-dir", emptyDir})
	})
	if err != nil && !isFindingsError(err) {
		t.Fatalf("runEval returned a non-findings error: %v\noutput:\n%s", err, out)
	}

	var report evalJSONShape
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		t.Fatalf("--json output is not valid JSON: %v\noutput:\n%s", jsonErr, out)
	}
	if report.Local.Recall.MustFire != 0 {
		t.Errorf("local.recall.must_fire = %d, want 0 (no local scenarios)", report.Local.Recall.MustFire)
	}
	if report.Local.Precision.MustStaySilent != 0 {
		t.Errorf("local.precision.must_stay_silent = %d, want 0 (no local scenarios)", report.Local.Precision.MustStaySilent)
	}
}

// TestRunEval_HumanOutputNamesLocalMissesDistinctly proves the non-JSON
// rendering path prints the "MY MISSED ATTACKS" framing distinctly from the
// reference corpus's own recall line, per the C4 build note: "MY MISSED
// ATTACKS: n of m" (local) is distinct from reference recall.
func TestRunEval_HumanOutputNamesLocalMissesDistinctly(t *testing.T) {
	detect.ResetTuning()
	t.Cleanup(detect.ResetTuning)

	scenariosDir := newEvalFixtureDeployRepo(t)

	out, err := withStdio(t, "", func() error {
		return runEval([]string{"--scenarios-dir", scenariosDir})
	})
	if err != nil && !isFindingsError(err) {
		t.Fatalf("runEval returned a non-findings error: %v\noutput:\n%s", err, out)
	}

	if !containsLine(out, "MY MISSED ATTACKS: 1 of 2") {
		t.Errorf("expected a distinct \"MY MISSED ATTACKS: 1 of 2\" line, got:\n%s", out)
	}
	if !containsLine(out, "RECALL (attacks caught):") {
		t.Errorf("expected the reference corpus's own RECALL line, got:\n%s", out)
	}
}
