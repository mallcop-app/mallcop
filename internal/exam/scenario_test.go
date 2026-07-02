package exam_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mallcop-app/mallcop/internal/exam"
)

// scenarioPath resolves a path relative to the repo root (two levels up from
// this test file's directory, which is internal/exam/).
func scenarioPath(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = .../internal/exam/scenario_test.go
	// repoRoot  = .../  (two levels up)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repoRoot, rel)
}

// TestLoad_HappyPath loads the canonical ID-01 scenario and asserts every
// required field is populated.
func TestLoad_HappyPath(t *testing.T) {
	path := scenarioPath(t, "exams/scenarios/identity/ID-01-new-actor-benign-onboarding.yaml")

	s, err := exam.Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if s.ID != "ID-01-new-actor-benign-onboarding" {
		t.Errorf("ID = %q, want %q", s.ID, "ID-01-new-actor-benign-onboarding")
	}
	if s.FailureMode == "" {
		t.Error("FailureMode is empty")
	}
	if s.Detector == "" {
		t.Error("Detector is empty")
	}
	if s.Category == "" {
		t.Error("Category is empty")
	}
	if s.Difficulty == "" {
		t.Error("Difficulty is empty")
	}
	if s.Finding == nil {
		t.Fatal("Finding is nil")
	}
	if s.Finding.Severity == "" {
		t.Error("Finding.Severity is empty")
	}
	if s.Finding.ID == "" {
		t.Error("Finding.ID is empty")
	}
	if len(s.Events) == 0 {
		t.Error("Events is empty")
	}
	for i, ev := range s.Events {
		if ev.ID == "" {
			t.Errorf("Events[%d].ID is empty", i)
		}
	}
	if s.Baseline == nil {
		t.Fatal("Baseline is nil")
	}
	if len(s.Baseline.KnownEntities.Actors) == 0 {
		t.Error("Baseline.KnownEntities.Actors is empty")
	}
	if s.ExpectedResolution == nil {
		t.Fatal("ExpectedResolution is nil")
	}
	if s.ExpectedResolution.ChainAction == "" {
		t.Error("ExpectedResolution.ChainAction is empty")
	}
}

// TestLoad_GroundTruthRoundtrip verifies that TrapDescription and
// TrapResolvedMeans are populated in ID-01, confirming that the loader CAN
// read them (so the blind-render layer has something to strip).
func TestLoad_GroundTruthRoundtrip(t *testing.T) {
	path := scenarioPath(t, "exams/scenarios/identity/ID-01-new-actor-benign-onboarding.yaml")

	s, err := exam.Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if s.TrapDescription == "" {
		t.Error("TrapDescription is empty — ground truth should be readable by the loader")
	}
	if s.TrapResolvedMeans == "" {
		t.Error("TrapResolvedMeans is empty — ground truth should be readable by the loader")
	}
}

// TestLoad_ExpectedDetectionRoundtrip verifies the expected_detection block
// round-trips through the loader: must_fire and must_not_fire family tokens are
// preserved exactly.
func TestLoad_ExpectedDetectionRoundtrip(t *testing.T) {
	yaml := `id: test-scenario
failure_mode: KA
detector: volume-anomaly
category: behavioral
difficulty: malicious-hard
finding:
  id: fnd_001
  detector: volume-anomaly
  title: Test finding
  severity: warn
events:
- id: evt_001
  timestamp: "2026-01-01T00:00:00Z"
  source: azure
  event_type: storage_access
  actor: ci-bot
  action: read_blob
  target: sub-1/storageAccounts/foo
  severity: warn
baseline:
  known_entities:
    actors:
    - ci-bot
    sources:
    - azure
expected:
  chain_action: escalated
  triage_action: escalated
expected_detection:
  must_fire:
  - volume-anomaly
  must_not_fire:
  - new-actor
  - unusual-timing
`
	path := writeTempYAML(t, yaml)
	s, err := exam.Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if s.ExpectedDetection == nil {
		t.Fatal("ExpectedDetection is nil — expected_detection block should round-trip")
	}
	if got, want := s.ExpectedDetection.MustFire, []string{"volume-anomaly"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("MustFire = %v, want %v", got, want)
	}
	wantNot := []string{"new-actor", "unusual-timing"}
	if got := s.ExpectedDetection.MustNotFire; len(got) != 2 || got[0] != wantNot[0] || got[1] != wantNot[1] {
		t.Errorf("MustNotFire = %v, want %v", got, wantNot)
	}
}

// TestLoad_ExpectedDetectionAbsent verifies a scenario WITHOUT an
// expected_detection block unmarshals to a nil pointer (the additive-field
// contract) — such scenarios are skipped by the exam-detect grader.
func TestLoad_ExpectedDetectionAbsent(t *testing.T) {
	path := scenarioPath(t, "exams/scenarios/identity/ID-01-new-actor-benign-onboarding.yaml")
	s, err := exam.Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if s.ExpectedDetection != nil {
		t.Errorf("ExpectedDetection = %+v, want nil for a scenario without the block", s.ExpectedDetection)
	}
}

// writeTempYAML writes content to a temp file and returns its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "scenario-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return f.Name()
}

// TestLoad_ValidationErrors is a table test that covers each sentinel error
// by constructing a minimal corrupted YAML for that specific violation.
func TestLoad_ValidationErrors(t *testing.T) {
	// Base valid YAML — we corrupt one field per subtest.
	validYAML := `id: test-scenario
failure_mode: KA
detector: new-actor
category: identity
difficulty: benign-obvious
finding:
  id: fnd_001
  detector: new-actor
  title: Test finding
  severity: warn
events:
- id: evt_001
  timestamp: "2026-01-01T00:00:00Z"
  source: azure
  event_type: login
  actor: user-a
  action: login
  target: tenant/foo
  severity: info
baseline:
  known_entities:
    actors:
    - user-a
    sources:
    - azure
expected:
  chain_action: resolved
  triage_action: resolved
`

	tests := []struct {
		name    string
		yaml    string
		wantErr error
	}{
		{
			name: "missing id",
			yaml: `failure_mode: KA
detector: new-actor
category: identity
difficulty: benign-obvious
finding:
  id: fnd_001
  detector: new-actor
  title: Test finding
  severity: warn
events:
- id: evt_001
  source: azure
  event_type: login
  actor: user-a
  action: login
  target: tenant/foo
  severity: info
baseline:
  known_entities:
    actors:
    - user-a
    sources:
    - azure
`,
			wantErr: exam.ErrMissingID,
		},
		{
			name: "missing finding",
			yaml: `id: test-scenario
failure_mode: KA
detector: new-actor
category: identity
difficulty: benign-obvious
events:
- id: evt_001
  source: azure
  event_type: login
  actor: user-a
  action: login
  target: tenant/foo
  severity: info
baseline:
  known_entities:
    actors:
    - user-a
    sources:
    - azure
`,
			wantErr: exam.ErrMissingFinding,
		},
		{
			name: "malformed events — event missing id",
			yaml: `id: test-scenario
failure_mode: KA
detector: new-actor
category: identity
difficulty: benign-obvious
finding:
  id: fnd_001
  detector: new-actor
  title: Test finding
  severity: warn
events:
- source: azure
  event_type: login
  actor: user-a
  action: login
  target: tenant/foo
  severity: info
baseline:
  known_entities:
    actors:
    - user-a
    sources:
    - azure
`,
			wantErr: exam.ErrMalformedEvents,
		},
		{
			name: "malformed baseline — known_entities empty",
			yaml: `id: test-scenario
failure_mode: KA
detector: new-actor
category: identity
difficulty: benign-obvious
finding:
  id: fnd_001
  detector: new-actor
  title: Test finding
  severity: warn
events:
- id: evt_001
  source: azure
  event_type: login
  actor: user-a
  action: login
  target: tenant/foo
  severity: info
baseline:
  known_entities:
    actors: []
    sources: []
`,
			wantErr: exam.ErrMalformedBaseline,
		},
	}

	// Ensure the base YAML itself loads cleanly (catches template regressions).
	t.Run("base yaml is valid", func(t *testing.T) {
		path := writeTempYAML(t, validYAML)
		if _, err := exam.Load(path); err != nil {
			t.Fatalf("base YAML should be valid but Load returned: %v", err)
		}
	})

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempYAML(t, tc.yaml)
			_, err := exam.Load(path)
			if err == nil {
				t.Fatalf("expected error wrapping %v but got nil", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("errors.Is(err, %v) = false; err = %v", tc.wantErr, err)
			}
		})
	}
}
