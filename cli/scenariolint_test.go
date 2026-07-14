package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const lintCapturedNoTwin = `id: LOCAL-lint-01-no-twin
provenance: captured
finding:
  id: fnd-1
  detector: new-actor
  title: captured attack
  severity: medium
  event_ids: [e1]
baseline:
  known_entities:
    actors: [known-actor]
events:
  - id: e1
    timestamp: '2026-07-01T00:00:00Z'
    source: github
    event_type: push
    actor: mallory
expected_detection:
  must_fire: [new-actor]
`

const lintCapturedWithTwinAttack = `id: LOCAL-lint-02-paired-attack
provenance: captured
finding:
  id: fnd-2
  detector: unusual-timing
  title: captured attack
  severity: medium
  event_ids: [e2]
baseline:
  known_entities:
    actors: [known-actor]
events:
  - id: e2
    timestamp: '2026-07-01T03:00:00Z'
    source: github
    event_type: push
    actor: mallory
expected_detection:
  must_fire: [unusual-timing]
`

const lintCapturedWithTwinBenign = `id: LOCAL-lint-03-paired-benign
provenance: captured
finding:
  id: fnd-3
  detector: unusual-timing
  title: captured benign twin
  severity: medium
  event_ids: [e3]
baseline:
  known_entities:
    actors: [known-actor]
events:
  - id: e3
    timestamp: '2026-07-01T14:00:00Z'
    source: github
    event_type: push
    actor: known-actor
expected_detection:
  must_not_fire: [unusual-timing]
`

const lintMalformedScenario = `finding:
  id: fnd-4
  detector: x
  title: no id
  severity: low
  event_ids: [e4]
events:
  - id: e4
    timestamp: '2026-07-01T00:00:00Z'
    source: github
    event_type: push
    actor: someone
`

func writeLintFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestScenarioLint_MissingTwin_WarnsButDoesNotBlock proves a captured
// must_fire family with no must_not_fire twin anywhere in the directory
// prints the exact family + a capture recipe, and still returns nil (a
// WARNING, never a block).
func TestScenarioLint_MissingTwin_WarnsButDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	writeLintFixture(t, dir, "no-twin.yaml", lintCapturedNoTwin)

	out, err := withStdio(t, "", func() error {
		return runScenarioLint([]string{"--scenarios-dir", dir})
	})
	if err != nil {
		t.Fatalf("runScenarioLint: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "WARNING") {
		t.Errorf("output missing WARNING marker:\n%s", out)
	}
	if !strings.Contains(out, "new-actor") {
		t.Errorf("output does not name the missing family (new-actor):\n%s", out)
	}
	if !strings.Contains(out, "LOCAL-lint-01-no-twin") {
		t.Errorf("output does not name the scenario that asserted the missing family:\n%s", out)
	}
	if !strings.Contains(out, "recipe:") {
		t.Errorf("output does not include a capture recipe:\n%s", out)
	}
}

// TestScenarioLint_PairedSet_NoWarning proves a captured must_fire scenario
// WITH a must_not_fire twin (any provenance) in the same directory produces
// no warning at all.
func TestScenarioLint_PairedSet_NoWarning(t *testing.T) {
	dir := t.TempDir()
	writeLintFixture(t, dir, "attack.yaml", lintCapturedWithTwinAttack)
	writeLintFixture(t, dir, "benign.yaml", lintCapturedWithTwinBenign)

	out, err := withStdio(t, "", func() error {
		return runScenarioLint([]string{"--scenarios-dir", dir})
	})
	if err != nil {
		t.Fatalf("runScenarioLint: %v\noutput:\n%s", err, out)
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("expected no WARNING for a fully-paired set:\n%s", out)
	}
	if !strings.Contains(out, "every captured must_fire family has at least one must_not_fire twin") {
		t.Errorf("expected the all-clear message:\n%s", out)
	}
}

// TestScenarioLint_ParseErrorBlocks proves a malformed scenario (missing the
// required id field) is a HARD failure, not a warning — the same
// internal/exam.Load validation 'mallcop eval' depends on.
func TestScenarioLint_ParseErrorBlocks(t *testing.T) {
	dir := t.TempDir()
	writeLintFixture(t, dir, "broken.yaml", lintMalformedScenario)

	_, err := withStdio(t, "", func() error {
		return runScenarioLint([]string{"--scenarios-dir", dir})
	})
	if err == nil {
		t.Fatal("expected an error for a scenario missing its required id field")
	}
}

// TestScenarioLint_MissingDirIsNotAnError mirrors cli/eval.go's default-dir
// handling: a scenarios/ directory that does not exist yet is an empty local
// corpus, not a failure.
func TestScenarioLint_MissingDirIsNotAnError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	out, err := withStdio(t, "", func() error {
		return runScenarioLint([]string{"--scenarios-dir", dir})
	})
	if err != nil {
		t.Fatalf("runScenarioLint on a missing dir: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "nothing to lint") {
		t.Errorf("expected a graceful nothing-to-lint message:\n%s", out)
	}
}
