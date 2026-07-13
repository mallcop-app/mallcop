// reserved_test.go — mallcoppro-db0: proves the RESERVED scenario type.
//
// A reserved scenario specifies a must-fire outcome for a detector family
// BEFORE the detector exists (authored by the requester — operator or a
// captured real customer event — independent of whoever eventually writes the
// detector). These tests write minimal, self-contained scenario YAML into a
// throwaway --extra-scenarios-dir (LoadExtraScenarios never touches
// corpus.pin, so no reference-corpus pin regeneration is needed) and grade it
// through the REAL RunExamDetectExtra + core/detect.Detect path — nothing
// mocked.
package eval

import (
	"os"
	"path/filepath"
	"testing"
)

// writeReservedFixture writes a single minimal, valid scenario YAML file
// (id + finding + one event are the only hard requirements — see
// internal/exam.Load) into a fresh temp dir and returns the dir.
func writeReservedFixture(t *testing.T, filename, yamlBody string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(yamlBody), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", filename, err)
	}
	return dir
}

// reservedUnregisteredYAML labels a must_fire family ("widget-leak-v2") that
// matches NO registered core/detect detector — the "reserve a test before the
// detector exists" case. The event content is irrelevant: no detector in the
// registry could ever satisfy this family regardless of payload.
const reservedUnregisteredYAML = `
id: RESERVED-01-unregistered-family
finding:
  id: fnd_reserved_01
  detector: widget-leak-v2
  title: reserved probe for a not-yet-authored detector
  severity: high
  event_ids: [evt_001]
events:
- id: evt_001
  timestamp: '2026-07-13T00:00:00Z'
  source: widgetapi
  event_type: widget.leak
  actor: some-actor
  action: leak
  target: widget-42
expected_detection:
  must_fire:
  - widget-leak-v2
  reserved: true
`

// reservedButRegisteredNoFireYAML reserves must_fire on volume-anomaly — a
// REAL, REGISTERED detector — with events that do not trigger it. This models
// the "detector has landed but this scenario still isn't satisfied" state:
// the reserved exemption must NOT apply once a detector is registered.
const reservedButRegisteredNoFireYAML = `
id: RESERVED-02-registered-family-still-silent
finding:
  id: fnd_reserved_02
  detector: volume-anomaly
  title: reserved probe against an already-registered detector that stays silent
  severity: high
  event_ids: [evt_001]
events:
- id: evt_001
  timestamp: '2026-07-13T00:00:00Z'
  source: github
  event_type: push
  actor: some-actor
  action: push
  target: acme/repo
expected_detection:
  must_fire:
  - volume-anomaly
  reserved: true
`

// reservedRegisteredFiresYAML reserves must_fire on new-external-access with
// an event that DOES trigger the real detector — the "detector landed and now
// satisfies the reserved ground truth" flip to a genuine pass.
const reservedRegisteredFiresYAML = `
id: RESERVED-03-registered-family-fires
finding:
  id: fnd_reserved_03
  detector: new-external-access
  title: reserved probe that the real detector now satisfies
  severity: critical
  event_ids: [evt_001]
events:
- id: evt_001
  timestamp: '2026-07-13T00:00:00Z'
  source: github
  event_type: repo.add_collaborator
  actor: admin-user
  action: add_collaborator
  target: acme-corp/atom-api
  metadata:
    collaborator: evil-actor-x
expected_detection:
  must_fire:
  - new-external-access
  reserved: true
`

// nonReservedUnregisteredYAML is the CONTROL: the identical unregistered
// family as reservedUnregisteredYAML, but WITHOUT reserved:true — proves the
// exemption is opt-in and an ordinary unmet label still hard-fails exactly as
// before this change.
const nonReservedUnregisteredYAML = `
id: RESERVED-04-control-not-reserved
finding:
  id: fnd_reserved_04
  detector: widget-leak-v2
  title: control — same unregistered family, no reserved flag
  severity: high
  event_ids: [evt_001]
events:
- id: evt_001
  timestamp: '2026-07-13T00:00:00Z'
  source: widgetapi
  event_type: widget.leak
  actor: some-actor
  action: leak
  target: widget-42
expected_detection:
  must_fire:
  - widget-leak-v2
`

// TestRunExamDetectExtra_ReservedUnregisteredFamilyIsTrackedNotFailed proves
// the headline property: a reserved must_fire family with no registered
// detector grades RED (Pass=false, visible on ReservedPending) but does NOT
// count toward Totals.Failed — the "not a hard failure" contract.
func TestRunExamDetectExtra_ReservedUnregisteredFamilyIsTrackedNotFailed(t *testing.T) {
	root := repoRootForTest(t)
	t.Cleanup(func() { SetRepoRootForTest("") })
	dir := writeReservedFixture(t, "reserved01.yaml", reservedUnregisteredYAML)

	report, err := RunExamDetectExtra(root, dir)
	if err != nil {
		t.Fatalf("RunExamDetectExtra: %v", err)
	}
	row := findRow(t, report, "RESERVED-01-unregistered-family")

	if !row.Reserved {
		t.Fatalf("row.Reserved = false, want true")
	}
	if row.Pass {
		t.Fatalf("row.Pass = true, want false — widget-leak-v2 has no registered detector, nothing could have fired")
	}
	if len(row.ReservedPending) != 1 || row.ReservedPending[0] != "widget-leak-v2" {
		t.Fatalf("row.ReservedPending = %v, want [widget-leak-v2]", row.ReservedPending)
	}
	if !row.Extra {
		t.Fatalf("row.Extra = false, want true (loaded via --extra-scenarios-dir)")
	}

	if report.Totals.Reserved != 1 {
		t.Errorf("Totals.Reserved = %d, want 1", report.Totals.Reserved)
	}
	// The whole point: this RED row must not land in Failed (the hard
	// exam/CI gate — see cli/examdetect.go's Totals.Failed > 0 check).
	if got := countFailedContains(report, "RESERVED-01-unregistered-family"); got {
		t.Errorf("RESERVED-01-unregistered-family contributed to Totals.Failed — reserved-and-unregistered must be tracked, not a hard failure")
	}
}

// countFailedContains reports whether the named row's non-pass outcome was
// counted as a hard failure rather than a tracked reservation, by checking
// whether it is BOTH not-passing and NOT carrying a ReservedPending
// exemption for every one of its must_fire families.
func countFailedContains(report ExamDetectReport, scenarioID string) bool {
	for _, r := range report.Rows {
		if r.ScenarioID != scenarioID {
			continue
		}
		if r.Pass {
			return false
		}
		// A row whose ReservedPending covers every must_fire family it failed
		// on is NOT a hard failure.
		return len(r.ReservedPending) == 0
	}
	return false
}

// TestRunExamDetectExtra_ReservedButRegisteredStillHardFails proves the
// "flips to a real pass/fail once the detector is registered" property from
// the miss side: once a REGISTERED detector exists for the family, a reserved
// scenario it still doesn't satisfy is graded as a REAL failure again, not
// exempted forever by the reserved flag.
func TestRunExamDetectExtra_ReservedButRegisteredStillHardFails(t *testing.T) {
	root := repoRootForTest(t)
	t.Cleanup(func() { SetRepoRootForTest("") })
	dir := writeReservedFixture(t, "reserved02.yaml", reservedButRegisteredNoFireYAML)

	report, err := RunExamDetectExtra(root, dir)
	if err != nil {
		t.Fatalf("RunExamDetectExtra: %v", err)
	}
	row := findRow(t, report, "RESERVED-02-registered-family-still-silent")

	if !row.Reserved {
		t.Fatalf("row.Reserved = false, want true")
	}
	if row.Pass {
		t.Fatalf("row.Pass = true, want false — volume-anomaly should not fire on a single lone push event")
	}
	if len(row.ReservedPending) != 0 {
		t.Fatalf("row.ReservedPending = %v, want empty — volume-anomaly IS a registered detector, the reserved exemption must not apply", row.ReservedPending)
	}
	if countFailedContains(report, "RESERVED-02-registered-family-still-silent") != true {
		t.Errorf("RESERVED-02 should count as a REAL failure once its family's detector is registered")
	}
}

// TestRunExamDetectExtra_ReservedFlipsToRealPass proves the flip from the
// success side: a reserved scenario whose family's detector is registered AND
// fires correctly is graded as an ordinary PASS — no different from any
// unreserved scenario.
func TestRunExamDetectExtra_ReservedFlipsToRealPass(t *testing.T) {
	root := repoRootForTest(t)
	t.Cleanup(func() { SetRepoRootForTest("") })
	dir := writeReservedFixture(t, "reserved03.yaml", reservedRegisteredFiresYAML)

	report, err := RunExamDetectExtra(root, dir)
	if err != nil {
		t.Fatalf("RunExamDetectExtra: %v", err)
	}
	row := findRow(t, report, "RESERVED-03-registered-family-fires")

	if !row.Pass {
		t.Fatalf("row.Pass = false, want true — new-external-access should fire on an unapproved repo.add_collaborator event (emitted: %v)", row.Emitted)
	}
	if len(row.ReservedPending) != 0 {
		t.Fatalf("row.ReservedPending = %v, want empty on a passing row", row.ReservedPending)
	}
	if !row.Reserved {
		t.Fatalf("row.Reserved = false, want true (the flag itself persists even once satisfied)")
	}
}

// TestRunExamDetectExtra_NonReservedUnregisteredFamilyHardFails is the
// control: WITHOUT reserved:true, an unmet must_fire family — even one with
// no registered detector — is graded exactly as before this change: a hard
// failure, not a tracked reservation.
func TestRunExamDetectExtra_NonReservedUnregisteredFamilyHardFails(t *testing.T) {
	root := repoRootForTest(t)
	t.Cleanup(func() { SetRepoRootForTest("") })
	dir := writeReservedFixture(t, "reserved04.yaml", nonReservedUnregisteredYAML)

	report, err := RunExamDetectExtra(root, dir)
	if err != nil {
		t.Fatalf("RunExamDetectExtra: %v", err)
	}
	row := findRow(t, report, "RESERVED-04-control-not-reserved")

	if row.Reserved {
		t.Fatalf("row.Reserved = true, want false — no reserved: true in the YAML")
	}
	if row.Pass {
		t.Fatalf("row.Pass = true, want false")
	}
	if len(row.ReservedPending) != 0 {
		t.Fatalf("row.ReservedPending = %v, want empty — the reserved exemption is opt-in", row.ReservedPending)
	}
	if !countFailedContains(report, "RESERVED-04-control-not-reserved") {
		t.Errorf("RESERVED-04-control-not-reserved should be a hard failure exactly like pre-db0 behavior")
	}
}

// TestRunExamDetectExtra_TotalsPartitionInvariant asserts Labeled ==
// Passed+Failed+Reserved over a mixed run (reference corpus + all four
// reserved fixtures unioned) — the accounting contract the CLI gate and any
// self-ext caller relies on.
func TestRunExamDetectExtra_TotalsPartitionInvariant(t *testing.T) {
	root := repoRootForTest(t)
	t.Cleanup(func() { SetRepoRootForTest("") })
	dir := t.TempDir()
	for name, body := range map[string]string{
		"reserved01.yaml": reservedUnregisteredYAML,
		"reserved02.yaml": reservedButRegisteredNoFireYAML,
		"reserved03.yaml": reservedRegisteredFiresYAML,
		"reserved04.yaml": nonReservedUnregisteredYAML,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	report, err := RunExamDetectExtra(root, dir)
	if err != nil {
		t.Fatalf("RunExamDetectExtra: %v", err)
	}
	totals := report.Totals
	if got, want := totals.Passed+totals.Failed+totals.Reserved, totals.Labeled; got != want {
		t.Errorf("Passed(%d)+Failed(%d)+Reserved(%d) = %d, want Labeled = %d", totals.Passed, totals.Failed, totals.Reserved, got, want)
	}
	if totals.Reserved < 1 {
		t.Errorf("Totals.Reserved = %d, want >= 1 (RESERVED-01 must be tracked)", totals.Reserved)
	}
}

// TestRegisteredFamilies_MatchesFrameworkDetectorNames pins registeredFamilies
// against the checked-in framework detector name list (core/detect's own
// TestFrameworkDetectorNamesMatchRegistry keeps that list honest against the
// live registry) — a basic sanity check that the reserved-exemption lookup is
// wired to the real registry, not an empty or stale set.
func TestRegisteredFamilies_MatchesFrameworkDetectorNames(t *testing.T) {
	set := registeredFamilies()
	if len(set) == 0 {
		t.Fatal("registeredFamilies() returned empty set — no detectors registered in this test binary")
	}
	for _, want := range []string{"volume-anomaly", "new-external-access", "unusual-timing"} {
		if !set[want] {
			t.Errorf("registeredFamilies() missing framework detector %q", want)
		}
	}
	if set["widget-leak-v2"] {
		t.Errorf("registeredFamilies() unexpectedly contains the fixture's fake family widget-leak-v2")
	}
}
