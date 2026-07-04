// customerminmutation_test.go — mandatory proof tests for mallcoppro-f95
// round 2: the veracity-reproduced bypass in checkCustomerEfficacy.
//
// THE BYPASS (opus veracity, independently reproduced, fixture recorded at
// rd mallcoppro-f95's progress notes): checkCustomerEfficacy verified only
// that a family had SOME passing must_fire row AND SOME passing must_not_fire
// row — never that the benign twin was a minimal mutation of the must-fire
// scenario. A detector for a novel family (zero reference-corpus rows, so the
// regression arm is an empty backstop) that fires on every event EXCEPT its
// own hand-picked twin event_type shipped a compliant must-fire + twin pair
// and PASSED.
//
// THE FIX (validate.go: checkMinimalMutationCoverage / minimalMutationPairOK
// / structuralIdentityMismatch / eventDiscriminatingDiff): the gate now
// requires the twin to share the must-fire event's structural identity
// (event_type/actor/source, same count/order) and differ only on a bounded,
// non-zero number of discriminating fields (action/target/severity/
// metadata) — see maxDiscriminatingFields's doc in validate.go for the
// PE-08/PE-09-derived justification.
//
// This file covers:
//   - unit-level proof of every gaming shape minimalMutationPairOK rejects,
//     and the legitimate near-miss shape it accepts (fast, no subprocess).
//   - an end-to-end ValidateProposal port of the EXACT reproduced attack
//     fixture (fire-on-everything-except-a-hand-picked-twin-event_type),
//     proving the real gate — real go build/vet, real wasip1/wazero grading
//     — now REJECTS it (mandatory test (a)).
package selfgate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/internal/exam"
)

// ---- unit-level proof: minimalMutationPairOK ------------------------------

// fireTwinEvent builds a single-event exam.Scenario for the unit tests below.
// id/timestamp are deliberately distinct per call (they are EXEMPT fields —
// see eventDiscriminatingDiff's doc) so a "byte-identical" test case still
// means "identical on every DISCRIMINATING field", not literally identical
// bytes.
func fireTwinEvent(id, eventType, actor, source, action, target, severity string, metadata exam.EventMetadata) *exam.Scenario {
	return &exam.Scenario{
		ID: id,
		Events: []exam.Event{{
			ID:        id,
			Timestamp: "2026-01-01T00:00:00Z",
			Source:    source,
			EventType: eventType,
			Actor:     actor,
			Action:    action,
			Target:    target,
			Severity:  severity,
			Metadata:  metadata,
		}},
	}
}

func TestMinimalMutationPairOK_LegitimateNearMissPasses(t *testing.T) {
	// The PE-08/PE-09 shape: same event_type/actor/source, ONE substantive
	// payload field (action) differs — a genuine near-miss.
	fire := fireTwinEvent("fire", "widget-secret-event", "cust-actor", "customer-app", "expose", "widget-1", "high", nil)
	twin := fireTwinEvent("twin", "widget-secret-event", "cust-actor", "customer-app", "rotate", "widget-1", "warn", nil)
	ok, reason := minimalMutationPairOK(fire, twin)
	if !ok {
		t.Fatalf("expected a legitimate near-miss (action differs, severity differs — 2 discriminating fields, bound is %d) to PASS, got reason=%q", maxDiscriminatingFields, reason)
	}
}

func TestMinimalMutationPairOK_ExactlyAtBoundPasses(t *testing.T) {
	// action + target + severity differ = exactly maxDiscriminatingFields (3).
	fire := fireTwinEvent("fire", "widget-secret-event", "cust-actor", "customer-app", "expose", "widget-1", "high", nil)
	twin := fireTwinEvent("twin", "widget-secret-event", "cust-actor", "customer-app", "rotate", "widget-2", "warn", nil)
	ok, reason := minimalMutationPairOK(fire, twin)
	if !ok {
		t.Fatalf("expected exactly-at-bound (3 discriminating fields) to PASS, got reason=%q", reason)
	}
}

func TestMinimalMutationPairOK_ByteIdenticalRejected(t *testing.T) {
	// Same event_type/actor/source AND same action/target/severity/metadata —
	// zero discrimination. Only id/timestamp differ (exempt fields).
	fire := fireTwinEvent("fire", "widget-secret-event", "cust-actor", "customer-app", "expose", "widget-1", "high", exam.EventMetadata{"k": "v"})
	twin := fireTwinEvent("twin", "widget-secret-event", "cust-actor", "customer-app", "expose", "widget-1", "high", exam.EventMetadata{"k": "v"})
	ok, reason := minimalMutationPairOK(fire, twin)
	if ok {
		t.Fatal("expected a byte-identical twin (zero discrimination) to be REJECTED")
	}
	if !containsAny([]string{reason}, "byte-identical") {
		t.Fatalf("expected a byte-identical rejection reason, got %q", reason)
	}
}

func TestMinimalMutationPairOK_EventTypeDiffersRejected(t *testing.T) {
	// THE REPRODUCED ATTACK SHAPE: the twin targets an entirely different,
	// unrelated event_type — a "hand-picked" carve-out, not a near-miss.
	fire := fireTwinEvent("fire", "gaming-target", "cust-actor", "customer-app", "", "", "", nil)
	twin := fireTwinEvent("twin", "gaming-handpicked-twin", "cust-actor", "customer-app", "", "", "", nil)
	ok, reason := minimalMutationPairOK(fire, twin)
	if ok {
		t.Fatal("expected a twin differing in event_type to be REJECTED (arbitrary carve-out, exactly the reproduced attack shape)")
	}
	if !containsAny([]string{reason}, "event_type differs") {
		t.Fatalf("expected an event_type-differs rejection reason, got %q", reason)
	}
}

func TestMinimalMutationPairOK_ActorDiffersRejected(t *testing.T) {
	fire := fireTwinEvent("fire", "widget-secret-event", "cust-actor-A", "customer-app", "expose", "", "", nil)
	twin := fireTwinEvent("twin", "widget-secret-event", "cust-actor-B", "customer-app", "rotate", "", "", nil)
	ok, reason := minimalMutationPairOK(fire, twin)
	if ok {
		t.Fatal("expected a twin differing in actor to be REJECTED (arbitrary carve-out, not a near-miss)")
	}
	if !containsAny([]string{reason}, "actor differs") {
		t.Fatalf("expected an actor-differs rejection reason, got %q", reason)
	}
}

func TestMinimalMutationPairOK_SourceDiffersRejected(t *testing.T) {
	fire := fireTwinEvent("fire", "widget-secret-event", "cust-actor", "customer-app-A", "expose", "", "", nil)
	twin := fireTwinEvent("twin", "widget-secret-event", "cust-actor", "customer-app-B", "rotate", "", "", nil)
	ok, reason := minimalMutationPairOK(fire, twin)
	if ok {
		t.Fatal("expected a twin differing in source to be REJECTED (arbitrary carve-out, not a near-miss)")
	}
	if !containsAny([]string{reason}, "source differs") {
		t.Fatalf("expected a source-differs rejection reason, got %q", reason)
	}
}

func TestMinimalMutationPairOK_EventCountDiffersRejected(t *testing.T) {
	fire := fireTwinEvent("fire", "widget-secret-event", "cust-actor", "customer-app", "expose", "", "", nil)
	twin := &exam.Scenario{ID: "twin", Events: append(
		[]exam.Event{fireTwinEvent("twin-a", "widget-secret-event", "cust-actor", "customer-app", "rotate", "", "", nil).Events[0]},
		fireTwinEvent("twin-b", "widget-secret-event", "cust-actor", "customer-app", "rotate", "", "", nil).Events[0],
	)}
	ok, reason := minimalMutationPairOK(fire, twin)
	if ok {
		t.Fatal("expected a twin with a different event count to be REJECTED")
	}
	if !containsAny([]string{reason}, "event count differs") {
		t.Fatalf("expected an event-count-differs rejection reason, got %q", reason)
	}
}

func TestMinimalMutationPairOK_ExceedsBoundRejected(t *testing.T) {
	// action + target + severity + 2 metadata keys = 5 discriminating fields,
	// exceeding the bound of 3 — too broad to be a genuine near-miss.
	fire := fireTwinEvent("fire", "widget-secret-event", "cust-actor", "customer-app", "expose", "widget-1", "high",
		exam.EventMetadata{"k1": "a", "k2": "b"})
	twin := fireTwinEvent("twin", "widget-secret-event", "cust-actor", "customer-app", "rotate", "widget-2", "warn",
		exam.EventMetadata{"k1": "x", "k2": "y"})
	ok, reason := minimalMutationPairOK(fire, twin)
	if ok {
		t.Fatal("expected a twin exceeding the discriminating-field bound to be REJECTED")
	}
	if !containsAny([]string{reason}, "exceeding the bound") {
		t.Fatalf("expected a bound-exceeded rejection reason, got %q", reason)
	}
}

// ---- end-to-end port: the exact reproduced attack fixture -----------------

// gamingFamily is a genuinely novel family the reference corpus has zero
// scenarios for — isolating this proof from the reference-corpus regression
// path exactly as the reproduction fixture does.
const gamingFamily = "gaming-novelgap"

// gamingDetectorMainSrc fires on EVERY event EXCEPT one hand-picked
// event_type ("gaming-handpicked-twin") the author ships as its own benign
// twin — the exact bypass shape mallcoppro-f95 round 2 closes: staying
// silent ONLY on the exact twin it ships, never genuinely discriminating.
const gamingDetectorMainSrc = `package main

import (
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type gamingDetector struct{}

func (gamingDetector) Name() string { return "` + gamingFamily + `" }

func (gamingDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type == "gaming-handpicked-twin" {
			continue // stay silent ONLY on the exact twin we ship
		}
		out = append(out, finding.Finding{
			ID:     "finding-" + ev.ID + "-gaming",
			Source: "detector:` + gamingFamily + `",
			Type:   "` + gamingFamily + `",
			Actor:  ev.Actor,
		})
	}
	return out
}

func main() { os.Exit(detectorhost.Run(gamingDetector{})) }
`

const gamingMustFire = `id: GAMING-01-must-fire
finding:
  id: fnd_gaming_01
  detector: gaming-novelgap
  title: 'gaming: must-fire target'
  severity: high
events:
- id: evt_gaming_01
  timestamp: '2026-07-01T00:20:00Z'
  source: customer-app
  event_type: gaming-target
  actor: cust-actor
expected_detection:
  must_fire:
  - gaming-novelgap
`

// gamingBenignTwin is a DIFFERENT, unrelated event_type the detector is coded
// to ignore — NOT a minimal mutation of the must-fire event. Before
// mallcoppro-f95 round 2, a gate that only enforced "some passing twin
// exists" accepted this.
const gamingBenignTwin = `id: GAMING-02-benign-twin
finding:
  id: fnd_gaming_02
  detector: gaming-novelgap
  title: 'gaming: hand-picked twin the detector ignores'
  severity: warn
events:
- id: evt_gaming_02
  timestamp: '2026-07-01T00:25:00Z'
  source: customer-app
  event_type: gaming-handpicked-twin
  actor: cust-actor
expected_detection:
  must_not_fire:
  - gaming-novelgap
`

// buildGamingShapedRepo builds the THIN-EMBED customer repo shipping the
// adversarial fire-on-everything-except-the-twin detector plus its own
// (gaming) must-fire/benign-twin scenario pair.
func buildGamingShapedRepo(t *testing.T) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")

	goMod := `module example.com/customer-fixture-gaming

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => ` + mallcopRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write customer repo go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("gaming fixture\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	scratchDir := filepath.Join(dir, "detectors", "tidyscratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		t.Fatalf("mkdir go.sum scratch dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scratchDir, "main.go"), []byte(gamingDetectorMainSrc), 0o644); err != nil {
		t.Fatalf("write go.sum scratch detector: %v", err)
	}
	if stdout, stderr, code, err := runTool(dir, []string{"GOFLAGS=-mod=mod"}, "go", "mod", "tidy"); err != nil || code != 0 {
		t.Fatalf("precompute go.sum via `go mod tidy`: err=%v code=%d\n%s%s", err, code, stdout, stderr)
	}
	if err := os.RemoveAll(scratchDir); err != nil {
		t.Fatalf("remove go.sum scratch dir: %v", err)
	}
	base = commitAll(t, dir, "base: THIN-EMBED scaffold (go.mod/go.sum only, no detector yet)")

	detDir := filepath.Join(dir, "detectors", "gaming")
	if err := os.MkdirAll(detDir, 0o755); err != nil {
		t.Fatalf("mkdir detectors/gaming: %v", err)
	}
	if err := os.WriteFile(filepath.Join(detDir, "main.go"), []byte(gamingDetectorMainSrc), 0o644); err != nil {
		t.Fatalf("write detector main.go: %v", err)
	}
	scenDir := filepath.Join(detDir, "scenarios")
	if err := os.MkdirAll(scenDir, 0o755); err != nil {
		t.Fatalf("mkdir gaming scenarios dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "must-fire.yaml"), []byte(gamingMustFire), 0o644); err != nil {
		t.Fatalf("write gaming must-fire scenario: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "benign-twin.yaml"), []byte(gamingBenignTwin), 0o644); err != nil {
		t.Fatalf("write gaming benign-twin scenario: %v", err)
	}
	head = commitAll(t, dir, "proposal: gaming detector, hand-picked twin")
	return dir, base, head
}

// TestValidateProposal_CustomerTreeExamRejectsHandPickedTwinGaming is
// mandatory test (a): the exact reproduced bypass — a fire-on-everything
// detector whose ONLY silence is a hand-picked, structurally-unrelated
// event_type it ships as its own "benign twin" — must now be REJECTED. Before
// mallcoppro-f95 round 2 this PASSED (res.Passed == true): checkCustomerEfficacy
// verified only that SOME must_fire row and SOME must_not_fire row passed,
// never that the twin was a measured minimal mutation of the must-fire
// scenario. This is the RED/GREEN proof: reverting checkMinimalMutationCoverage's
// call in checkCustomerEfficacy (or the enforcement it implements) flips this
// test back to failing — see the item's progress notes for the manual
// before/after run.
func TestValidateProposal_CustomerTreeExamRejectsHandPickedTwinGaming(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildGamingShapedRepo(t)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal must return a REAL verdict, not an operational error: %v", err)
	}
	if res.Passed {
		t.Fatalf("GAMING SHAPE PASSED THE GATE: fire-on-everything with a hand-picked, structurally-unrelated twin for a novel family — got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	examStage := res.Stages[2]
	if examStage.Passed {
		t.Fatalf("exam-detect stage must be the failing stage, got %+v", examStage)
	}
	requireRejected(t, examStage.Findings, RuleCustomerExamFail, "detectors/gaming")
	if !containsAny(findingDetails(examStage.Findings), "MEASURED MINIMAL MUTATION") {
		t.Fatalf("expected the minimal-mutation rejection detail, got %+v", examStage.Findings)
	}
	if !containsAny(findingDetails(examStage.Findings), "event_type differs") {
		t.Fatalf("expected the rejection to name the event_type mismatch (the exact carve-out), got %+v", examStage.Findings)
	}
}
