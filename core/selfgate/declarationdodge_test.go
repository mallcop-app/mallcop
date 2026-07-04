// declarationdodge_test.go — mandatory hunt (e), mallcoppro-f95 FINAL ruling:
// a detector's own detectors/<name>/scenarios/*.yaml declaration
// (customerDeclaredFamilies, sourced from Extra==true rows) is entirely
// AUTHOR-CONTROLLED — the attacker writes those files. checkCustomerHeldOut
// NewFirings's excusal for a reference-corpus (Extra==false) row is read
// SOLELY from that row's OWN MustFire label (never from any Extra row) — see
// its doc in validate.go. This file HUNTS for a bypass of that design: can an
// attacker's own extra scenario, reusing a REAL reference-corpus scenario ID,
// buy an excusal for that real scenario's row?
//
// HUNT RESULT: no. RunExamDetectExtra (core/eval/examdetect.go) grades
// corpus.Scenarios and the extra dir as two ENTIRELY SEPARATE loops appended
// to the SAME report — a duplicate scenario_id produces TWO rows (one
// Extra==false with the REAL corpus events/labels, one Extra==true with the
// attacker's fabricated events/labels), never a merge or override of either.
// checkCustomerHeldOutNewFirings reads c.MustFire directly off the candidate
// row it is currently examining (the REAL Extra==false row for that ID) — an
// attacker's same-ID Extra row is a physically distinct GuardFinding input
// the loop never even reaches when it is processing the reference row. This
// test proves that holds empirically, not just by code inspection: an
// attacker's own scenarios/*.yaml that reuses a real reference-corpus
// scenario ID and declares the family there does NOT suppress the new-firing
// rejection on the real row.
package selfgate

import (
	"os"
	"path/filepath"
	"testing"
)

const dodgeFamily = "adv-dodge"

// dodgeDetectorSrc fires on EVERY event (the same fire-on-everything shape as
// the metadata-marker adversary), except it stays silent on its OWN declared
// benign twin so its efficacy pair is technically compliant — the interesting
// question here is entirely about the new-firing / declaration boundary, not
// about re-proving the efficacy checks.
const dodgeDetectorSrc = `package main

import (
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type dodgeDetector struct{}

func (dodgeDetector) Name() string { return "` + dodgeFamily + `" }

func (dodgeDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type == "dodge-benign-twin" {
			continue
		}
		out = append(out, finding.Finding{
			ID:     "finding-" + ev.ID + "-dodge",
			Source: "detector:` + dodgeFamily + `",
			Type:   "` + dodgeFamily + `",
			Actor:  ev.Actor,
		})
	}
	return out
}

func main() { os.Exit(detectorhost.Run(dodgeDetector{})) }
`

// dodgeMustFire / dodgeBenignTwin are the detector's OWN (Extra==true)
// efficacy pair — ordinary, unremarkable, both distinct novel event types the
// real reference corpus never carries.
const dodgeMustFire = `id: DODGE-01-must-fire
finding:
  id: fnd_dodge_01
  detector: adv-dodge
  title: 'dodge: must-fire target'
  severity: high
events:
- id: evt_dodge_01
  timestamp: '2026-07-01T00:40:00Z'
  source: customer-app
  event_type: dodge-target
  actor: cust-actor
expected_detection:
  must_fire:
  - adv-dodge
`

const dodgeBenignTwin = `id: DODGE-02-benign-twin
finding:
  id: fnd_dodge_02
  detector: adv-dodge
  title: 'dodge: benign twin'
  severity: warn
events:
- id: evt_dodge_02
  timestamp: '2026-07-01T00:41:00Z'
  source: customer-app
  event_type: dodge-benign-twin
  actor: cust-actor
expected_detection:
  must_not_fire:
  - adv-dodge
`

// dodgeCollisionScenario is THE ATTACK: an extra scenario reusing the REAL
// reference-corpus scenario ID "VA-01-deploy-burst" (see exams/scenarios/
// behavioral/VA-01-deploy-burst.yaml — a real must_not_fire:[volume-anomaly]
// scenario), attempting to DECLARE adv-dodge as a must_fire target under that
// same ID — hoping it excuses (or overrides/merges into) the REAL VA-01 row's
// grading, since the detector fires on literally everything including the
// real VA-01 events.
const dodgeCollisionScenario = `id: VA-01-deploy-burst
finding:
  id: fnd_dodge_collision
  detector: adv-dodge
  title: 'dodge: collision with a REAL reference-corpus scenario ID'
  severity: high
events:
- id: evt_dodge_collision
  timestamp: '2026-07-01T00:42:00Z'
  source: customer-app
  event_type: dodge-collision-fabricated
  actor: cust-actor
expected_detection:
  must_fire:
  - adv-dodge
`

func buildDodgeRepo(t *testing.T) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")
	goMod := `module example.com/customer-fixture-dodge

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => ` + mallcopRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("dodge fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scratchDir := filepath.Join(dir, "detectors", "tidyscratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratchDir, "main.go"), []byte(dodgeDetectorSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if stdout, stderr, code, err := runTool(dir, []string{"GOFLAGS=-mod=mod"}, "go", "mod", "tidy"); err != nil || code != 0 {
		t.Fatalf("tidy: %v %d %s%s", err, code, stdout, stderr)
	}
	if err := os.RemoveAll(scratchDir); err != nil {
		t.Fatal(err)
	}
	base = commitAll(t, dir, "base: THIN-EMBED scaffold (go.mod/go.sum only, no detector yet)")

	detDir := filepath.Join(dir, "detectors", "dodge")
	if err := os.MkdirAll(detDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(detDir, "main.go"), []byte(dodgeDetectorSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	scenDir := filepath.Join(detDir, "scenarios")
	if err := os.MkdirAll(scenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "must-fire.yaml"), []byte(dodgeMustFire), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "benign-twin.yaml"), []byte(dodgeBenignTwin), 0o644); err != nil {
		t.Fatal(err)
	}
	// THE ATTACK: a THIRD scenario file, reusing a real reference-corpus ID.
	if err := os.WriteFile(filepath.Join(scenDir, "collision.yaml"), []byte(dodgeCollisionScenario), 0o644); err != nil {
		t.Fatal(err)
	}
	head = commitAll(t, dir, "proposal: adv-dodge fire-on-everything detector attempting a scenario-ID collision")
	return dir, base, head
}

// TestHunt_DeclarationCannotDodgeHeldOutNewFiring is mandatory hunt (e): a
// detector that fires on literally everything and tries to neutralize the
// held-out-corpus new-firing control by declaring (in its OWN, author-
// controlled scenarios/ dir) a scenario ID that COLLIDES with a real
// reference-corpus scenario ID must still be REJECTED — the real reference
// row's own grading is untouched by the attacker's same-ID declaration.
func TestHunt_DeclarationCannotDodgeHeldOutNewFiring(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildDodgeRepo(t)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	if res.Passed {
		t.Fatalf("DECLARATION-DODGE BYPASS SURVIVED: a fire-on-everything detector that collides its own scenario ID with a real reference-corpus scenario PASSED the gate, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	examStage := res.Stages[2]
	if examStage.Passed {
		t.Fatalf("exam-detect stage must be the failing stage, got %+v", examStage)
	}
	// The REAL VA-01-deploy-burst row (Extra==false, the reference corpus's own
	// events) must still be flagged as an undeclared new firing for adv-dodge —
	// proving the attacker's same-ID Extra declaration bought it nothing.
	found := false
	for _, f := range examStage.Findings {
		if f.Rule == RuleCustomerExamFail &&
			containsAny([]string{f.Detail}, "VA-01-deploy-burst") &&
			containsAny([]string{f.Detail}, dodgeFamily) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a rejection naming the REAL VA-01-deploy-burst row and family %q (proving the attacker's same-ID declaration did not excuse it), got %+v",
			dodgeFamily, examStage.Findings)
	}
}
