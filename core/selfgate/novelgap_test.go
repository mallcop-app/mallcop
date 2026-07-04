// novelgap_test.go — mandatory tests for mallcoppro-f95's FINAL (BOTH) ruling:
//
//	(A) the held-out-corpus new-firing control (checkCustomerHeldOutNewFirings
//	    in validate.go) is the PRIMARY anti-gaming defense — proven adversarial
//	    in adversary_metadata_marker_test.go.
//	(B) GateResult.NovelGap: true when a detector's declared family has ZERO
//	    labeled must_fire rows in the reference corpus — the corpus cannot
//	    independently grade that gap, so (A) has no signal on it either way,
//	    and the caller (mallcop-pro's router/engine) must force a human review
//	    regardless of the autonomy dial.
//
// This file proves mandatory test (b): a REAL, NARROW, well-behaved detector
// targeting a genuinely novel family (the reference corpus has zero must_fire
// rows for it) PASSES the technical gate (Passed==true, zero findings) AND
// GateResult.NovelGap==true — the gate does not conflate "the corpus has no
// opinion" with "reject"; it passes the detector on its own proven merits and
// separately flags the structural blind spot for a human to review.
//
// Contrast: TestValidateProposal_CustomerTreeExamAcceptsPassingDetector
// (customergate_test.go) uses customFixtureFamily ("custfixture-leak"), which
// buildReferenceExamTree ALSO labels a reference-corpus scenario for (CUSTFIX-
// 01/02) — that family is REFERENCE-COVERED, so NovelGap is false there (see
// TestValidateProposal_CustomerTreeExamAcceptsPassingDetector_ReferenceCovered
// FamilyIsNotNovelGap below). The fixture in THIS file deliberately ships NO
// reference-corpus scenario for its family at all.
package selfgate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// novelNarrowFamily is a family the reference corpus (buildReferenceExamTree)
// has NO opinion about whatsoever — no must_fire, no must_not_fire, anywhere.
const novelNarrowFamily = "novelnarrow-quarantine"

// novelNarrowDetectorSrc is a REAL, NARROW, well-behaved detector: it fires
// ONLY on event_type "widget-quarantine-event" with action=="breach", staying
// silent on the SAME event_type with action=="routine" — a measured minimal
// mutation (same event_type/actor/source, one discriminating payload field),
// exactly the SIDECAR-WIDGETLEAK pattern customergate_test.go already
// establishes as the safe shape. This event_type never occurs anywhere in the
// real reference corpus, so it emits NOTHING when graded against it — the
// held-out-corpus control (part A) sees zero emissions and has nothing to
// reject; the detector's OWN scenarios (below) are what prove it.
const novelNarrowDetectorSrc = `package main

import (
	"encoding/json"
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type novelNarrowDetector struct{}

func (novelNarrowDetector) Name() string { return "` + novelNarrowFamily + `" }

func (novelNarrowDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type != "widget-quarantine-event" {
			continue
		}
		var payload struct {
			Action string ` + "`json:\"action\"`" + `
		}
		_ = json.Unmarshal(ev.Payload, &payload)
		if payload.Action != "breach" {
			continue
		}
		out = append(out, finding.Finding{
			ID:     "finding-" + ev.ID + "-novelnarrow",
			Source: "detector:` + novelNarrowFamily + `",
			Type:   "` + novelNarrowFamily + `",
			Actor:  ev.Actor,
		})
	}
	return out
}

func main() { os.Exit(detectorhost.Run(novelNarrowDetector{})) }
`

const novelNarrowMustFireScenario = `id: NOVELNARROW-01-must-fire
finding:
  id: fnd_novelnarrow_01
  detector: novelnarrow-quarantine
  title: 'novel narrow: quarantine breach'
  severity: high
events:
- id: evt_novelnarrow_01
  timestamp: '2026-07-01T00:30:00Z'
  source: customer-app
  event_type: widget-quarantine-event
  actor: cust-actor
  action: breach
expected_detection:
  must_fire:
  - novelnarrow-quarantine
`

const novelNarrowBenignTwinScenario = `id: NOVELNARROW-02-benign-twin
finding:
  id: fnd_novelnarrow_02
  detector: novelnarrow-quarantine
  title: 'novel narrow: quarantine routine (measured minimal mutation: same event_type/actor/source, action differs)'
  severity: warn
events:
- id: evt_novelnarrow_02
  timestamp: '2026-07-01T00:35:00Z'
  source: customer-app
  event_type: widget-quarantine-event
  actor: cust-actor
  action: routine
expected_detection:
  must_not_fire:
  - novelnarrow-quarantine
`

func buildNovelNarrowRepo(t *testing.T) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")
	goMod := `module example.com/customer-fixture-novelnarrow

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => ` + mallcopRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("novel-narrow fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scratchDir := filepath.Join(dir, "detectors", "tidyscratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratchDir, "main.go"), []byte(novelNarrowDetectorSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if stdout, stderr, code, err := runTool(dir, []string{"GOFLAGS=-mod=mod"}, "go", "mod", "tidy"); err != nil || code != 0 {
		t.Fatalf("tidy: %v %d %s%s", err, code, stdout, stderr)
	}
	if err := os.RemoveAll(scratchDir); err != nil {
		t.Fatal(err)
	}
	base = commitAll(t, dir, "base: THIN-EMBED scaffold (go.mod/go.sum only, no detector yet)")

	detDir := filepath.Join(dir, "detectors", "novelnarrow")
	if err := os.MkdirAll(detDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(detDir, "main.go"), []byte(novelNarrowDetectorSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	scenDir := filepath.Join(detDir, "scenarios")
	if err := os.MkdirAll(scenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "must-fire.yaml"), []byte(novelNarrowMustFireScenario), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scenDir, "benign-twin.yaml"), []byte(novelNarrowBenignTwinScenario), 0o644); err != nil {
		t.Fatal(err)
	}
	head = commitAll(t, dir, "proposal: add novel-narrow quarantine-breach detector")
	return dir, base, head
}

// TestValidateProposal_RealNarrowNovelDetectorPassesWithNovelGap is mandatory
// test (b): a real, narrow, well-behaved detector for a genuinely novel
// family (zero reference-corpus must_fire rows) PASSES the technical gate —
// the held-out-corpus control (part A) correctly does NOT reject a detector
// that simply never fires on the held-out corpus at all — AND GateResult.
// NovelGap is true, because the corpus structurally cannot grade this gap
// independently. Both signals must be present simultaneously: a passing gate
// is not sufficient proof of safety for a novel-gap detector, and the router/
// engine on the mallcop-pro side is what turns NovelGap into a mandatory
// human review (see internal/selfext/router + engine tests on that side).
func TestValidateProposal_RealNarrowNovelDetectorPassesWithNovelGap(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildNovelNarrowRepo(t)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	b, _ := json.Marshal(res)
	t.Logf("result: %s", string(b))

	if !res.Passed {
		t.Fatalf("a real narrow novel detector must PASS the technical gate, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	if len(res.Stages[2].Findings) != 0 {
		t.Fatalf("exam-detect stage should be clean for a well-behaved detector, got %+v", res.Stages[2].Findings)
	}
	if !res.NovelGap {
		t.Errorf("expected NovelGap=true (zero reference-corpus must_fire coverage for %q), got false", novelNarrowFamily)
	}
	found := false
	for _, f := range res.NovelGapFamilies {
		if f == novelNarrowFamily {
			found = true
		}
	}
	if !found {
		t.Errorf("expected NovelGapFamilies to name %q, got %v", novelNarrowFamily, res.NovelGapFamilies)
	}
}

// TestValidateProposal_CustomerTreeExamAcceptsPassingDetector_ReferenceCoveredFamilyIsNotNovelGap
// is the contrast case: customFixtureFamily ("custfixture-leak", used by
// TestValidateProposal_CustomerTreeExamAcceptsPassingDetector) DOES have
// reference-corpus must_fire coverage (buildReferenceExamTree's own CUSTFIX-01
// fixture scenario) — so NovelGap must be false, and a "fully" autonomy dial
// on the mallcop-pro side may treat it as an ordinary auto-mergeable clean
// widen (see the router/engine "reference-covered family -> normal auto"
// tests on that side).
func TestValidateProposal_CustomerTreeExamAcceptsPassingDetector_ReferenceCoveredFamilyIsNotNovelGap(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildCustomerShapedRepo(t, customerFixtureDetectorMainSrc)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	if !res.Passed {
		t.Fatalf("well-behaved reference-covered detector must pass, got %+v", res)
	}
	if res.NovelGap {
		t.Errorf("a family with reference-corpus must_fire coverage must NOT be flagged NovelGap, got families=%v", res.NovelGapFamilies)
	}
}
