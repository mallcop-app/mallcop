package selfgate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ADVERSARY PROBE, PORTED (veracity, mallcoppro-f95 FINAL ruling — see BOTH
// A+B in validate.go's customerTreeExamStage doc): originally a round-2
// SURVIVING BYPASS (this test used to assert res.Passed==true and fail
// loudly about it — see the git history of this file / the round-2 postmortem
// for the red run). The reproduced attack that motivated round 2 carved out
// its benign twin by EVENT_TYPE; that fix (checkMinimalMutationCoverage's
// structural-identity requirement) rejects that shape. This probe asks: can
// the SAME fire-on-everything intent survive by moving the carve-out from
// event_type to a METADATA MARKER, keeping event_type/actor/source identical
// so the pair is a STRUCTURALLY VALID 1-field minimal mutation — passing
// BOTH round-2 checks (checkCustomerEfficacy's fires/twin arms AND
// checkMinimalMutationCoverage) because both grade only the attacker's own
// two scenarios?
//
// It did: the detector below has NO event_type filter in Detect at all — it
// fires on EVERY event passed to it, period, except one carrying an
// attacker-invented metadata marker (payload.metadata.benign_marker ==
// "yes") that no real-world event carries. Graded only against its own
// scenarios (which happen to use a distinct event_type as label color), the
// round-2 gate could not tell this apart from a genuinely narrow detector.
//
// checkCustomerHeldOutNewFirings (mallcoppro-f95 BOTH ruling, part A) is what
// now catches it: run for real against the reference corpus's own unrelated
// benign scenarios (which this detector was never shown by round 2's checks),
// it fires almost everywhere, an avalanche of undeclared new firings the
// attacker cannot suppress because it does not control the reference corpus.
// This is now a FIXED regression proof, not a live bypass — asserting
// res.Passed==false below is the green state; TestAdversary_
// MetadataMarkerFireOnAllOfType's own doc history is the red/green record (git
// stash the customerTreeExamStage changes to reproduce PASSED=true).
const advMetaFamily = "adv-metamarker"

const advMetaDetectorSrc = `package main

import (
	"encoding/json"
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type advDetector struct{}

func (advDetector) Name() string { return "` + advMetaFamily + `" }

func (advDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		var p struct {
			Metadata map[string]any ` + "`json:\"metadata\"`" + `
		}
		_ = json.Unmarshal(ev.Payload, &p)
		if p.Metadata != nil && p.Metadata["benign_marker"] == "yes" {
			continue // stay silent ONLY on the hand-picked marker twin
		}
		out = append(out, finding.Finding{
			ID:     "finding-" + ev.ID + "-adv",
			Source: "detector:` + advMetaFamily + `",
			Type:   "` + advMetaFamily + `",
			Actor:  ev.Actor,
		})
	}
	return out
}

func main() { os.Exit(detectorhost.Run(advDetector{})) }
`

const advMustFire = `id: ADV-01-must-fire
finding:
  id: fnd_adv_01
  detector: adv-metamarker
  title: 'adv: must-fire target'
  severity: high
events:
- id: evt_adv_01
  timestamp: '2026-07-01T00:20:00Z'
  source: customer-app
  event_type: adv-novel-x
  actor: cust-actor
  action: do-thing
  target: res-1
  severity: high
expected_detection:
  must_fire:
  - adv-metamarker
`

// Twin: SAME event_type/actor/source/action/target/severity, differs ONLY in
// the single metadata key benign_marker -> exactly 1 discriminating field.
const advBenignTwin = `id: ADV-02-benign-twin
finding:
  id: fnd_adv_02
  detector: adv-metamarker
  title: 'adv: metadata-marker twin'
  severity: high
events:
- id: evt_adv_02
  timestamp: '2026-07-01T00:25:00Z'
  source: customer-app
  event_type: adv-novel-x
  actor: cust-actor
  action: do-thing
  target: res-1
  severity: high
  metadata:
    benign_marker: yes
expected_detection:
  must_not_fire:
  - adv-metamarker
`

func buildAdvMetaRepo(t *testing.T) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")
	goMod := `module example.com/customer-fixture-adv

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => ` + mallcopRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("adv fixture\n"), 0o644)
	scratchDir := filepath.Join(dir, "detectors", "tidyscratch")
	os.MkdirAll(scratchDir, 0o755)
	os.WriteFile(filepath.Join(scratchDir, "main.go"), []byte(advMetaDetectorSrc), 0o644)
	if stdout, stderr, code, err := runTool(dir, []string{"GOFLAGS=-mod=mod"}, "go", "mod", "tidy"); err != nil || code != 0 {
		t.Fatalf("tidy: %v %d %s%s", err, code, stdout, stderr)
	}
	os.RemoveAll(scratchDir)
	base = commitAll(t, dir, "base")
	detDir := filepath.Join(dir, "detectors", "adv")
	os.MkdirAll(detDir, 0o755)
	os.WriteFile(filepath.Join(detDir, "main.go"), []byte(advMetaDetectorSrc), 0o644)
	scenDir := filepath.Join(detDir, "scenarios")
	os.MkdirAll(scenDir, 0o755)
	os.WriteFile(filepath.Join(scenDir, "must-fire.yaml"), []byte(advMustFire), 0o644)
	os.WriteFile(filepath.Join(scenDir, "benign-twin.yaml"), []byte(advBenignTwin), 0o644)
	head = commitAll(t, dir, "proposal: adv metadata-marker detector")
	return dir, base, head
}

func TestAdversary_MetadataMarkerFireOnAllOfType(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildAdvMetaRepo(t)
	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("op err: %v", err)
	}
	t.Logf("PASSED=%v", res.Passed)
	for _, st := range res.Stages {
		b, _ := json.Marshal(st.Findings)
		t.Logf("stage %s passed=%v evidence=%s findings=%s", st.Name, st.Passed, st.Evidence, string(b))
	}
	if res.Passed {
		t.Errorf("SURVIVING BYPASS: metadata-marker fire-on-all-of-type detector PASSED the gate")
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	requireRejected(t, res.Stages[2].Findings, RuleCustomerExamFail, "detectors/adv")
	if !containsAny(findingDetails(res.Stages[2].Findings), advMetaFamily) {
		t.Fatalf("expected the held-out new-firing rejection to name family %q, got %+v", advMetaFamily, res.Stages[2].Findings)
	}
	if !containsAny(findingDetails(res.Stages[2].Findings), "undeclared new firing") {
		t.Fatalf("expected the rejection detail to name the held-out new-firing control, got %+v", res.Stages[2].Findings)
	}
	// NovelGap must ALSO be true here: the reference corpus has zero
	// must_fire rows for advMetaFamily at all — the held-out control has no
	// independent ground truth for this family, only the ability to prove the
	// detector fires WRONGLY elsewhere (which it does). Both signals are real
	// and independent; a caller (mallcop-pro's router/engine) must force human
	// review on NovelGap regardless of whether the gate ALSO already rejected.
	if !res.NovelGap {
		t.Errorf("expected NovelGap=true (zero reference-corpus must_fire coverage for %q), got NovelGap=false, families=%v", advMetaFamily, res.NovelGapFamilies)
	}
}
