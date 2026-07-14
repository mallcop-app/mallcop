package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/detect"
)

func TestE2E_FullFidelityDump(t *testing.T) {
	root := repoRootForTest(t)
	SetRepoRootForTest(root)
	t.Cleanup(func() { SetRepoRootForTest("") })

	corpus, err := Load(root)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	type RowOut struct {
		ScenarioID       string   `json:"scenario_id"`
		ExpectedDetector string   `json:"expected_detector"`
		ExpectedActor    string   `json:"expected_actor"`
		ExpectedAction   string   `json:"expected_action"`
		EmittedDetectors []string `json:"emitted_detectors"`
		Outcome          string   `json:"outcome"`
	}

	var rows []RowOut
	reproduced, detectMiss, mismatch := 0, 0, 0

	for _, ls := range corpus.Scenarios {
		s := ls.Scenario
		emitted := detect.Detect(scenarioEvents(s), baselineFromScenario(s))
		row := classifyDetectFidelity(s, emitted, nil)

		rows = append(rows, RowOut{
			ScenarioID:       row.ScenarioID,
			ExpectedDetector: row.ExpectedDetector,
			ExpectedActor:    row.ExpectedActor,
			ExpectedAction:   row.ExpectedAction,
			EmittedDetectors: row.EmittedDetectors,
			Outcome:          string(row.Outcome),
		})

		switch row.Outcome {
		case OutcomeReproduced:
			reproduced++
		case OutcomeDetectMiss:
			detectMiss++
		case OutcomeMismatch:
			mismatch++
		}
	}

	out, _ := json.MarshalIndent(rows, "", "  ")
	if dest := os.Getenv("FIDELITY_DUMP_PATH"); dest != "" {
		if err := os.WriteFile(dest, out, 0o644); err != nil {
			t.Fatalf("write fidelity dump: %v", err)
		}
	}
	_ = strings.Contains // suppress unused import

	fmt.Printf("TOTALS: reproduced=%d detect_miss=%d mismatch=%d total=%d\n", reproduced, detectMiss, mismatch, corpus.Count)
}

// TestAggregateDetectFidelity_RecallPrecisionSplit proves aggregateDetectFidelity
// (mallcoppro C2) splits EndToEndPass by ExpectedAction into E2ERecall (attacks)
// and E2EPrecision (benigns) independently of EndToEndPassRate — a synthetic
// 2-attack/2-benign mix with one miss on each side must NOT let a passing
// benign hide a missed attack (or vice versa) inside one blended number.
func TestAggregateDetectFidelity_RecallPrecisionSplit(t *testing.T) {
	rows := []DetectFidelityRow{
		{ScenarioID: "attack-reproduced-pass", ExpectedAction: "escalated", Outcome: OutcomeReproduced, EndToEndPass: true},
		{ScenarioID: "attack-detect-miss", ExpectedAction: "escalate-or-stronger", Outcome: OutcomeDetectMiss, EndToEndPass: false},
		{ScenarioID: "benign-detect-miss-correct", ExpectedAction: "resolved", Outcome: OutcomeDetectMiss, EndToEndPass: true, NoFindingCorrect: true},
		{ScenarioID: "benign-mismatch-overescalated", ExpectedAction: "resolved", Outcome: OutcomeMismatch, EndToEndPass: false},
	}
	df := aggregateDetectFidelity(rows)

	if df.Total != 4 {
		t.Fatalf("Total = %d, want 4", df.Total)
	}
	// Blended EndToEndPassRate: 2 of 4 pass. This is EXACTLY the number the split
	// exists to unpack — a reader must not mistake 50% for "half the attacks
	// caught" when it is actually "1 attack caught, 1 attack missed, 1 benign
	// correct, 1 benign false-alarmed."
	if df.EndToEndPassRate != 0.5 {
		t.Fatalf("EndToEndPassRate = %.4f, want 0.5 (2/4 blended)", df.EndToEndPassRate)
	}
	if df.E2ERecall != 0.5 {
		t.Fatalf("E2ERecall = %.4f, want 0.5 (1 of 2 attacks: reproduced-pass caught, detect-miss missed)", df.E2ERecall)
	}
	if df.E2EPrecision != 0.5 {
		t.Fatalf("E2EPrecision = %.4f, want 0.5 (1 of 2 benigns: detect-miss correctly silent, mismatch over-escalated)", df.E2EPrecision)
	}

	// Zero-denominator sides must not panic or produce NaN: an all-attack row set
	// leaves E2EPrecision at its zero value (mirrors harness.go's rate() helper,
	// which returns 0 — not a vacuous 1.0 — for an empty denominator).
	allAttacks := aggregateDetectFidelity([]DetectFidelityRow{
		{ScenarioID: "a1", ExpectedAction: "escalated", EndToEndPass: true},
		{ScenarioID: "a2", ExpectedAction: "escalated", EndToEndPass: true},
	})
	if allAttacks.E2ERecall != 1.0 {
		t.Fatalf("all-attacks E2ERecall = %.4f, want 1.0", allAttacks.E2ERecall)
	}
	if allAttacks.E2EPrecision != 0 {
		t.Fatalf("all-attacks E2EPrecision = %.4f, want 0 (no benign rows, zero denominator)", allAttacks.E2EPrecision)
	}
}
