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
