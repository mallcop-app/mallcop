// examdetect.go — the OFFLINE detect-layer exam (`mallcop exam-detect`).
//
// This is the K1 keystone of the self-extension loop: a deterministic,
// LLM-free grader that runs the REAL core/detect.Detect over every LABELED
// corpus scenario and grades the emitted findings against the scenario's
// expected_detection ground truth (must_fire / must_not_fire detector family
// tokens). A labeled-and-unfixed detection gap (e.g. VA-03's volume-anomaly
// false negative) shows up as a RED row — the exam is the interlock the loop
// closes against when it grows a detector.
//
// Grading contract:
//
//   - The corpus is loaded via Load(repoRoot) — the corpus.pin integrity
//     interlock stays in the path (a drifted corpus runs NOTHING).
//   - Events/baseline are projected through the SAME unexported projections the
//     e2e runner uses (scenarioEvents / baselineFromScenario) — detectors read
//     payloadMeta discriminators from the projected payload, so a naive
//     re-projection would silently blind them.
//   - Findings are graded on family PRESENCE over the whole emitted set
//     (findingFamilyToken), NOT counts or actors — multi-firing detectors
//     (e.g. unusual-timing) legitimately emit several findings per family.
//   - UNLABELED scenarios (nil ExpectedDetection) are skipped-but-counted:
//     grading covers only explicit labels; the corpus-wide backfill is a
//     deferred human decision.
package eval

import (
	"strings"

	"github.com/mallcop-app/mallcop/core/detect"
)

// ExamDetectRow is the per-labeled-scenario grading record.
type ExamDetectRow struct {
	// ScenarioID is the scenario's YAML id.
	ScenarioID string `json:"scenario_id"`
	// MustFire lists the detector family tokens that must appear among the
	// emitted findings' families (normalized lowercase).
	MustFire []string `json:"must_fire"`
	// MustNotFire lists the detector family tokens that must be absent.
	MustNotFire []string `json:"must_not_fire"`
	// Emitted lists the family token of every finding detect emitted, in
	// emission order (duplicates preserved — the visible multi-fire).
	Emitted []string `json:"emitted"`
	// Pass is true when every must_fire family is present and every
	// must_not_fire family is absent.
	Pass bool `json:"pass"`
}

// ExamDetectTotals aggregates the run.
type ExamDetectTotals struct {
	// Labeled is the number of scenarios carrying an expected_detection block.
	Labeled int `json:"labeled"`
	// Unlabeled is the number of scenarios WITHOUT the block — skipped from
	// grading but counted so coverage drift is visible.
	Unlabeled int `json:"unlabeled"`
	// Passed / Failed partition the labeled set.
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

// ExamDetectReport is the full run result: one row per labeled scenario (in
// corpus order — sorted by relpath, deterministic) plus totals.
type ExamDetectReport struct {
	Rows   []ExamDetectRow  `json:"rows"`
	Totals ExamDetectTotals `json:"totals"`
}

// normalizeFamilyToken canonicalizes a label/emitted family token for
// comparison (lowercase, trimmed) — the same normalization findingFamilyToken
// applies to stored findings.
func normalizeFamilyToken(tok string) string {
	return strings.ToLower(strings.TrimSpace(tok))
}

// RunExamDetect loads the pinned corpus under repoRoot and grades the REAL
// core/detect.Detect output of every labeled scenario against its
// expected_detection ground truth. Offline, deterministic, LLM-free — no
// inference client is constructed anywhere on this path.
func RunExamDetect(repoRoot string) (ExamDetectReport, error) {
	corpus, err := Load(repoRoot)
	if err != nil {
		return ExamDetectReport{}, err
	}

	var report ExamDetectReport
	for _, ls := range corpus.Scenarios {
		s := ls.Scenario
		if s.ExpectedDetection == nil {
			report.Totals.Unlabeled++
			continue
		}
		report.Totals.Labeled++

		// The REAL detect layer over the runner's own projections.
		emitted := detect.Detect(scenarioEvents(s), baselineFromScenario(s))

		present := make(map[string]bool, len(emitted))
		emittedTokens := make([]string, 0, len(emitted))
		for _, f := range emitted {
			tok := findingFamilyToken(f)
			present[tok] = true
			emittedTokens = append(emittedTokens, tok)
		}

		pass := true
		for _, want := range s.ExpectedDetection.MustFire {
			if !present[normalizeFamilyToken(want)] {
				pass = false
			}
		}
		for _, banned := range s.ExpectedDetection.MustNotFire {
			if present[normalizeFamilyToken(banned)] {
				pass = false
			}
		}

		if pass {
			report.Totals.Passed++
		} else {
			report.Totals.Failed++
		}
		report.Rows = append(report.Rows, ExamDetectRow{
			ScenarioID:  s.ID,
			MustFire:    append([]string{}, s.ExpectedDetection.MustFire...),
			MustNotFire: append([]string{}, s.ExpectedDetection.MustNotFire...),
			Emitted:     emittedTokens,
			Pass:        pass,
		})
	}
	return report, nil
}
