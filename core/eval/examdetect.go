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
	"fmt"
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
	// Extra is true when this row came from an --extra-scenarios-dir UNION
	// (mallcoppro-f95) rather than the pinned reference corpus — a customer
	// detector's OWN co-located efficacy scenarios (detectors/<name>/scenarios/
	// *.yaml), graded through the identical real .wasm/detecthost path but
	// UNPINNED: they never touch corpus.pin and never count toward the
	// reference corpus's own integrity digest. Omitted (false) for every
	// ordinary reference-corpus row, so the wire shape is unchanged for every
	// existing caller that never passes an extra dir.
	Extra bool `json:"extra,omitempty"`
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
//
// This is RunExamDetectExtra(repoRoot, "") — byte-identical to the prior
// behavior (no extra scenarios dir touched, no wire-shape change: Extra is
// always its zero value and thus omitted from JSON).
func RunExamDetect(repoRoot string) (ExamDetectReport, error) {
	return RunExamDetectExtra(repoRoot, "")
}

// RunExamDetectExtra is RunExamDetect, additionally UNIONING the labeled
// scenarios found under extraScenariosDir (mallcoppro-f95) into the grading
// pass — a customer detector's OWN co-located efficacy scenarios
// (detectors/<name>/scenarios/*.yaml), loaded via LoadExtraScenarios (NO pin
// check, NEVER touching corpus.pin or the reference corpus's own digest).
// extraScenariosDir == "" reproduces RunExamDetect's exact prior behavior.
//
// Every row this grades — reference or extra — runs through the IDENTICAL
// core/detect.Detect call over the SAME scenario/baseline projections; the
// only difference is provenance, carried on the row as Extra so callers (e.g.
// core/selfgate's customer-tree stage) can tell a detector's OWN proof
// scenarios apart from the reference corpus's.
func RunExamDetectExtra(repoRoot, extraScenariosDir string) (ExamDetectReport, error) {
	corpus, err := Load(repoRoot)
	if err != nil {
		return ExamDetectReport{}, err
	}
	extra, err := LoadExtraScenarios(extraScenariosDir)
	if err != nil {
		return ExamDetectReport{}, fmt.Errorf("loading extra scenarios dir %s: %w", extraScenariosDir, err)
	}

	var report ExamDetectReport
	grade := func(ls LoadedScenario, isExtra bool) {
		s := ls.Scenario
		if s.ExpectedDetection == nil {
			report.Totals.Unlabeled++
			return
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
			Extra:       isExtra,
		})
	}

	for _, ls := range corpus.Scenarios {
		grade(ls, false)
	}
	for _, ls := range extra {
		grade(ls, true)
	}
	return report, nil
}
