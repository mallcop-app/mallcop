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
//     (findingFamilyToken), NOT counts or actors — some detectors legitimately
//     emit multiple findings per family in one scan (e.g. unusual-timing:
//     one finding per distinct (actor, hour) GROUP per scan, not one per
//     event — mallcoppro-d73 collapsed the old per-event fan-out — so a scan
//     touching several novel actor-hours still yields several findings).
//   - UNLABELED scenarios (nil ExpectedDetection) are skipped-but-counted:
//     grading covers only explicit labels; the corpus-wide backfill is a
//     deferred human decision.
//   - RESERVED scenarios (expected_detection.reserved: true, mallcoppro-db0)
//     specify a must-fire outcome for a detector that may not exist yet — the
//     REQUESTER's ground truth, authored independent of and prior to whoever
//     eventually writes the detector. A reserved must_fire family with no
//     REGISTERED detector (core/detect.Detectors()) grades as a TRACKED
//     expected-miss (ExamDetectTotals.Reserved), not a hard failure — it
//     still shows RED on the row, it just doesn't block the exam or CI. The
//     day a detector implementing that family registers, grading reverts to
//     the ordinary hard rule for it automatically — no re-flagging required.
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
	// Reserved mirrors the scenario's expected_detection.reserved flag
	// (mallcoppro-db0) — an operator/requester-authored must-fire ground
	// truth for a detector that may not exist yet. Omitted (false) for every
	// ordinary row.
	Reserved bool `json:"reserved,omitempty"`
	// ReservedPending lists the normalized must_fire family tokens that are
	// STILL unregistered — no core/detect.Detectors() entry emits that family
	// in this process — on a Reserved row. Non-empty only when Reserved is
	// true. A row with ReservedPending is still Pass=false (the family
	// genuinely did not fire — it shows RED like any other unmet label) but
	// is EXCLUDED from ExamDetectTotals.Failed and instead counted in
	// ExamDetectTotals.Reserved: a TRACKED expected-miss, not a hard exam
	// failure. Every OTHER must_fire/must_not_fire label on the same row —
	// including a must_fire family whose detector HAS registered but still
	// doesn't fire, and any must_not_fire violation — is graded by the
	// ordinary hard rule and can still fail the row for real.
	ReservedPending []string `json:"reserved_pending,omitempty"`
}

// ExamDetectTotals aggregates the run.
type ExamDetectTotals struct {
	// Labeled is the number of scenarios carrying an expected_detection block.
	Labeled int `json:"labeled"`
	// Unlabeled is the number of scenarios WITHOUT the block — skipped from
	// grading but counted so coverage drift is visible.
	Unlabeled int `json:"unlabeled"`
	// Passed / Failed / Reserved partition the labeled set (Labeled ==
	// Passed+Failed+Reserved). Reserved counts rows whose ONLY reason for not
	// passing is a still-unregistered Reserved must_fire family
	// (ExamDetectRow.ReservedPending) — a TRACKED expected-miss, deliberately
	// excluded from Failed so a reserved-but-not-yet-authored detector never
	// hard-fails the exam or blocks CI (mallcoppro-db0).
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Reserved int `json:"reserved,omitempty"`
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

// registeredFamilies returns the set of normalized family tokens backed by a
// REGISTERED detector in THIS process — core/detect.Detectors(), keyed by
// each detector's own Name() (framework detectors' Type/Name pair are
// identical tokens, e.g. "volume-anomaly"; see core/detect/*.go). This is the
// live registration state a Reserved scenario's must_fire family is checked
// against: a family with no entry here has no detector that can possibly
// satisfy it yet, regardless of what the scenario's events contain.
func registeredFamilies() map[string]bool {
	dets := detect.Detectors()
	set := make(map[string]bool, len(dets))
	for _, d := range dets {
		set[normalizeFamilyToken(d.Name())] = true
	}
	return set
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
	return RunExamDetectOverCorpus(corpus, extra), nil
}

// RunExamDetectOverCorpus grades corpus.Scenarios (Extra=false) UNIONED with
// extraScenarios (Extra=true) through the IDENTICAL core/detect.Detect
// grading loop RunExamDetectExtra uses — factored out as the corpus-SOURCE-
// AGNOSTIC seam (mallcoppro-bc2, `mallcop eval`'s C4 build) that lets a
// caller supply a corpus loaded any way it likes (LoadEmbedded, in
// particular: the shipped reference corpus baked into a customer deploy-repo
// binary, mallcop eval's default source) rather than only the on-disk pinned
// corpus Load(repoRoot) resolves. RunExamDetectExtra is now a thin wrapper:
// Load(repoRoot) + LoadExtraScenarios(dir), then this.
func RunExamDetectOverCorpus(corpus Corpus, extraScenarios []LoadedScenario) ExamDetectReport {
	// Computed once per run — the live detector registration state a Reserved
	// scenario's must_fire families are checked against (mallcoppro-db0).
	registered := registeredFamilies()

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

		// realFailure tracks any must_fire/must_not_fire violation that is NOT
		// exempted as a reserved-and-unregistered gap. reservedPending
		// collects the must_fire families that WERE exempted — a Reserved
		// scenario whose family has no registered detector yet
		// (mallcoppro-db0). must_not_fire violations are never exempted.
		realFailure := false
		var reservedPending []string
		for _, want := range s.ExpectedDetection.MustFire {
			tok := normalizeFamilyToken(want)
			if present[tok] {
				continue
			}
			if s.ExpectedDetection.Reserved && !registered[tok] {
				reservedPending = append(reservedPending, tok)
				continue
			}
			realFailure = true
		}
		for _, banned := range s.ExpectedDetection.MustNotFire {
			if present[normalizeFamilyToken(banned)] {
				realFailure = true
			}
		}

		pass := !realFailure && len(reservedPending) == 0
		switch {
		case pass:
			report.Totals.Passed++
		case !realFailure && len(reservedPending) > 0:
			// Tracked expected-miss: RED, but not a hard exam failure.
			report.Totals.Reserved++
		default:
			report.Totals.Failed++
		}
		report.Rows = append(report.Rows, ExamDetectRow{
			ScenarioID:      s.ID,
			MustFire:        append([]string{}, s.ExpectedDetection.MustFire...),
			MustNotFire:     append([]string{}, s.ExpectedDetection.MustNotFire...),
			Emitted:         emittedTokens,
			Pass:            pass,
			Extra:           isExtra,
			Reserved:        s.ExpectedDetection.Reserved,
			ReservedPending: reservedPending,
		})
	}

	for _, ls := range corpus.Scenarios {
		grade(ls, false)
	}
	for _, ls := range extraScenarios {
		grade(ls, true)
	}
	return report
}
