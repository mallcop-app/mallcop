// coverage.go — the per-detector-family COVERAGE MATRIX over an exam-detect run.
//
// This is the corpus-expansion STEERING artifact (mallcoppro selfeval-c7): it
// rolls the flat per-scenario exam-detect rows up by detector family so a human
// (or the self-heal loop) can see, at a glance, which families are THIN — few
// labels, or labels the current detector can't satisfy — and therefore which
// family the corpus should grow next.
//
// The matrix is a pure re-aggregation of an already-graded ExamDetectReport: it
// runs NO detector, reads NO corpus, and adds NO grading semantics. Every count
// is derived from the rows the grader already produced (examdetect.go), so the
// matrix is exactly as offline/deterministic/LLM-free as the report it
// summarizes. It is exposed as an additive `coverage` field on the exam-detect
// JSON (ExamDetectReport.Coverage) — the recall-first view (recall.go) answers
// "how many attacks did we catch"; this answers "how is that spread across
// families, and where is the denominator still a toy."
//
// Definitions (mechanical, no benign/attack moral judgment — a must_fire label
// is the recall/attack side, a must_not_fire label is the precision/benign
// side, exactly as the grader treats them):
//
//   - AttackLabels  — # rows carrying this family in must_fire.
//   - BenignLabels  — # rows carrying this family in must_not_fire.
//   - Missed        — # must_fire rows where this family is ABSENT from the
//                     emitted set AND is not reserved-pending: a real recall
//                     gap (a registered detector that should fire but doesn't,
//                     or an unregistered family on a NON-reserved row).
//   - FalseAlarms   — # must_not_fire rows where this family IS present in the
//                     emitted set: a precision gap (the detector fired on a
//                     benign twin it should have stayed silent on).
//   - Reserved      — # must_fire rows where this family is reserved-pending
//                     (ExamDetectRow.ReservedPending): a TRACKED expected-miss
//                     for a family with no registered detector yet — counted
//                     apart from Missed so a not-yet-authored family doesn't
//                     read as a detector regression.
package eval

import "sort"

// FamilyCoverage is one detector family's row in the coverage matrix.
type FamilyCoverage struct {
	// Family is the normalized detector family token (e.g. "priv-escalation").
	Family string `json:"family"`
	// AttackLabels is the number of graded rows that list this family in
	// must_fire — the recall denominator this family contributes.
	AttackLabels int `json:"attack_labels"`
	// BenignLabels is the number of graded rows that list this family in
	// must_not_fire — the precision denominator this family contributes.
	BenignLabels int `json:"benign_labels"`
	// Missed is the number of must_fire rows where this family did NOT appear
	// in the emitted findings and was not reserved-pending — a live recall gap.
	Missed int `json:"missed"`
	// FalseAlarms is the number of must_not_fire rows where this family DID
	// appear in the emitted findings — a live precision gap.
	FalseAlarms int `json:"false_alarms"`
	// Reserved is the number of must_fire rows where this family is
	// reserved-pending (no registered detector) — a tracked expected-miss, held
	// apart from Missed.
	Reserved int `json:"reserved"`
}

// CoverageMatrix re-aggregates an exam-detect report into one FamilyCoverage row
// per detector family that appears in ANY row's must_fire or must_not_fire
// list. Families are returned sorted by token for a deterministic wire shape.
//
// Pure and total: it never runs a detector or touches the corpus, and an empty
// report yields an empty (non-nil-safe, len 0) slice. A family that is only ever
// emitted incidentally (present in Emitted but never labeled must_fire/
// must_not_fire on any row) is intentionally NOT a matrix row — the matrix
// tracks the LABELED coverage surface, not raw detector chatter.
func CoverageMatrix(report ExamDetectReport) []FamilyCoverage {
	byFamily := map[string]*FamilyCoverage{}
	get := func(fam string) *FamilyCoverage {
		fam = normalizeFamilyToken(fam)
		fc, ok := byFamily[fam]
		if !ok {
			fc = &FamilyCoverage{Family: fam}
			byFamily[fam] = fc
		}
		return fc
	}

	for _, row := range report.Rows {
		// The set of families this row actually emitted (dedup — presence, not
		// count, mirrors the grader's family-presence contract).
		present := make(map[string]bool, len(row.Emitted))
		for _, e := range row.Emitted {
			present[normalizeFamilyToken(e)] = true
		}
		// The reserved-pending families on this row (already normalized by the
		// grader), for holding a not-yet-authored family apart from Missed.
		pending := make(map[string]bool, len(row.ReservedPending))
		for _, p := range row.ReservedPending {
			pending[normalizeFamilyToken(p)] = true
		}

		for _, want := range row.MustFire {
			tok := normalizeFamilyToken(want)
			fc := get(tok)
			fc.AttackLabels++
			if present[tok] {
				continue
			}
			if pending[tok] {
				fc.Reserved++
			} else {
				fc.Missed++
			}
		}
		for _, banned := range row.MustNotFire {
			tok := normalizeFamilyToken(banned)
			fc := get(tok)
			fc.BenignLabels++
			if present[tok] {
				fc.FalseAlarms++
			}
		}
	}

	out := make([]FamilyCoverage, 0, len(byFamily))
	for _, fc := range byFamily {
		out = append(out, *fc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}
