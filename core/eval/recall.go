// recall.go — the RECALL-FIRST honest-measurement view over an ExamDetectReport.
//
// THE HONEST DENOMINATOR THE SELF-HEAL LOOP AND THE OPERATOR BOTH NEED. The
// default exam-detect view reports one aggregate pass/fail per labeled scenario
// (Totals.Passed / Failed). That number blends two fundamentally different kinds
// of failure into one pile:
//
//   - A MISSED ATTACK — an attack that MUST fire but did not. This is a FATAL
//     production false-negative: the attack was never surfaced, the operator was
//     never warned. In detection terms it is a RECALL failure.
//   - A FALSE ALARM — a benign scenario that MUST stay silent but fired. This is
//     noise: the operator gets paged for nothing. In detection terms it is a
//     PRECISION failure.
//
// Conflating them hides the number that actually matters. An exam at "90% pass"
// could be missing every real attack (0% recall) while acing the benign twins,
// or catching every attack while crying wolf on the benign set. The self-heal
// loop must know WHICH, because it grows detectors to close recall gaps and
// tunes them to kill false alarms — opposite moves.
//
// This file splits the SAME labeled corpus by ground truth and reports the two
// numbers separately, with the failures NAMED:
//
//   - RECALL    = detected / must-fire, over every scenario whose expected_
//     detection carries a must_fire family (an attack that MUST be caught). The
//     MISSED attacks are listed prominently — they are the fatal failures.
//   - PRECISION = correct-silent / must-stay-silent, over every scenario with NO
//     must_fire family (a benign case). The FALSE ALARMS are listed by name.
//
// The split is derived ENTIRELY from the existing ExamDetectRow labels
// (MustFire / MustNotFire / Emitted) — it re-runs no detector and changes no
// grading. It is a second lens on the same graded rows, so it is exactly as
// deterministic and LLM-free as the report it reads.
package eval

// MissedAttack names one must-fire scenario whose attack was NOT fully detected
// — the fatal recall failure. Missing lists the must_fire family tokens
// (normalized) that did not appear among the scenario's emitted findings.
type MissedAttack struct {
	ScenarioID string `json:"scenario_id"`
	// Missing is the must_fire family tokens (normalized) absent from the
	// emitted set — the detectors that should have fired and did not.
	Missing []string `json:"missing_families"`
	// Reserved is true when EVERY missing family is a tracked reserved-pending
	// gap (expected_detection.reserved: true and no detector for that family is
	// registered yet, mallcoppro-db0). The attack is genuinely not caught — so
	// it IS a recall miss, counted in the denominator like any other — but the
	// gap is KNOWN and awaiting an authored detector, not a regression. A miss
	// where any missing family has a registered detector reads as Reserved=false
	// so it surfaces as an ordinary fatal failure.
	Reserved bool `json:"reserved,omitempty"`
}

// FalseAlarm names one must-stay-silent (benign) scenario that fired a family it
// was labeled to never fire — a precision failure. Fired lists the must_not_fire
// family tokens (normalized) that appeared among the emitted findings.
type FalseAlarm struct {
	ScenarioID string   `json:"scenario_id"`
	Fired      []string `json:"fired_families"`
}

// RecallStat is the recall side of the split: the attack scenarios and how many
// were fully caught.
type RecallStat struct {
	// MustFire is the denominator — the number of scenarios labeled with at
	// least one must_fire family (the attacks that MUST be caught).
	MustFire int `json:"must_fire"`
	// Detected is the numerator — attack scenarios where EVERY must_fire family
	// appeared among the emitted findings.
	Detected int `json:"detected"`
	// Rate is Detected/MustFire, or 1.0 when there are no attack scenarios (a
	// vacuously perfect recall — avoids NaN in JSON).
	Rate float64 `json:"rate"`
	// Missed lists every attack that was NOT fully detected — the fatal failures,
	// named. Empty when recall is 100%.
	Missed []MissedAttack `json:"missed,omitempty"`
}

// PrecisionStat is the precision side of the split: the benign scenarios and how
// many stayed correctly silent.
type PrecisionStat struct {
	// MustStaySilent is the denominator — scenarios with NO must_fire family (the
	// benign cases that must not raise their labeled must_not_fire families).
	MustStaySilent int `json:"must_stay_silent"`
	// CorrectSilent is the numerator — benign scenarios where none of the labeled
	// must_not_fire families fired.
	CorrectSilent int `json:"correct_silent"`
	// Rate is CorrectSilent/MustStaySilent, or 1.0 when there are no benign
	// scenarios.
	Rate float64 `json:"rate"`
	// FalseAlarms lists every benign scenario that fired a must_not_fire family,
	// named. Empty when precision is 100%.
	FalseAlarms []FalseAlarm `json:"false_alarms,omitempty"`
}

// RecallReport is the recall-first view over an ExamDetectReport: recall
// (attacks caught) and precision (benign kept silent) reported separately, each
// with its failures named.
type RecallReport struct {
	Recall    RecallStat    `json:"recall"`
	Precision PrecisionStat `json:"precision"`
}

// RecallFromReport derives the recall-first split from a graded ExamDetectReport.
// Each labeled row is classified by its ground truth: a row with >=1 must_fire
// family is a MUST-FIRE (attack) scenario scored for recall; a row with no
// must_fire family is a MUST-STAY-SILENT (benign) scenario scored for precision.
// The split re-runs no detector — it reads only the labels and emitted families
// already on the rows — so it is as deterministic as the report it reads.
func RecallFromReport(report ExamDetectReport) RecallReport {
	var rr RecallReport
	for _, row := range report.Rows {
		present := make(map[string]bool, len(row.Emitted))
		for _, tok := range row.Emitted {
			present[normalizeFamilyToken(tok)] = true
		}

		if len(row.MustFire) > 0 {
			// MUST-FIRE: an attack that must be detected. Score recall.
			rr.Recall.MustFire++
			var missing []string
			for _, fam := range row.MustFire {
				tok := normalizeFamilyToken(fam)
				if !present[tok] {
					missing = append(missing, tok)
				}
			}
			if len(missing) == 0 {
				rr.Recall.Detected++
			} else {
				rr.Recall.Missed = append(rr.Recall.Missed, MissedAttack{
					ScenarioID: row.ScenarioID,
					Missing:    missing,
					Reserved:   allReservedPending(missing, row.ReservedPending),
				})
			}
			continue
		}

		// MUST-STAY-SILENT: a benign scenario. Score precision.
		rr.Precision.MustStaySilent++
		var fired []string
		for _, fam := range row.MustNotFire {
			tok := normalizeFamilyToken(fam)
			if present[tok] {
				fired = append(fired, tok)
			}
		}
		if len(fired) == 0 {
			rr.Precision.CorrectSilent++
		} else {
			rr.Precision.FalseAlarms = append(rr.Precision.FalseAlarms, FalseAlarm{
				ScenarioID: row.ScenarioID,
				Fired:      fired,
			})
		}
	}

	rr.Recall.Rate = detectionRatio(rr.Recall.Detected, rr.Recall.MustFire)
	rr.Precision.Rate = detectionRatio(rr.Precision.CorrectSilent, rr.Precision.MustStaySilent)
	return rr
}

// allReservedPending reports whether EVERY missing family is a tracked
// reserved-pending gap (in the row's ReservedPending set). Returns false when
// missing is empty or any missing family is NOT reserved-pending — i.e. the miss
// is (at least partly) a real regression, not a known-and-awaited gap.
func allReservedPending(missing, reservedPending []string) bool {
	if len(missing) == 0 {
		return false
	}
	pending := make(map[string]bool, len(reservedPending))
	for _, tok := range reservedPending {
		pending[normalizeFamilyToken(tok)] = true
	}
	for _, m := range missing {
		if !pending[normalizeFamilyToken(m)] {
			return false
		}
	}
	return true
}

// detectionRatio is numerator/denominator, or 1.0 for an empty denominator (a
// vacuously perfect rate — keeps the JSON free of NaN).
func detectionRatio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1.0
	}
	return float64(numerator) / float64(denominator)
}
