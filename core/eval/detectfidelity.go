// detectfidelity.go — the LOAD-BEARING detect-fidelity accounting for -mode e2e.
//
// THE HEADLINE RESULT e2e EXPOSES: core/detect produces DIFFERENT / FEWER / ZERO
// findings than the YAML finding blocks the eval modes inject. Examples the detect
// map proved:
//   - AC-01: no `new-external-access` detector exists and the event type
//     (repo.add_collaborator) is in no detector's event-type set → ZERO findings.
//   - UT-03: `unusual-timing` is not reproduced (the scenario event lacks the
//     hour-profile the detector needs); `unusual-login` fires for the actor instead
//     → the EXPECTED `unusual-timing` finding is not reproduced.
//   - VA-03: volume-anomaly's frequency key does not match → ZERO findings.
//
// So detect-fidelity is NOT incidental — it is the headline. This file MEASURES it
// explicitly and the harness reports it; it is NEVER silently passed or folded into
// the chain_action pass-rate as if the agent had decided correctly.
//
// Per scenario, after pipeline.Run, classify into one of three outcomes by
// comparing detect's stored findings against the scenario's YAML finding block:
//
//	REPRODUCED  — a stored finding matches the expected (Actor, detector-family).
//	              The resolution for THAT finding is graded against expected
//	              chain_action. This is the only case that contributes a real
//	              agent-accuracy data point comparable to -mode real.
//	MISMATCH    — detect emitted finding(s) but NONE match the expected family+actor.
//	              We grade the closest-by-actor resolution as a "substitute" for
//	              provenance, but the type drift is flagged.
//	DETECT-MISS — detect emitted ZERO findings. No resolution to grade. A miss on an
//	              expected-ESCALATE scenario is a real production false-negative (the
//	              attack was never surfaced) — counted as an END-TO-END FAIL. A miss
//	              on an expected-RESOLVE scenario means nothing was flagged, which is
//	              the correct production outcome (nothing to escalate) — reported as
//	              "no-finding-correct", but still tracked separately and NEVER
//	              conflated with an agent resolve.
package eval

import (
	"strings"

	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// DetectOutcome is the per-scenario detect-fidelity bucket.
type DetectOutcome string

const (
	// OutcomeReproduced — detect emitted a finding matching the expected
	// (actor, family). The matched resolution is the graded data point.
	OutcomeReproduced DetectOutcome = "REPRODUCED"
	// OutcomeMismatch — detect emitted finding(s) but none match the expected
	// family+actor (type/actor drift).
	OutcomeMismatch DetectOutcome = "MISMATCH"
	// OutcomeDetectMiss — detect emitted ZERO findings (no resolution to grade).
	OutcomeDetectMiss DetectOutcome = "DETECT-MISS"
)

// DetectFidelityRow is the per-scenario fidelity record surfaced in the report.
type DetectFidelityRow struct {
	ScenarioID string `json:"scenario_id"`
	// ExpectedDetector is the scenario's YAML finding detector family (the family
	// the eval modes would inject).
	ExpectedDetector string `json:"expected_detector"`
	// ExpectedActor is the scenario's finding actor.
	ExpectedActor string `json:"expected_actor"`
	// ExpectedAction is the scenario's expected chain_action ("escalated" /
	// "resolved" / "escalate-or-stronger").
	ExpectedAction string `json:"expected_action"`
	// EmittedDetectors lists the (detector-family/actor) of every finding detect
	// emitted for this scenario — the visible drift.
	EmittedDetectors []string `json:"emitted_detectors"`
	// Outcome is the fidelity bucket.
	Outcome DetectOutcome `json:"outcome"`
	// MatchedFindingID is the id of the stored finding that matched (REPRODUCED) or
	// the closest-by-actor substitute (MISMATCH). Empty on DETECT-MISS.
	MatchedFindingID string `json:"matched_finding_id,omitempty"`
	// GradedOnSubstitute is true when the graded resolution belongs to a MISMATCH
	// substitute finding (provenance: the pass/fail did NOT come from a reproduced
	// finding). Always false for REPRODUCED.
	GradedOnSubstitute bool `json:"graded_on_substitute,omitempty"`
	// EndToEndPass is the TRUE "does live scan get the right answer from raw events"
	// verdict over ALL scenarios: DETECT-MISS / MISMATCH on an expected-escalate is a
	// FAIL; a DETECT-MISS on an expected-resolve is a PASS (correct: nothing flagged);
	// a REPRODUCED scenario inherits the chain_action grade. This is NOT the same as
	// the ScenarioResult.Pass (the agent-reasoning number over REPRODUCED only).
	EndToEndPass bool `json:"end_to_end_pass"`
	// NoFindingCorrect is true for the DETECT-MISS-on-expected-resolve case: nothing
	// was flagged and nothing should have been. Reported separately, never conflated
	// with an agent resolve.
	NoFindingCorrect bool `json:"no_finding_correct,omitempty"`
}

// DetectFidelity is the report block aggregating per-scenario fidelity (§e2e).
type DetectFidelity struct {
	Total      int `json:"total"`
	Reproduced int `json:"reproduced"`
	Mismatch   int `json:"mismatch"`
	DetectMiss int `json:"detect_miss"`
	// ReproductionRate = Reproduced / Total. Reported PROMINENTLY: a low rate means
	// the validated -mode real number does NOT yet transfer to live scan because the
	// detector fleet cannot produce most scenario findings.
	ReproductionRate float64 `json:"reproduction_rate"`
	// EndToEndPassRate is passes / Total over ALL scenarios where DETECT-MISS-on-
	// escalate and MISMATCH-on-escalate count as fails — the honest "live scan from
	// raw events" number. Far below the agent-reasoning rate when reproduction is low.
	EndToEndPassRate float64 `json:"end_to_end_pass_rate"`
	// E2ERecall is EndToEndPass / count over rows whose ExpectedAction demands
	// escalate (actionIsEscalate) — the TRUE live-scan attack-detection rate: a
	// DETECT-MISS or a MISMATCH that never escalates on an attack scenario counts
	// as a miss. Split out of EndToEndPassRate the same way harness.go's
	// RunResult.RecallRate splits the blended agent-reasoning PassRate (mallcoppro
	// C2; mirrors recall.go's exam-detect split at the detect-fidelity layer).
	E2ERecall float64 `json:"e2e_recall"`
	// E2EPrecision is EndToEndPass / count over rows whose ExpectedAction does NOT
	// demand escalate (the benign scenarios) — the TRUE live-scan rate of correctly
	// leaving benign activity alone (1.0 = no live-scan over-escalations).
	E2EPrecision float64 `json:"e2e_precision"`
	// Rows is the per-scenario fidelity detail.
	Rows []DetectFidelityRow `json:"rows"`
}

// classifyDetectFidelity buckets one scenario by comparing detect's emitted
// findings against the scenario's YAML finding block, and computes the end-to-end
// verdict. resolutions is the store's resolution stream (one per emitted finding,
// keyed by FindingID) — used only to locate the matched/substitute resolution; the
// pass/fail GRADING happens in Grade, this only records provenance + the end-to-end
// verdict.
func classifyDetectFidelity(s *exam.Scenario, emitted []finding.Finding, resolutions []resolution.Resolution) DetectFidelityRow {
	row := DetectFidelityRow{
		ScenarioID:       s.ID,
		ExpectedDetector: expectedDetector(s),
		ExpectedActor:    expectedActor(s),
		ExpectedAction:   expectedChainAction(s),
		EmittedDetectors: emittedSummary(emitted),
	}

	expectEscalate := actionIsEscalate(row.ExpectedAction)

	// DETECT-MISS: detect emitted nothing. No resolution to grade.
	if len(emitted) == 0 {
		row.Outcome = OutcomeDetectMiss
		if expectEscalate {
			// A real production false-negative: the attack was never surfaced.
			row.EndToEndPass = false
		} else {
			// Nothing flagged, nothing should have been: the correct production
			// outcome. Reported separately, never conflated with an agent resolve.
			row.EndToEndPass = true
			row.NoFindingCorrect = true
		}
		return row
	}

	// Look for an exact (actor, family) match → REPRODUCED.
	if m := matchExpected(s, emitted); m != nil {
		row.Outcome = OutcomeReproduced
		row.MatchedFindingID = m.ID
		// The end-to-end verdict for a reproduced scenario is the chain_action grade
		// of its matched resolution (the SAME axis Grade gates on).
		row.EndToEndPass = gradedActionMatches(s, resolutionFor(m.ID, resolutions))
		return row
	}

	// detect emitted findings but none match → MISMATCH (type/actor drift).
	row.Outcome = OutcomeMismatch
	// Grade on the closest-by-actor substitute for provenance; flag the drift.
	if sub := closestByActor(row.ExpectedActor, emitted); sub != nil {
		row.MatchedFindingID = sub.ID
		row.GradedOnSubstitute = true
	}
	// End-to-end: a MISMATCH on an expected-escalate is a fail UNLESS some emitted
	// finding for the expected actor escalated (the attack was still surfaced, just
	// under a different detector). On expected-resolve, a spurious extra finding that
	// escalates is an over-escalation fail; a resolve is correct.
	if expectEscalate {
		row.EndToEndPass = anyActorFindingEscalated(row.ExpectedActor, emitted, resolutions)
	} else {
		// expected resolve: end-to-end correct iff NO finding for the actor escalated.
		row.EndToEndPass = !anyActorFindingEscalated(row.ExpectedActor, emitted, resolutions)
	}
	return row
}

// matchExpected returns the stored finding whose (actor, detector-family) equals
// the scenario's expected (actor, family), or nil. Family equality is on the
// finding.Type / finding.Source family token; actor is case-insensitive.
func matchExpected(s *exam.Scenario, emitted []finding.Finding) *finding.Finding {
	wantActor := strings.ToLower(strings.TrimSpace(expectedActor(s)))
	wantFamily := strings.ToLower(strings.TrimSpace(expectedDetector(s)))
	for i := range emitted {
		f := &emitted[i]
		if strings.ToLower(strings.TrimSpace(f.Actor)) != wantActor {
			continue
		}
		if findingFamilyToken(*f) == wantFamily {
			return f
		}
	}
	return nil
}

// closestByActor returns the first emitted finding for the expected actor (any
// family), or nil — the MISMATCH substitute graded for provenance.
func closestByActor(actor string, emitted []finding.Finding) *finding.Finding {
	want := strings.ToLower(strings.TrimSpace(actor))
	for i := range emitted {
		if strings.ToLower(strings.TrimSpace(emitted[i].Actor)) == want {
			return &emitted[i]
		}
	}
	return nil
}

// anyActorFindingEscalated reports whether ANY emitted finding for the actor has a
// store resolution with action "escalate" (mirrors grader.go:136's "any escalate
// satisfies escalate-or-stronger").
func anyActorFindingEscalated(actor string, emitted []finding.Finding, resolutions []resolution.Resolution) bool {
	want := strings.ToLower(strings.TrimSpace(actor))
	for _, f := range emitted {
		if strings.ToLower(strings.TrimSpace(f.Actor)) != want {
			continue
		}
		if r := resolutionFor(f.ID, resolutions); r != nil && strings.EqualFold(r.Action, "escalate") {
			return true
		}
	}
	return false
}

// resolutionFor returns the stored resolution for a finding id, or nil.
func resolutionFor(findingID string, resolutions []resolution.Resolution) *resolution.Resolution {
	for i := range resolutions {
		if resolutions[i].FindingID == findingID {
			return &resolutions[i]
		}
	}
	return nil
}

// gradedActionMatches reports whether a stored resolution's mapped action
// satisfies the scenario's expected chain_action — the SAME logic Grade applies,
// used to compute the end-to-end verdict for a REPRODUCED scenario without
// re-running Grade.
func gradedActionMatches(s *exam.Scenario, r *resolution.Resolution) bool {
	if r == nil {
		return false
	}
	mapped := mapStoreAction(r.Action)
	exp := expectedChainAction(s)
	switch {
	case strings.EqualFold(exp, "escalate-or-stronger"):
		return strings.EqualFold(mapped, "escalated")
	default:
		return strings.EqualFold(mapped, exp)
	}
}

// terminalFromFidelity selects the resolution to feed Grade and maps its store
// action onto the grader's vocabulary. For REPRODUCED, the matched finding's
// resolution. For MISMATCH, the substitute. For DETECT-MISS, there is NO resolution
// — the terminal action is "" (Grade fails chain_action, which the harness reports
// as a fail) and the no-finding-correct provenance lives on the fidelity row.
func terminalFromFidelity(row DetectFidelityRow, resolutions []resolution.Resolution) (action, reason string, forced bool) {
	if row.MatchedFindingID == "" {
		return "", "", false
	}
	r := resolutionFor(row.MatchedFindingID, resolutions)
	if r == nil {
		return "", "", false
	}
	return mapStoreAction(r.Action), r.Reason, false
}

// mapStoreAction maps the store's resolve/escalate onto the grader's
// resolved/escalated (the action-string mismatch the e2e seam map flags: the store
// writes resolve/escalate via toResolutionRecord; the grader expects
// resolved/escalated). Forgetting this mapping makes EVERY scenario fail
// chain_action and the report shows 0% — a wiring bug masquerading as an accuracy
// collapse. The canned-verification test asserts ≥1 Pass to catch it.
func mapStoreAction(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "escalate":
		return "escalated"
	case "resolve":
		return "resolved"
	default:
		return a
	}
}

// --- scenario field extractors (expected side) --------------------------------

// expectedDetector is the scenario's YAML finding detector family (falling back to
// the top-level scenario detector). This is the family the eval modes inject and
// e2e checks detect against.
func expectedDetector(s *exam.Scenario) string {
	if s.Finding != nil && s.Finding.Detector != "" {
		return s.Finding.Detector
	}
	return s.Detector
}

// expectedActor is the scenario finding's actor metadata (falling back to the first
// event's actor) — the SAME derivation scenarioActor uses.
func expectedActor(s *exam.Scenario) string {
	return scenarioActor(s)
}

// expectedChainAction is the scenario's expected chain_action, or "".
func expectedChainAction(s *exam.Scenario) string {
	if s.ExpectedResolution != nil {
		return s.ExpectedResolution.ChainAction
	}
	return ""
}

// actionIsEscalate reports whether an expected chain_action demands an escalate
// (either "escalated" or "escalate-or-stronger").
func actionIsEscalate(action string) bool {
	return strings.EqualFold(action, "escalated") || strings.EqualFold(action, "escalate-or-stronger")
}

// findingFamilyToken returns the canonical family token of a stored finding: its
// Type, falling back to the "detector:<family>" Source suffix.
func findingFamilyToken(f finding.Finding) string {
	if t := strings.ToLower(strings.TrimSpace(f.Type)); t != "" {
		return t
	}
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(f.Source), "detector:"))
}

// emittedSummary renders the emitted findings as "family/actor" tokens for the
// report (the visible drift), deterministically in store order.
func emittedSummary(emitted []finding.Finding) []string {
	out := make([]string, 0, len(emitted))
	for _, f := range emitted {
		out = append(out, findingFamilyToken(f)+"/"+f.Actor)
	}
	return out
}

// aggregateDetectFidelity rolls per-scenario rows into the report block.
func aggregateDetectFidelity(rows []DetectFidelityRow) DetectFidelity {
	df := DetectFidelity{Total: len(rows), Rows: rows}
	endToEndPasses := 0
	attacks, attacksPassed := 0, 0
	benigns, benignsPassed := 0, 0
	for _, r := range rows {
		switch r.Outcome {
		case OutcomeReproduced:
			df.Reproduced++
		case OutcomeMismatch:
			df.Mismatch++
		case OutcomeDetectMiss:
			df.DetectMiss++
		}
		if r.EndToEndPass {
			endToEndPasses++
		}
		// Recall/precision split (mallcoppro C2): the SAME actionIsEscalate test
		// classifyDetectFidelity used to derive expectEscalate for this row.
		if actionIsEscalate(r.ExpectedAction) {
			attacks++
			if r.EndToEndPass {
				attacksPassed++
			}
		} else {
			benigns++
			if r.EndToEndPass {
				benignsPassed++
			}
		}
	}
	if df.Total > 0 {
		df.ReproductionRate = float64(df.Reproduced) / float64(df.Total)
		df.EndToEndPassRate = float64(endToEndPasses) / float64(df.Total)
	}
	if attacks > 0 {
		df.E2ERecall = float64(attacksPassed) / float64(attacks)
	}
	if benigns > 0 {
		df.E2EPrecision = float64(benignsPassed) / float64(benigns)
	}
	return df
}
