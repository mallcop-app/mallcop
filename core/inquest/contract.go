// contract.go — deterministic, model-free enforcement of the narrate CONTRACT
// over the single model reply (mallcoppro-044). Two jobs, both PURE Go over the
// already-assembled Evidence numeric/bool fields — never over an actor name, a
// finding.Type string, or a finding ID:
//
//   - rejectFabricatedEvidence: a hard reject when the narrative cites a datum
//     the record structurally does not contain (a "logs"/"audit-trail" source
//     that no Evidence section models; a "no prior history" claim contradicted
//     by recurrence; an "unknown actor" claim contradicted by baseline). The
//     v0.16.2 prompt-only consistency rules (mallcop #218) DID NOT HOLD — the
//     model named fabricated evidence to satisfy them — so the same rules are
//     promoted here into code the model cannot talk its way past.
//   - calibrateVerdict: down-weights an over-confident THREAT verdict when the
//     evidence is the signature of automated operational infrastructure (a
//     baseline-known actor repeating an identical action hundreds of times at
//     machine cadence) and NO evidence section names a break that shape does
//     not explain. A sub-threshold scan-correlation (correlated=false on a
//     near-miss matched_fraction) is deliberately NEVER consulted as a
//     deviation, so it can never flip a verdict on its own.
//
// CONSENSUS INVARIANT (why this is not a "family-match rule that bypasses
// consensus"): inquest runs strictly AFTER the committee's resolutions stream is
// durably committed (see the package doc). Verdict/Confidence here are the
// investigator's OWN post-hoc assessment (Record.Role="evidence"), never the
// committee's disposition, and this file writes to NO findings/resolutions/
// directives stream. It also branches ONLY on generic Evidence numeric/bool
// fields (occurrences, known_actor, known_role, cadence, target-presence) — it
// never reads a literal actor name, detector type, or finding id — so it cannot
// become a per-actor/per-family override. That "actor/type-string-blind"
// property is a hard invariant a reviewer must preserve.
package inquest

import (
	"fmt"
	"regexp"
)

// minOperationalOccurrences is the occurrence count at/above which a
// baseline-known actor's repeated identical action reads as automated
// operational infrastructure rather than a one-off actor. Well below the
// forge-proxy motivating case (693) and comfortably above any human-cadence
// actor a scan window realistically accumulates.
const minOperationalOccurrences = 20

// machineCadenceCeilingSeconds is the median inter-arrival gap at/under which a
// cadence reads as machine-generated even when cadenceLabel buckets it
// "irregular" — the forge-proxy relay's ~1s cadence is the motivating case
// (cadenceLabel only names minutely/hourly/daily/weekly, so a 1s median labels
// "irregular (~1s)" yet is unmistakably automated). No human sustains hundreds
// of identical actions at a sub-minute median.
const machineCadenceCeilingSeconds = 60

// operationalDowngradeConfidenceCap bounds confidence once the operational-
// infrastructure calibration fires — a downgraded/derated verdict must not
// carry high confidence.
const operationalDowngradeConfidenceCap = 0.4

// reFabricatedLogs matches a narrative citing a "logs"/"audit-trail" data
// source. The assembled Evidence chain (identity/neighbors/recurrence/baseline/
// scan_correlation/org_context) models no such section, so ANY such mention is
// by definition citing evidence absent from the record. \blogs?\b matches only
// standalone "log"/"logs" — "login", "logging", "catalog" do not trip it.
var reFabricatedLogs = regexp.MustCompile(`(?i)(\blogs?\b|audit trail)`)

// reNoPriorHistory matches a narrative asserting the activity has never been
// seen before — a fabrication when recurrence shows more than one occurrence.
var reNoPriorHistory = regexp.MustCompile(`(?i)(no prior history|first time|no previous|not previously (seen|observed|recorded)|never (been )?seen before)`)

// reUnknownActor matches a narrative calling the actor unknown/unrecognized — a
// fabrication when baseline marks it a known actor.
var reUnknownActor = regexp.MustCompile(`(?i)(unknown actor|unrecognized actor|unrecogni[sz]ed|never (been )?seen before|not (a )?known actor)`)

// rejectFabricatedEvidence returns (true, reason) when the narrative cites a
// datum the assembled Evidence does not contain. A reject maps to
// StatusAbsentInvalidOutput — the same treatment as any other malformed reply
// (the deterministic evidence chain still ships; only the fabricated narrative
// is discarded). It reads ONLY Evidence numeric/bool fields, never a name/type/
// id, so it is not a family-match override.
func rejectFabricatedEvidence(narrative string, ev Evidence) (bool, string) {
	if reFabricatedLogs.MatchString(narrative) {
		return true, "cites logs/audit-trail — no such section exists in the assembled evidence"
	}
	if ev.Recurrence.Occurrences > 1 && reNoPriorHistory.MatchString(narrative) {
		return true, fmt.Sprintf("denies prior history but recurrence records %d occurrences", ev.Recurrence.Occurrences)
	}
	if ev.Baseline.KnownActor && reUnknownActor.MatchString(narrative) {
		return true, "calls the actor unknown but baseline marks it a known actor"
	}
	return false, ""
}

// isRegularCadence reports whether the recurrence cadence reads as automated:
// a named cadence bucket (minutely/hourly/daily/weekly), OR a sub-minute median
// that cadenceLabel could only bucket "irregular" yet is plainly machine-paced
// (the forge-proxy ~1s case). Reads only the two numeric cadence fields.
func isRegularCadence(r RecurrenceEvidence) bool {
	switch r.CadenceLabel {
	case "minutely", "hourly", "daily", "weekly":
		return true
	}
	return r.CadenceSecondsMedian > 0 && r.CadenceSecondsMedian <= machineCadenceCeilingSeconds
}

// isOperationalInfrastructureSignature is the "automated operational
// infrastructure" shape: a baseline-known actor repeating an identical action
// many times at machine cadence. This is precisely the forge-proxy signature
// (known relay, 693 occurrences, ~1s cadence) the item exists to stop mislabel-
// ing as a threat. It branches ONLY on Evidence numeric/bool fields.
func isOperationalInfrastructureSignature(ev Evidence) bool {
	return ev.Baseline.KnownActor &&
		ev.Recurrence.Occurrences >= minOperationalOccurrences &&
		isRegularCadence(ev.Recurrence)
}

// evidenceNamesDeviation is the escape hatch: it reports whether some Evidence
// section shows a genuine break the recurring-infrastructure shape does NOT
// explain — a target/role this actor was never known to touch. Only then may a
// threat verdict stand on operational-infra-shaped evidence.
//
// Scan-correlation is DELIBERATELY not consulted here: a sub-threshold
// correlated=false is a near-miss against mallcop's OWN scan schedule (the live
// case's matched_fraction=0.64), never threat-positive evidence (item outcome
// 2), so it can never name a deviation. Reads only Evidence bool/string-presence
// fields — the Target CHECK is presence-only (Target != ""), never a match on
// Target's literal value.
func evidenceNamesDeviation(ev Evidence) bool {
	return ev.Identity.Target != "" && !ev.Baseline.KnownRole
}

// calibrateVerdict applies the operational-infrastructure calibration to the
// investigator's own (verdict, confidence). When the evidence is the
// operational-infra signature AND no section names a deviation:
//   - a THREAT verdict is downgraded to SUSPICIOUS and confidence capped
//     (outcome 2/3: a high-recurrence known SERVICE is not auto-threat, and a
//     sub-threshold correlation never flips it);
//   - any other non-benign verdict keeps its verdict but has confidence capped
//     (outcome 3: the only "anomaly" is that a detector fired on known infra).
//
// A benign verdict, or any verdict where the evidence is NOT operational-infra
// or DOES name a deviation, passes through unchanged — so a genuine threat on a
// baseline-unknown/novel-target actor still escalates at full confidence. It is
// PURE post-processing over the ONE existing reply — never a second model call.
func calibrateVerdict(v Verdict, confidence float64, ev Evidence) (Verdict, float64, []string) {
	if v == VerdictBenign {
		return v, confidence, nil
	}
	if !isOperationalInfrastructureSignature(ev) || evidenceNamesDeviation(ev) {
		return v, confidence, nil
	}

	var notes []string
	if v == VerdictThreat {
		notes = append(notes, fmt.Sprintf(
			"downgraded threat->suspicious: baseline-known actor at machine cadence (%d occurrences) with no evidenced deviation reads as operational infrastructure, not an attack",
			ev.Recurrence.Occurrences))
		v = VerdictSuspicious
	} else {
		notes = append(notes, fmt.Sprintf(
			"confidence derated: the only anomaly is a detector firing on a baseline-known operational-infrastructure actor (%d occurrences); no evidence section names a deviation",
			ev.Recurrence.Occurrences))
	}
	if confidence > operationalDowngradeConfidenceCap {
		confidence = operationalDowngradeConfidenceCap
	}
	return v, confidence, notes
}
