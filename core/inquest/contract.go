// contract.go — deterministic, model-free enforcement of the narrate CONTRACT
// over the single model reply (mallcoppro-044). Two jobs:
//
//   - rejectFabricatedEvidence: a hard reject when the narrative cites a datum
//     the record does not contain (a "logs"/"audit-trail" source the assembled
//     user document — Finding fields plus Evidence — never mentions anywhere; a
//     "no prior history" claim contradicted by recurrence; an "unknown actor"
//     claim contradicted by baseline). The v0.16.2 prompt-only consistency
//     rules (mallcop #218) DID NOT HOLD — the model named fabricated evidence to
//     satisfy them — so the same rules are promoted here into code the model
//     cannot talk its way past. The logs/audit-trail check is grounded against
//     the FULL document sent to the model (userDoc), not Evidence alone: a
//     log_bucket_delete/audit_log_disabled finding's own Type/Reason legitimately
//     names "log" — narrating that back is not fabrication (mallcoppro-044
//     review finding 1). That grounding walks userDoc's parsed JSON VALUES only
//     (logTermInDocValues) — never its object keys — so a struct field NAME Go
//     always emits (e.g. "has_login_profile") can never itself ground the
//     check; only an actual finding/evidence value can (mallcoppro-044 review
//     finding: a prior version scanned the raw marshaled string and always
//     matched "log" via that field name's own "login" substring, making the
//     reject permanently dead in production).
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
// directives stream. calibrateVerdict — the ONLY function here that can move a
// verdict — branches strictly on generic Evidence numeric/bool fields
// (occurrences, known_actor, known_role, cadence, target-presence); it never
// reads a literal actor name, detector type, or finding id, so it cannot become
// a per-actor/per-family override. That "actor/type-string-blind" property is a
// hard invariant a reviewer must preserve for calibrateVerdict.
// rejectFabricatedEvidence's logs/audit-trail check is different in kind: it
// grounds a literal-string claim against the literal document the model was
// given (userDoc — Finding fields plus Evidence, exactly what buildUserMessage
// sent), never against a finding-type allowlist/denylist. It does not decide
// escalate/suppress; a reject only discards a malformed narrative exactly like
// any other STRICT-validation failure, and the finding still surfaces at
// whatever verdict the committee already resolved.
package inquest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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
// source. \blogs?\b matches only standalone "log"/"logs" — "login", "logging",
// "catalog" do not trip it. A match is NOT automatically a fabrication: some
// finding families (log_bucket_delete, audit_log_disabled) are themselves ABOUT
// a log resource, so the finding's own Type/Reason legitimately names "log" —
// see rejectFabricatedEvidence, which grounds a match against the full userDoc
// before rejecting.
var reFabricatedLogs = regexp.MustCompile(`(?i)(\blogs?\b|audit trail)`)

// reLogTermInValue is the GROUNDING regex, applied to each lowercased leaf VALUE
// of userDoc. It matches "log"/"logs"/"audit" only as a letter-delimited token
// ((?:^|[^a-z]) … (?:[^a-z]|$)), NOT as a raw substring (mallcoppro-044 review
// finding 1). A raw `strings.Contains(value, "log")` grounds on any coincidental
// "log" substring — "ConsoleLogin", "catalog", "login", "dialog", "backlog" —
// so a value that merely happens to contain those letters would ground a
// fabricated "absence of logs" claim and silently kill the reject. The token
// boundary keeps genuine log/audit sources that use separators (log_bucket_delete,
// audit_log_disabled, "cloudtrail-log-bucket", "the audit trail") grounding the
// check, while coincidental substrings do not. Separators (space, _, -, digits)
// are boundaries; only letters are not, so "ConsoleLogin"'s "log" is glued
// between letters ('l'…'i') and never matches.
var reLogTermInValue = regexp.MustCompile(`(?:^|[^a-z])(logs?|audit)(?:[^a-z]|$)`)

// reNoPriorHistory matches a narrative asserting the activity has never been
// seen before — a fabrication when recurrence shows more than one occurrence.
var reNoPriorHistory = regexp.MustCompile(`(?i)(no prior history|first time|no previous|not previously (seen|observed|recorded)|never (been )?seen before)`)

// reUnknownActor matches a narrative calling the ACTOR unknown/unrecognized — a
// fabrication when baseline marks it a known actor. Anchored to "actor" (both
// "unrecognized"/"unrecognised" spellings) so it never trips on a narrative
// calling some OTHER field of a known actor's own activity unrecognized/novel
// (an unrecognized source IP, region, role, or pattern) — that is a legitimate,
// often threat-relevant, claim about a known actor behaving anomalously, not a
// claim that the actor itself is unknown (mallcoppro-044 review finding 2).
var reUnknownActor = regexp.MustCompile(`(?i)(unknown actor|unrecogni[sz]ed actor|never (been )?seen before|not (a )?known actor)`)

// rejectFabricatedEvidence returns (true, reason) when the narrative cites a
// datum absent from the record. A reject maps to StatusAbsentInvalidOutput —
// the same treatment as any other malformed reply (the deterministic evidence
// chain still ships; only the fabricated narrative is discarded).
//
// userDoc is the EXACT document buildUserMessage sent to the model (Finding
// fields plus Evidence, JSON-encoded) — the logs/audit-trail check is grounded
// against it via logTermInDocValues, NOT a raw substring scan of the whole
// marshaled JSON (mallcoppro-044 review finding: a raw scan for "log" always
// matches, because Go always emits the STRUCT FIELD NAME
// "has_login_profile" — whose own substring "login" contains "log" — even
// when Evidence.Baseline.HasLoginProfile is false and no finding/evidence
// VALUE ever mentions logs; that made the reject dead in production).
// logTermInDocValues instead walks the parsed JSON tree and inspects only
// leaf VALUES, never map keys, so a log_bucket_delete/audit_log_disabled
// finding whose own Type/Reason VALUE names "log" still grounds the check
// (narrating that back is not fabrication — mallcoppro-044 review finding 1),
// while a bystander boolean field's KEY never does. The no-prior-history and
// unknown-actor checks read only Evidence numeric/bool fields (occurrences,
// known_actor) — never a name/type/id — so neither can become a family-match
// override.
func rejectFabricatedEvidence(narrative string, ev Evidence, userDoc string) (bool, string) {
	if reFabricatedLogs.MatchString(narrative) && !logTermInDocValues(userDoc) {
		return true, "cites logs/audit-trail — no such term appears anywhere in the assembled record"
	}
	if ev.Recurrence.Occurrences > 1 && reNoPriorHistory.MatchString(narrative) {
		return true, fmt.Sprintf("denies prior history but recurrence records %d occurrences", ev.Recurrence.Occurrences)
	}
	if ev.Baseline.KnownActor && reUnknownActor.MatchString(narrative) {
		return true, "calls the actor unknown but baseline marks it a known actor"
	}
	return false, ""
}

// logTermInDocValues reports whether a "log"/"logs"/"audit" TOKEN (matched by
// reLogTermInValue — a letter-delimited token, not a raw substring, so a
// coincidental "log" inside "ConsoleLogin"/"catalog"/"login"/"dialog" never
// grounds it — mallcoppro-044 review finding 1) appears in some leaf VALUE of
// userDoc — never a JSON object key. userDoc is re-parsed into a generic
// JSON tree (map[string]any / []any / string / float64 / bool / nil) and
// walked recursively, inspecting only the string leaves: struct field NAMES
// that Go always emits (e.g. "has_login_profile", "cadence_label") are map
// keys in that tree and are never visited, so a bystander field name can
// never ground the check — only an actual finding/evidence VALUE (a Type,
// Reason, Actor, Target, error string, etc.) can. A malformed/unparseable
// userDoc grounds nothing (fails closed toward rejecting the fabrication
// claim, consistent with STRICT validation elsewhere in this package).
func logTermInDocValues(userDoc string) bool {
	var v interface{}
	if err := json.Unmarshal([]byte(userDoc), &v); err != nil {
		return false
	}
	return valuesContainLogTerm(v)
}

// valuesContainLogTerm is logTermInDocValues' recursive walker.
func valuesContainLogTerm(v interface{}) bool {
	switch t := v.(type) {
	case string:
		// Token match (reLogTermInValue), NOT a raw substring: a coincidental
		// "log" inside "ConsoleLogin"/"catalog"/"login"/"dialog" must NOT ground
		// the check (mallcoppro-044 review finding 1).
		return reLogTermInValue.MatchString(strings.ToLower(t))
	case map[string]interface{}:
		for _, val := range t { // keys deliberately never inspected
			if valuesContainLogTerm(val) {
				return true
			}
		}
	case []interface{}:
		for _, item := range t {
			if valuesContainLogTerm(item) {
				return true
			}
		}
	}
	return false
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
// explain. The operational-infra calibration may cap/downgrade a verdict ONLY
// when the record names NO deviation at all (mallcoppro-044 review finding 2:
// recognizing too FEW deviation kinds silently downgraded a genuine threat on a
// known SERVICE — a novel source IP / off-hours use — to suspicious@0.4). It
// recognizes every deviation type the assembled Evidence can carry:
//
//   - novel target/role — a role/target this actor was never known to touch
//     (Target present AND !KnownRole);
//   - novel source IP — the actor's key used from an IP absent from its baseline
//     profile (SourceIP present AND !KnownIP): the classic credential-theft
//     signal on an OTHERWISE-known actor;
//   - off-hours/timing — the action fell outside the actor's known hours, and
//     ONLY when the actor actually has an hour baseline (HourBaselined AND
//     !KnownHour); an actor with no hour history must never read as off-hours.
//
// Each branch is PRESENCE-GATED on the relevant identity field (Target/SourceIP
// present, or an hour baseline existing) so a bare false zero-value can never be
// mistaken for a deviation. Every branch reads only generic Evidence bool/
// string-presence fields — never an actor name, detector type, or finding id —
// so this stays actor/type-string-blind and cannot become a family-match rule.
//
// This function only ever WIDENS the escape hatch: naming a deviation makes
// calibrateVerdict pass the model's own verdict through UNCHANGED. It can never
// force, escalate, or suppress anything — a genuine threat signal always
// survives it, which is exactly the invariant the item requires. Scan-
// correlation is DELIBERATELY still not consulted: a sub-threshold
// correlated=false is a near-miss against mallcop's OWN scan schedule (the live
// case's matched_fraction=0.64), never threat-positive evidence (item outcome
// 2), so it can never name a deviation.
func evidenceNamesDeviation(ev Evidence) bool {
	novelTarget := ev.Identity.Target != "" && !ev.Baseline.KnownRole
	novelIP := ev.Identity.SourceIP != "" && !ev.Baseline.KnownIP
	offHours := ev.Baseline.HourBaselined && !ev.Baseline.KnownHour
	return novelTarget || novelIP || offHours
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
