// triagerisk.go — FIX 2: the FORBID-TERMINAL-TRIAGE-RESOLVE-ON-RISKY-FINDINGS gate.
//
// THE STRUCTURAL DEFECT this closes (parity-fixes, malicious-hard UNDER-ESCALATION):
// triage's cleanResolve() (tier.go) lets the cheap glm-4.7-flash model CLOSE a
// finding as benign at model_calls=1 the moment it SELF-REPORTS confidence>=4 +
// positive_evidence. On a real attack the cheap model games exactly those two
// self-reported fields — so 9 malicious-hard scenarios resolved terminally at
// triage and were never investigated. The portable core scored 68% vs legion's
// ~90-96% almost entirely on this path.
//
// THE FIX (asymmetric, calibrated): a clean triage resolve is allowed to TERMINATE
// only when the finding is OBVIOUSLY benign — low/medium severity AND carrying no
// malicious-shaped structural markers. A RISKY proposed-resolve (high/critical
// severity, OR a malicious-shaped marker on the finding) does NOT terminate: it is
// converted to a triage ESCALATE that hands off to investigate, so the finding gets
// GuardResolve + the <0.55 structural gate + the deep×3 panel before ANY close.
//
// CALIBRATION DISCIPLINE — this is NOT "blanket-escalate every critical":
//   - Blanket-escalating every critical would tank benign-hard PRECISION (every
//     hard benign finding would burn the full deep panel) and destroy the
//     cheap-triage economy (the whole point of a cheap triage tier is to close the
//     obvious-benign volume at model_calls=1).
//   - So the gate fires ONLY on the genuinely risky shape: high/critical severity,
//     OR a malicious-shaped marker. An obvious-benign low/medium finding the model
//     cleanly resolves STILL terminates at triage — precision and economy preserved.
//
// VERDICT-ISOLATION PRESERVED: this gate reads ONLY runtime-side fields — the
// finding's own severity/type/reason (already untrusted, but it is the SAME data
// the floor routes on) and the triage tier's OBSERVABLE signals. It never reads the
// model's verdict from prompt text; the verdict still comes from the model reply
// (tier.go's parseVerdict). TestCascade_VerdictIsolation stays green.
package agent

import (
	"strings"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// riskySeverities are the severities a clean triage resolve may NOT terminate on.
// A finding at this severity that the cheap model wants to close benign is exactly
// the malicious-hard case the deeper tier exists for — escalate it to investigate.
var riskySeverities = map[string]struct{}{
	"high":     {},
	"critical": {},
}

// maliciousShapedMarkers are substrings whose presence in a finding's type or
// reason marks the finding as carrying a malicious-shaped STRUCTURAL signature —
// the kind of attack the cheap triage model is least able to clear about itself.
// A clean triage resolve on a finding carrying any of these does NOT terminate at
// triage even when the severity is low/medium: the marker is the risk signal.
//
// These are deliberately attack-shape families/phrasings (lateral movement,
// privilege/credential/exfiltration/persistence signatures), NOT benign-workflow
// words — so an obvious-benign maintenance/onboarding finding does not trip them
// and keeps terminating cheaply at triage. Compared case-insensitively after
// separator-stripping so "lateral-movement", "lateral_movement", and
// "Lateral Movement" all match.
var maliciousShapedMarkers = []string{
	"lateralmovement",
	"privilegeescalation",
	"privesc",
	"credentialtheft",
	"credentialstuffing",
	"exfiltration",
	"persistence",
	"backdoor",
	"datatampering",
	"tokentheft",
	"impossibletravel",
}

// triageResolveMustEscalate reports whether a CLEAN triage resolve (already
// cleanResolve()==true) must be forbidden from terminating and instead handed off
// to investigate. It returns (true, reason) for a RISKY finding and (false, "") for
// an obvious-benign one that may close cheaply at triage.
//
// Risk signal #1 — severity: high/critical findings the cheap model wants to close
// are the malicious-hard under-escalation cases; force the deeper look.
//
// Risk signal #2 — malicious-shaped structural marker on the finding's own
// type/reason: an attack signature (lateral movement, credential theft,
// exfiltration, persistence, …) the cheap model cannot reliably clear about itself.
//
// Everything else (low/medium severity, no malicious marker) is OBVIOUS-benign and
// terminates at triage — the cheap-triage economy and benign-hard precision the
// task requires us to preserve.
func triageResolveMustEscalate(f finding.Finding) (bool, string) {
	if _, ok := riskySeverities[strings.ToLower(strings.TrimSpace(f.Severity))]; ok {
		return true, "high/critical severity finding: a triage-tier resolve is not trustworthy on a malicious-hard severity; escalating to investigate (GuardResolve + structural gate + deep panel)"
	}
	if marker, ok := hasMaliciousShapedMarker(f); ok {
		return true, "malicious-shaped marker (" + marker + ") on the finding: the cheap triage model cannot clear this signature about itself; escalating to investigate"
	}
	return false, ""
}

// FIX 3 (OBSERVABLE, EVENT-KEYED SAFETY FLOOR) is wired directly in cascade.go's
// triage gate, reading the runtime-measured ToolEvidence predicates carried on the
// tierResult (zeroHistoryAccess / roleGrantByActor). The two predicates are
// CALIBRATED DIFFERENTLY against the asymmetric error policy and the corpus:
//
//	ROLE-GRANT by the finding actor with no precedent → TERMINAL escalate
//	  (NEVER_AUTO_RESOLVE). The doc's "Privilege changes → always ESCALATE
//	  (non-negotiable)" override. The corpus confirms ZERO benign-expected scenario
//	  carries this predicate, so a terminal force never flips a benign finding.
//
//	ZERO-HISTORY ACCESS (a target with relationship count 0) → HANDOFF to
//	  investigate (NOT terminal). Zero-history is a JUDGMENT signal, not a structural
//	  invariant: the corpus has 5+ resolved-expected scenarios where a KNOWN actor
//	  legitimately makes a first-time access (a batch job reading a new container
//	  under an account it already uses, an onboarding MFA enrollment, a deploy to a
//	  fresh app). Terminally escalating those would tank benign-hard precision, so
//	  the predicate only forces the finding OFF the cheap-triage terminal-resolve
//	  path INTO investigate, where the stronger model weighs it in combination.
//
// Both are keyed on the EVENT the runner observed (relationships / surfaced events),
// never on the detector family — VA-01 (every target IN the actor's relationships,
// no role grant) is not caught and keeps resolving; ID-01 (role grant authored by a
// KNOWN granter, not the finding actor; the finding actor performs no zero-history
// access) is not caught and still resolves at triage. VERDICT-ISOLATION PRESERVED:
// every input is a runtime-measured ToolEvidence signal, never the model's verdict
// and never the boxed untrusted transcript text.

// hasMaliciousShapedMarker reports whether the finding's type or reason carries a
// malicious-shaped structural marker, and which one. Both fields are
// separator-stripped + lower-cased (the same hardening normalizeFamily uses) before
// the substring scan, so alias/separator/case variants all match.
func hasMaliciousShapedMarker(f finding.Finding) (string, bool) {
	hay := stripSeparators(f.Type) + " " + stripSeparators(f.Reason)
	for _, m := range maliciousShapedMarkers {
		if strings.Contains(hay, m) {
			return m, true
		}
	}
	return "", false
}
