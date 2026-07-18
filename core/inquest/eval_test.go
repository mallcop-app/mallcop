package inquest

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// eval_test.go — the CI eval harness (mallcoppro-044 outcome 1). It pins the
// FINAL narrate behavior on the known-benign-infrastructure shape so the
// forge-proxy regression (a baseline-known, high-recurrence, machine-cadence
// SERVICE narrated as an over-confident THREAT with FABRICATED supporting
// evidence) can never reship. It runs as a plain `go test` with the package's
// own deterministic scriptedClient seam — no live model call, $0, already
// covered by ci.yml's `go test -count=1 ./...` (no new CI wiring).
//
// Each case pairs an Evidence fixture (the operational-infra shape) with an
// ADVERSARIAL model reply reproducing the postmortem's fabrication style, and
// asserts the finding is NEVER surfaced as a StatusOK threat: it is either
// REJECTED (a fabricated "logs"/"no-history"/"unknown-actor" claim -> absent-
// invalid-output) or DOWNGRADED (threat -> suspicious with capped confidence).

// benignInfraEvidence is the forge-proxy shape: a baseline-known relay
// repeating an identical action hundreds of times at ~1s machine cadence, whose
// scan-correlation is a sub-threshold near-miss (correlated=false, matched
// fraction 0.64), and whose target/role is KNOWN (no evidenced deviation).
func benignInfraEvidence() Evidence {
	return Evidence{
		Identity: IdentityEvidence{
			Actor:  "forge-proxy",
			Caller: "arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy",
			Target: "mallcop-bedrock-relay",
		},
		Recurrence: RecurrenceEvidence{
			Occurrences:          693,
			CadenceSecondsMedian: 1,
			CadenceLabel:         "irregular (~1s)",
		},
		Baseline: BaselineEvidence{
			KnownActor: true,
			KnownRole:  true,
		},
		ScanCorrelation: ScanCorrelationEvidence{
			ScanCount:       30,
			MatchedFraction: 0.64,
			Correlated:      false,
		},
	}
}

func replyJSON(verdict string, confidence float64, narrative string) string {
	return `{"verdict":"` + verdict + `","confidence":` + strconv.FormatFloat(confidence, 'f', -1, 64) + `,"narrative":"` + narrative + `"}`
}

// TestNarrateContract_KnownBenignInfrastructureCorpus is the corpus gate: every
// benign-infrastructure fixture paired with an adversarial threat reply must
// come out NOT-threat — rejected or downgraded — never StatusOK+threat.
func TestNarrateContract_KnownBenignInfrastructureCorpus(t *testing.T) {
	cases := []struct {
		name     string
		ev       Evidence
		reply    string
		wantKind string // "rejected" (absent-invalid-output) or "downgraded" (ok+suspicious)
	}{
		{
			name:     "fabricates_absent_logs",
			ev:       benignInfraEvidence(),
			reply:    replyJSON("threat", 0.85, "forge-proxy activity is not consistent with prior benign activity; the absence of justifying logs is concerning."),
			wantKind: "rejected",
		},
		{
			name:     "denies_prior_history_while_recurring",
			ev:       benignInfraEvidence(),
			reply:    replyJSON("threat", 0.9, "This is the first time forge-proxy has assumed this role; no prior history supports it."),
			wantKind: "rejected",
		},
		{
			name:     "calls_known_actor_unknown",
			ev:       benignInfraEvidence(),
			reply:    replyJSON("threat", 0.9, "An unknown actor assumed mallcop-bedrock-relay and should be revoked."),
			wantKind: "rejected",
		},
		{
			name:     "clean_threat_narrative_downgraded",
			ev:       benignInfraEvidence(),
			reply:    replyJSON("threat", 0.85, "forge-proxy assumed mallcop-bedrock-relay 693 times at ~1s cadence; the trust policy is broad and the account should be revoked."),
			wantKind: "downgraded",
		},
		{
			name:     "subthreshold_correlation_cited_as_threat_downgraded",
			ev:       benignInfraEvidence(),
			reply:    replyJSON("threat", 0.85, "forge-proxy does not correlate with the scan schedule, so this recurring role assumption is a deviation."),
			wantKind: "downgraded",
		},
		{
			name:     "overconfident_suspicious_on_infra_derated",
			ev:       benignInfraEvidence(),
			reply:    replyJSON("suspicious", 0.9, "forge-proxy repeatedly assumed mallcop-bedrock-relay; the volume alone warrants attention."),
			wantKind: "downgraded", // verdict stays suspicious, confidence capped
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := &scriptedClient{reply: c.reply}
			out := narrate(context.Background(), client, "investigate", 1024, "{}", c.ev)

			// The universal invariant: a benign-infrastructure record is NEVER
			// surfaced as a StatusOK threat.
			if out.Status == StatusOK && out.Verdict == VerdictThreat {
				t.Fatalf("benign-infra fixture surfaced as StatusOK threat (conf=%v) — the regression reshipped", out.Confidence)
			}

			switch c.wantKind {
			case "rejected":
				if out.Status != StatusAbsentInvalidOutput {
					t.Fatalf("Status = %q, want absent-invalid-output (fabricated evidence should be rejected)", out.Status)
				}
				if out.Err == nil {
					t.Error("expected a non-nil Err explaining the fabrication reject")
				}
			case "downgraded":
				if out.Status != StatusOK {
					t.Fatalf("Status = %q, want ok (a clean but over-confident reply should downgrade, not reject)", out.Status)
				}
				if out.Verdict == VerdictThreat {
					t.Fatalf("Verdict = threat, want it downgraded off threat on operational-infra evidence")
				}
				if out.Confidence > operationalDowngradeConfidenceCap {
					t.Errorf("Confidence = %v, want <= %v after calibration", out.Confidence, operationalDowngradeConfidenceCap)
				}
				if len(out.ContractNotes) == 0 {
					t.Error("expected a ContractNotes audit line recording the calibration")
				}
			}
			if client.calls != 1 {
				t.Errorf("client called %d times, want exactly 1 (contract is pure post-processing, never a re-ask)", client.calls)
			}
		})
	}
}

// TestNarrateContract_ForgeProxyPostmortemCase_NeverThreat is the exact
// regression: the LITERAL live-case numbers (known_actor=true, 693 occurrences,
// ~1s cadence, correlated=false, matched_fraction=0.64) paired with the exact
// fabrication the model produced (verdict threat 0.85, narrative citing "not
// consistent with prior benign activity", "deviation from baseline behavior",
// "absence of justifying logs"). It must NOT become a StatusOK threat — here it
// is rejected because the narrative cites logs absent from the record.
func TestNarrateContract_ForgeProxyPostmortemCase_NeverThreat(t *testing.T) {
	ev := benignInfraEvidence()
	if ev.Recurrence.Occurrences != 693 || ev.ScanCorrelation.MatchedFraction != 0.64 || !ev.Baseline.KnownActor {
		t.Fatalf("fixture drifted from the live case: %+v", ev)
	}
	reply := replyJSON("threat", 0.85,
		"forge-proxy is not consistent with prior benign activity; this is a deviation from baseline behavior, and the absence of justifying logs plus the fact it does not correlate with scan schedule indicates a threat. Revoke the trust policy.")

	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, "{}", ev)

	if out.Status == StatusOK && out.Verdict == VerdictThreat {
		t.Fatalf("the forge-proxy postmortem case surfaced as a StatusOK threat again — regression reshipped (conf=%v)", out.Confidence)
	}
	if out.Status != StatusAbsentInvalidOutput {
		t.Fatalf("Status = %q, want absent-invalid-output: the narrative fabricates 'logs' absent from the record", out.Status)
	}
	if out.Err == nil || !strings.Contains(out.Err.Error(), "absent from the record") {
		t.Errorf("Err = %v, want a fabrication-reject explanation", out.Err)
	}
}

// TestNarrateContract_PostmortemNumbersDowngradeWhenNarrativeIsClean proves the
// CALIBRATION path independently of the fabricated-logs reject: the same live-
// case evidence with a threat reply that fabricates nothing (no logs / no-
// history / unknown-actor words) is still forced off threat, because a
// baseline-known actor at machine cadence with no evidenced deviation is
// operational infrastructure. This is the check that makes the sub-threshold
// correlated=false near-miss (matched_fraction=0.64) unable to sustain a threat.
func TestNarrateContract_PostmortemNumbersDowngradeWhenNarrativeIsClean(t *testing.T) {
	ev := benignInfraEvidence()
	reply := replyJSON("threat", 0.85,
		"forge-proxy assumed mallcop-bedrock-relay 693 times at roughly one-second cadence; the granted trust is broad, so revoke the policy.")

	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, "{}", ev)

	if out.Status != StatusOK {
		t.Fatalf("Status = %q, want ok (clean narrative should downgrade, not reject)", out.Status)
	}
	if out.Verdict != VerdictSuspicious {
		t.Fatalf("Verdict = %q, want suspicious (threat downgraded on operational-infra evidence)", out.Verdict)
	}
	if out.Confidence > operationalDowngradeConfidenceCap {
		t.Errorf("Confidence = %v, want <= %v", out.Confidence, operationalDowngradeConfidenceCap)
	}
	if len(out.ContractNotes) == 0 || !strings.Contains(out.ContractNotes[0], "operational infrastructure") {
		t.Errorf("ContractNotes = %v, want a downgrade audit line", out.ContractNotes)
	}
}

// TestNarrateContract_GenuineThreatStillEscalates is the positive control: a
// baseline-UNKNOWN actor, single occurrence, novel target — NOT the operational-
// infra signature — with a clean threat reply passes through UNMODIFIED at full
// confidence. This proves the calibration is narrow (it fires only on the
// specific known-actor/high-recurrence/machine-cadence shape) and never blanket-
// suppresses a real threat.
func TestNarrateContract_GenuineThreatStillEscalates(t *testing.T) {
	ev := Evidence{
		Identity: IdentityEvidence{
			Actor:  "attacker-x",
			Caller: "arn:aws:iam::999988887777:user/attacker-x",
			Target: "prod-admin-role",
		},
		Recurrence: RecurrenceEvidence{Occurrences: 1},
		Baseline:   BaselineEvidence{KnownActor: false, KnownRole: false},
		ScanCorrelation: ScanCorrelationEvidence{
			ScanCount:  30,
			Correlated: false,
		},
	}
	reply := replyJSON("threat", 0.95,
		"attacker-x, an actor absent from the baseline, assumed prod-admin-role granting broad administrative access; escalate and revoke.")

	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, "{}", ev)

	if out.Status != StatusOK {
		t.Fatalf("Status = %q, want ok for a clean genuine-threat reply", out.Status)
	}
	if out.Verdict != VerdictThreat {
		t.Fatalf("Verdict = %q, want threat (calibration must not suppress a real threat)", out.Verdict)
	}
	if out.Confidence != 0.95 {
		t.Errorf("Confidence = %v, want 0.95 unchanged", out.Confidence)
	}
	if len(out.ContractNotes) != 0 {
		t.Errorf("ContractNotes = %v, want none (no calibration should fire)", out.ContractNotes)
	}
}

// TestNarrate_FabricationRejects drives the three hard-reject fabrication
// categories through narrate directly, each with the Evidence shape that makes
// the claim a fabrication, asserting StatusAbsentInvalidOutput — the same
// treatment as any other malformed reply. Mirrors TestNarrate_ValidationMatrix's
// invalid-cases table style, but per-case Evidence is required (the reject
// predicates read Evidence numeric/bool fields).
func TestNarrate_FabricationRejects(t *testing.T) {
	cases := []struct {
		name  string
		ev    Evidence
		reply string
	}{
		{
			name:  "logs_mention_absent_from_record",
			ev:    Evidence{}, // unconditional: no Evidence section models logs
			reply: replyJSON("benign", 0.5, "the audit logs show a routine assume-role."),
		},
		{
			name:  "unknown_actor_when_baseline_known",
			ev:    Evidence{Baseline: BaselineEvidence{KnownActor: true}},
			reply: replyJSON("suspicious", 0.6, "an unknown actor performed this action for the first time."),
		},
		{
			name:  "no_history_when_recurring",
			ev:    Evidence{Recurrence: RecurrenceEvidence{Occurrences: 5}},
			reply: replyJSON("suspicious", 0.6, "there is no prior history of this activity in the environment."),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := &scriptedClient{reply: c.reply}
			out := narrate(context.Background(), client, "", 1024, "{}", c.ev)
			if out.Status != StatusAbsentInvalidOutput {
				t.Fatalf("Status = %q, want absent-invalid-output for fabrication case %q", out.Status, c.name)
			}
			if out.Err == nil {
				t.Error("expected a non-nil Err explaining the fabrication")
			}
			if client.calls != 1 {
				t.Errorf("client called %d times, want exactly 1 (no re-ask)", client.calls)
			}
		})
	}
}

// TestNarrate_CleanReplyOnBenignInfraUnaltered guards the narrow-ness from the
// other side: a BENIGN verdict on the operational-infra shape passes through
// untouched (no downgrade, no confidence cap, no notes) — calibration only ever
// pulls a non-benign verdict DOWN, never perturbs an already-benign one.
func TestNarrate_CleanReplyOnBenignInfraUnaltered(t *testing.T) {
	ev := benignInfraEvidence()
	reply := replyJSON("benign", 0.95, "forge-proxy is the operator's own inference relay assuming mallcop-bedrock-relay at machine cadence; routine.")
	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, "{}", ev)
	if out.Status != StatusOK || out.Verdict != VerdictBenign || out.Confidence != 0.95 {
		t.Fatalf("benign infra reply altered: status=%q verdict=%q conf=%v", out.Status, out.Verdict, out.Confidence)
	}
	if len(out.ContractNotes) != 0 {
		t.Errorf("ContractNotes = %v, want none for an unaltered benign verdict", out.ContractNotes)
	}
}

// TestNarrateContract_LogFindingNarrativeNotFabricated proves the fix for
// mallcoppro-044 review finding 1: reFabricatedLogs is grounded against the
// FULL userDoc (Finding fields + Evidence), not Evidence alone. A
// log_bucket_delete finding's own genuine narrative necessarily names
// "log"/"audit trail" — that IS the finding's subject, taken verbatim from
// finding.Type/Reason which buildUserMessage puts in userDoc — so it must NOT
// be discarded as citing evidence absent from the record. Evidence is
// deliberately NOT the operational-infra shape (single occurrence,
// baseline-unknown actor) so a genuine threat passes through uncalibrated,
// isolating the fabrication-reject path from the calibration path.
func TestNarrateContract_LogFindingNarrativeNotFabricated(t *testing.T) {
	f := finding.Finding{
		ID:        "f-log-1",
		Type:      "log_bucket_delete",
		Severity:  "critical",
		Actor:     "attacker-x",
		Reason:    "the CloudTrail log bucket was deleted, destroying the audit trail",
		Timestamp: time.Now(),
	}
	ev := Evidence{
		Identity:   IdentityEvidence{Actor: "attacker-x", Target: "cloudtrail-log-bucket"},
		Recurrence: RecurrenceEvidence{Occurrences: 1},
		Baseline:   BaselineEvidence{KnownActor: false, KnownRole: false},
	}
	userDoc, err := buildUserMessage(f, ResolutionRef{Action: "escalate"}, ev)
	if err != nil {
		t.Fatalf("buildUserMessage: %v", err)
	}
	reply := replyJSON("threat", 0.9,
		"attacker-x deleted the CloudTrail log bucket, destroying the audit trail; this is a defense-evasion action and should be escalated.")

	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, userDoc, ev)

	if out.Status != StatusOK {
		t.Fatalf("Status = %q, want ok — a log_bucket_delete finding's own genuine 'log'/'audit trail' narrative must not be rejected as fabricated (err=%v)", out.Status, out.Err)
	}
	if out.Verdict != VerdictThreat {
		t.Fatalf("Verdict = %q, want threat (single-occurrence baseline-unknown actor is not the operational-infra shape, so calibration must not fire)", out.Verdict)
	}
}

// TestNarrateContract_UnrecognizedIPOnKnownActorNotFabricated proves the fix
// for mallcoppro-044 review finding 2: reUnknownActor is anchored to
// "unrecogni[sz]ed actor" so it never trips on "unrecognized" describing some
// OTHER field of a known actor's activity (a source IP, region, role,
// pattern) — a legitimate, often threat-relevant, credential-theft signal
// about a KNOWN actor behaving anomalously, not a claim that the actor itself
// is unknown.
func TestNarrateContract_UnrecognizedIPOnKnownActorNotFabricated(t *testing.T) {
	ev := Evidence{
		Identity:   IdentityEvidence{Actor: "forge-proxy", SourceIP: "203.0.113.7"},
		Recurrence: RecurrenceEvidence{Occurrences: 1},
		Baseline:   BaselineEvidence{KnownActor: true, KnownRole: true},
	}
	reply := replyJSON("threat", 0.85,
		"forge-proxy's key was used from an unrecognized source IP inconsistent with its usual origin, a strong credential-theft indicator; revoke the key.")

	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, "{}", ev)

	if out.Status != StatusOK {
		t.Fatalf("Status = %q, want ok — 'unrecognized source IP' on a known actor must not be rejected as an 'unknown actor' fabrication (err=%v)", out.Status, out.Err)
	}
	if out.Verdict != VerdictThreat {
		t.Fatalf("Verdict = %q, want threat (single occurrence is not the operational-infra shape, so calibration must not fire)", out.Verdict)
	}
	if out.Confidence != 0.85 {
		t.Errorf("Confidence = %v, want 0.85 unchanged (no calibration should fire)", out.Confidence)
	}
}
