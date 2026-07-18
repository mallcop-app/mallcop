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

// benignInfraFinding is the finding half of the forge-proxy shape, paired
// with benignInfraEvidence() to build the REAL production userDoc via
// buildUserMessage — never the synthetic "{}" placeholder. Its Type/Reason
// deliberately name nothing "log"-shaped, so a case that must reject a
// fabricated "logs" claim in these tests is proving the reject fires when the
// record genuinely says nothing about logs, not merely when the test forgot
// to assemble a document at all (mallcoppro-044 review finding: the eval
// harness's prior "{}" documents could not have caught the production bug
// where userDoc always superficially contains "log" via the
// "has_login_profile" JSON field name).
func benignInfraFinding() finding.Finding {
	return finding.Finding{
		ID: "finding-forge-proxy-1", Type: "assume_role", Severity: "high",
		Actor: "forge-proxy", Reason: "AssumeRole into mallcop-bedrock-relay",
		Timestamp: time.Now(),
	}
}

// mustBuildUserDoc builds the real production userDoc (finding.Finding +
// Evidence, exactly as buildUserMessage renders it) for a test case, failing
// the test on a build error rather than silently falling back to a synthetic
// document.
func mustBuildUserDoc(t *testing.T, f finding.Finding, ev Evidence) string {
	t.Helper()
	doc, err := buildUserMessage(f, ResolutionRef{Action: "escalate"}, ev)
	if err != nil {
		t.Fatalf("buildUserMessage: %v", err)
	}
	return doc
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
			userDoc := mustBuildUserDoc(t, benignInfraFinding(), c.ev)
			client := &scriptedClient{reply: c.reply}
			out := narrate(context.Background(), client, "investigate", 1024, userDoc, c.ev)

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

	userDoc := mustBuildUserDoc(t, benignInfraFinding(), ev)
	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, userDoc, ev)

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

	userDoc := mustBuildUserDoc(t, benignInfraFinding(), ev)
	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, userDoc, ev)

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
			// Real production userDoc (mallcoppro-044 review finding), not the
			// synthetic "{}" placeholder — benignInfraFinding's Type/Reason
			// deliberately name nothing "log"-shaped, so the
			// logs_mention_absent_from_record case actually proves the reject
			// fires against a real assembled record, not merely an empty one.
			userDoc := mustBuildUserDoc(t, benignInfraFinding(), c.ev)
			client := &scriptedClient{reply: c.reply}
			out := narrate(context.Background(), client, "", 1024, userDoc, c.ev)
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

// TestNarrateContract_HasLoginProfileFieldNameDoesNotGroundLogsFabrication is
// the exact regression proof for the mallcoppro-044 code-review finding: a
// naive substring scan of the whole marshaled userDoc always "finds" the term
// "log", because Go always emits BaselineEvidence.HasLoginProfile as the JSON
// KEY "has_login_profile" (no omitempty) and that KEY's own text contains
// "log" via "login" — regardless of its true/false VALUE and regardless of
// whether any finding/evidence VALUE ever mentions logs. That made the
// logs/audit-trail reject permanently dead in production. Here the finding
// (Type/Reason) and every Evidence value deliberately name nothing
// "log"/"audit trail"-shaped, so the ONLY "log"-shaped text anywhere in
// userDoc is the "has_login_profile" field NAME itself — proving the fix
// grounds the check against VALUES, not the raw marshaled string.
func TestNarrateContract_HasLoginProfileFieldNameDoesNotGroundLogsFabrication(t *testing.T) {
	f := finding.Finding{
		ID: "f-assume-role-1", Type: "assume_role", Severity: "high",
		Actor: "forge-proxy", Reason: "AssumeRole into mallcop-bedrock-relay",
		Timestamp: time.Now(),
	}
	ev := Evidence{
		Identity:   IdentityEvidence{Actor: "forge-proxy", Target: "mallcop-bedrock-relay"},
		Recurrence: RecurrenceEvidence{Occurrences: 1},
		// HasLoginProfile is the field whose JSON KEY name ("has_login_profile")
		// contains "log" — set true so the field's presence (and its boolean
		// VALUE, which is never text) is exercised either way.
		Baseline: BaselineEvidence{KnownActor: true, HasLoginProfile: true},
	}
	userDoc, err := buildUserMessage(f, ResolutionRef{Action: "escalate"}, ev)
	if err != nil {
		t.Fatalf("buildUserMessage: %v", err)
	}
	if !strings.Contains(strings.ToLower(userDoc), "log") {
		t.Fatalf("test fixture invalid: userDoc must contain the substring \"log\" via the has_login_profile field name for this to be a meaningful regression proof:\n%s", userDoc)
	}
	reply := replyJSON("suspicious", 0.7, "the absence of justifying logs for this assume-role call is concerning.")

	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, userDoc, ev)

	if out.Status != StatusAbsentInvalidOutput {
		t.Fatalf("Status = %q, want absent-invalid-output — the fabricated 'logs' claim must be rejected even though userDoc's has_login_profile FIELD NAME contains \"log\" (only VALUES should ground the check)", out.Status)
	}
	if out.Err == nil || !strings.Contains(out.Err.Error(), "absent from the record") {
		t.Errorf("Err = %v, want a fabrication-reject explanation", out.Err)
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

// TestNarrateContract_ConsoleLoginSubstringDoesNotGroundLogsFabrication is the
// exact regression for mallcoppro-044 review finding 1: the logs/audit-trail
// grounding must match "log"/"audit" as a letter-delimited TOKEN, not a raw
// substring. Here the assembled record's VALUES contain "ConsoleLogin" and
// "catalog" — both carry the coincidental substring "log" — but NOTHING that is
// genuinely a log/audit source. A raw `strings.Contains(value, "log")` grounds
// on "ConsoleLogin", concludes the record legitimately references logs, and so
// SILENTLY SKIPS the reject for a narrative that fabricates "the absence of
// justifying logs" — the exact way the guard died in production. The token
// grounding finds no real log/audit term, so the fabricated claim is rejected.
func TestNarrateContract_ConsoleLoginSubstringDoesNotGroundLogsFabrication(t *testing.T) {
	f := finding.Finding{
		ID: "f-console-login-1", Type: "unusual_console_login", Severity: "high",
		Actor:     "forge-proxy",
		Reason:    "ConsoleLogin from a new source; the catalog service was also queried",
		Timestamp: time.Now(),
	}
	ev := Evidence{
		// Values carry the coincidental "log" substring (ConsoleLogin / catalog),
		// never a real log/audit token. Single occurrence + baseline-unknown role
		// keeps this OFF the operational-infra calibration path, so the ONLY thing
		// that can move the verdict is the fabrication reject under test.
		Identity:   IdentityEvidence{Actor: "forge-proxy", Caller: "AWSConsoleLogin", Target: "catalog-service"},
		Recurrence: RecurrenceEvidence{Occurrences: 1},
		Baseline:   BaselineEvidence{KnownActor: true, KnownRole: false},
	}
	userDoc, err := buildUserMessage(f, ResolutionRef{Action: "escalate"}, ev)
	if err != nil {
		t.Fatalf("buildUserMessage: %v", err)
	}
	// Guard the regression is meaningful: userDoc MUST carry the raw substring
	// "log" (via ConsoleLogin/catalog) so a substring scan WOULD have grounded —
	// otherwise this proves nothing about the token fix.
	if !strings.Contains(strings.ToLower(userDoc), "log") {
		t.Fatalf("fixture invalid: userDoc must contain the coincidental substring \"log\" (ConsoleLogin/catalog) for this to be a meaningful regression proof:\n%s", userDoc)
	}
	reply := replyJSON("threat", 0.85,
		"forge-proxy activity is not consistent with prior benign activity; the absence of justifying logs is concerning. Revoke the key.")

	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, userDoc, ev)

	if out.Status != StatusAbsentInvalidOutput {
		t.Fatalf("Status = %q, want absent-invalid-output — a fabricated 'absence of logs' claim must be rejected even though the record's VALUES coincidentally contain \"log\" via \"ConsoleLogin\"/\"catalog\" (only a real log/audit TOKEN should ground the check)", out.Status)
	}
	if out.Err == nil || !strings.Contains(out.Err.Error(), "absent from the record") {
		t.Errorf("Err = %v, want a fabrication-reject explanation", out.Err)
	}
}

// TestNarrateContract_GenuineThreatOnKnownServiceEscapesCalibration is the exact
// regression for mallcoppro-044 review finding 2: evidenceNamesDeviation must
// recognize EVERY deviation kind the record can carry, so a genuine threat on a
// baseline-KNOWN service (the operational-infra shape) is not silently
// downgraded to suspicious@0.4 just because its deviation is a novel source IP
// or an off-hours use rather than a novel target. calibrateVerdict may cap only
// when the record names NO deviation at all. Both cases below are the
// operational-infra signature (known actor, 693 occurrences, ~1s cadence) with a
// single evidenced deviation and a CLEAN threat narrative (no fabricated
// logs/history/unknown-actor words), so the ONLY thing that could move the
// verdict is the calibration under test. The verdict must pass through as a
// full-confidence threat, unchanged.
func TestNarrateContract_GenuineThreatOnKnownServiceEscapesCalibration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(ev *Evidence)
		reply  string
	}{
		{
			name: "novel_source_ip",
			mutate: func(ev *Evidence) {
				// Known service, but its key is used from an IP absent from the
				// baseline profile — a classic credential-theft signal.
				ev.Identity.SourceIP = "203.0.113.7"
				ev.Baseline.KnownIP = false
			},
			reply: "forge-proxy's key was used from a source IP absent from its baseline profile, inconsistent with the recurring pattern — a credential-theft indicator. Escalate and revoke the key.",
		},
		{
			name: "off_hours",
			mutate: func(ev *Evidence) {
				// Known service with an established hour baseline, but this action
				// fell outside its known hours.
				ev.Baseline.HourBaselined = true
				ev.Baseline.KnownHour = false
			},
			reply: "forge-proxy assumed the role at an hour outside its established operating window; combined with the sensitivity of the grant this warrants escalation.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := benignInfraEvidence() // operational-infra shape, KnownRole=true
			c.mutate(&ev)
			if !isOperationalInfrastructureSignature(ev) {
				t.Fatalf("fixture invalid: case must be the operational-infra shape so the calibration path is actually exercised: %+v", ev.Baseline)
			}
			userDoc := mustBuildUserDoc(t, benignInfraFinding(), ev)
			client := &scriptedClient{reply: replyJSON("threat", 0.9, c.reply)}
			out := narrate(context.Background(), client, "investigate", 1024, userDoc, ev)

			if out.Status != StatusOK {
				t.Fatalf("Status = %q, want ok — a clean genuine-threat narrative must not be rejected (err=%v)", out.Status, out.Err)
			}
			if out.Verdict != VerdictThreat {
				t.Fatalf("Verdict = %q, want threat — an evidenced deviation (%s) on a known service must escape the operational-infra cap, not downgrade to suspicious", out.Verdict, c.name)
			}
			if out.Confidence != 0.9 {
				t.Errorf("Confidence = %v, want 0.9 unchanged — an evidenced deviation must not have confidence capped at %v", out.Confidence, operationalDowngradeConfidenceCap)
			}
			if len(out.ContractNotes) != 0 {
				t.Errorf("ContractNotes = %v, want none (calibration must not fire when the record names a deviation)", out.ContractNotes)
			}
		})
	}
}

// TestNarrateContract_NovelIPNeverSeenBeforePhrasingNotFabricated is the exact
// regression for the review's finding 1: reUnknownActor's UNANCHORED
// "never (been )?seen before" alternative false-rejected a legitimate
// novel-source-IP credential-theft narrative on a KNOWN actor. The narrative
// phrases the novel IP (not the actor) as "never been seen before for this
// actor" — a REAL threat-relevant deviation the escape hatch must preserve. A
// single occurrence keeps this off the operational-infra calibration path, so
// the ONLY thing that could reject it is the (now removed) unanchored
// reUnknownActor alternative. The verdict must pass through unchanged.
func TestNarrateContract_NovelIPNeverSeenBeforePhrasingNotFabricated(t *testing.T) {
	ev := Evidence{
		Identity:   IdentityEvidence{Actor: "forge-proxy", SourceIP: "203.0.113.7"},
		Recurrence: RecurrenceEvidence{Occurrences: 1},
		Baseline:   BaselineEvidence{KnownActor: true, KnownRole: true, KnownIP: false},
	}
	reply := replyJSON("threat", 0.9,
		"forge-proxy's key was used from a source IP that has never been seen before for this actor; a credential-theft indicator. Escalate and revoke the key.")

	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, "{}", ev)

	if out.Status != StatusOK {
		t.Fatalf("Status = %q, want ok — a novel-IP narrative phrased 'never seen before for this actor' must not be rejected as an 'unknown actor' fabrication (err=%v)", out.Status, out.Err)
	}
	if out.Verdict != VerdictThreat {
		t.Fatalf("Verdict = %q, want threat (a genuine novel-IP threat must survive)", out.Verdict)
	}
	if out.Confidence != 0.9 {
		t.Errorf("Confidence = %v, want 0.9 unchanged (single occurrence is not the operational-infra shape)", out.Confidence)
	}
}

// TestNarrateContract_FirstTimeOffHoursOnKnownServiceNotFabricated is the exact
// regression for the review's finding 2: reNoPriorHistory false-rejected a
// legitimate off-hours / novel-target genuine-threat narrative because
// Recurrence.Occurrences is keyed on (actor,type) — target-blind and hour-blind
// — so a high count does NOT contradict a novelty claim scoped to THIS hour or
// THIS role. Both cases are the operational-infra shape (known actor, 693
// occurrences, ~1s cadence) with a single evidenced deviation and a "first
// time"-style narrative describing that REAL deviation. The reject must be gated
// off by evidenceNamesDeviation, and the evidenced deviation must also escape
// the calibration cap, so the verdict passes through as a full-confidence
// threat, unchanged.
func TestNarrateContract_FirstTimeOffHoursOnKnownServiceNotFabricated(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(ev *Evidence)
		reply  string
	}{
		{
			name: "off_hours_first_time_at_this_hour",
			mutate: func(ev *Evidence) {
				ev.Baseline.HourBaselined = true
				ev.Baseline.KnownHour = false
			},
			reply: "forge-proxy assumed the role at an hour outside its established window; this is the first time it has operated at this hour, a strong off-hours deviation. Escalate.",
		},
		{
			name: "novel_target_first_time_assuming_this_role",
			mutate: func(ev *Evidence) {
				ev.Identity.Target = "prod-admin-role"
				ev.Baseline.KnownRole = false
			},
			reply: "forge-proxy assumed prod-admin-role for the first time; the role grants broad administrative access and was never in its baseline. Escalate and revoke.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := benignInfraEvidence()
			c.mutate(&ev)
			if !isOperationalInfrastructureSignature(ev) {
				t.Fatalf("fixture invalid: case must be the operational-infra shape so the reject/calibration path is exercised: %+v", ev.Baseline)
			}
			if ev.Recurrence.Occurrences <= 1 {
				t.Fatalf("fixture invalid: recurrence must exceed 1 so reNoPriorHistory would fire absent the deviation gate: %d", ev.Recurrence.Occurrences)
			}
			userDoc := mustBuildUserDoc(t, benignInfraFinding(), ev)
			client := &scriptedClient{reply: replyJSON("threat", 0.9, c.reply)}
			out := narrate(context.Background(), client, "investigate", 1024, userDoc, ev)

			if out.Status != StatusOK {
				t.Fatalf("Status = %q, want ok — a 'first time'-style narrative describing a REAL evidenced deviation must not be rejected as fabrication (err=%v)", out.Status, out.Err)
			}
			if out.Verdict != VerdictThreat {
				t.Fatalf("Verdict = %q, want threat — an evidenced deviation (%s) must survive both the fabrication reject and the calibration cap", out.Verdict, c.name)
			}
			if out.Confidence != 0.9 {
				t.Errorf("Confidence = %v, want 0.9 unchanged", out.Confidence)
			}
			if len(out.ContractNotes) != 0 {
				t.Errorf("ContractNotes = %v, want none (neither reject nor calibration must fire when the record names a deviation)", out.ContractNotes)
			}
		})
	}
}

// TestNarrateContract_GlobalNoHistoryClaimStillRejectedWithoutDeviation guards
// that the finding-2 fix only WIDENS the escape hatch and does not blind the
// reject: when the record names NO deviation (known actor, known role, no novel
// IP, no hour baseline), a "first time"/"no prior history" claim on a
// high-recurrence actor is still a global fabrication contradicted by the
// (actor,type) occurrence count, and must still be rejected.
func TestNarrateContract_GlobalNoHistoryClaimStillRejectedWithoutDeviation(t *testing.T) {
	ev := benignInfraEvidence() // KnownRole=true, no SourceIP, no hour baseline => no deviation
	if evidenceNamesDeviation(ev) {
		t.Fatalf("fixture invalid: benign-infra evidence must name NO deviation for this reject test: %+v", ev.Baseline)
	}
	reply := replyJSON("threat", 0.9,
		"This is the first time forge-proxy has assumed this role; no prior history supports it.")
	userDoc := mustBuildUserDoc(t, benignInfraFinding(), ev)
	client := &scriptedClient{reply: reply}
	out := narrate(context.Background(), client, "investigate", 1024, userDoc, ev)

	if out.Status != StatusAbsentInvalidOutput {
		t.Fatalf("Status = %q, want absent-invalid-output — a global no-history claim with no evidenced deviation must still be rejected as fabrication", out.Status)
	}
	if out.Err == nil || !strings.Contains(out.Err.Error(), "recurrence records") {
		t.Errorf("Err = %v, want a prior-history fabrication-reject explanation", out.Err)
	}
}
