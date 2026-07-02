// validate_decl_test.go — PROOF (e) for K6: a declarative-rule widen proposal
// rides the EXISTING validate-proposal pipeline. The self-extension loop authors
// THREE data artifacts — a new rule in detectors/rules.yaml, a new labeled exam
// scenario whose must_fire names the rule's family, AND a benign-twin scenario
// whose must_not_fire proves the rule stays silent on a look-alike — plus the
// paired corpus.pin regen. base→head is the real widen; the gate must pass with
// coverage +1, no regression, no undeclared new firings, and the mandatory
// benign-twin floor (now enforced on the decl lane too) satisfied.
//
// Ground-source (invariant 10): this runs the FULL gate over a real clone —
// real guard, real worktrees, real `go build`, real exam-detect subprocesses
// that build each tree's OWN binary. The head binary auto-loads
// detectors/rules.yaml from its resolved repo root (cmd/mallcop wiring), so the
// decl rule actually registers and fires on the new scenario. No stage mocked.
package selfgate

import (
	"fmt"
	"testing"
)

// declRulesHead is the head detectors/rules.yaml: the empty seed widened by one
// rule. A globally-unique keyword with an empty event-type gate guarantees the
// rule fires ONLY on the new scenario below (never on any of the ~58 existing
// corpus scenarios), so the monotonic no-new-firings contract holds.
const declRulesHead = `# rules corpus (K6 decl-rule widen proof)
rules:
  - name: k6-probe
    match:
      kind: keyword
      patterns: ["mallcopk6declprobetoken"]
    severity: high
    reason_template: "declarative probe matched {match} by {actor} ({rule})"
    dedup_key: event
`

// declScenario is the new labeled scenario proving decl:k6-probe fires. Its
// event payload carries the unique keyword; expected_detection.must_fire names
// the rule's family token, so exam-detect grades it PASS at head (and it is
// absent at base — the +1 coverage).
const declScenario = `id: DECL-01-k6-probe
failure_mode: KA
detector: decl:k6-probe
category: signature
difficulty: malicious-obvious
trap_description: "A declarative rule (loop-authored data) fires on a unique probe token."
finding:
  id: fnd_decl_k6
  detector: decl:k6-probe
  title: "Declarative probe match"
  severity: high
  event_ids:
  - evt_decl_1
  metadata:
    actor: attacker-k6
events:
- id: evt_decl_1
  timestamp: '2026-03-10T18:00:01Z'
  ingested_at: '2026-03-10T18:01:00Z'
  source: azure
  event_type: http_request
  actor: attacker-k6
  action: api_request
  target: acme-corp/api/v1/users
  severity: high
  metadata:
    note: 'mallcopk6declprobetoken'
  raw: {}
expected_detection:
  must_fire:
  - decl:k6-probe
  must_not_fire: []
`

// declBenignTwinScenario is the MUST-NOT-FIRE true negative for decl:k6-probe: a
// benign event of the SAME event type that LACKS the unique probe token, so the
// rule correctly stays silent and the row passes. It is the benign twin the K6
// lane now REQUIRES (mirroring the authored lane), proving decl:k6-probe is not a
// trigger-happy family that fires on a look-alike.
const declBenignTwinScenario = `id: DECL-02-k6-probe-benign
failure_mode: KA
detector: decl:k6-probe
category: signature
difficulty: benign-obvious
trap_description: "A benign event of the same shape but WITHOUT the probe token — the declarative rule must stay silent."
finding:
  id: fnd_decl_k6_benign
  detector: decl:k6-probe
  title: "Benign request, decl:k6-probe must stay silent"
  severity: low
  event_ids:
  - evt_decl_2
  metadata:
    actor: analyst-k6
events:
- id: evt_decl_2
  timestamp: '2026-03-10T18:05:01Z'
  ingested_at: '2026-03-10T18:06:00Z'
  source: azure
  event_type: http_request
  actor: analyst-k6
  action: api_request
  target: acme-corp/api/v1/reports
  severity: low
  metadata:
    note: 'routine analytics query, nothing to see here'
  raw: {}
expected_detection:
  must_fire: []
  must_not_fire:
  - decl:k6-probe
`

// applyDeclRuleProposal materializes, into clone's working tree, the shape of a
// decl-rule widen proposal: the new rule in detectors/rules.yaml, the must_fire
// scenario, optionally the benign twin, and the paired corpus.pin regen. The
// caller commits it.
func applyDeclRuleProposal(t *testing.T, clone string, withTwin bool) {
	t.Helper()
	writeRepoFile(t, clone, "detectors/rules.yaml", declRulesHead)
	writeRepoFile(t, clone, "exams/scenarios/signature/DECL-01-k6-probe.yaml", declScenario)
	if withTwin {
		writeRepoFile(t, clone, "exams/scenarios/signature/DECL-02-k6-probe-benign.yaml", declBenignTwinScenario)
	}
	count, sha := recomputeCorpusPin(t, clone)
	writeRepoFile(t, clone, "exams/scenarios/corpus.pin",
		fmt.Sprintf("# regen for the K6 decl-rule widen proof\ncount %d\nsha256 %s\n", count, sha))
}

// TestValidateProposal_AcceptsDeclRuleWidenProposal is PROOF (e): a decl-rule
// widen (new rule + must_fire scenario + benign twin + corpus.pin regen) passes
// the full free-tier gate with coverage +1, no undeclared new firings, and the
// mandatory benign-twin floor satisfied on the decl lane.
func TestValidateProposal_AcceptsDeclRuleWidenProposal(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)

	// The pristine committed HEAD is the base: it carries the EMPTY seed
	// detectors/rules.yaml, so base detection knows nothing of decl:k6-probe.
	base := headOf(t, clone)

	applyDeclRuleProposal(t, clone, true) // with benign twin
	head := commitAll(t, clone, "proposal: decl rule k6-probe + must_fire DECL-01 + benign twin DECL-02")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}

	if !res.Passed {
		t.Fatalf("the decl-rule widen must pass the free tier, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	for _, stage := range res.Stages {
		if !stage.Passed || len(stage.Findings) != 0 {
			t.Fatalf("stage %q not clean: %+v", stage.Name, stage)
		}
	}
	if res.CoveragePlus != 1 {
		t.Fatalf("CoveragePlus = %d, want 1 (DECL-01 newly labeled and passing on the decl rule)", res.CoveragePlus)
	}
	if len(res.NewFirings) != 0 {
		t.Fatalf("NewFirings = %v, want none (the decl rule fires only on its own new scenario)", res.NewFirings)
	}
}

// TestValidateProposal_RejectsDeclRuleMissingBenignTwin is the K6 REJECT proof
// that closes the asymmetry: the SAME decl rule + must_fire scenario, but WITHOUT
// the benign twin, passes guard + structural (the static layers cannot see the
// gap) and dies at exam-detect with the mandatory-benign-twin finding — exactly
// as an authored detector missing its twin does. Before this fix the decl lane
// bypassed the floor entirely (addedAuthoredFamilies scanned only the authored
// tree), so a loop-authored rule proven only on its happy path would have merged.
func TestValidateProposal_RejectsDeclRuleMissingBenignTwin(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)
	base := headOf(t, clone)

	applyDeclRuleProposal(t, clone, false) // NO benign twin
	head := commitAll(t, clone, "proposal: decl rule k6-probe with NO benign twin")

	res, err := ValidateProposal(clone, base, head, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
	if res.Passed {
		t.Fatalf("a decl rule missing its benign twin must be REJECTED, got %+v", res)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	if !res.Stages[0].Passed || !res.Stages[1].Passed || res.Stages[2].Passed {
		t.Fatalf("want guard+structural PASS and exam-detect FAIL, got %+v", res.Stages)
	}
	requireRejected(t, res.Stages[2].Findings, RuleExamMissingBenignTwin, StageExamDetect)
	// The must_fire IS present (DECL-01), so there must be NO missing-must-fire finding.
	for _, f := range res.Stages[2].Findings {
		if f.Rule == RuleExamMissingMustFire {
			t.Fatalf("unexpected missing-must-fire finding — DECL-01 provides the must_fire: %+v", f)
		}
	}
	// The finding must name the decl family, proving it is the decl lane being floored.
	requireDetailContains(t, res.Stages[2].Findings, RuleExamMissingBenignTwin, "decl:k6-probe")
	// The coverage gain (DECL-01) is real, so the rejection is SPECIFICALLY the
	// missing twin, not a coverage failure.
	if res.CoveragePlus != 1 {
		t.Fatalf("CoveragePlus = %d, want 1 (DECL-01 still a real gain; the rejection is the missing twin)", res.CoveragePlus)
	}
}
