// validate_decl_test.go — PROOF (e) for K6: a declarative-rule widen proposal
// rides the EXISTING validate-proposal pipeline. The self-extension loop authors
// TWO data artifacts — a new rule in detectors/rules.yaml and a new labeled exam
// scenario whose must_fire names the rule's family — plus the paired corpus.pin
// regen. base→head is the real widen; the gate must pass with coverage +1, no
// regression, and no undeclared new firings.
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

// TestValidateProposal_AcceptsDeclRuleWidenProposal is PROOF (e): a decl-rule
// widen (new rule + new labeled scenario + corpus.pin regen) passes the full
// free-tier gate with coverage +1 and no undeclared new firings.
func TestValidateProposal_AcceptsDeclRuleWidenProposal(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)

	// The pristine committed HEAD is the base: it carries the EMPTY seed
	// detectors/rules.yaml, so base detection knows nothing of decl:k6-probe.
	base := headOf(t, clone)

	// The proposal, authored as DATA in the clone working tree.
	writeRepoFile(t, clone, "detectors/rules.yaml", declRulesHead)
	writeRepoFile(t, clone, "exams/scenarios/signature/DECL-01-k6-probe.yaml", declScenario)
	count, sha := recomputeCorpusPin(t, clone)
	writeRepoFile(t, clone, "exams/scenarios/corpus.pin",
		fmt.Sprintf("# regen for the K6 decl-rule widen proof\ncount %d\nsha256 %s\n", count, sha))
	head := commitAll(t, clone, "proposal: decl rule k6-probe + labeled scenario DECL-01")

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
