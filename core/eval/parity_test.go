// parity_test.go — THE EVAL-PARITY PROOF (mallcoppro prod-toolrunner).
//
// HARD REQUIREMENT: the production core/toolrun.Runner must emit IDENTICAL
// observables to the eval scenarioToolRunner across the representative corpus, so
// the validated 83.9% / 2-missed-attacks number transfers to production WITHOUT
// re-running the model (this is a $0 test: no inference, no network).
//
// LOCATION DEVIATION (noted): the design specified core/toolrun/parity_test.go, but
// the eval seam this test drives BOTH runners from — seedScenarioStore,
// baselineFromScenario, newScenarioToolRunner, scenarioActor/Source/Family,
// findingFromScenario — is UNEXPORTED in package eval. Placing the test in package
// eval (importing core/toolrun, which does NOT import eval, so no cycle) is the
// minimal way to reach that seam without exporting harness internals into the
// shipped API. The mechanism is otherwise exactly the design's: same seed, same
// store, same baseline, both runners, assert the six gate-relevant fields equal
// (plus the boxed transcript text for context fidelity).
package eval

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/toolrun"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// parityScenarios are the bakeoff discriminators named in the design — the
// scenarios whose observable forces decide the cascade and therefore the 83.9%
// number. If prod == eval on every one of these, the cascade decision (and the
// bakeoff) is identical without a model call.
var parityScenarios = []string{
	"behavioral/VA-01-deploy-burst.yaml",
	"behavioral/VA-02-month-end-batch.yaml",
	"behavioral/VA-03-data-exfil.yaml",
	"behavioral/VA-05-quarterly-report-burst.yaml",
	"behavioral/UT-01-competing-signals.yaml",
	"behavioral/UT-07-deploy-window-ops.yaml",
	"behavioral/URA-02-lateral-movement.yaml",
	"behavioral/URA-03-admin-new-resource.yaml",
	"behavioral/URA-04-sibling-resource-rotation.yaml",
	"cross_cutting/CO-02-benign-events-first.yaml",
	"cross_cutting/IT-02-baseline-contradicts-reasoning.yaml",
	"cross_cutting/IT-03-connector-tool-suspicious-but-resolved.yaml",
	"cross_cutting/ND-01-authorized-data-export.yaml",
	"cross_cutting/CC-01-quarterly-report-multi-signal.yaml",
	"cross_cutting/CC-02-deploy-window-multi-signal.yaml",
	"identity/ID-01-new-actor-benign-onboarding.yaml",
}

// prodFindingFromScenario builds the production finding.Finding shape the prod
// runner derives its filters from, carrying the SAME inputs eval derives from the
// scenario (actor / source / family / event_type) — so any match proves the
// derivation contract holds, not just the shared predicate. event_type rides in the
// finding Evidence (the production detector's metadata channel) so the prod runner's
// findingObservableMeta surfaces it exactly as eval's scenarioObservableMeta does.
func prodFindingFromScenario(t *testing.T, s *exam.Scenario) finding.Finding {
	t.Helper()
	// Start from the eval-derived finding so ID/Type/Source/Actor match the eval
	// runner's own derivation, then enrich Evidence with the event_type the eval
	// runner pulls from scenarioObservableMeta.
	f := findingFromScenario(s)
	f.Actor = scenarioActor(s)
	f.Type = scenarioFamily(s)
	if f.Source == "" {
		f.Source = "detector:" + scenarioSource(s)
	}
	meta := scenarioObservableMeta(s)
	evid := map[string]any{
		"source": scenarioSource(s),
	}
	if et := meta["event_type"]; et != "" {
		evid["event_type"] = et
	}
	raw, err := json.Marshal(evid)
	if err != nil {
		t.Fatalf("marshal finding evidence: %v", err)
	}
	f.Evidence = raw
	return f
}

// TestProdToolRunnerParity_ObservablesMatchEval is the load-bearing parity proof:
// for every discriminator scenario, at BOTH tiers, the prod Runner's six
// gate-relevant ToolEvidence fields equal the eval scenarioToolRunner's. These six
// are exactly the cascade's structural force-escalate inputs (ZeroHistory*,
// RoleGrant*, BulkExport*, ToolEmpty, ToolCalls, DistinctTools); matching them per
// scenario means the cascade decision — and the bakeoff number — is identical.
func TestProdToolRunnerParity_ObservablesMatchEval(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")

	for _, rel := range parityScenarios {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, rel)

			// EVAL runner: per-scenario, frozen snapshot over a seeded git store.
			evalTmp := t.TempDir()
			evalRunner, err := newScenarioToolRunner(evalTmp, root, ls.Scenario)
			if err != nil {
				t.Fatalf("eval runner seed: %v", err)
			}

			// PROD runner: open the SAME committed store the eval runner seeded, with
			// the SAME reconstructed baseline + the SAME pinned RepoRoot. Driving both
			// off one seed isolates the comparison to the runner derivation+logic.
			st, err := store.Open(evalTmp)
			if err != nil {
				t.Fatalf("open seeded store for prod runner: %v", err)
			}
			prodRunner := &toolrun.Runner{
				Store:    st,
				Baseline: baselineFromScenario(ls.Scenario),
				RepoRoot: root,
			}

			evalFinding := findingFromScenario(ls.Scenario)
			prodFinding := prodFindingFromScenario(t, ls.Scenario)

			for _, tier := range []string{"triage", "investigate"} {
				ev, err := evalRunner.RunTools(context.Background(), tier, evalFinding)
				if err != nil {
					t.Fatalf("%s eval RunTools: %v", tier, err)
				}
				pv, err := prodRunner.RunTools(context.Background(), tier, prodFinding)
				if err != nil {
					t.Fatalf("%s prod RunTools: %v", tier, err)
				}

				// The SIX gate-relevant observables MUST match — these drive the cascade.
				if ev.ZeroHistoryAccess != pv.ZeroHistoryAccess || ev.ZeroHistoryDetail != pv.ZeroHistoryDetail {
					t.Errorf("%s/%s ZeroHistory divergence: eval=(%t,%q) prod=(%t,%q)",
						rel, tier, ev.ZeroHistoryAccess, ev.ZeroHistoryDetail, pv.ZeroHistoryAccess, pv.ZeroHistoryDetail)
				}
				if ev.RoleGrantByActor != pv.RoleGrantByActor || ev.RoleGrantDetail != pv.RoleGrantDetail {
					t.Errorf("%s/%s RoleGrant divergence: eval=(%t,%q) prod=(%t,%q)",
						rel, tier, ev.RoleGrantByActor, ev.RoleGrantDetail, pv.RoleGrantByActor, pv.RoleGrantDetail)
				}
				if ev.BulkExportNoJustification != pv.BulkExportNoJustification || ev.BulkExportDetail != pv.BulkExportDetail {
					t.Errorf("%s/%s BulkExport divergence: eval=(%t,%q) prod=(%t,%q)",
						rel, tier, ev.BulkExportNoJustification, ev.BulkExportDetail, pv.BulkExportNoJustification, pv.BulkExportDetail)
				}
				if ev.ToolEmpty != pv.ToolEmpty {
					t.Errorf("%s/%s ToolEmpty divergence: eval=%t prod=%t", rel, tier, ev.ToolEmpty, pv.ToolEmpty)
				}
				if ev.ToolCalls != pv.ToolCalls {
					t.Errorf("%s/%s ToolCalls divergence: eval=%d prod=%d", rel, tier, ev.ToolCalls, pv.ToolCalls)
				}
				if ev.DistinctTools != pv.DistinctTools {
					t.Errorf("%s/%s DistinctTools divergence: eval=%d prod=%d", rel, tier, ev.DistinctTools, pv.DistinctTools)
				}

				// STRONGER (context fidelity): the boxed transcript the model sees must be
				// byte-identical too, so the §3.8 matched_rules fold + meta union match and
				// the bakeoff cannot drift on model CONTEXT.
				if ev.EventsText != pv.EventsText {
					t.Errorf("%s/%s EventsText divergence:\n--- eval ---\n%s\n--- prod ---\n%s", rel, tier, ev.EventsText, pv.EventsText)
				}
				if ev.BaselineText != pv.BaselineText {
					t.Errorf("%s/%s BaselineText divergence:\n--- eval ---\n%s\n--- prod ---\n%s", rel, tier, ev.BaselineText, pv.BaselineText)
				}
				if ev.FindingsText != pv.FindingsText {
					t.Errorf("%s/%s FindingsText divergence:\n--- eval ---\n%s\n--- prod ---\n%s", rel, tier, ev.FindingsText, pv.FindingsText)
				}
			}
		})
	}
}
