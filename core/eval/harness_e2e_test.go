// harness_e2e_test.go — the $0 CANNED VERIFICATION that the e2e harness drives the
// REAL pipeline correctly BEFORE spending a cent on live inference.
//
// It runs ModeE2E (RunScenarioE2E) against a cannedbackend over a small,
// hand-picked scenario subset and asserts the harness loads → connects → DETECTS
// (the real core/detect fleet) → resolves → reads the store back → grades, AND
// that the detect-fidelity accounting is honest:
//
//   - the cannedbackend recorded ≥1 call (the model was actually reached THROUGH
//     pipeline.Run on a reproduced finding — not bypassed);
//   - the per-scenario store's KindResolutions stream is non-empty (durably
//     written) — proven by a non-empty terminal action + ModelCalls > 0;
//   - the DetectFidelity block classifies each scenario correctly — a known
//     REPRODUCED scenario lands REPRODUCED, and a known ZERO-finding scenario
//     (VA-04: the volume magnitude lives only in finding metadata, so the
//     representative event sample cannot fire volume-anomaly) lands DETECT-MISS,
//     proving the fidelity accounting is honest;
//   - Grade returns a deterministic pass/fail matching the canned verdict (the
//     action-string-mismatch trap: ≥1 Pass proves resolve/escalate → resolved/
//     escalated mapping is wired; without it EVERY scenario fails at 0%).
//
// $0: no real model. Runs in CI. The package suite runs with -race, proving the
// temp-store-per-scenario isolation holds.
package eval

import (
	"context"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
)

// e2eEscalateScript is a content-aware canned script that drives every tier to
// ESCALATE (triage escalate → investigate escalate → escalate-formatter alert, and
// any fan-out deep tier escalates). It is deterministic under the deep-panel's 3
// concurrent calls because it routes on the request's tier marker, not a call index
// (the same residual-flake fix goldenScript documents).
func e2eEscalateScript(body []byte) string {
	tier, hyp := routeFromBody(body)
	switch tier {
	case tierTriage:
		return `{"action":"escalate","confidence":3,"positive_evidence":false,"strong_evidence":false,"insufficient_data":false,"reason":"triage: escalating for review."}`
	case tierInvestigate:
		return `{"action":"escalate","confidence":4,"positive_evidence":false,"strong_evidence":true,"insufficient_data":false,"reason":"investigate: confirmed; escalating."}`
	case tierDeep:
		if hyp == hypMalicious {
			return `{"action":"escalate","confidence":5,"positive_evidence":false,"strong_evidence":true,"insufficient_data":false,"reason":"deep(malicious): decisive; escalating."}`
		}
		return `{"action":"escalate","confidence":2,"positive_evidence":false,"strong_evidence":false,"insufficient_data":false,"reason":"deep: cannot confirm benign; escalating."}`
	case tierEscalate:
		return "SECURITY ALERT: suspicious activity requires human review."
	default:
		return "SECURITY ALERT: suspicious activity requires human review."
	}
}

// pickScenario returns the loaded scenario whose ID has the given prefix, failing
// the test if absent (a corpus drift the canned verification must surface).
func pickScenario(t *testing.T, corpus Corpus, idPrefix string) LoadedScenario {
	t.Helper()
	for _, ls := range corpus.Scenarios {
		if strings.HasPrefix(ls.Scenario.ID, idPrefix) {
			return ls
		}
	}
	t.Fatalf("canned verification: scenario with id prefix %q not in corpus", idPrefix)
	return LoadedScenario{}
}

// TestE2E_CannedVerification proves the e2e harness drives the real pipeline +
// grades + reports detect-fidelity, at $0.
func TestE2E_CannedVerification(t *testing.T) {
	root := repoRootForTest(t)
	SetRepoRootForTest(root)
	agent.SetRepoRootForTest(root)
	t.Cleanup(func() {
		SetRepoRootForTest("")
		agent.SetRepoRootForTest("")
	})

	corpus, err := Load(root)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	// Hand-pick a subset with KNOWN detect-fidelity outcomes (verified by
	// TestE2E_DetectReproductionProbe / the detect map):
	//   ID-03 — detect emits new-actor/ext-user-7f3a, the scenario's expected
	//           (new-actor, ext-user-7f3a) → REPRODUCED (expected escalated).
	//   VA-04 — the volume spike's magnitude lives only in the finding metadata
	//           (volume_ratio); the corpus emits a representative handful of
	//           api_call events whose RAW count never clears the 3× baseline, so
	//           volume-anomaly cannot fire from events alone → DETECT-MISS
	//           (expected escalated → an end-to-end FAIL). A durable corpus-data
	//           limit, not a detector defect — the canonical DETECT-MISS anchor.
	const wantReproduced = "ID-03-new-actor-suspicious-unknown"
	const wantDetectMiss = "VA-04-api-enumeration"
	subset := []LoadedScenario{
		pickScenario(t, corpus, wantReproduced),
		pickScenario(t, corpus, wantDetectMiss),
	}

	// Canned backend: escalate verdict on every tier. Reached through pipeline.Run
	// on the reproduced finding (ID-03). A DirectClient aimed at it is exactly what
	// RealClientFromEnv builds, but pointed at the fake — $0.
	be := &cannedbackend.CannedBackend{CannedContentFunc: e2eEscalateScript}
	if err := be.Start(); err != nil {
		t.Fatalf("start canned backend: %v", err)
	}
	defer be.Stop()
	client := &inference.DirectClient{BaseURL: be.URL(), Key: "test-key", Model: "e2e-canned"}

	ctx := context.Background()
	opts := agent.CascadeOptions{ConsensusRuns: agent.DefaultConsensusRuns}

	rows := make([]DetectFidelityRow, 0, len(subset))
	resolutionsSeen := 0
	reproducedPassed := false
	for _, ls := range subset {
		out, err := RunScenarioE2E(ctx, client, ls, opts, root)
		if err != nil {
			t.Fatalf("RunScenarioE2E(%s): %v", ls.Scenario.ID, err)
		}
		rows = append(rows, out.Fidelity)

		switch ls.Scenario.ID {
		case wantReproduced:
			if out.Fidelity.Outcome != OutcomeReproduced {
				t.Errorf("%s: want REPRODUCED, got %s (emitted=%v)", ls.Scenario.ID, out.Fidelity.Outcome, out.Fidelity.EmittedDetectors)
			}
			if out.Result.ModelCalls == 0 {
				t.Errorf("%s: reproduced finding made 0 model calls — model bypassed", ls.Scenario.ID)
			}
			if !strings.EqualFold(out.Result.TerminalAction, "escalated") {
				t.Errorf("%s: terminal action %q != escalated (action-string mapping broken?)", ls.Scenario.ID, out.Result.TerminalAction)
			}
			if out.Result.Pass {
				reproducedPassed = true
			}
		case wantDetectMiss:
			if out.Fidelity.Outcome != OutcomeDetectMiss {
				t.Errorf("%s: want DETECT-MISS, got %s (emitted=%v)", ls.Scenario.ID, out.Fidelity.Outcome, out.Fidelity.EmittedDetectors)
			}
			if out.Fidelity.EndToEndPass {
				t.Errorf("%s: DETECT-MISS on expected-escalate must be an end-to-end FAIL", ls.Scenario.ID)
			}
		}

		if out.Fidelity.Outcome != OutcomeDetectMiss && out.Result.ModelCalls > 0 && out.Result.TerminalAction != "" {
			resolutionsSeen++
		}
	}

	if be.CallCount() == 0 {
		t.Fatal("canned backend recorded 0 calls — pipeline.Run never reached the model (model bypassed)")
	}
	if resolutionsSeen == 0 {
		t.Fatal("no scenario produced a durable resolution — store read-back is empty")
	}
	if !reproducedPassed {
		t.Error("reproduced escalate scenario did not PASS — the resolve/escalate→resolved/escalated mapping may be missing (would show as a 0% accuracy collapse)")
	}

	df := aggregateDetectFidelity(rows)
	if df.Reproduced != 1 || df.DetectMiss != 1 || df.Mismatch != 0 {
		t.Errorf("fidelity aggregate: reproduced=%d detect_miss=%d mismatch=%d (want 1/1/0)", df.Reproduced, df.DetectMiss, df.Mismatch)
	}
	if df.ReproductionRate <= 0 {
		t.Errorf("reproduction rate %v <= 0 — fidelity accounting broken", df.ReproductionRate)
	}
}

// TestE2E_DetectReproductionProbe documents the detect-fidelity landscape over the
// FULL corpus: it asserts the known REPRODUCED + DETECT-MISS anchors so a detector
// change that silently alters reproduction is caught. Detect-only (no model), so $0
// and fast.
func TestE2E_DetectReproductionProbe(t *testing.T) {
	root := repoRootForTest(t)
	SetRepoRootForTest(root)
	t.Cleanup(func() { SetRepoRootForTest("") })

	corpus, err := Load(root)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	reproduced, detectMiss := 0, 0
	for _, ls := range corpus.Scenarios {
		s := ls.Scenario
		emitted := detect.Detect(scenarioEvents(s), baselineFromScenario(s))
		row := classifyDetectFidelity(s, emitted, nil)
		switch row.Outcome {
		case OutcomeReproduced:
			reproduced++
		case OutcomeDetectMiss:
			detectMiss++
		}
		if strings.HasPrefix(s.ID, "ID-03-") && row.Outcome != OutcomeReproduced {
			t.Errorf("ID-03 expected REPRODUCED, got %s (emitted=%v)", row.Outcome, row.EmittedDetectors)
		}
		// AC-01 now REPRODUCES (new-external-access detector). VA-04 is the durable
		// DETECT-MISS anchor: the volume magnitude lives only in finding metadata,
		// so volume-anomaly cannot fire from the representative event sample.
		if strings.HasPrefix(s.ID, "AC-01-") && row.Outcome != OutcomeReproduced {
			t.Errorf("AC-01 expected REPRODUCED, got %s (emitted=%v)", row.Outcome, row.EmittedDetectors)
		}
		if strings.HasPrefix(s.ID, "VA-04-") && row.Outcome != OutcomeDetectMiss {
			t.Errorf("VA-04 expected DETECT-MISS, got %s (emitted=%v)", row.Outcome, row.EmittedDetectors)
		}
	}
	if reproduced == 0 {
		t.Fatal("NO scenario reproduces under core/detect — the e2e grade path is never exercised")
	}
	if detectMiss == 0 {
		t.Fatal("NO scenario is a DETECT-MISS — the detect-fidelity gap the e2e mode exists to surface is absent (suspicious)")
	}
	t.Logf("detect-fidelity over %d scenarios: reproduced=%d detect_miss=%d", corpus.Count, reproduced, detectMiss)
}
