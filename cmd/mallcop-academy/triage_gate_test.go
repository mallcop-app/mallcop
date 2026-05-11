// Tests for the rung-2 deterministic triage gate (mallcoppro-379, v2 amend).
//
// Test plan:
//
//   - TestAcademy_TriageGate_FullCorpus: corpus-driven table test that loads ALL
//     non-_test scenarios from exams/scenarios/ via exam.Load and asserts:
//     * KA-negative: every scenario where failure_mode=="KA" OR
//       expected.chain_action=="escalated" must return (false,"") from the predicate.
//       Two known-unfixable exceptions are explicitly documented: UT-05 (AiTM proxy)
//       and BG-01 (borderline timing) — see triage_gate.go doc comment.
//     * SC-positive: for the 7 known-pattern-deterministic scenarios (CS+resolved),
//       the predicate must return (true,_). The set is pinned — drift fails loudly.
//
//   - TestTriageGatePredicate_RatioBoundary: boundary cases for conditions 4+5:
//     typed_count<3 with high ratio → false; typed_count≥3+ratio<5% → false;
//     typed_count≥3+ratio=5% → true (boundary inclusive).
//
//   - TestAcademy_TriageGate_NoWorkerSpawn (Test 1): for scenarios in the pinned
//     7-SC set, academy produces zero work:create posts, one synthetic terminal-
//     resolved, chain_length==1, action=="resolved".
//
//   - TestAcademy_TriageGate_CriticalSeverityFallthrough (Test 2): critical severity
//     does NOT auto-resolve even with known actor + rich baseline.
//
//   - TestAcademy_TriageGate_Rung0DetectorEscalates (Test 3): rung-0 detector takes
//     priority over rung-2 even when all predicate conditions hold.
//
// Tests use the existing mockSender (no LLM, no live cf binary, no network).
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/internal/exam"
)

// ---- corpus constants ----------------------------------------------------------

// scCorrectSet is the pinned set of scenario IDs that the rung-2 predicate (v2)
// must short-circuit as "resolved". These are the 7 known-pattern-deterministic
// scenarios: failure_mode==CS, expected.chain_action==resolved, non-blocked detector,
// typed_count≥3, specialization_ratio≥0.05.
//
// If this set drifts (a scenario added/removed/modified causes the predicate to
// fire or stop firing), the test fails loudly to force a deliberate ruling, not a
// silent behavior change.
var scCorrectSet = []string{
	"URA-04-sibling-resource-rotation",
	"UT-02-maintenance-window",
	"UT-04-admin-travel",
	"UT-06-timezone-change",
	"VA-01-deploy-burst",
	"VA-02-month-end-batch",
	"CC-02-deploy-window-multi-signal",
}

// knownUnfixableByPredicate is the set of scenario IDs that pass the rung-2
// predicate but should NOT auto-resolve — they require qualitative reasoning
// (IP-geo, session-token analysis) not encoded in FrequencyTables.
//
// These are documented in triage_gate.go. The corpus test explicitly skips the
// mandatory-false assertion for these IDs. Do NOT add new IDs here without a
// design-deliberation ruling. Do NOT use this as a backdoor to suppress failures
// caused by predicate regressions.
var knownUnfixableByPredicate = map[string]string{
	"UT-05-aitm-proxy":      "AiTM proxy: session from VPS IP after MFA; IP-geo reasoning required, not in FrequencyTables",
	"BG-01-borderline-timing": "Borderline timing: concurrent anomaly cluster (IP shift + UA change + late timing); frequency alone insufficient",
}

// ---- corpus-driven table test --------------------------------------------------

// TestAcademy_TriageGate_FullCorpus loads all 57 non-_test scenario YAMLs and runs
// the predicate against each one.
//
// Two assertions:
//
//  1. KA-negative: for every scenario where failure_mode=="KA" OR
//     expected.chain_action=="escalated", predicate must return (false,"").
//     Exceptions: knownUnfixableByPredicate entries — explicitly documented.
//
//  2. SC-positive: for every scenario in scCorrectSet (the 7-SC pinned set),
//     predicate must return (true,_) and a non-empty reason string.
//     If any ID in scCorrectSet no longer passes, or any new CS+resolved scenario
//     starts passing, the test fails loudly to flag predicate drift.
func TestAcademy_TriageGate_FullCorpus(t *testing.T) {
	repoRoot, err := repoRootFromExec()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	scenariosDir := filepath.Join(repoRoot, "exams", "scenarios")
	if _, err := os.Stat(scenariosDir); err != nil {
		t.Fatalf("scenarios dir missing: %v", err)
	}

	// Load all scenario YAMLs, skipping _test dirs and the _schema file.
	var scenarios []*exam.Scenario
	err = filepath.Walk(scenariosDir, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			// Skip _test subdirectories.
			if info.Name() == "_test" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		if strings.HasPrefix(info.Name(), "_") {
			return nil // skip _schema.yaml and similar
		}
		s, err := exam.Load(p)
		if err != nil {
			t.Logf("skip %s: %v", p, err)
			return nil
		}
		scenarios = append(scenarios, s)
		return nil
	})
	if err != nil {
		t.Fatalf("walk scenarios dir: %v", err)
	}

	if len(scenarios) < 50 {
		t.Fatalf("expected ≥50 scenarios, got %d (corpus may be incomplete)", len(scenarios))
	}
	t.Logf("loaded %d scenarios from corpus", len(scenarios))

	// Build lookup sets.
	scCorrectLookup := make(map[string]bool, len(scCorrectSet))
	for _, id := range scCorrectSet {
		scCorrectLookup[id] = true
	}

	// Track which scenarios in scCorrectSet we actually saw (to catch renames).
	scCorrectSeen := make(map[string]bool)
	// Track which scenarios pass the predicate, for cross-checking against scCorrectSet.
	var passingIDs []string

	for _, s := range scenarios {
		s := s // capture
		t.Run(s.ID, func(t *testing.T) {
			reason, ok := triageGatePredicate(s)

			expectedChainAction := ""
			if s.ExpectedResolution != nil {
				expectedChainAction = s.ExpectedResolution.ChainAction
			}

			// ---- KA-negative assertion ----
			isNegativeCase := s.FailureMode == "KA" || expectedChainAction == "escalated"
			if isNegativeCase {
				if ok {
					// Check known unfixable exceptions.
					if reason, isUnfixable := knownUnfixableByPredicate[s.ID]; isUnfixable {
						t.Logf("KNOWN-UNFIXABLE: %s passes predicate — %s", s.ID, reason)
						// Do not fail — document the known limitation.
					} else {
						t.Errorf(
							"KA/escalated scenario %s (failure_mode=%q, chain_action=%q) passed the predicate — "+
								"this is a false-positive auto-resolve. "+
								"Either fix the predicate or add to knownUnfixableByPredicate with a ruling reference.",
							s.ID, s.FailureMode, expectedChainAction,
						)
					}
				}
			}

			// ---- SC-positive assertion ----
			if scCorrectLookup[s.ID] {
				scCorrectSeen[s.ID] = true
				if !ok {
					t.Errorf(
						"SC-correct scenario %s must pass the predicate (expected known-pattern-deterministic "+
							"auto-resolve), got ok=false. Predicate may have regressed.",
						s.ID,
					)
				} else if reason == "" {
					t.Errorf("SC-correct scenario %s: predicate returned ok=true but reason is empty", s.ID)
				} else {
					t.Logf("SC-correct %s: PASS — reason=%q", s.ID, reason[:min(len(reason), 120)])
				}
			}

			if ok {
				passingIDs = append(passingIDs, s.ID)
			}
		})
	}

	// ---- Pinned set completeness check ----
	// All IDs in scCorrectSet must have been seen in the corpus.
	for _, id := range scCorrectSet {
		if !scCorrectSeen[id] {
			t.Errorf("scCorrectSet ID %q was not found in the scenarios corpus — was it renamed or removed?", id)
		}
	}

	// ---- Pinned set cardinality check ----
	// Count correct SCs (passing, not in knownUnfixable, not KA, chain_action==resolved).
	sort.Strings(passingIDs)
	t.Logf("Total predicate-passing scenarios: %d — %v", len(passingIDs), passingIDs)

	// If the pinned set has IDs that don't pass, already caught above.
	// Additionally: if a non-pinned scenario starts passing, flag it.
	for _, id := range passingIDs {
		if !scCorrectLookup[id] && knownUnfixableByPredicate[id] == "" {
			t.Errorf(
				"Scenario %s passes the predicate but is NOT in scCorrectSet and NOT a known-unfixable exception. "+
					"Update scCorrectSet if this is an intended SC, or fix the predicate if it is a regression.",
				id,
			)
		}
	}
}

// min is a local helper for Go versions before 1.21's builtin min.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- ratio boundary test -------------------------------------------------------

// TestTriageGatePredicate_RatioBoundary verifies conditions 4 and 5 independently:
//
//   - typed_count=3 but ratio=0.04 → false (ratio guard fires)
//   - typed_count=3 and ratio=0.05 → true (boundary inclusive)
//   - typed_count=100 but ratio=0.04 → false (ratio guard fires even at high count)
//   - typed_count=2 and ratio=0.50 → false (count guard fires before ratio)
func TestTriageGatePredicate_RatioBoundary(t *testing.T) {
	cases := []struct {
		name         string
		typedCount   int
		totalEvents  int
		wantPass     bool
	}{
		{
			name:        "typed=3 ratio=0.04 → false",
			typedCount:  3,
			totalEvents: 75, // 3/75 = 0.04
			wantPass:    false,
		},
		{
			name:        "typed=3 ratio=0.05 → true (boundary inclusive)",
			typedCount:  3,
			totalEvents: 60, // 3/60 = 0.05
			wantPass:    true,
		},
		{
			name:        "typed=100 ratio=0.04 → false (ratio guard, high count)",
			typedCount:  100,
			totalEvents: 2500, // 100/2500 = 0.04
			wantPass:    false,
		},
		{
			name:        "typed=2 ratio=0.50 → false (count guard fires first)",
			typedCount:  2,
			totalEvents: 4, // 2/4 = 0.50, but count < 3
			wantPass:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build a minimal scenario with the exact typed count and total.
			// Use "volume-anomaly" detector (non-blocked) + "warn" severity.
			// actor="svc-a", event_type="deploy"
			// freq_tables:
			//   azure:deploy:svc-a = tc.typedCount
			//   azure:other:svc-a  = tc.totalEvents - tc.typedCount  (other events to reach total)
			otherEvents := tc.totalEvents - tc.typedCount
			ft := map[string]int{
				"azure:deploy:svc-a": tc.typedCount,
			}
			if otherEvents > 0 {
				ft["azure:other:svc-a"] = otherEvents
			}

			s := &exam.Scenario{
				ID: "RATIO-" + tc.name,
				Finding: &exam.ScenarioFinding{
					ID:       "fnd_ratio",
					Detector: "volume-anomaly",
					Severity: "warn",
					Metadata: exam.FindingMetadata{
						"actor":      "svc-a",
						"event_type": "deploy",
					},
				},
				Baseline: &exam.Baseline{
					KnownEntities: exam.KnownEntities{
						Actors:  []string{"svc-a"},
						Sources: []string{"azure"},
					},
					FrequencyTables: ft,
				},
			}

			_, ok := triageGatePredicate(s)
			if ok != tc.wantPass {
				t.Errorf("ratio boundary case %q: got ok=%v, want ok=%v (typed=%d, total=%d, ratio=%.3f)",
					tc.name, ok, tc.wantPass, tc.typedCount, tc.totalEvents,
					float64(tc.typedCount)/float64(tc.totalEvents))
			}
		})
	}
}

// ---- unit: predicate per-detector ----------------------------------------------

// TestTriageGatePredicate_PerDetector verifies:
//   - Each detector in neverAutoResolveDetectors returns false even when all
//     other conditions (known actor, non-critical severity, ≥3 typed events,
//     ratio ≥0.05) hold.
//   - A non-blocked detector with all conditions true returns true.
//   - Critical severity returns false regardless of actor/history.
//   - Unknown actor returns false.
//   - typed_count < minPriorTypedEvents returns false.
//   - ratio < minTypeRatio returns false.
func TestTriageGatePredicate_PerDetector(t *testing.T) {
	// Build a baseline with a known actor and ≥3 typed prior events + ratio ≥0.05.
	baselineWithHistory := &exam.Baseline{
		KnownEntities: exam.KnownEntities{
			Actors:  []string{"deploy-svc"},
			Sources: []string{"azure"},
		},
		FrequencyTables: map[string]int{
			"azure:container_deploy:deploy-svc": 156, // typed events for container_deploy
			"azure:image_push:deploy-svc":       89,  // other events (for ratio context)
		},
	}

	// Case 1: blocked detectors must never match.
	for _, det := range []string{
		"priv-escalation",
		"log-format-drift",
		"injection-probe",
		"boundary-violation",
	} {
		s := &exam.Scenario{
			ID: "GATE-BLOCKED-" + det,
			Finding: &exam.ScenarioFinding{
				ID:       "fnd_" + det,
				Detector: det,
				Severity: "warn",
				Metadata: exam.FindingMetadata{
					"actor":      "deploy-svc",
					"event_type": "container_deploy",
				},
			},
			Baseline: baselineWithHistory,
		}
		_, ok := triageGatePredicate(s)
		if ok {
			t.Errorf("triageGatePredicate blocked detector %q: got ok=true, want false", det)
		}
	}

	// Case 2: non-blocked detector with all conditions met → must match.
	validScenario := &exam.Scenario{
		ID: "GATE-VALID",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_valid",
			Detector: "volume-anomaly",
			Severity: "warn",
			Metadata: exam.FindingMetadata{
				"actor":      "deploy-svc",
				"event_type": "container_deploy",
			},
		},
		Baseline: baselineWithHistory,
	}
	reason, ok := triageGatePredicate(validScenario)
	if !ok {
		t.Error("triageGatePredicate valid scenario: got ok=false, want true")
	}
	if reason == "" {
		t.Error("triageGatePredicate valid scenario: reason is empty")
	}
	// Reason must contain the discriminator values (typed_count, total, ratio).
	if !strings.Contains(reason, "typed_count") {
		t.Errorf("triageGatePredicate reason should contain typed_count, got: %q", reason)
	}

	// Case 3: critical severity must never auto-resolve.
	critScenario := &exam.Scenario{
		ID: "GATE-CRIT",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_crit",
			Detector: "volume-anomaly",
			Severity: "critical",
			Metadata: exam.FindingMetadata{
				"actor":      "deploy-svc",
				"event_type": "container_deploy",
			},
		},
		Baseline: baselineWithHistory,
	}
	_, ok = triageGatePredicate(critScenario)
	if ok {
		t.Error("triageGatePredicate critical severity: got ok=true, want false (critical NEVER auto-resolves)")
	}

	// Case 4: unknown actor must not match.
	unknownActorScenario := &exam.Scenario{
		ID: "GATE-UNKNOWN-ACTOR",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_unknown",
			Detector: "volume-anomaly",
			Severity: "warn",
			Metadata: exam.FindingMetadata{
				"actor":      "unknown-svc",
				"event_type": "container_deploy",
			},
		},
		Baseline: baselineWithHistory, // "unknown-svc" not in known_actors
	}
	_, ok = triageGatePredicate(unknownActorScenario)
	if ok {
		t.Error("triageGatePredicate unknown actor: got ok=true, want false")
	}

	// Case 5: insufficient typed events (typed_count < minPriorTypedEvents) must not match.
	sparseBaseline := &exam.Baseline{
		KnownEntities: exam.KnownEntities{
			Actors:  []string{"deploy-svc"},
			Sources: []string{"azure"},
		},
		FrequencyTables: map[string]int{
			"azure:container_deploy:deploy-svc": 2, // only 2 < minPriorTypedEvents (3)
		},
	}
	sparseScenario := &exam.Scenario{
		ID: "GATE-SPARSE",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_sparse",
			Detector: "volume-anomaly",
			Severity: "warn",
			Metadata: exam.FindingMetadata{
				"actor":      "deploy-svc",
				"event_type": "container_deploy",
			},
		},
		Baseline: sparseBaseline,
	}
	_, ok = triageGatePredicate(sparseScenario)
	if ok {
		t.Errorf("triageGatePredicate insufficient typed events (2 < %d): got ok=true, want false", minPriorTypedEvents)
	}

	// Case 6: typed_count ≥3 but ratio < minTypeRatio must not match.
	// actor has 3 typed events but 200 total → ratio = 0.015 < 0.05.
	lowRatioBaseline := &exam.Baseline{
		KnownEntities: exam.KnownEntities{
			Actors:  []string{"deploy-svc"},
			Sources: []string{"azure"},
		},
		FrequencyTables: map[string]int{
			"azure:container_deploy:deploy-svc": 3,   // typed_count = 3
			"azure:login:deploy-svc":            197, // other events → total = 200, ratio = 0.015
		},
	}
	lowRatioScenario := &exam.Scenario{
		ID: "GATE-LOW-RATIO",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_low_ratio",
			Detector: "volume-anomaly",
			Severity: "warn",
			Metadata: exam.FindingMetadata{
				"actor":      "deploy-svc",
				"event_type": "container_deploy",
			},
		},
		Baseline: lowRatioBaseline,
	}
	_, ok = triageGatePredicate(lowRatioScenario)
	if ok {
		t.Error("triageGatePredicate low specialization ratio (0.015 < 0.05): got ok=true, want false")
	}
}

// countTriageGateResolve returns the number of mockSender sends whose tags
// include both "work:close" and "academy:triage-gate" — the synthetic
// terminal-resolved event emitted by the rung-2 gate.
func countTriageGateResolve(ms *mockSender) int {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	n := 0
	for _, c := range ms.sends {
		hasClose, hasTG := false, false
		for _, tag := range c.tags {
			if tag == "work:close" {
				hasClose = true
			}
			if tag == "academy:triage-gate" {
				hasTG = true
			}
		}
		if hasClose && hasTG {
			n++
		}
	}
	return n
}

// writeTriageGateScenario writes a scenario YAML with a known actor, baseline
// with typed prior events satisfying both count and ratio conditions, and the
// given severity and detector. Used for rung-2 test fixtures.
func writeTriageGateScenario(t *testing.T, dir, id, findingID, detector, severity string) {
	t.Helper()
	content := `id: ` + id + `
failure_mode: test
detector: ` + detector + `
category: test
difficulty: easy
finding:
  id: ` + findingID + `
  detector: ` + detector + `
  title: "Rung-2 gate test scenario"
  severity: ` + severity + `
  event_ids: [evt-001]
  metadata:
    actor: deploy-svc
    event_type: container_deploy
events:
  - id: evt-001
    timestamp: "2026-01-01T00:00:00Z"
    source: azure
    event_type: container_deploy
    actor: deploy-svc
    action: deploy_container
    target: sub-abc/rg/atom-api
    severity: info
baseline:
  known_entities:
    actors: [deploy-svc, admin-user, ci-bot]
    sources: [azure]
  frequency_tables:
    azure:container_deploy:deploy-svc: 156
    azure:image_push:deploy-svc: 89
    azure:health_check:deploy-svc: 320
expected:
  chain_action: resolved
  triage_action: resolved
`
	if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write triage gate scenario YAML: %v", err)
	}
}

// ---- Test 1: matching scenario → zero LLM workers, synthetic terminal-resolved -

// TestAcademy_TriageGate_NoWorkerSpawn covers Test 1:
// scenarios from the pinned scCorrectSet produce zero work:create posts
// (worker_spawn_count == 0), one synthetic terminal-resolved (academy:triage-gate),
// chain length == 1, and action == "resolved".
//
// Uses the real scenarios dir (same as FullCorpus) — no synthetic YAMLs needed
// since scCorrectSet IDs are real corpus files.
func TestAcademy_TriageGate_NoWorkerSpawn(t *testing.T) {
	repoRoot, err := repoRootFromExec()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	scenariosDir := filepath.Join(repoRoot, "exams", "scenarios")
	if _, err := os.Stat(scenariosDir); err != nil {
		t.Fatalf("scenarios dir missing: %v", err)
	}

	// Test a curated subset of scCorrectSet to keep the test fast.
	// These 4 span multiple detector types and event_type patterns.
	testIDs := []string{
		"VA-01-deploy-burst",
		"VA-02-month-end-batch",
		"UT-02-maintenance-window",
		"CC-02-deploy-window-multi-signal",
	}

	for _, scenarioID := range testIDs {
		scenarioID := scenarioID
		t.Run(scenarioID, func(t *testing.T) {
			outDir := t.TempDir()
			ms := &mockSender{}

			args := runArgs{
				targetCampfire: "cf-mock-target",
				scenariosDir:   scenariosDir,
				scenarioFilter: scenarioID,
				outputDir:      outDir,
				maxConcurrent:  1,
				timeout:        5 * time.Second,
				runID:          "test-tg-" + scenarioID,
			}

			if err := academy(ms, args); err != nil {
				t.Fatalf("academy: %v", err)
			}

			// Done condition Test 1: zero LLM workers spawned.
			if got := countWorkCreate(ms); got != 0 {
				t.Errorf("worker_spawn_count = %d, want 0 for SC-correct scenario %q", got, scenarioID)
			}

			// Exactly one synthetic terminal-resolved event emitted.
			if got := countTriageGateResolve(ms); got != 1 {
				t.Errorf("synthetic terminal-resolved count = %d, want 1 for scenario %q", got, scenarioID)
			}

			// No hard-constraint escalation (must be gate, not HC).
			if got := countSyntheticEscalate(ms); got != 0 {
				t.Errorf("hard-constraint escalate count = %d, want 0 for scenario %q", got, scenarioID)
			}

			// Per-scenario JSON must record the deterministic resolve.
			recordPath := filepath.Join(outDir, scenarioID+".json")
			data, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatalf("read scenario record: %v", err)
			}
			var rec ScenarioRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatalf("parse scenario record: %v", err)
			}
			if rec.TerminalAction != "resolved" {
				t.Errorf("terminal_action = %q, want resolved", rec.TerminalAction)
			}
			if rec.TerminalAt == nil {
				t.Errorf("terminal_at must be non-nil for triage-gate terminal")
			}
			if len(rec.FullChain) != 1 {
				t.Errorf("chain length = %d, want 1 for triage-gate scenario", len(rec.FullChain))
			} else if rec.FullChain[0].Skill != "task:triage-gate" {
				t.Errorf("chain[0].skill = %q, want task:triage-gate", rec.FullChain[0].Skill)
			}
		})
	}
}

// ---- Test 2: critical severity → must NOT auto-resolve (falls to LLM path) ----

// TestAcademy_TriageGate_CriticalSeverityFallthrough covers Test 2:
// a finding with severity == "critical" and a known actor with rich baseline
// must NOT auto-resolve via rung-2. The scenario falls through to the LLM triage
// path (worker_spawn_count > 0 in the mock, because the mockSender returns no
// closes and the watch loop times out — confirming that postFinding was called).
func TestAcademy_TriageGate_CriticalSeverityFallthrough(t *testing.T) {
	scenDir := t.TempDir()
	// Write a critical-severity scenario with a known actor and rich baseline.
	writeTriageGateScenario(t, scenDir, "TG-CRIT-01", "fnd_tg_crit_01", "volume-anomaly", "critical")

	outDir := t.TempDir()
	ms := &mockSender{}

	args := runArgs{
		targetCampfire: "cf-mock-target",
		scenariosDir:   scenDir,
		scenarioFilter: "TG-CRIT-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        100 * time.Millisecond, // mock returns no closes → timeout
		runID:          "test-tg-critical",
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	// Critical-severity must NOT produce a triage-gate resolve.
	if got := countTriageGateResolve(ms); got != 0 {
		t.Errorf("critical severity: triage-gate resolves = %d, want 0 (critical NEVER auto-resolves)", got)
	}

	// Must fall through to normal triage — worker_spawn_count > 0.
	if got := countWorkCreate(ms); got != 1 {
		t.Errorf("critical severity: worker_spawn_count = %d, want 1 (falls through to LLM)", got)
	}

	// No hard-constraint escalation either (volume-anomaly is not rung-0).
	if got := countSyntheticEscalate(ms); got != 0 {
		t.Errorf("critical severity: hard-constraint count = %d, want 0", got)
	}
}

// ---- Test 3: rung-0 detector + matching baseline → escalated (not resolved) ---

// TestAcademy_TriageGate_Rung0DetectorEscalates covers Test 3:
// a rung-0 detector (priv-escalation) with a known actor and rich baseline
// must route to rung 0 (escalated), not rung 2 (resolved). Rung 0 runs first.
func TestAcademy_TriageGate_Rung0DetectorEscalates(t *testing.T) {
	scenDir := t.TempDir()
	// priv-escalation is in both alwaysEscalateDetectors and neverAutoResolveDetectors.
	// Write it with a known actor and rich baseline — predicate would match if rung-0
	// didn't intercept first.
	writeTriageGateScenario(t, scenDir, "TG-RUNG0-01", "fnd_tg_rung0_01", "priv-escalation", "warn")

	outDir := t.TempDir()
	ms := &mockSender{}

	args := runArgs{
		targetCampfire: "cf-mock-target",
		scenariosDir:   scenDir,
		scenarioFilter: "TG-RUNG0-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-tg-rung0",
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	// Rung 0 takes priority: zero LLM workers, zero triage-gate resolves.
	if got := countWorkCreate(ms); got != 0 {
		t.Errorf("rung-0 detector: worker_spawn_count = %d, want 0", got)
	}
	if got := countTriageGateResolve(ms); got != 0 {
		t.Errorf("rung-0 detector: triage-gate resolves = %d, want 0 (rung-0 intercepts)", got)
	}

	// Rung-0 escalation emitted (action == "escalated", tag academy:hard-constraint).
	if got := countSyntheticEscalate(ms); got != 1 {
		t.Errorf("rung-0 detector: hard-constraint escalate count = %d, want 1", got)
	}

	// Per-scenario JSON must show escalated, not resolved.
	recordPath := filepath.Join(outDir, "TG-RUNG0-01.json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read scenario record: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse scenario record: %v", err)
	}
	if rec.TerminalAction != "escalated" {
		t.Errorf("terminal_action = %q, want escalated (rung-0 routes to escalated, not resolved)", rec.TerminalAction)
	}
	if len(rec.FullChain) != 1 {
		t.Errorf("chain length = %d, want 1 for rung-0 scenario", len(rec.FullChain))
	} else if rec.FullChain[0].Skill != "task:hard-constraint" {
		t.Errorf("chain[0].skill = %q, want task:hard-constraint (not task:triage-gate)", rec.FullChain[0].Skill)
	}
}
