// Regression test for mallcoppro-462: per-scenario forge_calls/tokens_in/tokens_out
// must be non-zero in ScenarioRecord when Forge metering data is available.
//
// This test was written to fail on origin/main (ScenarioRecord had no forge_calls
// field) and pass after the fix.
//
// Test strategy: inject a mock usageFetcher (implementing the usageFetcher interface)
// that returns real-shaped usage data, run academy with it, and assert the emitted
// ScenarioRecord JSON has non-zero forge usage fields.
//
// No real Forge API call is made. The mock implements the same interface as
// httpUsageFetcher. This tests the full data-flow path:
//   mock fetcher → writeScenarioRecord → ScenarioRecord.ForgeCalls/TokensIn/TokensOut
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mockUsageFetcher is a test double for usageFetcher.
// It returns a fixed ScenarioUsage regardless of the time window.
type mockUsageFetcher struct {
	usage ScenarioUsage
	calls int
}

func (m *mockUsageFetcher) fetch(_, _ time.Time) (ScenarioUsage, error) {
	m.calls++
	return m.usage, nil
}

// TestScenarioRecord_ForgeUsageFields_NonZero is the mallcoppro-462 regression test.
//
// Before the fix: ScenarioRecord had no forge_calls/tokens_in/tokens_out fields —
//
//	this test could not compile on origin/main.
//
// After the fix: ScenarioRecord has these fields and writeScenarioRecord populates
//
//	them from the injected usageFetcher.
//
// The test verifies the full data-flow from fetcher → ScenarioRecord JSON.
func TestScenarioRecord_ForgeUsageFields_NonZero(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()
	termAt := now.Add(30 * time.Second)

	// Mock fetcher returns realistic usage data.
	fetcher := &mockUsageFetcher{
		usage: ScenarioUsage{
			ForgeCalls: 7,
			TokensIn:   12450,
			TokensOut:  3820,
			CostUSD:    0.00847,
		},
	}

	ts := &trackedScenario{
		scenarioID:     "AC-01",
		findingID:      "academy-run-usage-test-AC-01",
		workItemID:     "msg-usage-test",
		postedAt:       now,
		chain:          []ChainEntry{{ItemID: "msg-usage-test", Skill: "task:triage"}, {ItemID: "item-resolved", Action: "resolved"}},
		terminal:       true,
		terminalAt:     termAt,
		terminalAction: "resolved",
		terminalItemID: "item-resolved",
	}

	if err := writeScenarioRecord(ts, "run-usage-test", "cf-test", outDir, fetcher); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	// Fetcher must have been called exactly once.
	if fetcher.calls != 1 {
		t.Errorf("fetcher.calls = %d, want 1", fetcher.calls)
	}

	// Read the written JSON file.
	recordPath := filepath.Join(outDir, "AC-01.json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read scenario record: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse scenario record: %v", err)
	}

	// Regression assertions: these fields must be non-zero.
	if rec.ForgeCalls == 0 {
		t.Errorf("forge_calls = 0, want > 0 (got %d) — metering data not propagated to ScenarioRecord", rec.ForgeCalls)
	}
	if rec.TokensIn == 0 {
		t.Errorf("tokens_in = 0, want > 0 (got %d) — metering data not propagated to ScenarioRecord", rec.TokensIn)
	}
	if rec.TokensOut == 0 {
		t.Errorf("tokens_out = 0, want > 0 (got %d) — metering data not propagated to ScenarioRecord", rec.TokensOut)
	}
	if rec.CostUSD == 0 {
		t.Errorf("cost_usd = 0, want > 0 — metering data not propagated to ScenarioRecord")
	}

	// Value fidelity: check the values match what the fetcher returned.
	if rec.ForgeCalls != 7 {
		t.Errorf("forge_calls = %d, want 7", rec.ForgeCalls)
	}
	if rec.TokensIn != 12450 {
		t.Errorf("tokens_in = %d, want 12450", rec.TokensIn)
	}
	if rec.TokensOut != 3820 {
		t.Errorf("tokens_out = %d, want 3820", rec.TokensOut)
	}

	// JSON shape: verify the emitted JSON has the expected field names.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse raw JSON: %v", err)
	}
	for _, field := range []string{"forge_calls", "tokens_in", "tokens_out"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("ScenarioRecord JSON missing field %q — summary.json aggregator cannot read it", field)
		}
	}
}

// TestScenarioRecord_ForgeUsageFields_ZeroWhenNoFetcher verifies that
// ScenarioRecord has zero usage fields when no fetcher is provided (backward-compat:
// old runs that don't have fetcher configured).
func TestScenarioRecord_ForgeUsageFields_ZeroWhenNoFetcher(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()
	termAt := now.Add(10 * time.Second)

	ts := &trackedScenario{
		scenarioID:     "AC-02",
		findingID:      "academy-run-nokey-AC-02",
		workItemID:     "msg-nokey",
		postedAt:       now,
		chain:          []ChainEntry{{ItemID: "msg-nokey", Skill: "task:triage"}},
		terminal:       true,
		terminalAt:     termAt,
		terminalAction: "resolved",
		terminalItemID: "item-resolved",
	}

	// No fetcher provided — uses zero-value path.
	if err := writeScenarioRecord(ts, "run-nokey", "cf-test", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "AC-02.json"))
	if err != nil {
		t.Fatalf("read scenario record: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse scenario record: %v", err)
	}

	// Without a fetcher, usage fields should be zero (default).
	if rec.ForgeCalls != 0 {
		t.Errorf("forge_calls = %d, want 0 when no fetcher", rec.ForgeCalls)
	}
	if rec.TokensIn != 0 {
		t.Errorf("tokens_in = %d, want 0 when no fetcher", rec.TokensIn)
	}
	if rec.TokensOut != 0 {
		t.Errorf("tokens_out = %d, want 0 when no fetcher", rec.TokensOut)
	}
}

// TestScenarioRecord_ForgeUsageFields_AcademyIntegration verifies the full
// academy() → writeScenarioRecord → ScenarioRecord path with a mock fetcher
// injected through runArgs.usage.
//
// This test proves that the wiring from runArgs → writeScenarioRecord is correct.
func TestScenarioRecord_ForgeUsageFields_AcademyIntegration(t *testing.T) {
	// Build a minimal scenario YAML.
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AC-03", "fnd_ac_003", "detector-rate-anomaly",
		"Rate anomaly detected", "high")

	outDir := t.TempDir()

	fetcher := &mockUsageFetcher{
		usage: ScenarioUsage{
			ForgeCalls: 5,
			TokensIn:   8000,
			TokensOut:  2100,
		},
	}

	// Use the mockSender from the existing test suite.
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target",
		scenariosDir:   scenDir,
		scenarioFilter: "AC-03",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-usage-integ",
		usage:          fetcher,
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

	// Wait for work:create, then inject terminal close.
	var sentID string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		ms.mu.Lock()
		if len(ms.sends) > 0 {
			sentID = ms.sends[0].returnID
		}
		ms.mu.Unlock()
		if sentID != "" {
			break
		}
	}
	if sentID == "" {
		t.Fatal("academy never posted work:create within timeout")
	}

	// Inject terminal close.
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "resolved",
		Skill:  "task:triage",
	})
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-usage-integ",
		Tags:    []string{"work:close", "action:resolved"},
		Payload: string(closePayloadBytes),
	})
	ms.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("academy did not complete within deadline")
	}

	// Read the scenario record and verify usage fields.
	data, err := os.ReadFile(filepath.Join(outDir, "AC-03.json"))
	if err != nil {
		t.Fatalf("AC-03.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse AC-03.json: %v", err)
	}

	if rec.ForgeCalls == 0 {
		t.Errorf("forge_calls = 0 after academy run with usage fetcher; want > 0")
	}
	if rec.TokensIn == 0 {
		t.Errorf("tokens_in = 0 after academy run with usage fetcher; want > 0")
	}
	if rec.ForgeCalls != 5 {
		t.Errorf("forge_calls = %d, want 5", rec.ForgeCalls)
	}
	if rec.TokensIn != 8000 {
		t.Errorf("tokens_in = %d, want 8000", rec.TokensIn)
	}
}

// ---- mallcoppro-237 A2: campfire tool-usage aggregation ----------------------------

// TestAccumulateToolUsage_MatchByFindingTag verifies that accumulateToolUsage
// correctly sums forge_calls/tokens_in/tokens_out for a scenario matched by
// finding:<id> tag on the message.
func TestAccumulateToolUsage_MatchByFindingTag(t *testing.T) {
	const findingID = "fnd_test_237_tag"
	tracked := map[string]*trackedScenario{
		"SC-237": {
			scenarioID: "SC-237",
			findingID:  findingID,
			workItemID: "posted-msg-sc237", // successfully posted
		},
	}

	payload, _ := json.Marshal(toolUsagePayload{
		ForgeCalls: 1,
		TokensIn:   500,
		TokensOut:  120,
	})
	msg := cfMessage{
		ID:      "tu-msg-1",
		Tags:    []string{"tool-usage", "finding:" + findingID},
		Payload: string(payload),
	}
	accumulateToolUsage(msg, tracked)

	ts := tracked["SC-237"]
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.toolUsageCalls != 1 {
		t.Errorf("toolUsageCalls = %d, want 1", ts.toolUsageCalls)
	}
	if ts.toolUsageTokensIn != 500 {
		t.Errorf("toolUsageTokensIn = %d, want 500", ts.toolUsageTokensIn)
	}
	if ts.toolUsageTokensOut != 120 {
		t.Errorf("toolUsageTokensOut = %d, want 120", ts.toolUsageTokensOut)
	}
}

// TestAccumulateToolUsage_MatchByPayloadFindingID verifies matching via the
// finding_id payload field when no finding: tag is present.
func TestAccumulateToolUsage_MatchByPayloadFindingID(t *testing.T) {
	const findingID = "fnd_test_237_payload"
	tracked := map[string]*trackedScenario{
		"SC-238": {
			scenarioID: "SC-238",
			findingID:  findingID,
			workItemID: "posted-msg-sc238", // successfully posted
		},
	}

	payload, _ := json.Marshal(toolUsagePayload{
		ForgeCalls: 2,
		FindingID:  findingID,
	})
	msg := cfMessage{
		ID:      "tu-msg-2",
		Tags:    []string{"tool-usage"},
		Payload: string(payload),
	}
	accumulateToolUsage(msg, tracked)

	ts := tracked["SC-238"]
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.toolUsageCalls != 2 {
		t.Errorf("toolUsageCalls = %d, want 2", ts.toolUsageCalls)
	}
}

// TestAccumulateToolUsage_MultipleMessages verifies that multiple tool-usage messages
// are summed correctly for the same scenario.
func TestAccumulateToolUsage_MultipleMessages(t *testing.T) {
	const findingID = "fnd_test_237_multi"
	tracked := map[string]*trackedScenario{
		"SC-239": {
			scenarioID: "SC-239",
			findingID:  findingID,
			workItemID: "posted-msg-sc239", // successfully posted
		},
	}

	for i := 0; i < 3; i++ {
		payload, _ := json.Marshal(toolUsagePayload{ForgeCalls: 1, TokensIn: 100, TokensOut: 50})
		accumulateToolUsage(cfMessage{
			Tags:    []string{"tool-usage", "finding:" + findingID},
			Payload: string(payload),
		}, tracked)
	}

	ts := tracked["SC-239"]
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.toolUsageCalls != 3 {
		t.Errorf("toolUsageCalls = %d, want 3", ts.toolUsageCalls)
	}
	if ts.toolUsageTokensIn != 300 {
		t.Errorf("toolUsageTokensIn = %d, want 300", ts.toolUsageTokensIn)
	}
}

// TestAccumulateToolUsage_NoMatchSkipped verifies that messages with no matching
// finding_id are silently skipped (no crash, no wrong attribution).
func TestAccumulateToolUsage_NoMatchSkipped(t *testing.T) {
	tracked := map[string]*trackedScenario{
		"SC-240": {scenarioID: "SC-240", findingID: "fnd_test_237_real", workItemID: "posted-msg-sc240"},
	}
	payload, _ := json.Marshal(toolUsagePayload{ForgeCalls: 1, FindingID: "fnd_test_237_other"})
	accumulateToolUsage(cfMessage{Tags: []string{"tool-usage"}, Payload: string(payload)}, tracked)

	ts := tracked["SC-240"]
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.toolUsageCalls != 0 {
		t.Errorf("toolUsageCalls = %d, want 0 (no match)", ts.toolUsageCalls)
	}
}

// TestAcademy_CampfireUsage_NonZeroForgeCalls verifies the full academy() → watch-loop
// → accumulateToolUsage → writeScenarioRecord path produces nonzero forge_calls
// when tool-usage messages appear in the mock campfire (mallcoppro-237).
//
// This is the primary integration test for A2: no mock usageFetcher is injected,
// yet forge_calls is nonzero because the watch loop accumulated tool-usage messages.
func TestAcademy_CampfireUsage_NonZeroForgeCalls(t *testing.T) {
	scenDir := t.TempDir()
	const findingBase = "fnd_237_campfire"
	writeMinimalScenario(t, scenDir, "TU-01", findingBase, "detector-new-actor",
		"Tool usage campfire test", "medium")

	outDir := t.TempDir()
	runID := "run-a2-test"

	// The mock sender assigns "mock-msg-1" to TU-01's work:create.
	// The work:create finding.id will be perRunFindingID(findingBase, runID).
	expectedFindingID := perRunFindingID(findingBase, runID)

	// Inject: tool-usage message (from resolve-finding) + terminal work:close.
	tuPayload, _ := json.Marshal(toolUsagePayload{
		ForgeCalls: 3,
		TokensIn:   1200,
		TokensOut:  400,
		FindingID:  expectedFindingID,
	})
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-1",
		Action: "resolved",
		Skill:  "task:triage",
	})

	ms := &mockSender{
		readMsgs: []cfMessage{
			{
				ID:      "tu-msg-a2",
				Tags:    []string{"tool-usage", "finding:" + expectedFindingID},
				Payload: string(tuPayload),
			},
			{
				ID:      "close-a2",
				Tags:    []string{"work:close", "action:resolved"},
				Payload: string(closePayloadBytes),
			},
		},
	}

	args := runArgs{
		targetCampfire: "cf-a2-test",
		scenariosDir:   scenDir,
		scenarioFilter: "TU-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          runID,
		// No usage fetcher — campfire path must supply forge_calls.
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	data, err := os.ReadFile(outDir + "/TU-01.json")
	if err != nil {
		t.Fatalf("TU-01.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse TU-01.json: %v", err)
	}

	if rec.ForgeCalls == 0 {
		t.Errorf("forge_calls = 0 — campfire tool-usage aggregation did not produce nonzero value (mallcoppro-237 A2 regression)")
	}
	if rec.ForgeCalls != 3 {
		t.Errorf("forge_calls = %d, want 3", rec.ForgeCalls)
	}
	if rec.TokensIn != 1200 {
		t.Errorf("tokens_in = %d, want 1200", rec.TokensIn)
	}
	if rec.TokensOut != 400 {
		t.Errorf("tokens_out = %d, want 400", rec.TokensOut)
	}
}

// TestWriteScenarioRecord_CampfireUsagePreferredOverFetcher verifies that when
// both campfire-accumulated usage and a HTTP fetcher are available, the campfire
// data takes priority (A2 over fallback path).
func TestWriteScenarioRecord_CampfireUsagePreferredOverFetcher(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()
	termAt := now.Add(10 * time.Second)

	// Campfire-accumulated data: 3 calls.
	ts := &trackedScenario{
		scenarioID:         "TU-02",
		findingID:          "fnd-tu-02",
		workItemID:         "msg-tu-02",
		postedAt:           now,
		chain:              []ChainEntry{{ItemID: "msg-tu-02", Skill: "task:triage"}},
		terminal:           true,
		terminalAt:         termAt,
		terminalAction:     "resolved",
		terminalItemID:     "msg-tu-02",
		toolUsageCalls:     3,
		toolUsageTokensIn:  900,
		toolUsageTokensOut: 300,
	}

	// HTTP fetcher returns different values — should NOT be used.
	fetcher := &mockUsageFetcher{
		usage: ScenarioUsage{ForgeCalls: 99, TokensIn: 99999, TokensOut: 9999},
	}

	if err := writeScenarioRecord(ts, "run-prefer-test", "cf-test", outDir, fetcher); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	// Fetcher must NOT have been called.
	if fetcher.calls != 0 {
		t.Errorf("fetcher.calls = %d, want 0 — campfire data should short-circuit the HTTP fetcher", fetcher.calls)
	}

	data, err := os.ReadFile(outDir + "/TU-02.json")
	if err != nil {
		t.Fatalf("TU-02.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse TU-02.json: %v", err)
	}

	if rec.ForgeCalls != 3 {
		t.Errorf("forge_calls = %d, want 3 (campfire data)", rec.ForgeCalls)
	}
	if rec.TokensIn != 900 {
		t.Errorf("tokens_in = %d, want 900 (campfire data)", rec.TokensIn)
	}
}

// TestAcademy_CampfireUsage_ProductionOrder is the regression test for mallcoppro-b87.
//
// The masking test (TestAcademy_CampfireUsage_NonZeroForgeCalls) injected messages in
// test order: tool-usage BEFORE work:close. In production, resolve-finding and the
// escalate-* tools previously emitted work:output BEFORE tool-usage, so the academy
// watch loop called writeScenarioRecord with toolUsageCalls=0, then the tool-usage
// message arrived too late.
//
// This test exercises the production message order: work:output (or work:close) arrives
// BEFORE tool-usage. After the fixes (emit swap in tools_f1g.go + accumulateToolUsage
// moved before inRunWindow guard), forge_calls must still be nonzero.
//
// To verify this catches the original bug: on the pre-fix code, readMsgs has work:close
// first — the watch loop triggers writeScenarioRecord immediately, then the tool-usage
// arrives and accumulates into a record that's already on disk → forge_calls=0.
func TestAcademy_CampfireUsage_ProductionOrder(t *testing.T) {
	scenDir := t.TempDir()
	const findingBase = "fnd_b87_prod_order"
	writeMinimalScenario(t, scenDir, "PO-01", findingBase, "detector-prod-order",
		"Production order forge_calls regression test", "high")

	outDir := t.TempDir()
	runID := "run-b87-prod-order"

	// The mock sender assigns "mock-msg-1" to PO-01's work:create.
	expectedFindingID := perRunFindingID(findingBase, runID)

	tuPayload, _ := json.Marshal(toolUsagePayload{
		ForgeCalls: 5,
		TokensIn:   2000,
		TokensOut:  800,
		FindingID:  expectedFindingID,
	})
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-1",
		Action: "resolved",
		Skill:  "task:triage",
	})

	// PRODUCTION ORDER: work:close arrives BEFORE tool-usage.
	// This is the order that caused forge_calls=0 before the fix.
	ms := &mockSender{
		readMsgs: []cfMessage{
			{
				ID:      "close-b87",
				Tags:    []string{"work:close", "action:resolved"},
				Payload: string(closePayloadBytes),
			},
			{
				ID:      "tu-msg-b87",
				Tags:    []string{"tool-usage", "finding:" + expectedFindingID},
				Payload: string(tuPayload),
			},
		},
	}

	args := runArgs{
		targetCampfire: "cf-b87-test",
		scenariosDir:   scenDir,
		scenarioFilter: "PO-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          runID,
		// No usage fetcher — campfire path must supply forge_calls.
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	data, err := os.ReadFile(outDir + "/PO-01.json")
	if err != nil {
		t.Fatalf("PO-01.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse PO-01.json: %v", err)
	}

	// This assertion fails on pre-fix code (mallcoppro-b87): the watch loop wrote
	// the record before the tool-usage message was accumulated.
	if rec.ForgeCalls == 0 {
		t.Errorf("forge_calls = 0 — production-order bug: tool-usage arrived after work:close but was not accumulated before writeScenarioRecord (mallcoppro-b87 regression)")
	}
	if rec.ForgeCalls != 5 {
		t.Errorf("forge_calls = %d, want 5", rec.ForgeCalls)
	}
	if rec.TokensIn != 2000 {
		t.Errorf("tokens_in = %d, want 2000", rec.TokensIn)
	}
	if rec.TokensOut != 800 {
		t.Errorf("tokens_out = %d, want 800", rec.TokensOut)
	}
}

// ---- mallcoppro-d93: HTTP fallback gating ----------------------------------------

// TestHTTPUsageFetcher_RequiresTenantKey verifies that newHTTPUsageFetcher returns
// nil when MALLCOP_FORGE_USAGE_HTTP_KEY is absent, regardless of FORGE_API_KEY.
//
// Before the fix: newHTTPUsageFetcher read FORGE_API_KEY and returned a non-nil
// fetcher. Customer-tier mallcop-sk-* keys get 403 on GET /v1/usage (RoleTenant
// required), so every non-HC scenario's forge_calls stayed 0 in the output JSON.
//
// After the fix: only MALLCOP_FORGE_USAGE_HTTP_KEY enables the HTTP path.
// FORGE_API_KEY alone is not sufficient (mallcoppro-d93).
func TestHTTPUsageFetcher_RequiresTenantKey(t *testing.T) {
	// Ensure MALLCOP_FORGE_USAGE_HTTP_KEY is unset for this test.
	orig := os.Getenv("MALLCOP_FORGE_USAGE_HTTP_KEY")
	os.Unsetenv("MALLCOP_FORGE_USAGE_HTTP_KEY")
	defer func() {
		if orig != "" {
			os.Setenv("MALLCOP_FORGE_USAGE_HTTP_KEY", orig)
		}
	}()

	// Even with FORGE_API_KEY set (customer-tier key), fetcher must be nil.
	origFAK := os.Getenv("FORGE_API_KEY")
	os.Setenv("FORGE_API_KEY", "mallcop-sk-test-customer-key")
	defer func() {
		if origFAK != "" {
			os.Setenv("FORGE_API_KEY", origFAK)
		} else {
			os.Unsetenv("FORGE_API_KEY")
		}
	}()

	f := newHTTPUsageFetcher()
	if f != nil {
		t.Errorf("newHTTPUsageFetcher returned non-nil when MALLCOP_FORGE_USAGE_HTTP_KEY is absent; "+
			"customer-tier FORGE_API_KEY must not enable the HTTP path (mallcoppro-d93)")
	}
}

// TestHTTPUsageFetcher_EnabledByTenantKey verifies that newHTTPUsageFetcher returns
// a non-nil fetcher when MALLCOP_FORGE_USAGE_HTTP_KEY is set.
func TestHTTPUsageFetcher_EnabledByTenantKey(t *testing.T) {
	orig := os.Getenv("MALLCOP_FORGE_USAGE_HTTP_KEY")
	os.Setenv("MALLCOP_FORGE_USAGE_HTTP_KEY", "tenant-key-for-usage-api")
	defer func() {
		if orig != "" {
			os.Setenv("MALLCOP_FORGE_USAGE_HTTP_KEY", orig)
		} else {
			os.Unsetenv("MALLCOP_FORGE_USAGE_HTTP_KEY")
		}
	}()

	f := newHTTPUsageFetcher()
	if f == nil {
		t.Errorf("newHTTPUsageFetcher returned nil when MALLCOP_FORGE_USAGE_HTTP_KEY is set")
	}
}

// TestWriteScenarioRecord_NoHTTPWhenNoCampfireAndNoKey verifies that when both
// campfire usage is zero AND no HTTP fetcher is provided, forge_calls stays 0
// and no HTTP call is attempted (mallcoppro-d93).
//
// This is the primary regression test: pre-fix code would attempt the HTTP call
// with the customer-tier FORGE_API_KEY, receive 403, log a warning, and produce
// forge_calls=0. Post-fix: the HTTP path is never entered when the fetcher is nil.
func TestWriteScenarioRecord_NoHTTPWhenNoCampfireAndNoKey(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()
	termAt := now.Add(10 * time.Second)

	// No campfire usage (toolUsageCalls=0) and no fetcher (nil) — simulates the
	// bakeoff scenario where MALLCOP_FORGE_USAGE_HTTP_KEY is unset.
	ts := &trackedScenario{
		scenarioID:     "D93-01",
		findingID:      "fnd-d93-01",
		workItemID:     "msg-d93-01",
		postedAt:       now,
		chain:          []ChainEntry{{ItemID: "msg-d93-01", Skill: "task:triage"}},
		terminal:       true,
		terminalAt:     termAt,
		terminalAction: "resolved",
		terminalItemID: "msg-d93-01",
		// toolUsageCalls intentionally left 0 (no campfire tool-usage messages).
	}

	// No fetcher argument — simulates MALLCOP_FORGE_USAGE_HTTP_KEY absent.
	if err := writeScenarioRecord(ts, "run-d93-test", "cf-test", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(outDir + "/D93-01.json")
	if err != nil {
		t.Fatalf("D93-01.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse D93-01.json: %v", err)
	}

	// forge_calls must stay 0 — no campfire data, no tenant key.
	// The canary (canary_check_lane) will flag this run as suspect, which is correct.
	if rec.ForgeCalls != 0 {
		t.Errorf("forge_calls = %d, want 0 when campfire usage absent and no HTTP key", rec.ForgeCalls)
	}
}
