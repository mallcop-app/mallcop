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
