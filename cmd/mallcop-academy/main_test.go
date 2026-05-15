// Tests for mallcop-academy.
//
// Unit tests cover:
//   - findingTrackingID determinism
//   - payload composition (sanitized finding shape)
//   - watch-loop classification (terminal vs intermediate actions)
//   - per-scenario JSON record writing
//
// Integration tests use real isolated campfires (cf init + cf create) to verify:
//   - work:create message posted with correct tags
//   - synthetic work:close classified as terminal
//   - per-scenario JSON artifact written
//
// No cf primitives are mocked. All campfire interaction uses real cf binary
// calls against isolated campfire instances in t.TempDir().
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/internal/exam"
)

// ---- unit: findingTrackingID --------------------------------------------------

func TestFindingTrackingID_Deterministic(t *testing.T) {
	id1 := findingTrackingID("run-001", "AC-01")
	id2 := findingTrackingID("run-001", "AC-01")
	if id1 != id2 {
		t.Errorf("findingTrackingID not deterministic: %q vs %q", id1, id2)
	}
	// Must embed run-id and scenario-id.
	if !strings.Contains(id1, "run-001") {
		t.Errorf("findingTrackingID %q does not contain run-id", id1)
	}
	if !strings.Contains(id1, "AC-01") {
		t.Errorf("findingTrackingID %q does not contain scenario-id", id1)
	}
}

func TestFindingTrackingID_DifferentInputsDifferentOutputs(t *testing.T) {
	a := findingTrackingID("run-001", "AC-01")
	b := findingTrackingID("run-001", "AC-02")
	c := findingTrackingID("run-002", "AC-01")
	if a == b {
		t.Errorf("different scenario IDs produced same tracking ID: %q", a)
	}
	if a == c {
		t.Errorf("different run IDs produced same tracking ID: %q", a)
	}
}

// ---- unit: perRunFindingID — cross-run collision prevention (mallcoppro-73b) ---

// TestPerRunFindingID_DistinctAcrossRuns verifies that two scenarios sharing the
// same base YAML finding ID but different run IDs produce distinct tracked.findingID
// values, and that a bare (unsuffixed) finding ID does not match either.
//
// This is the regression guard for the cross-run finding-ID collision that caused
// work:output messages to be mis-attributed across bakeoff lanes sharing YAML
// scenario files.
func TestPerRunFindingID_DistinctAcrossRuns(t *testing.T) {
	const baseFindingID = "fnd_shk_005"

	id1 := perRunFindingID(baseFindingID, "bk-lane1")
	id2 := perRunFindingID(baseFindingID, "bk-lane2")

	if id1 == id2 {
		t.Errorf("same base finding ID with different run IDs produced the same perRunFindingID: %q", id1)
	}

	// A bare finding ID (no run suffix) must match neither suffixed form.
	if id1 == baseFindingID {
		t.Errorf("perRunFindingID(%q, %q) = %q equals the bare finding ID — not per-run-unique",
			baseFindingID, "bk-lane1", id1)
	}
	if id2 == baseFindingID {
		t.Errorf("perRunFindingID(%q, %q) = %q equals the bare finding ID — not per-run-unique",
			baseFindingID, "bk-lane2", id2)
	}
}

// TestAcademyMock_PerRunFindingID_TwoRunsSameYAML verifies the academy tracked map:
// when two scenarios share the same base YAML finding ID but are run under
// different run IDs, tracked.findingID is distinct for each and a work:output
// with the bare (unsuffixed) finding ID matches neither scenario.
func TestAcademyMock_PerRunFindingID_TwoRunsSameYAML(t *testing.T) {
	const baseFindingID = "fnd_shared_001"

	// Scenario SC-01 with finding.id = baseFindingID, run under run-alpha.
	scenDirA := t.TempDir()
	writeMinimalScenario(t, scenDirA, "SC-01", baseFindingID, "detector-shared",
		"Shared finding scenario", "medium")
	outDirA := t.TempDir()

	// Scenario SC-01 with finding.id = baseFindingID, run under run-beta.
	scenDirB := t.TempDir()
	writeMinimalScenario(t, scenDirB, "SC-01", baseFindingID, "detector-shared",
		"Shared finding scenario", "medium")
	outDirB := t.TempDir()

	// Run alpha: inject a work:output with the BARE finding ID (finding:fnd_shared_001).
	// This must NOT match the run-alpha scenario (since it's not suffixed).
	// Run alpha also gets its real terminal close by item_id.
	bareOutputPayload, _ := json.Marshal(map[string]interface{}{
		"finding_id": baseFindingID,
		"action":     "resolved",
	})
	// mock-msg-1 is the work:create ID for run alpha's SC-01.
	closeAlphaPayload, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-1",
		Action: "resolved",
		Skill:  "task:triage",
	})

	msAlpha := &mockSender{
		readMsgs: []cfMessage{
			// work:output with bare finding ID — must NOT match run-alpha's scenario.
			{
				ID:      "bare-output-msg",
				Tags:    []string{"work:output", "action:resolved", "finding:" + baseFindingID},
				Payload: string(bareOutputPayload),
			},
			// Real terminal close for alpha's SC-01 via item_id.
			{
				ID:      "close-alpha",
				Tags:    []string{"work:close", "action:resolved"},
				Payload: string(closeAlphaPayload),
			},
		},
	}

	argsAlpha := runArgs{
		targetCampfire: "cf-run-alpha",
		scenariosDir:   scenDirA,
		scenarioFilter: "SC-01",
		outputDir:      outDirA,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "run-alpha",
	}
	if err := academy(msAlpha, argsAlpha); err != nil {
		t.Fatalf("academy run-alpha: %v", err)
	}

	// Run beta: inject a work:output with the BARE finding ID.
	// mock-msg-1 is again the work:create ID (fresh sender) for run beta's SC-01.
	closeBetaPayload, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-1",
		Action: "escalated",
		Skill:  "task:triage",
	})

	msBeta := &mockSender{
		readMsgs: []cfMessage{
			// work:output with bare finding ID — must NOT match run-beta's scenario.
			{
				ID:      "bare-output-msg-2",
				Tags:    []string{"work:output", "action:resolved", "finding:" + baseFindingID},
				Payload: string(bareOutputPayload),
			},
			// Real terminal close for beta's SC-01 via item_id.
			{
				ID:      "close-beta",
				Tags:    []string{"work:close", "action:escalated"},
				Payload: string(closeBetaPayload),
			},
		},
	}

	argsBeta := runArgs{
		targetCampfire: "cf-run-beta",
		scenariosDir:   scenDirB,
		scenarioFilter: "SC-01",
		outputDir:      outDirB,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "run-beta",
	}
	if err := academy(msBeta, argsBeta); err != nil {
		t.Fatalf("academy run-beta: %v", err)
	}

	// Read run-alpha's SC-01.json.
	alphaData, err := os.ReadFile(fmt.Sprintf("%s/SC-01.json", outDirA))
	if err != nil {
		t.Fatalf("run-alpha SC-01.json not found: %v", err)
	}
	var alphaRec ScenarioRecord
	if err := json.Unmarshal(alphaData, &alphaRec); err != nil {
		t.Fatalf("parse run-alpha SC-01.json: %v", err)
	}

	// Read run-beta's SC-01.json.
	betaData, err := os.ReadFile(fmt.Sprintf("%s/SC-01.json", outDirB))
	if err != nil {
		t.Fatalf("run-beta SC-01.json not found: %v", err)
	}
	var betaRec ScenarioRecord
	if err := json.Unmarshal(betaData, &betaRec); err != nil {
		t.Fatalf("parse run-beta SC-01.json: %v", err)
	}

	// The finding_id in each record must be the suffixed form, not the bare ID.
	if alphaRec.FindingID == baseFindingID {
		t.Errorf("run-alpha finding_id = %q — must be per-run-suffixed, not bare", alphaRec.FindingID)
	}
	if betaRec.FindingID == baseFindingID {
		t.Errorf("run-beta finding_id = %q — must be per-run-suffixed, not bare", betaRec.FindingID)
	}

	// The two runs must have distinct finding IDs.
	if alphaRec.FindingID == betaRec.FindingID {
		t.Errorf("run-alpha and run-beta have identical finding_id %q — cross-run collision not prevented",
			alphaRec.FindingID)
	}

	// Alpha's terminal must come from the real close (mock-msg-1 / close-alpha),
	// NOT from the bare work:output. If the bare work:output had matched, terminal
	// action would be "resolved" from work:output rather than via item_id close.
	// Since the real close action is also "resolved", we check that finding_id is
	// the suffixed form and does NOT equal the bare finding ID (already checked above).
	//
	// Beta's terminal action must be "escalated" (from the real close), NOT
	// "resolved" (from the bare work:output).
	if betaRec.TerminalAction != "escalated" {
		t.Errorf("run-beta terminal_action = %q, want escalated — bare work:output may have matched incorrectly",
			betaRec.TerminalAction)
	}
	if alphaRec.TerminalAction != "resolved" {
		t.Errorf("run-alpha terminal_action = %q, want resolved", alphaRec.TerminalAction)
	}
}

// ---- unit: payload composition -----------------------------------------------

func TestPayloadComposition_FindingFields(t *testing.T) {
	s := &exam.Scenario{
		ID: "AC-01",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_ac_001",
			Detector: "detector-unusual-login",
			Title:    "Unusual login from new actor",
			Severity: "medium",
			EventIDs: []string{"evt-001", "evt-002"},
			Metadata: exam.FindingMetadata{"actor": "deploy-svc-new"},
		},
		ExpectedResolution: &exam.ExpectedResolution{
			ChainAction: "escalated",
		},
	}

	// Build payload the same way postFinding does.
	runID := "test-run"
	fid := findingTrackingID(runID, s.ID)
	// postFinding uses perRunFindingID for the finding payload ID (mallcoppro-73b).
	payloadFindingID := perRunFindingID(s.Finding.ID, runID)
	fp := findingPayload{
		ID:       payloadFindingID,
		Detector: s.Finding.Detector,
		Title:    s.Finding.Title,
		Severity: s.Finding.Severity,
		EventIDs: s.Finding.EventIDs,
		Metadata: filterAcademyMetadata(s.Finding.Metadata),
	}
	payload := academyFindingPayload{
		ID:      fid,
		Title:   s.Finding.Title,
		Skill:   "task:triage",
		Finding: fp,
		AcademyMetadata: academyMetadata{
			ScenarioID: s.ID,
			RunID:      runID,
			Expected:   s.ExpectedResolution,
		},
	}

	// ID must be the tracking ID.
	if payload.ID != fid {
		t.Errorf("payload.ID = %q, want %q", payload.ID, fid)
	}
	// Skill must be task:triage.
	if payload.Skill != "task:triage" {
		t.Errorf("payload.Skill = %q, want task:triage", payload.Skill)
	}
	// Finding ID must be the per-run-suffixed form (not the bare YAML finding ID).
	if payload.Finding.ID != payloadFindingID {
		t.Errorf("finding.ID = %q, want per-run-suffixed %q", payload.Finding.ID, payloadFindingID)
	}
	if payload.Finding.ID == s.Finding.ID {
		t.Errorf("finding.ID %q equals bare YAML finding ID — not per-run-unique", payload.Finding.ID)
	}
	// Finding must carry original fields.
	if payload.Finding.Detector != "detector-unusual-login" {
		t.Errorf("finding.Detector = %q, want detector-unusual-login", payload.Finding.Detector)
	}
	if len(payload.Finding.EventIDs) != 2 {
		t.Errorf("finding.EventIDs len = %d, want 2", len(payload.Finding.EventIDs))
	}
	// AcademyMetadata must carry scenario_id, run_id, expected.
	if payload.AcademyMetadata.ScenarioID != "AC-01" {
		t.Errorf("academy_metadata.scenario_id = %q, want AC-01", payload.AcademyMetadata.ScenarioID)
	}
	if payload.AcademyMetadata.Expected == nil {
		t.Error("academy_metadata.expected must not be nil")
	} else if payload.AcademyMetadata.Expected.ChainAction != "escalated" {
		t.Errorf("expected.chain_action = %q, want escalated", payload.AcademyMetadata.Expected.ChainAction)
	}

	// Must marshal cleanly.
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if len(b) == 0 {
		t.Error("marshalled payload is empty")
	}
}

// ---- unit: terminal action classification ------------------------------------

func TestTerminalActions_KnownValues(t *testing.T) {
	terminal := []string{"resolved", "escalated", "remediated", "false-positive", "closed"}
	for _, a := range terminal {
		if !terminalActions[a] {
			t.Errorf("action %q should be terminal", a)
		}
	}
}

func TestTerminalActions_IntermediateNotTerminal(t *testing.T) {
	intermediate := []string{"created", "updated", "in-progress", "work:create", ""}
	for _, a := range intermediate {
		if terminalActions[a] {
			t.Errorf("action %q should not be terminal", a)
		}
	}
}

// ---- unit: hasTag helper ------------------------------------------------------

func TestHasTag(t *testing.T) {
	tags := []string{"work:close", "action:resolved", "run:abc"}
	if !hasTag(tags, "work:close") {
		t.Error("hasTag: should find work:close")
	}
	if hasTag(tags, "work:create") {
		t.Error("hasTag: should not find work:create")
	}
	if hasTag(nil, "any") {
		t.Error("hasTag: nil tags should return false")
	}
}

// ---- unit: scenario record writing -------------------------------------------

func TestWriteScenarioRecord_Terminal(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()
	termAt := now.Add(5 * time.Second)

	ts := &trackedScenario{
		scenarioID:     "AC-01",
		findingID:      "academy-run-001-AC-01",
		workItemID:     "msg-abc123",
		postedAt:       now,
		chain:          []ChainEntry{{ItemID: "msg-abc123", Skill: "task:triage"}, {ItemID: "item-xyz", Action: "resolved"}},
		terminal:       true,
		terminalAt:     termAt,
		terminalAction: "resolved",
		terminalItemID: "item-xyz",
	}

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	recordPath := filepath.Join(outDir, "AC-01.json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}
	if rec.ScenarioID != "AC-01" {
		t.Errorf("scenario_id = %q, want AC-01", rec.ScenarioID)
	}
	if rec.FindingID != "academy-run-001-AC-01" {
		t.Errorf("finding_id = %q, want academy-run-001-AC-01", rec.FindingID)
	}
	if rec.TerminalAction != "resolved" {
		t.Errorf("terminal_action = %q, want resolved", rec.TerminalAction)
	}
	if rec.TerminalItemID != "item-xyz" {
		t.Errorf("terminal_item_id = %q, want item-xyz", rec.TerminalItemID)
	}
	if rec.WallSeconds <= 0 {
		t.Errorf("wall_seconds = %f, want > 0", rec.WallSeconds)
	}
	if rec.TerminalAt == nil {
		t.Error("terminal_at must be non-nil for terminal scenario")
	}
	if len(rec.FullChain) != 2 {
		t.Errorf("full_chain len = %d, want 2", len(rec.FullChain))
	}
}

func TestWriteScenarioRecord_NonTerminal(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()

	ts := &trackedScenario{
		scenarioID: "AC-02",
		findingID:  "academy-run-001-AC-02",
		workItemID: "msg-def456",
		postedAt:   now,
		chain:      []ChainEntry{{ItemID: "msg-def456", Skill: "task:triage"}},
	}

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "AC-02.json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.TerminalAt != nil {
		t.Error("terminal_at should be nil for non-terminal scenario")
	}
	if rec.TerminalAction != "" {
		t.Errorf("terminal_action should be empty, got %q", rec.TerminalAction)
	}
}

// ---- unit: run.json writing ---------------------------------------------------

func TestWriteRunJSON(t *testing.T) {
	outDir := t.TempDir()
	rec := RunRecord{
		RunID:          "acad-12345",
		TargetCampfire: "cf-abc",
		ScenariosDir:   "/some/dir",
		JudgeModel:     "claude-haiku-4-5",
		BudgetUSD:      10.0,
		MaxConcurrent:  4,
		Timeout:        "30m",
		StartedAt:      time.Now(),
	}
	if err := writeJSON(filepath.Join(outDir, "run.json"), rec); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var parsed RunRecord
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse run.json: %v", err)
	}
	if parsed.RunID != "acad-12345" {
		t.Errorf("run_id = %q, want acad-12345", parsed.RunID)
	}
	if parsed.JudgeModel != "claude-haiku-4-5" {
		t.Errorf("judge_model = %q, want claude-haiku-4-5", parsed.JudgeModel)
	}
}

// ---- mock Sender for unit tests ----------------------------------------------

// mockSender records calls without touching a real campfire.
type mockSender struct {
	mu       sync.Mutex
	sends    []mockSendCall
	readMsgs []cfMessage
	nextID   int
}

type mockSendCall struct {
	campfireID string
	payload    string
	tags       []string
	returnID   string
}

func (m *mockSender) send(campfireID, payload string, tags []string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	id := fmt.Sprintf("mock-msg-%d", m.nextID)
	m.sends = append(m.sends, mockSendCall{campfireID: campfireID, payload: payload, tags: tags, returnID: id})
	return id, nil
}

func (m *mockSender) readAll(campfireID string) ([]cfMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]cfMessage, len(m.readMsgs))
	copy(out, m.readMsgs)
	return out, nil
}

// ---- unit: academy with mock sender ------------------------------------------

func TestAcademyMock_PostsWorkCreate(t *testing.T) {
	// Build a minimal scenario YAML in a temp dir.
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AC-01", "fnd_ac_001", "detector-new-actor",
		"New actor observed: deploy-svc-new", "medium")

	outDir := t.TempDir()
	ms := &mockSender{
		readMsgs: []cfMessage{
			// Simulate a work:close terminal message that arrives after posting.
			// The close references the work:create message ID which we'll fill in.
		},
	}

	// We'll do a short-timeout run; mock sender returns no close messages → timeout.
	args := runArgs{
		targetCampfire: "cf-mock-target",
		scenariosDir:   scenDir,
		scenarioFilter: "AC-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        100 * time.Millisecond, // very short for mock test
		runID:          "test-mock-run",
	}

	err := academy(ms, args)
	if err != nil {
		t.Fatalf("academy: %v", err)
	}

	// One work:create must have been sent.
	ms.mu.Lock()
	nSends := len(ms.sends)
	ms.mu.Unlock()
	if nSends != 1 {
		t.Errorf("expected 1 work:create send, got %d", nSends)
	}

	ms.mu.Lock()
	call := ms.sends[0]
	ms.mu.Unlock()

	if call.campfireID != "cf-mock-target" {
		t.Errorf("send campfireID = %q, want cf-mock-target", call.campfireID)
	}
	if !contains(call.tags, "work:create") {
		t.Errorf("send tags missing work:create; got %v", call.tags)
	}
	if !contains(call.tags, "task:triage") {
		t.Errorf("send tags missing task:triage; got %v", call.tags)
	}
	if !contains(call.tags, "academy:scenario") {
		t.Errorf("send tags missing academy:scenario; got %v", call.tags)
	}

	// Payload must be valid JSON with skill=task:triage.
	var p academyFindingPayload
	if err := json.Unmarshal([]byte(call.payload), &p); err != nil {
		t.Fatalf("parse send payload: %v", err)
	}
	if p.Skill != "task:triage" {
		t.Errorf("payload.skill = %q, want task:triage", p.Skill)
	}
	if p.AcademyMetadata.ScenarioID != "AC-01" {
		t.Errorf("academy_metadata.scenario_id = %q, want AC-01", p.AcademyMetadata.ScenarioID)
	}

	// run.json must exist.
	if _, err := os.Stat(filepath.Join(outDir, "run.json")); err != nil {
		t.Errorf("run.json not found: %v", err)
	}
	// Partial scenario record written (non-terminal because mock returned no closes).
	if _, err := os.Stat(filepath.Join(outDir, "AC-01.json")); err != nil {
		t.Errorf("AC-01.json not found: %v", err)
	}
}

func TestAcademyMock_TerminalCloseWritesRecord(t *testing.T) {
	// Build a minimal scenario YAML.
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AC-02", "fnd_ac_002", "detector-priv-escalation",
		"Privilege escalation detected", "high")

	outDir := t.TempDir()

	// Mock sender that returns a close message after we know the send ID.
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target",
		scenariosDir:   scenDir,
		scenarioFilter: "AC-02",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-mock-run-2",
	}

	// Run academy in a goroutine; once we see the send, inject the close message.
	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

	// Wait until the work:create is sent, then inject the terminal close.
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

	// Inject a terminal work:close message.
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "resolved",
		Skill:  "task:triage",
	})
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-msg-001",
		Tags:    []string{"work:close", "action:resolved"},
		Payload: string(closePayloadBytes),
	})
	ms.mu.Unlock()

	// Wait for academy to finish.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("academy did not complete within deadline")
	}

	// AC-02.json must exist and be terminal.
	data, err := os.ReadFile(filepath.Join(outDir, "AC-02.json"))
	if err != nil {
		t.Fatalf("AC-02.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse AC-02.json: %v", err)
	}
	if rec.TerminalAction != "resolved" {
		t.Errorf("terminal_action = %q, want resolved", rec.TerminalAction)
	}
	if rec.TerminalAt == nil {
		t.Error("terminal_at must not be nil")
	}
}

// ---- integration: real isolated campfire -------------------------------------

// requireCF skips the test if the cf binary is not on PATH.
func requireCF(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skip("cf binary not found on PATH — skipping real campfire integration tests")
	}
	return p
}

// newIsolatedCampfire creates a fresh CF_HOME + campfire in a temp dir.
func newIsolatedCampfire(t *testing.T, cfBin string) (cfHome, campfireID string) {
	t.Helper()
	cfHome = t.TempDir()

	// cf init
	cmd := exec.Command(cfBin, "init")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cf init: %v\n%s", err, out)
	}

	// cf create
	cmd = exec.Command(cfBin, "create", "--description", "academy-test-"+t.Name())
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cf create: %v\n%s", err, out)
	}

	// Extract 64-char hex ID from output.
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isHex(line) {
			campfireID = line
			break
		}
	}
	if campfireID == "" {
		t.Fatalf("could not parse campfire ID from: %s", out)
	}
	return cfHome, campfireID
}

// cfSendRaw sends a message via cf send and returns the parsed cfMessage.
func cfSendRaw(t *testing.T, cfBin, cfHome, campfireID, payload string, tags []string) cfMessage {
	t.Helper()
	args := []string{"send", campfireID, payload, "--json"}
	for _, tag := range tags {
		args = append(args, "--tag", tag)
	}
	cmd := exec.Command(cfBin, args...)
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cf send: %v\nout: %s", err, out)
	}
	var msg cfMessage
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatalf("parse cf send output: %v\nraw: %s", err, out)
	}
	return msg
}

// cfReadAll reads all messages from the campfire.
func cfReadAll(t *testing.T, cfBin, cfHome, campfireID string) []cfMessage {
	t.Helper()
	cmd := exec.Command(cfBin, "read", campfireID, "--json", "--all")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var msgs []cfMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		t.Logf("cf read parse error: %v; raw: %s", err, out)
		return nil
	}
	return msgs
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// TestAcademyIntegration_RealCampfire verifies that academy:
//  1. Posts a work:create to the real campfire with the correct tags.
//  2. Classifies a synthetic work:close as terminal.
//  3. Writes a per-scenario JSON artifact.
func TestAcademyIntegration_RealCampfire(t *testing.T) {
	cfBin := requireCF(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	// Build a minimal scenario YAML.
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AC-01", "fnd_ac_001", "detector-new-actor",
		"New actor observed: deploy-svc-new", "medium")

	outDir := t.TempDir()

	// Use a real cfSender pointed at the isolated campfire.
	sender := &cfSender{cfBin: cfBin, cfHome: cfHome}

	args := runArgs{
		targetCampfire: campfireID,
		scenariosDir:   scenDir,
		scenarioFilter: "AC-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        10 * time.Second,
		runID:          "integ-test-001",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(sender, args)
	}()

	// Wait for the work:create to appear in the campfire.
	var sentMsgID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		msgs := cfReadAll(t, cfBin, cfHome, campfireID)
		for _, msg := range msgs {
			if hasTag(msg.Tags, "work:create") {
				sentMsgID = msg.ID
				break
			}
		}
		if sentMsgID != "" {
			break
		}
	}
	if sentMsgID == "" {
		t.Fatal("academy never posted work:create to real campfire within timeout")
	}

	// Verify tags on the work:create message.
	msgs := cfReadAll(t, cfBin, cfHome, campfireID)
	var workCreateMsg *cfMessage
	for i := range msgs {
		if msgs[i].ID == sentMsgID {
			workCreateMsg = &msgs[i]
			break
		}
	}
	if workCreateMsg == nil {
		t.Fatal("could not find work:create message by ID")
	}
	for _, want := range []string{"work:create", "task:triage", "academy:scenario", "scenario:AC-01"} {
		if !hasTag(workCreateMsg.Tags, want) {
			t.Errorf("work:create message missing tag %q; got %v", want, workCreateMsg.Tags)
		}
	}

	// Verify payload is valid JSON with skill=task:triage.
	var p academyFindingPayload
	if err := json.Unmarshal([]byte(workCreateMsg.Payload), &p); err != nil {
		t.Fatalf("parse work:create payload: %v", err)
	}
	if p.Skill != "task:triage" {
		t.Errorf("payload.skill = %q, want task:triage", p.Skill)
	}
	trackingID := findingTrackingID("integ-test-001", "AC-01")
	if p.ID != trackingID {
		t.Errorf("payload.id = %q, want %q", p.ID, trackingID)
	}

	// Assert that Finding.ID is the per-run-suffixed form, not the bare YAML finding ID.
	expectedFindingID := perRunFindingID("fnd_ac_001", "integ-test-001")
	if p.Finding.ID != expectedFindingID {
		t.Errorf("Finding.ID = %q, want %q (per-run suffix required)", p.Finding.ID, expectedFindingID)
	}

	// Post a synthetic work:close referencing the sent message ID.
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: sentMsgID,
		Action: "resolved",
		Skill:  "task:triage",
	})
	cfSendRaw(t, cfBin, cfHome, campfireID, string(closePayloadBytes),
		[]string{"work:close", "action:resolved"})

	// Wait for academy to finish (it should detect terminal close).
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("academy did not complete within deadline after terminal close")
	}

	// run.json must exist.
	runJSON := filepath.Join(outDir, "run.json")
	if _, err := os.Stat(runJSON); err != nil {
		t.Errorf("run.json not found: %v", err)
	}
	runData, err := os.ReadFile(runJSON)
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var runRec RunRecord
	if err := json.Unmarshal(runData, &runRec); err != nil {
		t.Fatalf("parse run.json: %v", err)
	}
	if runRec.RunID != "integ-test-001" {
		t.Errorf("run.json run_id = %q, want integ-test-001", runRec.RunID)
	}
	if runRec.TargetCampfire != campfireID {
		t.Errorf("run.json target_campfire = %q, want %q", runRec.TargetCampfire, campfireID)
	}

	// Per-scenario JSON must exist and be terminal.
	scenJSON := filepath.Join(outDir, "AC-01.json")
	if _, err := os.Stat(scenJSON); err != nil {
		t.Errorf("AC-01.json not found: %v", err)
	}
	scenData, err := os.ReadFile(scenJSON)
	if err != nil {
		t.Fatalf("read AC-01.json: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(scenData, &rec); err != nil {
		t.Fatalf("parse AC-01.json: %v", err)
	}
	if rec.ScenarioID != "AC-01" {
		t.Errorf("scenario_id = %q, want AC-01", rec.ScenarioID)
	}
	if rec.TerminalAction != "resolved" {
		t.Errorf("terminal_action = %q, want resolved", rec.TerminalAction)
	}
	if rec.TerminalAt == nil {
		t.Error("terminal_at must not be nil")
	}
	if rec.WallSeconds <= 0 {
		t.Errorf("wall_seconds = %f, want > 0", rec.WallSeconds)
	}
	if len(rec.FullChain) == 0 {
		t.Error("full_chain must not be empty")
	}
}

// ---- unit: loadScenarios --scenario-prefix filter (mallcoppro-bab) -----------

// TestLoadScenarios_PrefixFilter verifies that --scenario-prefix filters
// scenarios by the comma-separated prefix list. Real YAML files are written
// and loaded via exam.Load — no mocks.
func TestLoadScenarios_PrefixFilter(t *testing.T) {
	dir := t.TempDir()
	// Write scenarios with various prefixes.
	writeMinimalScenario(t, dir, "PE-01", "fnd-pe-01", "detector-priv-escalation", "Priv escalation", "high")
	writeMinimalScenario(t, dir, "PE-02", "fnd-pe-02", "detector-priv-escalation", "Priv escalation 2", "medium")
	writeMinimalScenario(t, dir, "IP-01", "fnd-ip-01", "detector-injection-probe", "Injection probe", "high")
	writeMinimalScenario(t, dir, "LFD-01", "fnd-lfd-01", "detector-log-format-drift", "Log format drift", "low")
	writeMinimalScenario(t, dir, "AC-01", "fnd-ac-01", "detector-unusual-login", "Unusual login", "medium")
	writeMinimalScenario(t, dir, "AF-01", "fnd-af-01", "detector-rate-anomaly", "Auth failure", "low")

	tests := []struct {
		name      string
		filter    string
		prefix    string
		wantCount int
		wantIDs   []string
	}{
		{
			name:      "no filter no prefix — all 6",
			wantCount: 6,
		},
		{
			name:      "single prefix PE — 2 scenarios",
			prefix:    "PE",
			wantCount: 2,
			wantIDs:   []string{"PE-01", "PE-02"},
		},
		{
			name:      "multi-prefix PE,IP,LFD — 4 scenarios",
			prefix:    "PE,IP,LFD",
			wantCount: 4,
			wantIDs:   []string{"PE-01", "PE-02", "IP-01", "LFD-01"},
		},
		{
			name:      "prefix with spaces trimmed",
			prefix:    " PE , IP ",
			wantCount: 3,
			wantIDs:   []string{"PE-01", "PE-02", "IP-01"},
		},
		{
			name:      "exact filter overrides prefix — returns one",
			filter:    "AC-01",
			prefix:    "PE",
			wantCount: 1,
			wantIDs:   []string{"AC-01"},
		},
		{
			name:      "prefix matching no scenarios — returns empty",
			prefix:    "ZZ",
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadScenarios(dir, tc.filter, tc.prefix)
			if err != nil {
				t.Fatalf("loadScenarios: %v", err)
			}
			if len(got) != tc.wantCount {
				ids := make([]string, len(got))
				for i, s := range got {
					ids[i] = s.ID
				}
				t.Errorf("loadScenarios count = %d, want %d; got IDs: %v", len(got), tc.wantCount, ids)
			}
			for _, wantID := range tc.wantIDs {
				found := false
				for _, s := range got {
					if s.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					ids := make([]string, len(got))
					for i, s := range got {
						ids[i] = s.ID
					}
					t.Errorf("expected scenario %q not found in results: %v", wantID, ids)
				}
			}
		})
	}
}

// TestRunArgs_ScenarioPrefix_WrittenToRunJSON verifies that the scenario_prefix
// field from runArgs is written to run.json for observability.
// Uses a mock sender — no real campfire required.
func TestRunArgs_ScenarioPrefix_WrittenToRunJSON(t *testing.T) {
	dir := t.TempDir()
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "PE-01", "fnd-pe-01", "detector-priv-escalation", "Priv escalation", "high")

	// Provide a terminal close so academy exits without timing out.
	// The work:create message is mock-msg-1; the close references it.
	closeJSON, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-1",
		Action: "resolved",
		Skill:  "task:triage",
	})
	ms := &mockSender{
		readMsgs: []cfMessage{
			{
				ID:      "close-msg-1",
				Tags:    []string{"work:close"},
				Payload: string(closeJSON),
			},
		},
	}

	args := runArgs{
		targetCampfire: "test-campfire-prefix",
		scenariosDir:   scenDir,
		scenarioFilter: "PE-01",
		scenarioPrefix: "PE,IP,LFD",
		outputDir:      dir,
		maxConcurrent:  1,
		timeout:        2 * time.Second,
		runID:          "run-prefix-test",
	}
	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	// Verify run.json contains scenario_prefix.
	runData, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var rec RunRecord
	if err := json.Unmarshal(runData, &rec); err != nil {
		t.Fatalf("parse run.json: %v", err)
	}
	if rec.ScenarioPrefix != "PE,IP,LFD" {
		t.Errorf("run.json scenario_prefix = %q, want %q", rec.ScenarioPrefix, "PE,IP,LFD")
	}
}

// ---- regression: work:create with no chain antecedent must not be assigned (mallcoppro-647) ----

// TestWorkItemToScenario_RequiresChainLink verifies that a work:create message
// whose workCreateID has no known antecedent in any tracked scenario's chain is
// not assigned to any scenario. This is the regression test for mallcoppro-647:
// the old "first non-terminal" fallback assigned foreign work:create items to
// arbitrary scenarios, causing spurious terminal attributions.
//
// Test shape:
//  1. Two scenarios (AC-03, AC-04) are posted; mock sender assigns them IDs
//     mock-msg-1 and mock-msg-2.
//  2. readAll returns:
//     a. A foreign work:create with workCreateID="totally-unrelated-id" —
//        not in either scenario's chain.
//     b. A terminal work:close with item_id="totally-unrelated-id" (action=resolved).
//     c. Real terminal closes for AC-03 (item_id=mock-msg-1) and AC-04
//        (item_id=mock-msg-2).
//  3. Expected: AC-03 and AC-04 both reach terminal via their own closes;
//     the foreign close does NOT cause either scenario to mark terminal
//     prematurely or record a spurious chain entry with
//     item_id="totally-unrelated-id".
//
// The assertion is: each scenario's full_chain must NOT contain the foreign
// workCreateID, and the terminal_item_id must be the scenario's own close item.
func TestWorkItemToScenario_RequiresChainLink(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AC-03", "fnd_ac_003", "detector-new-actor-03",
		"New actor 03", "medium")
	writeMinimalScenario(t, scenDir, "AC-04", "fnd_ac_004", "detector-new-actor-04",
		"New actor 04", "medium")

	outDir := t.TempDir()

	// The mock sender assigns IDs sequentially: AC-03→mock-msg-1, AC-04→mock-msg-2.
	// We inject readMsgs BEFORE academy starts so the watch loop sees all messages
	// in its first readAll poll.
	//
	// Foreign work:create: workCreateID="totally-unrelated-id", msg.ID="foreign-msg-1".
	// Foreign close: item_id="totally-unrelated-id", action=resolved (terminal).
	// Real close AC-03: item_id="mock-msg-1", action=resolved.
	// Real close AC-04: item_id="mock-msg-2", action=resolved.
	foreignWorkCreatePayload, _ := json.Marshal(map[string]interface{}{
		"id":    "totally-unrelated-id",
		"skill": "task:triage",
		"title": "foreign finding from a different run",
	})
	foreignClosePayload, _ := json.Marshal(closePayload{
		ItemID: "totally-unrelated-id",
		Action: "resolved",
		Skill:  "task:triage",
	})
	closeAC03Payload, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-1",
		Action: "resolved",
		Skill:  "task:triage",
	})
	closeAC04Payload, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-2",
		Action: "resolved",
		Skill:  "task:triage",
	})

	ms := &mockSender{
		readMsgs: []cfMessage{
			// Foreign work:create — no antecedent in any scenario's chain.
			{
				ID:      "foreign-msg-1",
				Tags:    []string{"work:create", "task:triage"},
				Payload: string(foreignWorkCreatePayload),
			},
			// Foreign terminal close — references the foreign workCreateID.
			// Must NOT be attributed to AC-03 or AC-04.
			{
				ID:      "foreign-close-1",
				Tags:    []string{"work:close", "action:resolved"},
				Payload: string(foreignClosePayload),
			},
			// Real terminal closes for the two academy scenarios.
			{
				ID:      "close-ac03",
				Tags:    []string{"work:close", "action:resolved"},
				Payload: string(closeAC03Payload),
			},
			{
				ID:      "close-ac04",
				Tags:    []string{"work:close", "action:resolved"},
				Payload: string(closeAC04Payload),
			},
		},
	}

	args := runArgs{
		targetCampfire: "cf-chain-link-test",
		scenariosDir:   scenDir,
		outputDir:      outDir,
		maxConcurrent:  2,
		timeout:        5 * time.Second,
		runID:          "chain-link-test",
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	// Read AC-03.json.
	ac03Data, err := os.ReadFile(filepath.Join(outDir, "AC-03.json"))
	if err != nil {
		t.Fatalf("AC-03.json not found: %v", err)
	}
	var ac03Rec ScenarioRecord
	if err := json.Unmarshal(ac03Data, &ac03Rec); err != nil {
		t.Fatalf("parse AC-03.json: %v", err)
	}

	// Read AC-04.json.
	ac04Data, err := os.ReadFile(filepath.Join(outDir, "AC-04.json"))
	if err != nil {
		t.Fatalf("AC-04.json not found: %v", err)
	}
	var ac04Rec ScenarioRecord
	if err := json.Unmarshal(ac04Data, &ac04Rec); err != nil {
		t.Fatalf("parse AC-04.json: %v", err)
	}

	// Both scenarios must be terminal via their own closes (not the foreign one).
	// The terminal_item_id must be one of the academy-posted work:create IDs
	// (mock-msg-1 or mock-msg-2), never the foreign workCreateID.
	const foreignWorkCreateID = "totally-unrelated-id"
	const foreignMsgID = "foreign-msg-1"

	if ac03Rec.TerminalAction != "resolved" {
		t.Errorf("AC-03 terminal_action = %q, want resolved", ac03Rec.TerminalAction)
	}
	if ac03Rec.TerminalAt == nil {
		t.Error("AC-03 terminal_at must not be nil")
	}
	if ac03Rec.TerminalItemID == foreignWorkCreateID || ac03Rec.TerminalItemID == foreignMsgID {
		t.Errorf("AC-03 terminal_item_id = %q — must not be the foreign item ID (chain-link guard failed)",
			ac03Rec.TerminalItemID)
	}

	if ac04Rec.TerminalAction != "resolved" {
		t.Errorf("AC-04 terminal_action = %q, want resolved", ac04Rec.TerminalAction)
	}
	if ac04Rec.TerminalAt == nil {
		t.Error("AC-04 terminal_at must not be nil")
	}
	if ac04Rec.TerminalItemID == foreignWorkCreateID || ac04Rec.TerminalItemID == foreignMsgID {
		t.Errorf("AC-04 terminal_item_id = %q — must not be the foreign item ID (chain-link guard failed)",
			ac04Rec.TerminalItemID)
	}

	// Neither scenario's full_chain must contain the foreign workCreateID.
	for _, rec := range []ScenarioRecord{ac03Rec, ac04Rec} {
		for _, ce := range rec.FullChain {
			if ce.ItemID == foreignWorkCreateID || ce.ItemID == foreignMsgID {
				t.Errorf("scenario %s full_chain contains foreign item %q — chain-link guard failed",
					rec.ScenarioID, ce.ItemID)
			}
		}
	}
}

// ---- unit: time-window filtering (mallcoppro-f6b) ----------------------------

// TestWatchLoop_TimeWindowFilter verifies that the watch loop's time-window guard
// skips messages whose timestamps are outside [runPostedAtMin-5s, runDeadline+5s].
//
// Test shape:
//   - One scenario (TW-01) posted via mock sender.
//   - readAll returns 5 synthetic cfMessages:
//     1. In-window work:create (chain extension — Timestamp = now)
//     2. In-window work:output with action:noted — Timestamp = now
//     3. In-window work:close action=resolved referencing the scenario's msg ID — Timestamp = now
//     4. Out-of-window (before): Timestamp = now - 1 hour → must be skipped
//     5. Out-of-window (after):  Timestamp = now + 2 hours → must be skipped
//
// Assertions:
//   - TW-01 reaches terminal via the in-window work:close.
//   - The out-of-window messages do not affect the result:
//     the scenario's chain does NOT contain the out-of-window item IDs.
//
// The out-of-window messages reference different item IDs so we can assert their
// absence from full_chain independently of deduplication.
func TestWatchLoop_TimeWindowFilter(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "TW-01", "fnd_tw_001", "detector-time-window",
		"Time window filter test", "medium")

	outDir := t.TempDir()

	now := time.Now()
	// The mock sender will assign "mock-msg-1" to the TW-01 work:create.
	// runPostedAtMin will be set to approximately now.UnixNano() after posting.
	// Window: [now-5s, now+timeout+5s]. Use timeout=2s → window=[now-5s, now+7s].
	inWindowTs := now.UnixNano()                          // within window
	beforeWindowTs := now.Add(-1 * time.Hour).UnixNano() // 1h before — outside window
	afterWindowTs := now.Add(2 * time.Hour).UnixNano()   // 2h after  — outside window (> deadline+5s)

	// In-window work:create (chain extension for a hypothetical escalation step).
	// References "in-window-chain-id" as its id. Should be processed by the
	// work:create map-building loop and registered.
	inWindowCreatePayload, _ := json.Marshal(map[string]interface{}{
		"id":    "mock-msg-1", // same id as the posted scenario — extends chain
		"skill": "task:investigate",
		"title": "investigate step",
	})
	// In-window work:output with action:noted.
	inWindowOutputPayload, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-1",
		Action: "noted",
		Skill:  "task:triage",
	})
	// In-window terminal work:close.
	inWindowClosePayload, _ := json.Marshal(closePayload{
		ItemID: "mock-msg-1",
		Action: "resolved",
		Skill:  "task:triage",
	})
	// Out-of-window (before) close. References a distinct item ID so we can assert
	// its absence from full_chain.
	outBeforePayload, _ := json.Marshal(closePayload{
		ItemID: "out-before-item",
		Action: "resolved",
		Skill:  "task:triage",
	})
	// Out-of-window (after) close. References another distinct item ID.
	outAfterPayload, _ := json.Marshal(closePayload{
		ItemID: "out-after-item",
		Action: "resolved",
		Skill:  "task:triage",
	})

	ms := &mockSender{
		readMsgs: []cfMessage{
			// 1. In-window work:create
			{
				ID:        "in-create-1",
				Tags:      []string{"work:create", "task:investigate"},
				Payload:   string(inWindowCreatePayload),
				Timestamp: inWindowTs,
			},
			// 2. In-window work:output
			{
				ID:        "in-output-1",
				Tags:      []string{"work:output", "action:noted"},
				Payload:   string(inWindowOutputPayload),
				Timestamp: inWindowTs,
			},
			// 3. In-window work:close (terminal)
			{
				ID:        "in-close-1",
				Tags:      []string{"work:close", "action:resolved"},
				Payload:   string(inWindowClosePayload),
				Timestamp: inWindowTs,
			},
			// 4. Out-of-window (before) — must be skipped
			{
				ID:        "out-before-1",
				Tags:      []string{"work:close", "action:resolved"},
				Payload:   string(outBeforePayload),
				Timestamp: beforeWindowTs,
			},
			// 5. Out-of-window (after) — must be skipped
			{
				ID:        "out-after-1",
				Tags:      []string{"work:close", "action:resolved"},
				Payload:   string(outAfterPayload),
				Timestamp: afterWindowTs,
			},
		},
	}

	args := runArgs{
		targetCampfire: "cf-tw-test",
		scenariosDir:   scenDir,
		scenarioFilter: "TW-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        2 * time.Second,
		runID:          "tw-test-run",
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	// TW-01 must be terminal (reached via in-window work:close).
	data, err := os.ReadFile(filepath.Join(outDir, "TW-01.json"))
	if err != nil {
		t.Fatalf("TW-01.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse TW-01.json: %v", err)
	}
	if rec.TerminalAction != "resolved" {
		t.Errorf("TW-01 terminal_action = %q, want resolved (in-window close must process)", rec.TerminalAction)
	}
	if rec.TerminalAt == nil {
		t.Error("TW-01 terminal_at must not be nil — in-window close must mark terminal")
	}

	// Out-of-window item IDs must NOT appear in full_chain.
	for _, ce := range rec.FullChain {
		if ce.ItemID == "out-before-item" {
			t.Errorf("full_chain contains out-of-window (before) item ID %q — time-window filter failed", ce.ItemID)
		}
		if ce.ItemID == "out-after-item" {
			t.Errorf("full_chain contains out-of-window (after) item ID %q — time-window filter failed", ce.ItemID)
		}
	}
}

// ---- helpers -----------------------------------------------------------------

// writeMinimalScenario writes a minimal scenario YAML to dir/<id>.yaml.
// All string fields are quoted to avoid YAML parse issues with spaces/colons.
func writeMinimalScenario(t *testing.T, dir, id, findingID, detector, title, severity string) {
	t.Helper()
	content := fmt.Sprintf(`id: %s
failure_mode: test
detector: %s
category: test
difficulty: easy
finding:
  id: %s
  detector: %s
  title: %q
  severity: %s
  event_ids: [evt-001]
events:
  - id: evt-001
    timestamp: "2026-01-01T00:00:00Z"
    source: github
    event_type: push
    actor: deploy-svc-new
    action: push
    target: repo/main
    severity: medium
baseline:
  known_entities:
    actors: [deploy-svc]
    sources: [github]
expected:
  chain_action: escalated
  triage_action: escalate
`, id, detector, findingID, detector, title, severity)
	if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write scenario YAML: %v", err)
	}
}

// contains checks if s is in slice.
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
