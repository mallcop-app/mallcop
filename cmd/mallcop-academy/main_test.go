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
	"syscall"
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
	// References "mock-msg-1" as its id. Should be processed by the
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
	if rec.TerminalItemID == "" {
		t.Error("terminal_item_id must be populated when in-window close arrives")
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

// ---- regression: SIGTERM partial-flush (mallcoppro-627) ----------------------

// TestAcademySIGTERM verifies that when academy receives SIGTERM mid-run:
//  1. All posted scenarios produce a JSON file (even if non-terminal).
//  2. Non-terminal scenarios get a terminal_action of "" (partial/unresolved record).
//  3. The process exits cleanly (exit code 0).
//
// This test spawns a subprocess (using the test binary itself) to safely test
// SIGTERM without killing the test runner. The subprocess runs
// TestAcademySIGTERM_Subprocess which starts academy in-process, waits for
// work:create posts to complete, writes a sentinel file, then blocks until
// SIGTERM arrives (from the parent test). The parent verifies JSON files exist.
func TestAcademySIGTERM(t *testing.T) {
	if os.Getenv("ACADEMY_SIGTERM_SUBPROCESS") == "1" {
		// Guard: if this is already the subprocess, skip to avoid recursion.
		t.Skip("subprocess marker present — skip to avoid recursion")
	}

	outDir := t.TempDir()
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "SIG-01", "fnd_sig_001", "detector-sigterm-test",
		"SIGTERM test finding 1", "medium")
	writeMinimalScenario(t, scenDir, "SIG-02", "fnd_sig_002", "detector-sigterm-test",
		"SIGTERM test finding 2", "low")

	// Build the test binary from the current package directory.
	pkgDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	binPath := filepath.Join(t.TempDir(), "academy-sigterm-test")
	buildCmd := exec.Command("go", "test", "-c", "-o", binPath, pkgDir)
	buildCmd.Env = os.Environ()
	if out, buildErr := buildCmd.CombinedOutput(); buildErr != nil {
		t.Fatalf("build test binary: %v\n%s", buildErr, out)
	}

	sentinelPath := filepath.Join(outDir, "READY")

	// Run the subprocess test that starts academy with a long timeout (will be
	// killed by SIGTERM before it times out naturally).
	cmd := exec.Command(binPath,
		"-test.run=TestAcademySIGTERM_Subprocess",
		"-test.v",
		"-test.timeout=60s",
	)
	cmd.Env = append(os.Environ(),
		"ACADEMY_SIGTERM_SUBPROCESS=1",
		"ACADEMY_SIGTERM_TEST_DIR="+outDir,
		"ACADEMY_SIGTERM_SCEN_DIR="+scenDir,
		"ACADEMY_SIGTERM_SENTINEL="+sentinelPath,
	)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start subprocess: %v", err)
	}

	// Wait until the subprocess writes the sentinel file (confirming work:create
	// posts have completed and academy is in the watch loop).
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sentinelPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(sentinelPath); err != nil {
		cmd.Process.Kill() // #nolint
		cmd.Wait()         // #nolint
		t.Fatalf("sentinel not written within 15s — subprocess may have crashed")
	}

	// Sentinel exists: academy is in the watch loop with all scenarios posted.
	// Now send SIGTERM.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	// Wait for subprocess to exit (the SIGTERM handler calls os.Exit(0)).
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill() // #nolint
		t.Fatal("subprocess did not exit within 10s after SIGTERM")
	}

	// Both scenarios must have produced JSON files (partial flush fired).
	for _, id := range []string{"SIG-01", "SIG-02"} {
		path := filepath.Join(outDir, id+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("SIGTERM partial flush: %s.json not written: %v", id, err)
			continue
		}
		var rec ScenarioRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Errorf("SIGTERM partial flush: parse %s.json: %v", id, err)
			continue
		}
		// Non-terminal record: terminal_action must be empty (partial/unresolved).
		if rec.TerminalAction != "" {
			t.Errorf("SIGTERM partial flush: %s.json terminal_action = %q, want empty (non-terminal record)",
				id, rec.TerminalAction)
		}
	}
}

// TestAcademySIGTERM_Subprocess is the in-process helper that runs academy
// with a long timeout so a SIGTERM from the parent test arrives mid-run.
// Only runs when ACADEMY_SIGTERM_SUBPROCESS=1.
//
// It writes a sentinel file once academy has posted all scenarios, then blocks
// in the watch loop until SIGTERM triggers the partial-flush and os.Exit(0).
func TestAcademySIGTERM_Subprocess(t *testing.T) {
	if os.Getenv("ACADEMY_SIGTERM_SUBPROCESS") != "1" {
		t.Skip("not in subprocess mode — skip")
	}

	outDir := os.Getenv("ACADEMY_SIGTERM_TEST_DIR")
	scenDir := os.Getenv("ACADEMY_SIGTERM_SCEN_DIR")
	sentinelPath := os.Getenv("ACADEMY_SIGTERM_SENTINEL")
	if outDir == "" || scenDir == "" {
		t.Fatal("ACADEMY_SIGTERM_TEST_DIR or ACADEMY_SIGTERM_SCEN_DIR not set")
	}

	// A mockSender that writes the sentinel after both sends complete.
	ms := &sigtermMockSender{
		sentinel:    sentinelPath,
		totalNeeded: 2, // SIG-01 and SIG-02
	}

	args := runArgs{
		targetCampfire: "cf-sigterm-test",
		scenariosDir:   scenDir,
		outputDir:      outDir,
		maxConcurrent:  2,
		timeout:        30 * time.Second, // long timeout; SIGTERM arrives before this
		runID:          "sigterm-test-run",
	}

	// academy blocks until SIGTERM arrives (from parent) or timeout.
	// The SIGTERM handler writes partial records and calls os.Exit(0).
	_ = academy(ms, args)
	// If we reach here, the normal timeout path fired (also writes partial records).
}

// sigtermMockSender is a mock Sender that writes a sentinel file once all
// expected work:create sends have been posted. This signals to the parent test
// that academy is in the watch loop and ready to receive SIGTERM.
type sigtermMockSender struct {
	mu          sync.Mutex
	sends       int
	totalNeeded int
	sentinel    string
	nextID      int
}

func (s *sigtermMockSender) send(campfireID, payload string, tags []string) (string, error) {
	s.mu.Lock()
	s.nextID++
	id := fmt.Sprintf("sigterm-mock-%d", s.nextID)
	if hasTag(tags, "work:create") {
		s.sends++
		if s.sends >= s.totalNeeded && s.sentinel != "" {
			// Write sentinel to signal parent test that all scenarios are posted.
			_ = os.WriteFile(s.sentinel, []byte("ready"), 0o644)
		}
	}
	s.mu.Unlock()
	return id, nil
}

func (s *sigtermMockSender) readAll(campfireID string) ([]cfMessage, error) {
	// Return no messages — keep academy in the watch loop indefinitely until
	// SIGTERM arrives.
	return nil, nil
}

// ---- regression: work:create tag-based attribution (mallcoppro-60e) ----------

// TestWorkItemToScenario_TagBasedAttribution verifies that a work:create message
// with a fresh payload.id (not in any scenario's chain) but carrying a
// "finding:<id>" tag is attributed to the correct scenario.
//
// This is the regression test for mallcoppro-60e: triage workers emit investigate
// items with fresh rd item IDs (e.g. "mallcopdeploy-c1d") that are not cf-msg-UUIDs
// and thus never appear in the chain map. The finding:<id> tag is the scoping signal
// that allows academy to attribute such downstream work correctly.
//
// The original 647 guard must still hold: a work:create with a fresh payload.id
// AND no finding/scenario tag must still be rejected (not assigned).
func TestWorkItemToScenario_TagBasedAttribution(t *testing.T) {
	scenDir := t.TempDir()
	const baseFindingID = "fnd_test_per-run-1"
	writeMinimalScenario(t, scenDir, "TAG-01", baseFindingID, "detector-tag-attribution",
		"Tag attribution test", "medium")

	outDir := t.TempDir()

	// The mock sender assigns mock-msg-1 to the TAG-01 work:create.
	// We inject:
	//   (a) A work:create with fresh ID "mallcopdeploy-c1d" + finding:<suffixed-id> tag.
	//       This must be attributed to TAG-01.
	//   (b) A work:close referencing "mallcopdeploy-c1d" (terminal).
	//       This close must reach TAG-01 via the attributed chain link.
	//   (c) A work:create with fresh ID "unrelated-item-abc" + NO finding tag.
	//       This must be REJECTED (647 guard still holds).
	//   (d) A work:close referencing "unrelated-item-abc".
	//       This close must NOT affect TAG-01.

	// The suffixed finding ID is what academy actually tracks:
	// perRunFindingID(baseFindingID, "tag-attr-run").
	suffixedFindingID := perRunFindingID(baseFindingID, "tag-attr-run")

	taggedWorkCreatePayload, _ := json.Marshal(map[string]interface{}{
		"id":    "mallcopdeploy-c1d",
		"skill": "task:investigate",
		"title": "investigate: " + baseFindingID,
	})
	taggedClosePayload, _ := json.Marshal(closePayload{
		ItemID: "mallcopdeploy-c1d",
		Action: "escalated",
		Skill:  "task:investigate",
	})
	unrelatedWorkCreatePayload, _ := json.Marshal(map[string]interface{}{
		"id":    "unrelated-item-abc",
		"skill": "task:triage",
		"title": "unrelated finding",
	})
	unrelatedClosePayload, _ := json.Marshal(closePayload{
		ItemID: "unrelated-item-abc",
		Action: "resolved",
		Skill:  "task:triage",
	})

	ms := &mockSender{
		readMsgs: []cfMessage{
			// (a) Tagged work:create — has finding:<suffixed-id> tag.
			{
				ID:   "tag-create-msg",
				Tags: []string{"work:create", "task:investigate", "finding:" + suffixedFindingID},
				Payload: string(taggedWorkCreatePayload),
			},
			// (b) Terminal close for the tagged investigate item.
			{
				ID:   "tag-close-msg",
				Tags: []string{"work:close", "action:escalated"},
				Payload: string(taggedClosePayload),
			},
			// (c) Unrelated work:create — no finding tag. 647 guard: must be rejected.
			{
				ID:   "unrelated-create-msg",
				Tags: []string{"work:create", "task:triage"},
				Payload: string(unrelatedWorkCreatePayload),
			},
			// (d) Close for the unrelated item. Must NOT affect TAG-01.
			{
				ID:   "unrelated-close-msg",
				Tags: []string{"work:close", "action:resolved"},
				Payload: string(unrelatedClosePayload),
			},
		},
	}

	args := runArgs{
		targetCampfire: "cf-tag-attribution-test",
		scenariosDir:   scenDir,
		scenarioFilter: "TAG-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "tag-attr-run",
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	// TAG-01.json must exist.
	data, err := os.ReadFile(filepath.Join(outDir, "TAG-01.json"))
	if err != nil {
		t.Fatalf("TAG-01.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse TAG-01.json: %v", err)
	}

	// TAG-01 must be terminal via the tagged investigate close (action=escalated).
	// If the tag-based attribution did NOT work, the tagged close would have been
	// rejected as unattributed and TAG-01 would either timeout (terminal_action="")
	// or be resolved via the unrelated close (terminal_action="resolved").
	if rec.TerminalAction != "escalated" {
		t.Errorf("TAG-01 terminal_action = %q, want escalated (tag-based attribution must work)",
			rec.TerminalAction)
	}
	if rec.TerminalAt == nil {
		t.Error("TAG-01 terminal_at must not be nil — tag-based close must reach terminal")
	}

	// The chain must include the tagged investigate item ID.
	foundTaggedItem := false
	for _, ce := range rec.FullChain {
		if ce.ItemID == "mallcopdeploy-c1d" {
			foundTaggedItem = true
			break
		}
	}
	if !foundTaggedItem {
		t.Errorf("TAG-01 full_chain does not contain 'mallcopdeploy-c1d' — tag-based attribution did not register chain link")
	}

	// The 647 guard: unrelated-item-abc must NOT appear in TAG-01's chain.
	for _, ce := range rec.FullChain {
		if ce.ItemID == "unrelated-item-abc" || ce.ItemID == "unrelated-create-msg" {
			t.Errorf("TAG-01 full_chain contains unrelated item %q — 647 guard broken", ce.ItemID)
		}
	}

	// The unrelated close (action=resolved) must NOT have set terminal on TAG-01
	// via the unrelated chain item (double-check: we already checked terminal_action=escalated).
	if rec.TerminalItemID == "unrelated-item-abc" || rec.TerminalItemID == "unrelated-create-msg" {
		t.Errorf("TAG-01 terminal_item_id = %q — 647 guard broken: unrelated close set terminal",
			rec.TerminalItemID)
	}
}

// ---- regression: forge_calls poll-dedup (mallcoppro-5119) --------------------

// TestAccumulateToolUsage_IdempotentAcrossPolls verifies that the same tool-usage
// campfire message delivered on two consecutive readAll batches is counted exactly
// once, not twice.
//
// Pre-fix behaviour: forge_calls would be 2 (once per poll).
// Post-fix behaviour: forge_calls must be 1.
func TestAccumulateToolUsage_IdempotentAcrossPolls(t *testing.T) {
	const (
		scenarioID   = "DEDUP-01"
		baseFindingID = "fnd_dedup_001"
		runID        = "dedup-test-run"
	)

	// Build a tracked scenario with the same setup academy uses.
	// workItemID is non-empty to represent a successfully posted scenario
	// (the guard added in mallcoppro-0f9 requires workItemID != "" to allow attribution).
	suffixedFindingID := perRunFindingID(baseFindingID, runID)
	ts := &trackedScenario{
		scenarioID:        scenarioID,
		findingID:         suffixedFindingID,
		altFindingID:      findingTrackingID(runID, scenarioID),
		workItemID:        "mock-work-item-dedup-01", // posted successfully
		seenToolUsageMsgs: make(map[string]bool),
	}
	tracked := map[string]*trackedScenario{scenarioID: ts}

	// Build a single tool-usage message that carries the matching finding tag.
	toolUsageMsg := cfMessage{
		ID: "tool-usage-msg-abc123",
		Tags: []string{
			"tool-usage",
			"finding:" + suffixedFindingID,
		},
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"forge_calls": 1,
		"tokens_in":   100,
		"tokens_out":  50,
		"finding_id":  suffixedFindingID,
	})
	toolUsageMsg.Payload = string(payload)

	// First poll delivers the message.
	accumulateToolUsage(toolUsageMsg, tracked)

	ts.mu.Lock()
	afterFirstPoll := ts.toolUsageCalls
	ts.mu.Unlock()

	if afterFirstPoll != 1 {
		t.Fatalf("forge_calls after first poll = %d, want 1", afterFirstPoll)
	}

	// Second poll re-delivers the SAME message (cf readAll is idempotent — it
	// returns all messages from the beginning of the campfire log every time).
	accumulateToolUsage(toolUsageMsg, tracked)

	ts.mu.Lock()
	afterSecondPoll := ts.toolUsageCalls
	ts.mu.Unlock()

	if afterSecondPoll != 1 {
		t.Errorf("forge_calls after second poll = %d, want 1 (poll-dedup failed: same msg counted twice)",
			afterSecondPoll)
	}

	// A DIFFERENT message with the same finding tag must still be counted.
	toolUsageMsg2 := cfMessage{
		ID:   "tool-usage-msg-def456",
		Tags: toolUsageMsg.Tags,
	}
	payload2, _ := json.Marshal(map[string]interface{}{
		"forge_calls": 1,
		"tokens_in":   200,
		"tokens_out":  80,
		"finding_id":  suffixedFindingID,
	})
	toolUsageMsg2.Payload = string(payload2)

	accumulateToolUsage(toolUsageMsg2, tracked)

	ts.mu.Lock()
	afterThirdMsg := ts.toolUsageCalls
	ts.mu.Unlock()

	if afterThirdMsg != 2 {
		t.Errorf("forge_calls after distinct second message = %d, want 2 (distinct messages must each be counted once)",
			afterThirdMsg)
	}
}

// ---- matchesFindingTag strict-exact-only (mallcoppro-4dc) ----

// TestMatchesFindingTag_StrictExactOnly verifies that matchesFindingTag uses exact
// equality only — no scenarioID-suffix fallback (mallcoppro-4dc). With timestamp
// run-IDs, stale messages from a prior run carry a different timestamp in their
// finding tag and will not match either findingID or altFindingID.
func TestMatchesFindingTag_StrictExactOnly(t *testing.T) {
	ts := &trackedScenario{
		scenarioID:   "X",
		findingID:    "fnd_X_bk-open-20260516",
		altFindingID: "academy-bk-open-20260516-X",
	}

	tests := []struct {
		name         string
		tagFindingID string
		want         bool
	}{
		{
			name:         "primary findingID exact match → true",
			tagFindingID: "fnd_X_bk-open-20260516",
			want:         true,
		},
		{
			name:         "altFindingID exact match → true",
			tagFindingID: "academy-bk-open-20260516-X",
			want:         true,
		},
		{
			name:         "stale primary findingID (different timestamp) → false",
			tagFindingID: "fnd_X_bk-open-20260515",
			want:         false,
		},
		{
			name:         "old scenarioID-suffix format no timestamp → false",
			tagFindingID: "academy-bk-open-X",
			want:         false,
		},
		{
			name:         "stale altFindingID (different timestamp) → false",
			tagFindingID: "academy-bk-open-20260515-X",
			want:         false,
		},
		{
			name:         "empty tag → false",
			tagFindingID: "",
			want:         false,
		},
		{
			name:         "partial prefix only → false",
			tagFindingID: "fnd_X_bk-open",
			want:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesFindingTag(ts, tc.tagFindingID)
			if got != tc.want {
				t.Errorf("matchesFindingTag(ts, %q) = %v, want %v", tc.tagFindingID, got, tc.want)
			}
		})
	}
}

// ---- regression: triage→investigate work:create attribution (mallcoppro-c33 + mallcoppro-4dc) -

// TestWorkItemToScenario_TriageInvestigateAttribution verifies that a work:create
// emitted by a triage worker using the CURRENT run's altFindingID is attributed
// to the correct scenario via strict exact matching (mallcoppro-4dc).
//
// With timestamp run-IDs (bk-<lane>-<YYYYMMDD-HHMMSS>), the altFindingID is
// unique per run. A triage worker that processes a current-run work:create and
// calls escalate-to-investigator embeds the current altFindingID exactly, so
// exact matching is sufficient. The 647 guard is preserved: bare work:create
// messages with no finding tag are still rejected.
func TestWorkItemToScenario_TriageInvestigateAttribution(t *testing.T) {
	const (
		scenarioID    = "TRIAGE-01"
		baseFindingID = "fnd_triage_001"
		currentRunID  = "bk-current-20260516"
	)

	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, scenarioID, baseFindingID, "detector-unusual-login",
		"Unusual login from triage scenario", "medium")

	outDir := t.TempDir()

	// The current run's altFindingID = "academy-bk-current-20260516-TRIAGE-01".
	// A triage worker that processes a current-run work:create and calls
	// escalate-to-investigator will embed this exact ID. Strict exact matching
	// attributes the investigate work:create to TRIAGE-01.
	currentAltFindingID := findingTrackingID(currentRunID, scenarioID) // "academy-bk-current-20260516-TRIAGE-01"

	investigateWorkCreatePayload, _ := json.Marshal(map[string]interface{}{
		"id":    "mallcopdeploy-abc",
		"skill": "task:investigate",
		"title": "investigate: " + currentAltFindingID,
	})
	investigateClosePayload, _ := json.Marshal(closePayload{
		ItemID: "mallcopdeploy-abc",
		Action: "escalated",
		Skill:  "task:investigate",
	})

	// Bare work:create with no finding tag — 647 guard: must be rejected.
	bareWorkCreatePayload, _ := json.Marshal(map[string]interface{}{
		"id":    "unscoped-item-xyz",
		"skill": "task:triage",
		"title": "some unrelated finding with no scope tag",
	})
	bareClosePayload, _ := json.Marshal(closePayload{
		ItemID: "unscoped-item-xyz",
		Action: "resolved",
		Skill:  "task:triage",
	})

	ms := &mockSender{
		readMsgs: []cfMessage{
			// Current-run investigate work:create: carries current-run altFindingID tag.
			// Must be attributed to TRIAGE-01 via exact altFindingID match (mallcoppro-4dc).
			{
				ID:      "current-investigate-create",
				Tags:    []string{"work:create", "skill:task:investigate", "finding:" + currentAltFindingID},
				Payload: string(investigateWorkCreatePayload),
			},
			// Terminal close for the investigate item.
			{
				ID:      "current-investigate-close",
				Tags:    []string{"work:close", "action:escalated"},
				Payload: string(investigateClosePayload),
			},
			// Bare work:create — no finding tag. 647 guard must reject this.
			{
				ID:      "bare-create-msg",
				Tags:    []string{"work:create", "task:triage"},
				Payload: string(bareWorkCreatePayload),
			},
			// Close for the bare item — must NOT reach TRIAGE-01.
			{
				ID:      "bare-close-msg",
				Tags:    []string{"work:close", "action:resolved"},
				Payload: string(bareClosePayload),
			},
		},
	}

	args := runArgs{
		targetCampfire: "cf-triage-investigate-test",
		scenariosDir:   scenDir,
		scenarioFilter: scenarioID,
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          currentRunID,
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, scenarioID+".json"))
	if err != nil {
		t.Fatalf("%s.json not found: %v", scenarioID, err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse %s.json: %v", scenarioID, err)
	}

	// TRIAGE-01 must be terminal via the investigate close (action=escalated).
	// Same-run altFindingID exact match must attribute correctly.
	if rec.TerminalAction != "escalated" {
		t.Errorf("%s terminal_action = %q, want escalated (same-run altFindingID exact match must attribute correctly)",
			scenarioID, rec.TerminalAction)
	}
	if rec.TerminalAt == nil {
		t.Errorf("%s terminal_at must not be nil — investigate close must reach terminal", scenarioID)
	}

	// The chain must include the investigate item.
	foundInvestigateItem := false
	for _, ce := range rec.FullChain {
		if ce.ItemID == "mallcopdeploy-abc" {
			foundInvestigateItem = true
			break
		}
	}
	if !foundInvestigateItem {
		t.Errorf("%s full_chain does not contain 'mallcopdeploy-abc' — same-run altFindingID attribution did not register chain link",
			scenarioID)
	}

	// 647 guard: the bare unscoped item must NOT appear in the chain or as terminal.
	for _, ce := range rec.FullChain {
		if ce.ItemID == "unscoped-item-xyz" || ce.ItemID == "bare-create-msg" {
			t.Errorf("%s full_chain contains unscoped item %q — 647 guard broken", scenarioID, ce.ItemID)
		}
	}
	if rec.TerminalItemID == "unscoped-item-xyz" || rec.TerminalItemID == "bare-create-msg" {
		t.Errorf("%s terminal_item_id = %q — 647 guard broken: bare close set terminal", scenarioID, rec.TerminalItemID)
	}
}

// TestWorkItemToScenario_StaleRunFindingTagRejected verifies that a work:create
// carrying a STALE run's altFindingID tag is NOT attributed to any scenario
// (mallcoppro-4dc strict matching). With timestamp run-IDs, cross-run tags
// have a different timestamp embedded and cannot match.
func TestWorkItemToScenario_StaleRunFindingTagRejected(t *testing.T) {
	const (
		scenarioID    = "TRIAGE-02"
		baseFindingID = "fnd_triage_002"
		currentRunID  = "bk-current-20260516"
		oldRunID      = "bk-current-20260515" // different timestamp = different run
	)

	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, scenarioID, baseFindingID, "detector-unusual-login",
		"Unusual login from stale-run rejection test", "medium")

	outDir := t.TempDir()

	// Stale-run tag: the tag the old-run worker would have emitted.
	// Does NOT match current run's altFindingID (different timestamp).
	staleAltFindingID := findingTrackingID(oldRunID, scenarioID) // "academy-bk-current-20260515-TRIAGE-02"

	staleInvestigateCreatePayload, _ := json.Marshal(map[string]interface{}{
		"id":    "mallcopdeploy-stale-xyz",
		"skill": "task:investigate",
		"title": "investigate: " + staleAltFindingID,
	})
	staleInvestigateClosePayload, _ := json.Marshal(closePayload{
		ItemID: "mallcopdeploy-stale-xyz",
		Action: "escalated",
		Skill:  "task:investigate",
	})

	ms := &mockSender{
		readMsgs: []cfMessage{
			// Stale-run investigate work:create: tag has old timestamp in run-id.
			// Strict exact matching must reject this (mallcoppro-4dc).
			{
				ID:      "stale-investigate-create",
				Tags:    []string{"work:create", "skill:task:investigate", "finding:" + staleAltFindingID},
				Payload: string(staleInvestigateCreatePayload),
			},
			// Close for the stale item — must NOT reach TRIAGE-02.
			{
				ID:      "stale-investigate-close",
				Tags:    []string{"work:close", "action:escalated"},
				Payload: string(staleInvestigateClosePayload),
			},
		},
	}

	args := runArgs{
		targetCampfire: "cf-stale-rejection-test",
		scenariosDir:   scenDir,
		scenarioFilter: scenarioID,
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          currentRunID,
	}

	if err := academy(ms, args); err != nil {
		t.Fatalf("academy: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, scenarioID+".json"))
	if err != nil {
		t.Fatalf("%s.json not found: %v", scenarioID, err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse %s.json: %v", scenarioID, err)
	}

	// TRIAGE-02 must NOT be terminal via the stale investigate close.
	// With strict exact matching, stale tags are rejected — scenario times out (terminal_action="").
	if rec.TerminalAction == "escalated" {
		t.Errorf("%s terminal_action = escalated — stale-run tag should be rejected by strict exact matching (mallcoppro-4dc), not attributed",
			scenarioID)
	}

	// The stale investigate item must NOT appear in the chain.
	for _, ce := range rec.FullChain {
		if ce.ItemID == "mallcopdeploy-stale-xyz" || ce.ItemID == "stale-investigate-create" {
			t.Errorf("%s full_chain contains stale item %q — strict exact matching broken: stale tag attributed",
				scenarioID, ce.ItemID)
		}
	}
}

// ---- regression: ghost forge_calls from unposted scenarios (mallcoppro-0f9) ----

// TestAccumulateToolUsage_SkipsUnpostedScenarios verifies that a tool-usage message
// whose finding tag matches a tracked scenario with workItemID="" (post failed) is
// NOT attributed to that scenario.
//
// Pre-fix behaviour: accumulateToolUsage would match via matchesFindingTag's c33
// suffix fallback and increment toolUsageCalls, producing ghost forge_calls.
// Post-fix behaviour: forge_calls must remain 0 for the unposted scenario.
func TestAccumulateToolUsage_SkipsUnpostedScenarios(t *testing.T) {
	const (
		scenarioID    = "UNPOSTED-01"
		baseFindingID = "fnd_test_001"
		runID         = "bk-test"
	)

	// Simulate a scenario whose cfWorkCreate post failed: workItemID is empty.
	suffixedFindingID := perRunFindingID(baseFindingID, runID) // "fnd_test_001_bk-test"
	ts := &trackedScenario{
		scenarioID:        scenarioID,
		findingID:         suffixedFindingID,
		altFindingID:      findingTrackingID(runID, scenarioID),
		workItemID:        "", // empty — post failed
		seenToolUsageMsgs: make(map[string]bool),
	}
	tracked := map[string]*trackedScenario{scenarioID: ts}

	// Build a tool-usage message carrying the matching finding tag.
	payload, _ := json.Marshal(map[string]interface{}{
		"forge_calls": 3,
		"tokens_in":   500,
		"tokens_out":  200,
		"finding_id":  suffixedFindingID,
	})
	toolUsageMsg := cfMessage{
		ID: "tool-usage-ghost-001",
		Tags: []string{
			"tool-usage",
			"finding:" + suffixedFindingID,
		},
		Payload: string(payload),
	}

	accumulateToolUsage(toolUsageMsg, tracked)

	ts.mu.Lock()
	calls := ts.toolUsageCalls
	ts.mu.Unlock()

	if calls != 0 {
		t.Errorf("forge_calls = %d for unposted scenario, want 0 — ghost attribution from prior bakeoff run not blocked",
			calls)
	}

	// Verify the c33 suffix fallback is also blocked: deliver a message whose tag
	// uses the altFindingID (academy-bk-test-UNPOSTED-01), which matches via suffix.
	altPayload, _ := json.Marshal(map[string]interface{}{
		"forge_calls": 5,
		"tokens_in":   800,
		"tokens_out":  300,
		"finding_id":  ts.altFindingID,
	})
	altMsg := cfMessage{
		ID: "tool-usage-ghost-alt-001",
		Tags: []string{
			"tool-usage",
			"finding:" + ts.altFindingID,
		},
		Payload: string(altPayload),
	}

	accumulateToolUsage(altMsg, tracked)

	ts.mu.Lock()
	callsAfterAlt := ts.toolUsageCalls
	ts.mu.Unlock()

	if callsAfterAlt != 0 {
		t.Errorf("forge_calls = %d after altFindingID tool-usage for unposted scenario, want 0 — ghost attribution not blocked",
			callsAfterAlt)
	}
}

// TestWorkItemToScenario_TagAttribution_SkipsUnpostedScenarios verifies that a
// work:create whose finding tag matches an unposted scenario (workItemID=="") is
// NOT attributed to that scenario in the workItemToScenario map, and that a
// tool-usage message similarly delivers zero forge_calls to it.
//
// Pre-fix behaviour: the watch loop would register the work:create against the
// unposted scenario, then any subsequent close for that item would incorrectly
// mark the scenario terminal; accumulateToolUsage would
// increment toolUsageCalls producing ghost forge_calls.
// Post-fix behaviour: the work:create is silently dropped (not assigned to any
// scenario); toolUsageCalls remains 0.
//
// Because a failed-post scenario is never written to disk (the timeout flush also
// gates on workItemID != ""), this test validates the in-memory trackedScenario
// state directly by building it without going through academy().
func TestWorkItemToScenario_TagAttribution_SkipsUnpostedScenarios(t *testing.T) {
	const (
		scenarioID    = "UNPOSTED-02"
		baseFindingID = "fnd_test_001"
		runID         = "bk-test"
	)

	// Construct a trackedScenario identical to what academy builds for a failed post.
	suffixedFindingID := perRunFindingID(baseFindingID, runID) // "fnd_test_001_bk-test"
	altFindingID := findingTrackingID(runID, scenarioID)        // "academy-bk-test-UNPOSTED-02"
	ts := &trackedScenario{
		scenarioID:        scenarioID,
		findingID:         suffixedFindingID,
		altFindingID:      altFindingID,
		workItemID:        "", // post failed — empty
		seenToolUsageMsgs: make(map[string]bool),
	}
	tracked := map[string]*trackedScenario{scenarioID: ts}

	// Scenario 1: tool-usage via primary findingID tag — must be blocked.
	primaryPayload, _ := json.Marshal(map[string]interface{}{
		"forge_calls": 3,
		"tokens_in":   400,
		"tokens_out":  150,
		"finding_id":  suffixedFindingID,
	})
	primaryMsg := cfMessage{
		ID:      "tool-usage-primary-001",
		Tags:    []string{"tool-usage", "finding:" + suffixedFindingID},
		Payload: string(primaryPayload),
	}
	accumulateToolUsage(primaryMsg, tracked)

	ts.mu.Lock()
	callsAfterPrimary := ts.toolUsageCalls
	ts.mu.Unlock()
	if callsAfterPrimary != 0 {
		t.Errorf("forge_calls = %d after primary-tag tool-usage for unposted scenario, want 0",
			callsAfterPrimary)
	}

	// Scenario 2: tool-usage via altFindingID tag — must also be blocked (workItemID="" guard).
	altPayload, _ := json.Marshal(map[string]interface{}{
		"forge_calls": 5,
		"tokens_in":   800,
		"tokens_out":  300,
		"finding_id":  altFindingID,
	})
	altMsg := cfMessage{
		ID:      "tool-usage-alt-001",
		Tags:    []string{"tool-usage", "finding:" + altFindingID},
		Payload: string(altPayload),
	}
	accumulateToolUsage(altMsg, tracked)

	ts.mu.Lock()
	callsAfterAlt := ts.toolUsageCalls
	ts.mu.Unlock()
	if callsAfterAlt != 0 {
		t.Errorf("forge_calls = %d after altFindingID tool-usage for unposted scenario, want 0 — ghost attribution not blocked",
			callsAfterAlt)
	}

	// Scenario 3: verify a POSTED scenario still gets tool-usage attributed normally.
	// This guards against the fix being too aggressive (blocking all attribution).
	tsPosted := &trackedScenario{
		scenarioID:        "POSTED-01",
		findingID:         perRunFindingID("fnd_other_002", runID),
		altFindingID:      findingTrackingID(runID, "POSTED-01"),
		workItemID:        "real-cf-msg-id-posted", // posted successfully
		seenToolUsageMsgs: make(map[string]bool),
	}
	trackedMixed := map[string]*trackedScenario{
		scenarioID: ts,
		"POSTED-01": tsPosted,
	}

	postedPayload, _ := json.Marshal(map[string]interface{}{
		"forge_calls": 2,
		"tokens_in":   300,
		"tokens_out":  100,
		"finding_id":  tsPosted.findingID,
	})
	postedMsg := cfMessage{
		ID:      "tool-usage-posted-001",
		Tags:    []string{"tool-usage", "finding:" + tsPosted.findingID},
		Payload: string(postedPayload),
	}
	accumulateToolUsage(postedMsg, trackedMixed)

	tsPosted.mu.Lock()
	callsPosted := tsPosted.toolUsageCalls
	tsPosted.mu.Unlock()
	if callsPosted != 2 {
		t.Errorf("forge_calls = %d for posted scenario, want 2 — attribution for valid posted scenario broken",
			callsPosted)
	}

	// Unposted scenario must still be 0 after the mixed-tracked run.
	ts.mu.Lock()
	callsUnpostedAfterMixed := ts.toolUsageCalls
	ts.mu.Unlock()
	if callsUnpostedAfterMixed != 0 {
		t.Errorf("forge_calls = %d for unposted scenario after mixed run, want 0",
			callsUnpostedAfterMixed)
	}
}

// ---- unit: normalizeTerminalAction (mallcoppro-190) -------------------------
//
// Background: legion (cmd/we) emits action="abandoned" on the wire when a
// worker exits end_turn without invoking any tool. The academy normalizes
// that into the security-domain terminal vocabulary as "escalated" plus a
// structural cause "abandoned-by-model". Other actions pass through unchanged.

func TestNormalizeTerminalAction_AbandonedBecomesEscalated(t *testing.T) {
	normalized, cause := normalizeTerminalAction("abandoned")
	if normalized != "escalated" {
		t.Errorf("normalized = %q, want escalated", normalized)
	}
	if cause != "abandoned-by-model" {
		t.Errorf("structural_cause = %q, want abandoned-by-model", cause)
	}
}

func TestNormalizeTerminalAction_ResolvedPassthrough(t *testing.T) {
	normalized, cause := normalizeTerminalAction("resolved")
	if normalized != "resolved" {
		t.Errorf("normalized = %q, want resolved", normalized)
	}
	if cause != "" {
		t.Errorf("structural_cause = %q, want empty for pass-through", cause)
	}
}

func TestNormalizeTerminalAction_EscalatedPassthrough(t *testing.T) {
	normalized, cause := normalizeTerminalAction("escalated")
	if normalized != "escalated" {
		t.Errorf("normalized = %q, want escalated", normalized)
	}
	if cause != "" {
		t.Errorf("structural_cause = %q, want empty for pass-through", cause)
	}
}

// TestAcademyMock_AbandonedNormalizedAtConsumption is the end-to-end gate:
// feed academy a real work:close with action="abandoned" and assert the
// emitted ScenarioRecord JSON has terminal_action="escalated" and
// structural_cause="abandoned-by-model". This exercises the consumption site
// in the watch loop, not just the normalizer in isolation.
func TestAcademyMock_AbandonedNormalizedAtConsumption(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AB-01", "fnd_ab_001", "detector-priv-escalation",
		"Abandoned-by-model normalization", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-abandoned",
		scenariosDir:   scenDir,
		scenarioFilter: "AB-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-mock-run-abandoned",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

	// Wait for the work:create.
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

	// Inject a terminal work:close with action="abandoned" — the wire form
	// emitted by legion when a worker exits end_turn without any tool call.
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "abandoned",
		Skill:  "task:investigate",
	})
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-abandoned-001",
		Tags:    []string{"work:close", "action:abandoned"},
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

	// Read AB-01.json off disk — assert the encoded JSON, not just struct
	// fields. structural_cause must appear; terminal_action must be normalized.
	data, err := os.ReadFile(filepath.Join(outDir, "AB-01.json"))
	if err != nil {
		t.Fatalf("AB-01.json not found: %v", err)
	}

	// Assert against the raw JSON map first — catches struct-tag regressions
	// (e.g. structural_cause field renamed without updating json tag).
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse AB-01.json as map: %v", err)
	}
	if got := raw["terminal_action"]; got != "escalated" {
		t.Errorf("JSON terminal_action = %v, want \"escalated\"", got)
	}
	if got := raw["structural_cause"]; got != "abandoned-by-model" {
		t.Errorf("JSON structural_cause = %v, want \"abandoned-by-model\"", got)
	}

	// Also decode through the struct to confirm the typed field carries
	// the normalized value.
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse AB-01.json as ScenarioRecord: %v", err)
	}
	if rec.TerminalAction != "escalated" {
		t.Errorf("ScenarioRecord.TerminalAction = %q, want escalated", rec.TerminalAction)
	}
	if rec.StructuralCause != "abandoned-by-model" {
		t.Errorf("ScenarioRecord.StructuralCause = %q, want abandoned-by-model", rec.StructuralCause)
	}
	if rec.TerminalAt == nil {
		t.Error("terminal_at must not be nil for normalized terminal close")
	}
}

// TestScenarioRecord_StructuralCauseOmitemptyWhenAbsent confirms the
// structural_cause JSON tag uses omitempty — a resolved scenario without
// normalization must not emit a "structural_cause": "" key.
func TestScenarioRecord_StructuralCauseOmitemptyWhenAbsent(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()
	termAt := now.Add(2 * time.Second)

	ts := &trackedScenario{
		scenarioID:     "AC-99",
		findingID:      "academy-run-099-AC-99",
		workItemID:     "msg-99",
		postedAt:       now,
		chain:          []ChainEntry{{ItemID: "msg-99", Skill: "task:triage"}},
		terminal:       true,
		terminalAt:     termAt,
		terminalAction: "resolved",
		terminalItemID: "msg-99",
		// structuralCause intentionally unset.
	}

	if err := writeScenarioRecord(ts, "run-099", "cf-x", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "AC-99.json"))
	if err != nil {
		t.Fatalf("AC-99.json not found: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse AC-99.json: %v", err)
	}
	if _, present := raw["structural_cause"]; present {
		t.Errorf("structural_cause must be omitted (omitempty) when empty; got %v", raw["structural_cause"])
	}
}

// ---- unit: chain-shape detector (mallcoppro-2f1) ----------------------------
//
// Background: a "no-triage-inference" chain is one where the academy posted a
// work:create + a triage worker emitted a work:close, but the triage worker
// never spawned an investigate work item AND never called resolve-finding
// (toolUsageCalls == 0). Before mallcoppro-2f1 this surfaced silently as
// terminal_action=null + forge_calls=0. Now the academy classifies the
// scenario at chain quiescence as escalated/no-triage-inference.

// TestChainShape_NoTriageInference_Escalates: synthetic chain with only the
// academy's task:triage work:create + a triage worker's task:triage work:close
// (no investigate spawn, no resolve-finding). Drive the academy() main loop
// to wall-timeout quiescence and assert the on-disk record. This exercises
// the full consumption path: mockSender → watch loop → quiescence path.
func TestChainShape_NoTriageInference_Escalates(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "NT-01", "fnd_nt_001", "detector-priv-escalation",
		"No triage inference", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-no-triage",
		scenariosDir:   scenDir,
		scenarioFilter: "NT-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		// Short timeout to drive quiescence (wall-timeout exit), but long
		// enough that the watch loop polls AT LEAST twice: once before we
		// inject the noop close, once after. The loop sleeps 2s between
		// iterations, so 5s gives us two read-iterations comfortably.
		timeout: 5 * time.Second,
		runID:   "test-mock-run-no-triage",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

	// Wait for the work:create post.
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

	// Do NOT inject a terminal work:close. The watch loop will time out;
	// chain-shape detector should fire at quiescence and classify the
	// scenario as escalated/no-triage-inference.
	//
	// Note: the academy adds a task:triage work:create entry to ts.chain at
	// post time. For chain-shape to match we also need a triage work:close
	// in the chain. Synthesize one — a triage worker that terminated without
	// inference would emit exactly this shape on the wire.
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "noop", // non-terminal action (not in terminalActions map)
		Skill:  "task:triage",
	})
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-noop-001",
		Tags:    []string{"work:close", "action:noop"},
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

	data, err := os.ReadFile(filepath.Join(outDir, "NT-01.json"))
	if err != nil {
		t.Fatalf("NT-01.json not found: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse NT-01.json: %v", err)
	}
	if got := raw["terminal_action"]; got != "escalated" {
		t.Errorf("JSON terminal_action = %v, want \"escalated\" (chain-shape detector)", got)
	}
	if got := raw["structural_cause"]; got != "no-triage-inference" {
		t.Errorf("JSON structural_cause = %v, want \"no-triage-inference\"", got)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse NT-01.json as ScenarioRecord: %v", err)
	}
	if rec.TerminalAction != "escalated" {
		t.Errorf("ScenarioRecord.TerminalAction = %q, want escalated", rec.TerminalAction)
	}
	if rec.StructuralCause != "no-triage-inference" {
		t.Errorf("ScenarioRecord.StructuralCause = %q, want no-triage-inference", rec.StructuralCause)
	}
	if rec.TerminalAt == nil {
		t.Error("terminal_at must not be nil for chain-shape promoted scenario")
	}
}

// TestChainShape_NormalChainNotAffected: when a chain includes a triage
// escalate-to-investigator (investigate work:create) followed by an investigate
// resolve-finding (terminal work:close, action=escalated), the chain-shape
// detector must NOT override the normal terminal classification. The terminal
// action stays "escalated" with empty structural_cause.
func TestChainShape_NormalChainNotAffected(t *testing.T) {
	// Unit-level: detector should return false for a normal chain that
	// reached terminal via the message-arrival path. ts.terminal=true is
	// the short-circuit guarding "already classified" scenarios.
	ts := &trackedScenario{
		scenarioID: "NT-02",
		workItemID: "msg-triage-01",
		terminal:   true, // normal terminal close already processed
		chain: []ChainEntry{
			{ItemID: "msg-triage-01", Skill: "task:triage"},                      // academy post
			{ItemID: "msg-invest-01", Skill: "task:investigate"},                 // triage escalated
			{ItemID: "msg-invest-01", Skill: "task:investigate", Action: "escalated"}, // resolve-finding
		},
		toolUsageCalls: 1, // resolve-finding tool call observed
	}
	if detectNoTriageInferenceChain(ts) {
		t.Error("detector fired on a normal chain that already reached terminal — must not fire")
	}

	// Also: even without ts.terminal=true, a chain that has an investigate
	// work:create must not be classified as no-triage-inference.
	ts2 := &trackedScenario{
		scenarioID: "NT-02b",
		workItemID: "msg-triage-02",
		terminal:   false,
		chain: []ChainEntry{
			{ItemID: "msg-triage-02", Skill: "task:triage"},
			{ItemID: "msg-invest-02", Skill: "task:investigate"},
			{ItemID: "msg-triage-02", Skill: "task:triage", Action: "completed"}, // triage close (non-terminal)
		},
	}
	if detectNoTriageInferenceChain(ts2) {
		t.Error("detector fired on a chain that includes an investigate work:create — must not fire")
	}

	// And: a chain with resolve-finding tool usage (toolUsageCalls > 0)
	// must not be classified as no-triage-inference even if the investigate
	// work:create is absent (triage resolved directly).
	ts3 := &trackedScenario{
		scenarioID: "NT-02c",
		workItemID: "msg-triage-03",
		terminal:   false,
		chain: []ChainEntry{
			{ItemID: "msg-triage-03", Skill: "task:triage"},
			{ItemID: "msg-triage-03", Skill: "task:triage", Action: "noop"},
		},
		toolUsageCalls: 2, // triage called resolve-finding
	}
	if detectNoTriageInferenceChain(ts3) {
		t.Error("detector fired on a chain with toolUsageCalls > 0 — must not fire")
	}
}

// TestChainShape_FiresAtQuiescence: the detector must NOT fire on every
// message arrival in the watch loop — only at chain quiescence (the
// wall-timeout exit path). Verify by driving academy with a fast terminal
// resolved close mid-flight: the chain-shape detector must not preempt the
// normal terminal classification, even though the no-investigate-spawn
// condition is briefly true while messages stream in.
func TestChainShape_FiresAtQuiescence(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "NT-03", "fnd_nt_003", "detector-priv-escalation",
		"Quiescence-only firing", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-quiescence",
		scenariosDir:   scenDir,
		scenarioFilter: "NT-03",
		outputDir:      outDir,
		maxConcurrent:  1,
		// Long timeout: if chain-shape fired on every poll, the test would
		// pass quickly with no-triage-inference set, but we want the normal
		// terminal close to win.
		timeout: 30 * time.Second,
		runID:   "test-mock-run-quiescence",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

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

	// Inject a normal terminal resolved close — no investigate spawn, no
	// resolve-finding tool-usage message. If chain-shape fired on message
	// arrival, the detector's match condition would be true at this point
	// (no investigate work:create, toolUsageCalls=0) and the scenario would
	// land as escalated/no-triage-inference. It must NOT — the watch loop's
	// terminal classification must win.
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "resolved",
		Skill:  "task:triage",
	})
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-resolved-q-001",
		Tags:    []string{"work:close", "action:resolved"},
		Payload: string(closePayloadBytes),
	})
	ms.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("academy did not complete within deadline")
	}

	data, err := os.ReadFile(filepath.Join(outDir, "NT-03.json"))
	if err != nil {
		t.Fatalf("NT-03.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse NT-03.json: %v", err)
	}
	if rec.TerminalAction != "resolved" {
		t.Errorf("TerminalAction = %q, want resolved (chain-shape must not preempt normal terminal close)", rec.TerminalAction)
	}
	if rec.StructuralCause != "" {
		t.Errorf("StructuralCause = %q, want empty (no normalization on a normal resolved close)", rec.StructuralCause)
	}
}

// TestChainShape_InvestigateWorkCreate_MisclassifiedAsNoTriageInference
// (mallcoppro-db3 — security sweep, HIGH).
//
// Demonstrates the dead-code structural gap in detectNoTriageInferenceChain:
// triage's escalate-to-investigator emits a work:create with skill:task:investigate,
// but academy's watch loop (main.go:858-944) only registers that message in
// workItemToScenario — it never appends a ChainEntry to ts.chain. As a result,
// the detector's "hasInvestigateCreate" branch (main.go:417-419) is structurally
// always false, and the only safety net against misclassification is
// ts.toolUsageCalls > 0.
//
// Adversarial scenario: triage worker escalates (legit work) but the
// tool-usage emission to the work campfire is dropped (network blip,
// best-effort cf send failure, malicious tool wrapper). At quiescence the
// detector sees: hasCreate (initial post), hasClose (triage close, non-terminal
// action), !hasInvestigateCreate (structural — never populated), and
// ts.toolUsageCalls == 0. The detector misclassifies as structural-fault
// "no-triage-inference" even though triage DID escalate.
//
// THIS TEST IS EXPECTED TO FAIL on the unpatched code path — the failure
// demonstrates the misclassification. Defense: extend the work:create handler
// (main.go:836-944) to ALSO append a ChainEntry{Skill: parsed-skill, Action: ""}
// to the matched scenario's chain whenever a work:create with skill:task:investigate
// (or any investigate-skill) is attributed to a scenario. Once that ships,
// hasInvestigateCreate fires correctly and this test should be inverted to
// assert non-misclassification.
func TestChainShape_InvestigateWorkCreate_MisclassifiedAsNoTriageInference(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "NT-IB", "fnd_nt_ib", "detector-priv-escalation",
		"Triage-escalated chain — tool-usage absent", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-misclassify",
		scenariosDir:   scenDir,
		scenarioFilter: "NT-IB",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        6 * time.Second, // allow at least 2 poll iterations
		runID:          "test-mock-run-misclassify",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

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

	// 1. Triage worker emits a work:create for task:investigate carrying the
	//    finding tag — this is what escalate-to-investigator (tools_f1g.go) does.
	//    Academy registers it in workItemToScenario via the finding-tag attribution
	//    path (main.go:899-933) BUT does not add it to ts.chain.
	investigateCreatePayload := `{"id":"item-investigate-001","skill":"task:investigate","title":"investigate fnd_nt_ib"}`

	// 2. Triage worker emits a work:close with a non-terminal action (e.g. "noop",
	//    "completed", "escalate-emitted"). The close is in ts.chain (with non-empty
	//    Action) but doesn't reach the terminal switch.
	closeNoopPayload, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "escalated", // wire action escalate WITHOUT structural-fault prefix; triage handed off cleanly
		Skill:  "task:triage",
	})

	// Tag must use the per-run finding ID — see main.go:1466 matchesFindingTag.
	perRunFinding := perRunFindingID("fnd_nt_ib", "test-mock-run-misclassify")
	ms.mu.Lock()
	// Order matters: work:create first so attribution happens; close second.
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "msg-invest-create-001",
		Tags:    []string{"work:create", "skill:task:investigate", "finding:" + perRunFinding},
		Payload: investigateCreatePayload,
	})
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "msg-triage-close-001",
		Tags:    []string{"work:close", "action:escalated"},
		Payload: string(closeNoopPayload),
	})
	// 3. CRUCIAL: NO tool-usage message. The triage escalation happened (real
	//    work occurred), but the tool-usage emission was dropped/best-effort lost.
	//    The detector falls back on toolUsageCalls > 0 — which is false — and
	//    fires no-triage-inference.
	ms.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("academy did not complete within deadline")
	}

	// terminal_action came from work:close action=escalated → academy treats
	// that as terminal via terminalActions["escalated"]. So the misclassification
	// surface here is that StructuralCause should NOT be "no-triage-inference"
	// — triage DID hand off. After the defense ships, StructuralCause stays
	// empty for a clean escalation.
	data, err := os.ReadFile(filepath.Join(outDir, "NT-IB.json"))
	if err != nil {
		t.Fatalf("NT-IB.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse NT-IB.json: %v", err)
	}
	// terminal_action must be "escalated" — that's the real outcome.
	if rec.TerminalAction != "escalated" {
		t.Errorf("TerminalAction = %q, want \"escalated\" (triage handed off cleanly)", rec.TerminalAction)
	}
	// StructuralCause must be empty. On the unpatched code path the detector
	// CANNOT fire because terminal was already set by the escalated close.
	// But: if the close had been omitted entirely (only the work:create),
	// quiescence would fire the detector and misclassify. This second case
	// is exercised by the helper below.
	if rec.StructuralCause != "" {
		t.Errorf("StructuralCause = %q, want empty (clean escalate, not a fault)", rec.StructuralCause)
	}
}

// TestChainShape_InvestigateWorkCreateOnly_QuiescenceMisclassifies (mallcoppro-db3 HIGH).
// Sharper restatement of the bypass: triage emits the escalate-to-investigator
// work:create but the triage worker is killed before posting its own work:close
// or tool-usage (e.g., wall timeout, SIGKILL). At quiescence the chain has the
// initial post, NO triage close, and an unobserved investigate work:create that
// academy registered only in workItemToScenario. detectNoTriageInferenceChain
// would normally short-circuit on !hasClose, so this exact case does NOT trip
// the false positive — but the next-related case (triage close present without
// terminal action AND investigate spawn present) DOES misclassify, because
// hasInvestigateCreate stays false. This test pins the desired behavior: when
// an investigate work:create has been attributed to the scenario, the detector
// MUST treat it as evidence of triage inference, regardless of whether it
// reached ts.chain.
//
// The fix is to either (a) populate ts.chain on attributed work:create messages,
// or (b) extend detectNoTriageInferenceChain to consult workItemToScenario for
// any investigate work:create attributed to this scenario.
func TestChainShape_InvestigateWorkCreateOnly_QuiescenceMisclassifies(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "NT-IC", "fnd_nt_ic", "detector-priv-escalation",
		"Triage escalated then died — only the work:create survived", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-orphaned-escalate",
		scenariosDir:   scenDir,
		scenarioFilter: "NT-IC",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        6 * time.Second, // allow at least 2 poll iterations
		runID:          "test-mock-run-orphaned-escalate",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

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

	// Real-world scenario: triage emitted escalate-to-investigator THEN posted
	// a non-terminal close (e.g., "noop") to signal worker exit cleanly. Triage
	// did real inference work — escalation is the proof — but tool-usage went
	// missing.
	investigateCreatePayload := `{"id":"item-orphaned-investigate","skill":"task:investigate","title":"investigate fnd_nt_ic"}`
	closeNoopPayload, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "noop", // non-terminal — does not match terminalActions
		Skill:  "task:triage",
	})

	perRunFinding := perRunFindingID("fnd_nt_ic", "test-mock-run-orphaned-escalate")
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "msg-orphan-invest-001",
		Tags:    []string{"work:create", "skill:task:investigate", "finding:" + perRunFinding},
		Payload: investigateCreatePayload,
	})
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "msg-orphan-triage-close-001",
		Tags:    []string{"work:close", "action:noop"},
		Payload: string(closeNoopPayload),
	})
	ms.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("academy did not complete within deadline")
	}

	data, err := os.ReadFile(filepath.Join(outDir, "NT-IC.json"))
	if err != nil {
		t.Fatalf("NT-IC.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse NT-IC.json: %v", err)
	}

	// Defense: even though tool-usage is absent, the academy MUST recognize
	// the attributed work:create as evidence of triage inference. The detector
	// must NOT fire "no-triage-inference" — that label paints triage as silent
	// when it actually performed the inference and produced the spawn.
	if rec.StructuralCause == "no-triage-inference" {
		t.Errorf("DETECTOR MISCLASSIFICATION: triage escalated (work:create posted) but " +
			"detector still flagged no-triage-inference because ts.chain never recorded " +
			"the work:create. Defense required: populate ts.chain on attributed " +
			"work:create messages, or extend detectNoTriageInferenceChain to consult " +
			"workItemToScenario for investigate-skill spawns.")
	}
}

// TestFecWireParse_AbandonedNormalizerWins_ContestedCause (mallcoppro-db3).
// Follow-up to orchestrator ruling cfbff880: the existing
// TestFecWireParse_AbandonedNormalizerWins short-circuits via HasPrefix on
// reason="watchdog timeout" — the precedence guard at main.go:1127
// (if ts.structuralCause == "") is never exercised because parseStructuralFaultReason
// returns ("", false) without contesting the slot.
//
// The contested case: action="abandoned" + reason="structural-fault: alt-cause".
// 190's normalizer runs first and sets structuralCause="abandoned-by-model".
// The fec parser THEN finds the prefix and returns ("alt-cause", true). The
// guard at line 1127 must keep "abandoned-by-model" and discard "alt-cause".
// Without the guard, the fec parser would overwrite the normalizer-set cause.
func TestFecWireParse_AbandonedNormalizerWins_ContestedCause(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "FC-04", "fnd_fc_004", "detector-priv-escalation",
		"abandoned-normalizer precedence — contested cause", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-contested",
		scenariosDir:   scenDir,
		scenarioFilter: "FC-04",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-mock-run-contested",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

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

	// Contested case: BOTH paths have a structural cause to write.
	//   1. action="abandoned" → normalizeTerminalAction sets cause="abandoned-by-model".
	//   2. reason="structural-fault: alt-cause" → parseStructuralFaultReason returns ("alt-cause", true).
	// The precedence guard at main.go:1127 must keep "abandoned-by-model".
	payload := closePayloadFull{
		ItemID: sentID,
		Action: "abandoned",
		Skill:  "task:investigate",
		Reason: "structural-fault: alt-cause",
	}
	payloadBytes, _ := json.Marshal(payload)
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-fec-contested-001",
		Tags:    []string{"work:close", "action:abandoned"},
		Payload: string(payloadBytes),
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

	data, err := os.ReadFile(filepath.Join(outDir, "FC-04.json"))
	if err != nil {
		t.Fatalf("FC-04.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse FC-04.json: %v", err)
	}
	if rec.StructuralCause != "abandoned-by-model" {
		t.Errorf("PRECEDENCE GUARD BROKEN: StructuralCause = %q, want abandoned-by-model "+
			"(190's normalizer must win over fec reason-parser in the contested case where "+
			"both have a non-empty cause). main.go:1127 guard `if ts.structuralCause == \"\"`",
			rec.StructuralCause)
	}
	if rec.TerminalAction != "escalated" {
		t.Errorf("TerminalAction = %q, want escalated (190's normalizer maps abandoned → escalated)",
			rec.TerminalAction)
	}
}

// ---- unit: fec-wire structural-fault parse (mallcoppro-2f1) -----------------
//
// Background: legion's EscalateOnStructuralFault (legion#343) emits a
// work:close payload with action="escalated" and reason="structural-fault: <cause>".
// The academy must lift <cause> onto ScenarioRecord.StructuralCause, except
// when 190's normalizer already set the cause from the wire action.

func TestParseStructuralFaultReason_Prefix(t *testing.T) {
	cause, ok := parseStructuralFaultReason("structural-fault: no-tool-use")
	if !ok {
		t.Fatal("ok = false, want true for valid prefix")
	}
	if cause != "no-tool-use" {
		t.Errorf("cause = %q, want \"no-tool-use\"", cause)
	}
}

func TestParseStructuralFaultReason_NoPrefix(t *testing.T) {
	if cause, ok := parseStructuralFaultReason("resolved cleanly with citations"); ok {
		t.Errorf("ok = true for non-prefixed reason; cause = %q", cause)
	}
}

func TestParseStructuralFaultReason_EmptyAfterPrefix(t *testing.T) {
	// Prefix present but no cause token — must not match (we don't emit empty
	// structural_cause).
	if cause, ok := parseStructuralFaultReason("structural-fault: "); ok {
		t.Errorf("ok = true for empty-cause prefix; cause = %q", cause)
	}
}

// TestFecWireParse_StructuralFaultPrefix: end-to-end via academy(). Feed a
// work:close with action=escalated and reason="structural-fault: no-tool-use".
// Assert ScenarioRecord.structural_cause == "no-tool-use" on disk.
func TestFecWireParse_StructuralFaultPrefix(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "FC-01", "fnd_fc_001", "detector-priv-escalation",
		"fec structural-fault wire parse", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-fec",
		scenariosDir:   scenDir,
		scenarioFilter: "FC-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-mock-run-fec",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

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

	// fec wire format: action=escalated, reason="structural-fault: <cause>".
	// Use the closePayloadFull shape directly to carry the reason field — the
	// parsing path in extractTerminalReason unmarshals this exact shape.
	payload := closePayloadFull{
		ItemID: sentID,
		Action: "escalated",
		Skill:  "task:triage",
		Reason: "structural-fault: no-tool-use",
	}
	payloadBytes, _ := json.Marshal(payload)
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-fec-001",
		Tags:    []string{"work:close", "action:escalated"},
		Payload: string(payloadBytes),
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

	data, err := os.ReadFile(filepath.Join(outDir, "FC-01.json"))
	if err != nil {
		t.Fatalf("FC-01.json not found: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse FC-01.json as map: %v", err)
	}
	// Guard struct-tag regressions: assert the JSON key spelling.
	if got := raw["structural_cause"]; got != "no-tool-use" {
		t.Errorf("JSON structural_cause = %v, want \"no-tool-use\"", got)
	}
	if got := raw["terminal_action"]; got != "escalated" {
		t.Errorf("JSON terminal_action = %v, want \"escalated\"", got)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse FC-01.json as ScenarioRecord: %v", err)
	}
	if rec.StructuralCause != "no-tool-use" {
		t.Errorf("ScenarioRecord.StructuralCause = %q, want no-tool-use", rec.StructuralCause)
	}
}

// TestFecWireParse_NoStructuralFaultPrefix: a normal resolved close whose
// reason does NOT start with the structural-fault prefix must leave
// ScenarioRecord.structural_cause empty (no false-positive parsing).
func TestFecWireParse_NoStructuralFaultPrefix(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "FC-02", "fnd_fc_002", "detector-priv-escalation",
		"non-fec reason leaves structural_cause empty", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-fec-noprefix",
		scenariosDir:   scenDir,
		scenarioFilter: "FC-02",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-mock-run-fec-noprefix",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

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

	payload := closePayloadFull{
		ItemID: sentID,
		Action: "escalated",
		Skill:  "task:triage",
		Reason: "resolved cleanly with citations",
	}
	payloadBytes, _ := json.Marshal(payload)
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-fec-noprefix-001",
		Tags:    []string{"work:close", "action:escalated"},
		Payload: string(payloadBytes),
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

	data, err := os.ReadFile(filepath.Join(outDir, "FC-02.json"))
	if err != nil {
		t.Fatalf("FC-02.json not found: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse FC-02.json: %v", err)
	}
	if _, present := raw["structural_cause"]; present {
		t.Errorf("structural_cause must be omitted (omitempty) for non-fec reason; got %v", raw["structural_cause"])
	}
	if got := raw["terminal_action"]; got != "escalated" {
		t.Errorf("JSON terminal_action = %v, want \"escalated\"", got)
	}
}

// TestFecWireParse_AbandonedNormalizerWins: when wire action="abandoned" with
// a non-prefix reason ("watchdog timeout"), 190's normalizer sets
// structural_cause="abandoned-by-model" and the fec reason-parser must NOT
// overwrite that (precedence: normalizer wins over reason).
func TestFecWireParse_AbandonedNormalizerWins(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "FC-03", "fnd_fc_003", "detector-priv-escalation",
		"abandoned-normalizer precedence", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-fec-abandoned",
		scenariosDir:   scenDir,
		scenarioFilter: "FC-03",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-mock-run-fec-abandoned",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

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

	// wire action="abandoned" + reason="watchdog timeout" — the normalizer
	// sets structural_cause="abandoned-by-model" before the fec parser sees
	// the reason; precedence must be preserved.
	payload := closePayloadFull{
		ItemID: sentID,
		Action: "abandoned",
		Skill:  "task:investigate",
		Reason: "watchdog timeout",
	}
	payloadBytes, _ := json.Marshal(payload)
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-fec-abandoned-001",
		Tags:    []string{"work:close", "action:abandoned"},
		Payload: string(payloadBytes),
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

	data, err := os.ReadFile(filepath.Join(outDir, "FC-03.json"))
	if err != nil {
		t.Fatalf("FC-03.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse FC-03.json: %v", err)
	}
	if rec.StructuralCause != "abandoned-by-model" {
		t.Errorf("ScenarioRecord.StructuralCause = %q, want abandoned-by-model (190's normalizer must win over fec reason-parser)", rec.StructuralCause)
	}
	if rec.TerminalAction != "escalated" {
		t.Errorf("ScenarioRecord.TerminalAction = %q, want escalated (190's normalizer maps abandoned → escalated)", rec.TerminalAction)
	}
}


// ---- mallcoppro-c6a defense: ts.chain population on attributed investigate work:create ----

// TestChainShape_InvestigateAttributed_PopulatesChain verifies the Defense 2
// invariant (mallcoppro-c6a): when a work:create message carrying a
// skill:task:investigate tag is attributed to a tracked scenario (via the
// finding-tag attribution path), the academy MUST append a ChainEntry to
// ts.chain so the chain-shape detector at quiescence sees the investigate
// dispatch and correctly skips the no-triage-inference verdict.
//
// Companion to TestChainShape_InvestigateWorkCreateOnly_QuiescenceMisclassifies
// in PR #101 — that test exercises the misclassification end-to-end; this test
// pins the specific population behavior so a future refactor that drops the
// chain append regresses visibly here, not only through the higher-level test.
func TestChainShape_InvestigateAttributed_PopulatesChain(t *testing.T) {
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "NT-CP", "fnd_nt_cp", "detector-priv-escalation",
		"Investigate spawn must reach ts.chain", "high")

	outDir := t.TempDir()
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target-chain-populate",
		scenariosDir:   scenDir,
		scenarioFilter: "NT-CP",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        6 * time.Second,
		runID:          "test-mock-run-chain-populate",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

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

	// Triage emits an investigate work:create (the canonical
	// escalate-to-investigator handoff shape: skill tag + finding tag).
	// Inject a triage close with non-terminal action ("noop") so the chain
	// quiesces without reaching the terminal switch — exercising the
	// quiescence detector path. The detector must NOT fire because the
	// investigate work:create populates ts.chain.
	investigateCreatePayload := `{"id":"item-attrib-invest-001","skill":"task:investigate","title":"investigate fnd_nt_cp"}`
	closeNoopPayload, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "noop",
		Skill:  "task:triage",
	})

	perRunFinding := perRunFindingID("fnd_nt_cp", "test-mock-run-chain-populate")
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "msg-chain-populate-invest-001",
		Tags:    []string{"work:create", "skill:task:investigate", "finding:" + perRunFinding},
		Payload: investigateCreatePayload,
	})
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "msg-chain-populate-close-001",
		Tags:    []string{"work:close", "action:noop"},
		Payload: string(closeNoopPayload),
	})
	ms.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("academy did not complete within deadline")
	}

	data, err := os.ReadFile(filepath.Join(outDir, "NT-CP.json"))
	if err != nil {
		t.Fatalf("NT-CP.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse NT-CP.json: %v", err)
	}

	// Defense: ts.chain MUST contain a ChainEntry with skill=task:investigate
	// and empty Action (work:create). FullChain is the on-disk projection.
	foundInvestigateCreate := false
	for _, ce := range rec.FullChain {
		if ce.Action == "" && isInvestigateSkill(ce.Skill) {
			foundInvestigateCreate = true
			break
		}
	}
	if !foundInvestigateCreate {
		t.Errorf("DEFENSE BROKEN: attributed work:create with skill:task:investigate did NOT "+
			"reach ts.chain. Chain entries: %+v. The chain-shape detector cannot "+
			"distinguish a triage that DID escalate from one that didn't — Defense 2 "+
			"(mallcoppro-c6a) is bypassed.", rec.FullChain)
	}

	// And: detector must NOT have classified this as no-triage-inference.
	if rec.StructuralCause == "no-triage-inference" {
		t.Errorf("Defense 2 regression: detector still classified as no-triage-inference "+
			"despite investigate work:create being attributed. record=%+v", rec)
	}
}
