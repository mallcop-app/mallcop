package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// seedCaptureStore opens a fresh git-backed store at t.TempDir() and appends
// the given events to KindEvents, one at a time, in order — mirroring what a
// real 'mallcop scan' run would have durably committed over time.
func seedCaptureStore(t *testing.T, events []event.Event) *store.Store {
	t.Helper()
	st, err := openOrInitStore(t.TempDir())
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}
	for _, ev := range events {
		if _, err := st.Append(store.KindEvents, ev); err != nil {
			t.Fatalf("append event %s: %v", ev.ID, err)
		}
	}
	return st
}

func mustPayload(t *testing.T, v map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

// TestScenarioCapture_ByActorWindow_RoundTripsThroughEval is the C5
// acceptance test: capture a brand-new actor's activity from a seeded store,
// write it as a must_fire scenario, and prove the SAME grading path
// 'mallcop eval' uses (eval.LoadExtraScenarios + eval.RunExamDetectOverCorpus)
// passes it — the captured event set genuinely triggers the registered
// "new-actor" detector because the derived baseline (built from every OTHER
// stored event) never saw this actor before.
func TestScenarioCapture_ByActorWindow_RoundTripsThroughEval(t *testing.T) {
	detect.ResetTuning()
	t.Cleanup(detect.ResetTuning)

	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	st := seedCaptureStore(t, []event.Event{
		// Background history: "carol" is a known, established actor.
		{ID: "bg-1", Source: "github", Type: "push", Actor: "carol", Timestamp: base.Add(-72 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "push"})},
		{ID: "bg-2", Source: "github", Type: "push", Actor: "carol", Timestamp: base.Add(-48 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "push"})},
		// The captured attack: a brand-new actor "mallory" shows up.
		{ID: "atk-1", Source: "github", Type: "repo.permission.grant", Actor: "mallory", Timestamp: base.Add(-2 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "grant_admin", "role_name": "admin"})},
		{ID: "atk-2", Source: "github", Type: "repo.clone", Actor: "mallory", Timestamp: base.Add(-1 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "clone_all_repos"})},
	})

	scenariosDir := filepath.Join(t.TempDir(), "scenarios")

	out, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--actor", "mallory",
			"--window", "24h",
			"--must-fire", "new-actor",
			"--id", "LOCAL-TEST-mallory",
			"--scenarios-dir", scenariosDir,
		})
	})
	if err != nil {
		t.Fatalf("runScenarioCapture: %v\noutput:\n%s", err, out)
	}

	outPath := filepath.Join(scenariosDir, "LOCAL-TEST-mallory.yaml")
	if _, statErr := os.Stat(outPath); statErr != nil {
		t.Fatalf("expected scenario file at %s: %v", outPath, statErr)
	}

	sc, err := exam.Load(outPath)
	if err != nil {
		t.Fatalf("internal/exam.Load(%s): %v", outPath, err)
	}
	if sc.EffectiveProvenance() != exam.ProvenanceCaptured {
		t.Errorf("provenance = %q, want %q", sc.Provenance, exam.ProvenanceCaptured)
	}
	if sc.ExpectedDetection == nil || len(sc.ExpectedDetection.MustFire) != 1 || sc.ExpectedDetection.MustFire[0] != "new-actor" {
		t.Fatalf("expected_detection = %+v, want must_fire=[new-actor]", sc.ExpectedDetection)
	}
	if len(sc.Events) != 2 {
		t.Fatalf("captured %d events, want 2 (atk-1, atk-2 only — background events excluded)", len(sc.Events))
	}
	for _, ev := range sc.Events {
		if ev.ID != "atk-1" && ev.ID != "atk-2" {
			t.Errorf("unexpected captured event id %q", ev.ID)
		}
	}
	if sc.Baseline == nil {
		t.Fatal("expected a baseline block (carol's background history should have baselined)")
	}
	found := false
	for _, a := range sc.Baseline.KnownEntities.Actors {
		if a == "carol" {
			found = true
		}
		if a == "mallory" {
			t.Error("mallory must NOT be in the derived baseline's known actors — that is exactly the finding under test")
		}
	}
	if !found {
		t.Errorf("expected carol in baseline known_entities.actors, got %v", sc.Baseline.KnownEntities.Actors)
	}

	// The round-trip: grade the captured scenario through the IDENTICAL path
	// 'mallcop eval' uses for an operator's own scenarios/ directory.
	extra, err := eval.LoadExtraScenarios(scenariosDir)
	if err != nil {
		t.Fatalf("eval.LoadExtraScenarios: %v", err)
	}
	if len(extra) != 1 {
		t.Fatalf("loaded %d extra scenarios, want 1", len(extra))
	}
	report := eval.RunExamDetectOverCorpus(eval.Corpus{}, extra)
	if report.Totals.Labeled != 1 {
		t.Fatalf("totals.labeled = %d, want 1", report.Totals.Labeled)
	}
	if report.Totals.Passed != 1 || report.Totals.Failed != 0 {
		t.Fatalf("totals = %+v, want exactly 1 passed row (new-actor genuinely fires on mallory)", report.Totals)
	}
}

// TestScenarioCapture_ByEventIDs proves the explicit --event-ids selector
// captures exactly the named events, in store order, regardless of actor.
func TestScenarioCapture_ByEventIDs(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	st := seedCaptureStore(t, []event.Event{
		{ID: "e1", Source: "aws", Type: "console_login", Actor: "alice", Timestamp: base, Payload: mustPayload(t, map[string]any{"action": "login"})},
		{ID: "e2", Source: "aws", Type: "console_login", Actor: "bob", Timestamp: base.Add(time.Hour), Payload: mustPayload(t, map[string]any{"action": "login"})},
		{ID: "e3", Source: "aws", Type: "console_login", Actor: "carol", Timestamp: base.Add(2 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "login"})},
	})

	scenariosDir := t.TempDir()
	out, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--event-ids", "e3,e1",
			"--must-not-fire", "new-actor",
			"--id", "LOCAL-TEST-explicit",
			"--scenarios-dir", scenariosDir,
		})
	})
	if err != nil {
		t.Fatalf("runScenarioCapture: %v\noutput:\n%s", err, out)
	}

	sc, err := exam.Load(filepath.Join(scenariosDir, "LOCAL-TEST-explicit.yaml"))
	if err != nil {
		t.Fatalf("exam.Load: %v", err)
	}
	if len(sc.Events) != 2 {
		t.Fatalf("captured %d events, want 2", len(sc.Events))
	}
	// Store order (e1 before e3), not request order (e3,e1).
	if sc.Events[0].ID != "e1" || sc.Events[1].ID != "e3" {
		t.Errorf("event order = [%s,%s], want [e1,e3] (store chronological order)", sc.Events[0].ID, sc.Events[1].ID)
	}
}

// TestScenarioCapture_MissingEventID_Errors proves a nonexistent explicit
// event id fails loudly rather than silently capturing a smaller set.
func TestScenarioCapture_MissingEventID_Errors(t *testing.T) {
	st := seedCaptureStore(t, []event.Event{
		{ID: "e1", Source: "aws", Type: "console_login", Actor: "alice", Timestamp: time.Now()},
	})
	_, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--event-ids", "e1,does-not-exist",
			"--must-not-fire", "new-actor",
			"--scenarios-dir", t.TempDir(),
		})
	})
	if err == nil {
		t.Fatal("expected an error for a nonexistent --event-ids entry")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error = %v, want it to name the missing id", err)
	}
}

// TestScenarioCapture_RedactsSecrets proves a credential-shaped metadata
// value is scrubbed from the captured YAML while ordinary fields (actor,
// action, non-secret metadata) survive verbatim.
func TestScenarioCapture_RedactsSecrets(t *testing.T) {
	st := seedCaptureStore(t, []event.Event{
		{
			ID: "leak-1", Source: "github", Type: "secret_scan_alert", Actor: "ci-bot",
			Timestamp: time.Now(),
			Payload: mustPayload(t, map[string]any{
				"action":       "commit_push",
				"github_token": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"repo":         "acme/widgets",
			}),
		},
	})

	scenariosDir := t.TempDir()
	out, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--event-ids", "leak-1",
			"--must-fire", "secrets-exposure",
			"--id", "LOCAL-TEST-secret",
			"--scenarios-dir", scenariosDir,
		})
	})
	if err != nil {
		t.Fatalf("runScenarioCapture: %v\noutput:\n%s", err, out)
	}

	raw, err := os.ReadFile(filepath.Join(scenariosDir, "LOCAL-TEST-secret.yaml"))
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	body := string(raw)
	if strings.Contains(body, "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Error("captured YAML contains the raw GitHub token — must be redacted")
	}
	if !strings.Contains(body, "REDACTED") {
		t.Error("captured YAML has no [REDACTED] marker — secret scrub did not run")
	}
	if !strings.Contains(body, "acme/widgets") {
		t.Error("captured YAML dropped a non-secret metadata field (repo) — over-redaction")
	}
	if !strings.Contains(body, "ci-bot") {
		t.Error("captured YAML dropped the actor — actors must be kept")
	}

	sc, err := exam.Load(filepath.Join(scenariosDir, "LOCAL-TEST-secret.yaml"))
	if err != nil {
		t.Fatalf("exam.Load: %v", err)
	}
	if len(sc.Events) != 1 {
		t.Fatalf("captured %d events, want 1", len(sc.Events))
	}
	if got, _ := sc.Events[0].Metadata["github_token"].(string); got != captureRedactedPlaceholder {
		t.Errorf("metadata.github_token = %q, want %q", got, captureRedactedPlaceholder)
	}
}

// TestScenarioCapture_MustFireAndMustNotFireMutuallyExclusive and the
// selector-validation cases below prove the flag-combination guard rails.
func TestScenarioCapture_ValidationErrors(t *testing.T) {
	st := seedCaptureStore(t, []event.Event{
		{ID: "e1", Source: "aws", Type: "console_login", Actor: "alice", Timestamp: time.Now()},
	})

	cases := []struct {
		name string
		args []string
	}{
		{"no store", []string{"--must-fire", "x", "--event-ids", "e1"}},
		{"no selector", []string{"--store", st.Path(), "--must-fire", "x"}},
		{"actor without window", []string{"--store", st.Path(), "--actor", "alice", "--must-fire", "x"}},
		{"window without actor", []string{"--store", st.Path(), "--window", "24h", "--must-fire", "x"}},
		{"no label", []string{"--store", st.Path(), "--event-ids", "e1"}},
		{"both labels", []string{"--store", st.Path(), "--event-ids", "e1", "--must-fire", "x", "--must-not-fire", "y"}},
		{"reserved without must-fire", []string{"--store", st.Path(), "--event-ids", "e1", "--must-not-fire", "y", "--reserved"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := withStdio(t, "", func() error { return runScenarioCapture(tc.args) })
			if err == nil {
				t.Fatalf("runScenarioCapture(%v): expected an error, got nil", tc.args)
			}
		})
	}
}
