package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout to a pipe during fn, then returns what was
// written. This lets us test run() without exec.Command.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return buf.String()
}

// makeFixtureDir creates a temp fixture directory with optional baseline.json,
// events.json, and findings.jsonl content.
func makeFixtureDir(t *testing.T, baseline, events, findings string) string {
	t.Helper()
	dir := t.TempDir()
	if baseline != "" {
		if err := os.WriteFile(filepath.Join(dir, "baseline.json"), []byte(baseline), 0o644); err != nil {
			t.Fatalf("write baseline.json: %v", err)
		}
	}
	if events != "" {
		if err := os.WriteFile(filepath.Join(dir, "events.json"), []byte(events), 0o644); err != nil {
			t.Fatalf("write events.json: %v", err)
		}
	}
	if findings != "" {
		if err := os.WriteFile(filepath.Join(dir, "findings.jsonl"), []byte(findings), 0o644); err != nil {
			t.Fatalf("write findings.jsonl: %v", err)
		}
	}
	return dir
}

// ---- check-baseline tests --------------------------------------------------

func TestCheckBaseline_HappyPath(t *testing.T) {
	baselineJSON := `{
		"known_entities": {
			"actors": ["alice@example.com"],
			"sources": ["github"]
		},
		"frequency_tables": {"alice@example.com": 42},
		"relationships": {
			"alice@example.com": {
				"count": 42,
				"first_seen": "2026-03-01T00:00:00Z",
				"last_seen": "2026-04-10T12:00:00Z"
			}
		}
	}`
	dir := makeFixtureDir(t, baselineJSON, "", "")

	var result baselineResult
	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "check-baseline",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "alice@example.com",
			"--source", "github",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if !result.Known {
		t.Errorf("Known = false, want true")
	}
	if result.Frequency != 42 {
		t.Errorf("Frequency = %d, want 42", result.Frequency)
	}
	if result.LastSeen != "2026-04-10T12:00:00Z" {
		t.Errorf("LastSeen = %q, want %q", result.LastSeen, "2026-04-10T12:00:00Z")
	}
	// TODO(mallcoppro-a97): roles always empty until upstream adds actor_roles.
	if result.Roles == nil {
		t.Errorf("Roles must not be nil (should be empty slice)")
	}
}

func TestCheckBaseline_NotFound(t *testing.T) {
	baselineJSON := `{
		"known_entities": {
			"actors": ["bob@example.com"],
			"sources": ["github"]
		}
	}`
	dir := makeFixtureDir(t, baselineJSON, "", "")

	var result baselineResult
	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "check-baseline",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "unknown@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result.Known {
		t.Errorf("Known = true for unknown entity, want false")
	}
	if result.Frequency != 0 {
		t.Errorf("Frequency = %d, want 0 for unknown entity", result.Frequency)
	}
}

func TestCheckBaseline_NoBaselineFile(t *testing.T) {
	// No baseline.json at all — empty fixture dir.
	dir := makeFixtureDir(t, "", "", "")

	var result baselineResult
	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "check-baseline",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "alice@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result.Known {
		t.Errorf("Known = true with no baseline file, want false")
	}
}

func TestCheckBaseline_ProductionStubbed(t *testing.T) {
	dir := makeFixtureDir(t, "", "", "")
	err := run([]string{
		"--tool", "check-baseline",
		"--mode", "production",
		"--fixture-dir", dir,
		"--entity", "alice@example.com",
	})
	if err == nil {
		t.Fatal("expected error for production mode, got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should mention 'not yet implemented', got: %v", err)
	}
}

// ---- search-events tests ---------------------------------------------------

const testEventsJSON = `{
	"events": [
		{
			"id": "evt-001",
			"timestamp": "2026-04-10T10:00:00Z",
			"source": "github",
			"event_type": "push",
			"actor": "alice@example.com",
			"action": "git.push",
			"target": "repo/main",
			"severity": "info"
		},
		{
			"id": "evt-002",
			"timestamp": "2026-04-09T08:00:00Z",
			"source": "azure",
			"event_type": "login",
			"actor": "bob@example.com",
			"action": "user.login",
			"target": "portal",
			"severity": "low"
		},
		{
			"id": "evt-003",
			"timestamp": "2026-04-10T11:00:00Z",
			"source": "github",
			"event_type": "login",
			"actor": "alice@example.com",
			"action": "user.login",
			"target": "github.com",
			"severity": "info"
		}
	]
}`

// decodeSearchEventsWrapped is a small test helper that parses the wrapped
// {events, matched_rules} envelope that search-events always emits.
func decodeSearchEventsWrapped(t *testing.T, out string) searchEventsResult {
	t.Helper()
	var result searchEventsResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse wrapped output: %v\nraw=%s", err, out)
	}
	return result
}

func TestSearchEvents_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--source", "github",
			"--since", "2026-04-10T00:00:00Z",
			"--until", "2026-04-10T23:59:59Z",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	result := decodeSearchEventsWrapped(t, out)
	if len(result.Events) != 2 {
		t.Errorf("want 2 events for alice on github on 2026-04-10, got %d\nout=%q", len(result.Events), out)
	}
	for _, ev := range result.Events {
		if !strings.EqualFold(ev.Actor, "alice@example.com") {
			t.Errorf("got actor %q, want alice@example.com", ev.Actor)
		}
		if !strings.EqualFold(ev.Source, "github") {
			t.Errorf("got source %q, want github", ev.Source)
		}
	}
}

func TestSearchEvents_ActorNotFound(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "nobody@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	result := decodeSearchEventsWrapped(t, out)
	if len(result.Events) != 0 {
		t.Errorf("expected zero events for unknown actor, got %d\nout=%q", len(result.Events), out)
	}
}

func TestSearchEvents_NoEventsFile(t *testing.T) {
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	result := decodeSearchEventsWrapped(t, out)
	if len(result.Events) != 0 {
		t.Errorf("expected zero events when no events.json, got %d\nout=%q", len(result.Events), out)
	}
	if len(result.MatchedRules) != 0 {
		t.Errorf("expected zero matched_rules when no events.json, got %d", len(result.MatchedRules))
	}
}

func TestSearchEvents_TypeFilter(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--type", "push",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	result := decodeSearchEventsWrapped(t, out)
	if len(result.Events) != 1 {
		t.Fatalf("want 1 push event for alice, got %d\nout=%q", len(result.Events), out)
	}
	if result.Events[0].EventType != "push" {
		t.Errorf("event_type = %q, want push", result.Events[0].EventType)
	}
}

func TestSearchEvents_ProductionStubbed(t *testing.T) {
	err := run([]string{
		"--tool", "search-events",
		"--mode", "production",
		"--actor", "alice@example.com",
	})
	if err == nil {
		t.Fatal("expected error for production mode, got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should mention 'not yet implemented', got: %v", err)
	}
}

// ---- search-findings tests -------------------------------------------------

const testFindingsJSONL = `{"id":"fnd-001","actor":"alice@example.com","source":"github","timestamp":"2026-04-10T10:00:00Z","title":"Unusual push pattern"}
{"id":"fnd-002","actor":"bob@example.com","source":"azure","timestamp":"2026-04-09T08:00:00Z","title":"Off-hours login"}
`

func TestSearchFindings_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-findings",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--since", "2026-04-10T00:00:00Z",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Errorf("want 1 finding for alice after 2026-04-10, got %d\nout=%q", len(lines), out)
	}
	var finding map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &finding); err != nil {
		t.Fatalf("parse finding: %v", err)
	}
	if finding["id"] != "fnd-001" {
		t.Errorf("id = %v, want fnd-001", finding["id"])
	}
}

func TestSearchFindings_ActorNotFound(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-findings",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "nobody@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output for unknown actor, got: %q", out)
	}
}

func TestSearchFindings_NoFindingsFile(t *testing.T) {
	// findings.jsonl may not exist yet — empty result is valid.
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-findings",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output when no findings.jsonl, got: %q", out)
	}
}

func TestSearchFindings_ProductionStubbed(t *testing.T) {
	err := run([]string{
		"--tool", "search-findings",
		"--mode", "production",
		"--actor", "alice@example.com",
	})
	if err == nil {
		t.Fatal("expected error for production mode, got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should mention 'not yet implemented', got: %v", err)
	}
}

// ---- read-finding ----------------------------------------------------------

const testFindingsForReadJSONL = `{"finding_id":"fnd-rf-001","actor":"alice@example.com","source":"github","title":"Unusual push pattern","severity":"medium"}
{"id":"fnd-rf-002","actor":"bob@example.com","source":"azure","title":"Off-hours login","severity":"low"}
`

func TestReadFinding_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsForReadJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-finding",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--finding-id", "fnd-rf-001",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var finding map[string]interface{}
	if err := json.Unmarshal([]byte(out), &finding); err != nil {
		t.Fatalf("parse finding: %v\nout=%q", err, out)
	}
	if finding["finding_id"] != "fnd-rf-001" {
		t.Errorf("finding_id = %v, want fnd-rf-001", finding["finding_id"])
	}
	if finding["actor"] != "alice@example.com" {
		t.Errorf("actor = %v, want alice@example.com", finding["actor"])
	}
	if finding["error"] != nil {
		t.Errorf("unexpected error key in happy-path output: %v", finding["error"])
	}
}

func TestReadFinding_HappyPath_IDFallback(t *testing.T) {
	// findings without finding_id but with id should still be findable.
	dir := makeFixtureDir(t, "", "", testFindingsForReadJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-finding",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--finding-id", "fnd-rf-002",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var finding map[string]interface{}
	if err := json.Unmarshal([]byte(out), &finding); err != nil {
		t.Fatalf("parse finding: %v\nout=%q", err, out)
	}
	if finding["id"] != "fnd-rf-002" {
		t.Errorf("id = %v, want fnd-rf-002", finding["id"])
	}
	if finding["error"] != nil {
		t.Errorf("unexpected error key in id-fallback output: %v", finding["error"])
	}
}

func TestReadFinding_NotFound(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsForReadJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-finding",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--finding-id", "fnd-rf-does-not-exist",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error for not-found: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v\nout=%q", err, out)
	}
	if result["error"] != "not_found" {
		t.Errorf("error = %v, want not_found", result["error"])
	}
	if result["finding_id"] != "fnd-rf-does-not-exist" {
		t.Errorf("finding_id echo = %v, want fnd-rf-does-not-exist", result["finding_id"])
	}
}

func TestReadFinding_NoFindingsFile(t *testing.T) {
	// findings.jsonl absent — must return not_found, not an error.
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-finding",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--finding-id", "fnd-rf-001",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error when findings.jsonl absent: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v\nout=%q", err, out)
	}
	if result["error"] != "not_found" {
		t.Errorf("error = %v, want not_found when findings.jsonl absent", result["error"])
	}
}

func TestReadFinding_RequiresFindingID(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsForReadJSONL)

	err := run([]string{
		"--tool", "read-finding",
		"--mode", "exam",
		"--fixture-dir", dir,
	})
	if err == nil {
		t.Fatal("expected error for missing --finding-id, got nil")
	}
	if !strings.Contains(err.Error(), "finding-id is required") {
		t.Errorf("error message = %v, want mention of finding-id required", err)
	}
}

// ---- baseline-stats tests --------------------------------------------------

// testBaselineEventsArray is a flat JSON array of event records used for
// baseline-stats tests.
const testBaselineEventsArray = `[
	{"actor":"alice@example.com","source":"github","type":"push","timestamp":"2026-04-10T09:00:00Z"},
	{"actor":"alice@example.com","source":"github","type":"push","timestamp":"2026-04-10T22:00:00Z"},
	{"actor":"alice@example.com","source":"aws","type":"login","timestamp":"2026-04-09T03:00:00Z"},
	{"actor":"bob@example.com","source":"github","type":"login","timestamp":"2026-04-10T10:00:00Z"}
]`

func TestBaselineStats_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, testBaselineEventsArray, "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "baseline-stats",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "alice@example.com",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result baselineStatsResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result.CountTotal != 3 {
		t.Errorf("CountTotal = %d, want 3 (3 alice events)", result.CountTotal)
	}
	if result.CountBySource["github"] != 2 {
		t.Errorf("CountBySource[github] = %d, want 2", result.CountBySource["github"])
	}
	if result.CountBySource["aws"] != 1 {
		t.Errorf("CountBySource[aws] = %d, want 1", result.CountBySource["aws"])
	}
	if result.CountByType["push"] != 2 {
		t.Errorf("CountByType[push] = %d, want 2", result.CountByType["push"])
	}
	if result.CountByType["login"] != 1 {
		t.Errorf("CountByType[login] = %d, want 1", result.CountByType["login"])
	}
	// Hour 09 and 22 and 03 for alice
	if result.TimeOfDayDistribution["09"] != 1 {
		t.Errorf("time_of_day_distribution[09] = %d, want 1", result.TimeOfDayDistribution["09"])
	}
	if result.TimeOfDayDistribution["22"] != 1 {
		t.Errorf("time_of_day_distribution[22] = %d, want 1", result.TimeOfDayDistribution["22"])
	}
	if result.FirstSeen == nil {
		t.Error("first_seen must not be nil")
	} else if *result.FirstSeen != "2026-04-09T03:00:00Z" {
		t.Errorf("first_seen = %q, want 2026-04-09T03:00:00Z", *result.FirstSeen)
	}
	if result.LastSeen == nil {
		t.Error("last_seen must not be nil")
	} else if *result.LastSeen != "2026-04-10T22:00:00Z" {
		t.Errorf("last_seen = %q, want 2026-04-10T22:00:00Z", *result.LastSeen)
	}
}

func TestBaselineStats_FilterEmpty(t *testing.T) {
	// Filter by entity that has no events — expect all zeros, null timestamps.
	dir := makeFixtureDir(t, testBaselineEventsArray, "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "baseline-stats",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "nobody@example.com",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result baselineStatsResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result.CountTotal != 0 {
		t.Errorf("CountTotal = %d, want 0 for unknown entity", result.CountTotal)
	}
	if result.FirstSeen != nil {
		t.Errorf("first_seen should be null for empty result, got %q", *result.FirstSeen)
	}
	if result.LastSeen != nil {
		t.Errorf("last_seen should be null for empty result, got %q", *result.LastSeen)
	}
	// time_of_day_distribution must have all 24 keys initialized to 0
	if len(result.TimeOfDayDistribution) != 24 {
		t.Errorf("time_of_day_distribution should have 24 keys, got %d", len(result.TimeOfDayDistribution))
	}
	for h := 0; h < 24; h++ {
		key := fmt.Sprintf("%02d", h)
		if result.TimeOfDayDistribution[key] != 0 {
			t.Errorf("time_of_day_distribution[%s] = %d, want 0 for empty result", key, result.TimeOfDayDistribution[key])
		}
	}
}

func TestBaselineStats_NoFile(t *testing.T) {
	// No baseline.json — returns empty stats, no error.
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "baseline-stats",
			"--mode", "exam",
			"--fixture-dir", dir,
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	var result baselineStatsResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result.CountTotal != 0 {
		t.Errorf("CountTotal = %d, want 0 when no file", result.CountTotal)
	}
	if result.FirstSeen != nil || result.LastSeen != nil {
		t.Errorf("first_seen/last_seen must be null when no file")
	}
}

// ---- read-config tests -----------------------------------------------------

const testConfigJSON = `{
	"detectors": {
		"brute-force-detector": {"threshold": 5, "enabled": true},
		"off-hours-login": {"threshold": 1, "enabled": false}
	},
	"connectors": {
		"github": {"scope": "org", "enabled": true, "sources": ["audit_log", "repos"]},
		"aws": {"scope": "account", "enabled": true, "sources": ["cloudtrail"]}
	}
}`

func TestReadConfig_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, "", "", "")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(testConfigJSON), 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-config",
			"--mode", "exam",
			"--fixture-dir", dir,
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result configResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if len(result.Detectors) != 2 {
		t.Errorf("want 2 detectors, got %d", len(result.Detectors))
	}
	if len(result.Connectors) != 2 {
		t.Errorf("want 2 connectors, got %d", len(result.Connectors))
	}
}

func TestReadConfig_FilterByDetector(t *testing.T) {
	dir := makeFixtureDir(t, "", "", "")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(testConfigJSON), 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-config",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--detector", "brute-force-detector",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result configResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if len(result.Detectors) != 1 {
		t.Errorf("want 1 detector (filtered), got %d", len(result.Detectors))
	}
	if _, ok := result.Detectors["brute-force-detector"]; !ok {
		t.Errorf("expected brute-force-detector in result")
	}
}

func TestReadConfig_NoFile(t *testing.T) {
	// config.json absent — returns empty config, no error.
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-config",
			"--mode", "exam",
			"--fixture-dir", dir,
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	var result configResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if len(result.Detectors) != 0 {
		t.Errorf("want 0 detectors when no file, got %d", len(result.Detectors))
	}
	if len(result.Connectors) != 0 {
		t.Errorf("want 0 connectors when no file, got %d", len(result.Connectors))
	}
}

// ---- load-skill tests ------------------------------------------------------

// writeCatalog writes a YAML skill catalog to a temp dir and sets
// MALLCOP_REPO_ROOT to point there, returning the dir and a cleanup func.
func writeCatalog(t *testing.T, yamlContent string) (repoRoot string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "skill-catalog.yaml"), []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write skill-catalog.yaml: %v", err)
	}
	orig := os.Getenv("MALLCOP_REPO_ROOT")
	os.Setenv("MALLCOP_REPO_ROOT", dir)
	return dir, func() {
		os.Setenv("MALLCOP_REPO_ROOT", orig)
	}
}

const testSkillCatalogYAML = `
skills:
  - name: aws-iam
    version: "1.0.0"
    source: aws
    description: AWS IAM privilege analysis skill.
    status: active
    binding: static-chart
    tools:
      - name: aws-iam-query
        description: Query IAM policies and roles.
  - name: github-audit
    version: "1.1.0"
    source: github
    description: GitHub audit log analysis.
    status: experimental
    binding: static-chart
    tools:
      - name: github-audit-query
        description: Query GitHub audit log.
`

func TestLoadSkill_HappyPath(t *testing.T) {
	_, cleanup := writeCatalog(t, testSkillCatalogYAML)
	defer cleanup()

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill"})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if len(result.Skills) != 2 {
		t.Errorf("want 2 skills (no filter), got %d", len(result.Skills))
	}
	if result.BindingNote == "" {
		t.Errorf("binding_note must not be empty")
	}
}

func TestLoadSkill_FilterBySkillName(t *testing.T) {
	_, cleanup := writeCatalog(t, testSkillCatalogYAML)
	defer cleanup()

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill", "--skill-name", "aws-iam"})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if len(result.Skills) != 1 {
		t.Errorf("want 1 skill (filtered by name), got %d", len(result.Skills))
	}
	if result.Skills[0].Name != "aws-iam" {
		t.Errorf("skill name = %q, want aws-iam", result.Skills[0].Name)
	}
}

func TestLoadSkill_FilterBySourceHint(t *testing.T) {
	_, cleanup := writeCatalog(t, testSkillCatalogYAML)
	defer cleanup()

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill", "--source-hint", "GitHub"}) // case-insensitive
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if len(result.Skills) != 1 {
		t.Errorf("want 1 skill (filtered by source_hint=github), got %d", len(result.Skills))
	}
	if result.Skills[0].Name != "github-audit" {
		t.Errorf("skill name = %q, want github-audit", result.Skills[0].Name)
	}
}

func TestLoadSkill_BindingNotePresent(t *testing.T) {
	_, cleanup := writeCatalog(t, testSkillCatalogYAML)
	defer cleanup()

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill"})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if !strings.Contains(result.BindingNote, "does not register new tools at runtime") {
		t.Errorf("binding_note must state that load-skill does not register new tools at runtime; got %q", result.BindingNote)
	}
	if !strings.Contains(result.BindingNote, "statically registered") {
		t.Errorf("binding_note must mention 'statically registered'; got %q", result.BindingNote)
	}
}

func TestLoadSkill_NoCatalogFile(t *testing.T) {
	// No catalog file — empty catalog is normal at boot.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	orig := os.Getenv("MALLCOP_REPO_ROOT")
	os.Setenv("MALLCOP_REPO_ROOT", dir)
	defer os.Setenv("MALLCOP_REPO_ROOT", orig)

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill"})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if len(result.Skills) != 0 {
		t.Errorf("want 0 skills when no catalog file, got %d", len(result.Skills))
	}
	if result.BindingNote == "" {
		t.Errorf("binding_note must not be empty even when catalog is absent")
	}
}

// ---- security invariant tests ----------------------------------------------

// TestInvestigateTools_NoNetworkImports greps main.go for forbidden imports.
// This test is the structural defence against network egress and shell escape.
// It strips Go line comments (//) and block comments (/* ... */) before
// checking, so doc-string mentions of forbidden packages don't trigger false
// positives.
func TestInvestigateTools_NoNetworkImports(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	// Strip line comments to avoid matching doc strings that mention the
	// forbidden packages by name (e.g. "No network egress: "net/http" ...").
	stripped := stripLineComments(src)

	// "syscall" is used for file permissions in stdlib internals but we don't
	// import it directly — block it. If you need errno constants, use
	// golang.org/x/sys/unix which can be audited per-symbol.
	forbidden := []string{
		`"net/http"`,
		`"net"`,
		`"os/exec"`,
		`"syscall"`,
	}
	for _, f := range forbidden {
		if bytes.Contains(stripped, []byte(f)) {
			t.Errorf("forbidden import %s present in investigate tools — security invariant broken", f)
		}
	}
}

// stripLineComments removes Go-style line comments (// ...) from src.
// This is intentionally simple: it removes everything from // to end-of-line.
// It does not handle string literals that contain "//", which is an acceptable
// trade-off for this invariant test — the invariant is about import declarations,
// not arbitrary string content.
func stripLineComments(src []byte) []byte {
	var out bytes.Buffer
	lines := bytes.Split(src, []byte("\n"))
	for _, line := range lines {
		if idx := bytes.Index(line, []byte("//")); idx >= 0 {
			line = line[:idx]
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// ---- chart allowlist name test ---------------------------------------------

// TestChartAllowlistMatch verifies that the binary name in the chart seed
// matches the binary name this cmd builds to. A name mismatch causes a silent
// boot-failure of the investigate disposition at legion startup.
func TestChartAllowlistMatch(t *testing.T) {
	// Binary name: the last path segment of the cmd directory.
	// By convention Go builds the binary from the directory name.
	const wantBinaryName = "mallcop-investigate-tools"

	// Read the chart template.
	chartPath := filepath.Join("..", "..", "charts", "exam.toml.tmpl")
	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("read %s: %v", chartPath, err)
	}

	content := string(data)

	// The investigate capability seed should have this binary in its tools list.
	// We look for the binary name as a quoted string entry adjacent to the
	// "investigate" section.
	if !strings.Contains(content, `"`+wantBinaryName+`"`) {
		t.Errorf("chart %s does not contain tool entry %q — investigate disposition will fail to boot",
			chartPath, wantBinaryName)
	}
}

// ---- symlink escape test ---------------------------------------------------

// TestSymlinkEscape verifies that safeOpen rejects paths that resolve outside
// the fixture dir via symlink traversal.
func TestSymlinkEscape(t *testing.T) {
	// Create a temp dir representing the fixture dir.
	fixtureDir := t.TempDir()

	// Create a second temp dir outside the fixture dir (the escape target).
	outsideDir := t.TempDir()
	secretFile := filepath.Join(outsideDir, "secret.json")
	if err := os.WriteFile(secretFile, []byte(`{"secret": "shh"}`), 0o644); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	// Create a symlink inside fixtureDir pointing to the outside dir.
	symlinkPath := filepath.Join(fixtureDir, "escape_link")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// Attempt to open the secret file via the symlink: fixture/escape_link/secret.json
	// safeOpen takes (baseDir, relPath) where relPath is relative to baseDir.
	_, err := safeOpen(fixtureDir, "escape_link/secret.json")
	if err == nil {
		t.Fatal("safeOpen should have rejected symlink escape, got nil error")
	}
	if !strings.Contains(err.Error(), "escapes fixture dir") {
		t.Errorf("error should mention 'escapes fixture dir', got: %v", err)
	}
}

// TestResolveScenarioFixtureDir_AcademyItemID verifies that the per-scenario
// subdir is resolved when MALLCOP_ITEM_ID matches the academy pattern.
//
// This was the primary blocker for fixture data reaching the model — without
// this resolution, check-baseline reads <fixture-dir>/baseline.json directly
// (academy writes to <fixture-dir>/<scenario-id>/baseline.json), so every
// bakeoff before 2026-06-03 had empty baseline + events data and the model
// could only escalate based on the finding's metadata field.
func TestResolveScenarioFixtureDir_AcademyItemID(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "exams", "fixtures", "bk-open-20260603-220156")
	scnDir := filepath.Join(runDir, "UT-02-maintenance-window")
	if err := os.MkdirAll(scnDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scnDir, "baseline.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	got := resolveScenarioFixtureDir(runDir, "academy-bk-open-20260603-220156-UT-02-maintenance-window")
	if got != scnDir {
		t.Errorf("scenario subdir: got %q, want %q", got, scnDir)
	}
}

// TestResolveScenarioFixtureDir_FallsBackWhenMissing verifies that we return
// "" when the candidate scenario subdir doesn't exist on disk, so the caller
// falls back to the run-level fixture dir (preserves legacy behavior for
// fixtures laid out at run-level only).
func TestResolveScenarioFixtureDir_FallsBackWhenMissing(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "exams", "fixtures", "bk-open-test")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	got := resolveScenarioFixtureDir(runDir, "academy-bk-open-test-DOES-NOT-EXIST")
	if got != "" {
		t.Errorf("missing subdir should return empty, got %q", got)
	}
}

// TestResolveScenarioFixtureDir_NonAcademyItemID verifies that item IDs not
// matching the academy pattern produce empty (legacy fallback).
func TestResolveScenarioFixtureDir_NonAcademyItemID(t *testing.T) {
	cases := []string{
		"",
		"mallcopdeploy-abc",
		"rd-item-123",
		"academy-",
		"academy-rid",                 // no scenario
		"academy-different-run-id-XX", // run-id doesn't match fixture-dir basename
	}
	for _, c := range cases {
		got := resolveScenarioFixtureDir("/tmp/exams/fixtures/bk-open-test", c)
		if got != "" {
			t.Errorf("resolveScenarioFixtureDir(%q): got %q, want empty", c, got)
		}
	}
}

// TestCheckBaseline_FrequencySumsCompoundKeys verifies the bug fix for
// frequency aggregation. Baseline fixtures use compound keys like
// `<source>:<event_type>:<actor>` and `time:<hour>:<actor>`; the previous
// direct-lookup logic always returned 0 because the bare entity name was
// never a literal key.
func TestCheckBaseline_FrequencySumsCompoundKeys(t *testing.T) {
	root := t.TempDir()
	baselineJSON := `{
		"known_entities":{
			"Actors":["deploy-svc","admin-user"],
			"Sources":["azure"]
		},
		"frequency_tables":{
			"azure:config_update:deploy-svc":48,
			"azure:container_restart:deploy-svc":156,
			"time:02:deploy-svc":24,
			"azure:login:admin-user":340
		}
	}`
	if err := os.WriteFile(filepath.Join(root, "baseline.json"), []byte(baselineJSON), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	// Redirect emitJSON to a buffer by reading stdout would require harness;
	// instead capture via runner. Use the dispatchActionTool path? checkBaseline
	// emits to stdout directly via emitJSON. For now exercise via the function
	// and rely on no error + the run separately. Here we verify the sum logic.
	captured := captureStdout(t, func() {
		if err := checkBaseline(root, "deploy-svc", "", "", 168); err != nil {
			t.Fatalf("checkBaseline: %v", err)
		}
	})
	var got struct {
		Known     bool `json:"known"`
		Frequency int  `json:"frequency"`
	}
	if err := json.Unmarshal([]byte(captured), &got); err != nil {
		t.Fatalf("decode result: %v\nraw: %s", err, captured)
	}
	if !got.Known {
		t.Errorf("known should be true (actor in known_entities)")
	}
	if got.Frequency != 228 {
		t.Errorf("frequency: got %d, want 228 (48+156+24)", got.Frequency)
	}
}

// ---- Fix 1 (mallcoppro-DB3) — search-events folds in matched_rules ---------

// searchEventsRulesFixture mirrors the observable-predicate operator-decisions
// schema (mallcoppro-df1). Predicates use only fields the matcher can derive
// or that the worker can pass via finding_metadata.
const searchEventsRulesFixture = `
rules:
  - id: "R-001"
    applies_to:
      family: "unusual-timing"
      metadata_match:
        maintenance_window: "true"
    operator_directive: |
      Off-hours activity inside a maintenance window is non-investigatory.

  - id: "R-003"
    applies_to:
      family: "auth-failure-burst"
      metadata_match:
        resolution_event: "login_success"
    operator_directive: |
      An auth-failure burst followed by a login_success from the same IP is
      the canonical credential-typo pattern.

  - id: "R-007"
    applies_to:
      family: "new-actor"
      metadata_match:
        automation_provenance: "terraform"
    operator_directive: |
      A new actor whose surfaced events all carry terraform user-agent signals
      is consistent with first-run IaC provisioning; resolve with reference
      to the terraform correlation id and operation.
`

// TestSearchEvents_ReturnsMatchedRules verifies that when --finding-family is
// supplied, search-events emits a single wrapped JSON object containing both
// the filtered events AND any matching operator-decision rules.
//
// Fixture scenario: an unusual-timing finding whose events carry
// maintenance_window=true — should match R-001.
func TestSearchEvents_ReturnsMatchedRules(t *testing.T) {
	_ = writeRulesFixture(t, searchEventsRulesFixture)

	eventsJSON := `{
		"events": [
			{
				"id": "evt-001",
				"timestamp": "2026-04-10T02:15:00Z",
				"source": "azure",
				"event_type": "container_restart",
				"actor": "deploy-svc",
				"action": "restart",
				"target": "prod-api",
				"severity": "info",
				"metadata": {
					"maintenance_window": "true",
					"window_id": "MW-2026-04-10",
					"reason": "scheduled patch"
				}
			}
		]
	}`
	dir := makeFixtureDir(t, "", eventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "deploy-svc",
			"--finding-family", "unusual-timing",
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	var result struct {
		Events       []rawEvent       `json:"events"`
		MatchedRules []map[string]any `json:"matched_rules"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse wrapped output: %v\nraw=%s", err, out)
	}
	if len(result.Events) != 1 {
		t.Errorf("want 1 event, got %d", len(result.Events))
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("want 1 matched rule, got %d (rules=%v)", len(result.MatchedRules), result.MatchedRules)
	}
	if id, _ := result.MatchedRules[0]["id"].(string); id != "R-001" {
		t.Errorf("matched rule id: got %q, want R-001", id)
	}
}

// TestSearchEvents_WrappedIsAlwaysEmitted verifies search-events emits the
// wrapped {events, matched_rules} envelope even when --finding-family is not
// supplied. PR #113 conditionally wrapped only when finding_family was set —
// the model never passed that flag (0 transcripts in 55 scenarios at bakeoff
// 5), so the wrap was structurally dead. The wrap is now non-negotiable.
func TestSearchEvents_WrappedIsAlwaysEmitted(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			// Deliberately no --finding-family.
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("expected wrapped {events, matched_rules} object, got: %s", out)
	}
	result := decodeSearchEventsWrapped(t, out)
	if len(result.Events) == 0 {
		t.Errorf("expected at least one event for alice, got 0\nout=%q", out)
	}
	// MatchedRules must be a present (possibly empty) slice — never absent.
	if result.MatchedRules == nil {
		t.Errorf("matched_rules must be present (possibly empty) even without finding_family")
	}
}

// TestSearchEvents_DerivedResolutionEvent verifies the matcher computes the
// derived flag resolution_event="login_success" from a login_success event
// surfaced in the filtered events — without the worker having to pass it.
//
// Fixture scenario: an auth-failure-burst finding whose events include a
// login_success — should match R-003 via the in-process derivation.
func TestSearchEvents_DerivedResolutionEvent(t *testing.T) {
	_ = writeRulesFixture(t, searchEventsRulesFixture)

	eventsJSON := `{
		"events": [
			{
				"id": "evt-001",
				"timestamp": "2026-04-10T10:00:00Z",
				"source": "azure",
				"event_type": "login_failure",
				"actor": "alice@example.com",
				"action": "user.login",
				"target": "portal",
				"severity": "low",
				"metadata": {"ip": "10.0.0.5"}
			},
			{
				"id": "evt-002",
				"timestamp": "2026-04-10T10:02:00Z",
				"source": "azure",
				"event_type": "login_success",
				"actor": "alice@example.com",
				"action": "user.login",
				"target": "portal",
				"severity": "info",
				"metadata": {"ip": "10.0.0.5"}
			}
		]
	}`
	dir := makeFixtureDir(t, "", eventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--finding-family", "auth-failure-burst",
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	var result struct {
		Events       []rawEvent       `json:"events"`
		MatchedRules []map[string]any `json:"matched_rules"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse wrapped output: %v\nraw=%s", err, out)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("want 1 matched rule (R-003) via derived resolution_event flag, got %d", len(result.MatchedRules))
	}
	if id, _ := result.MatchedRules[0]["id"].(string); id != "R-003" {
		t.Errorf("matched rule id: got %q, want R-003", id)
	}
}

// TestSearchEvents_DerivedAutomationProvenance verifies the matcher computes
// automation_provenance="terraform" from event.metadata.user_agent that
// contains the substring "terraform" — covers the ID-02 new-actor CI bot
// scenario (B1 over-escalation root cause #2).
func TestSearchEvents_DerivedAutomationProvenance(t *testing.T) {
	_ = writeRulesFixture(t, searchEventsRulesFixture)

	eventsJSON := `{
		"events": [
			{
				"id": "evt-001",
				"timestamp": "2026-03-10T02:17:00Z",
				"source": "azure",
				"event_type": "resource_write",
				"actor": "tf-automation",
				"action": "create",
				"target": "Microsoft.Storage/storageAccounts/foo",
				"severity": "info",
				"metadata": {
					"user_agent": "terraform-provider-azurerm/3.90.0 (+https://www.terraform.io)",
					"correlation_id": "tf-run-20260310-0217"
				}
			},
			{
				"id": "evt-002",
				"timestamp": "2026-03-10T02:18:00Z",
				"source": "azure",
				"event_type": "resource_write",
				"actor": "tf-automation",
				"action": "create",
				"target": "Microsoft.Network/virtualNetworks/bar",
				"severity": "info",
				"metadata": {
					"user_agent": "terraform-provider-azurerm/3.90.0",
					"correlation_id": "tf-run-20260310-0217"
				}
			}
		]
	}`
	dir := makeFixtureDir(t, "", eventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "tf-automation",
			"--finding-family", "new-actor",
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	var result struct {
		Events       []rawEvent       `json:"events"`
		MatchedRules []map[string]any `json:"matched_rules"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse wrapped output: %v\nraw=%s", err, out)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("want 1 matched rule (R-007) via derived automation_provenance flag, got %d", len(result.MatchedRules))
	}
	if id, _ := result.MatchedRules[0]["id"].(string); id != "R-007" {
		t.Errorf("matched rule id: got %q, want R-007", id)
	}
}

// TestSearchEvents_FindingMetadataMergedIntoMatch verifies that a finding-side
// metadata map passed via --finding-metadata-json is included in the predicate
// match. This is the path the worker uses to assert "the finding itself says X"
// without relying on derived-from-events flags.
func TestSearchEvents_FindingMetadataMergedIntoMatch(t *testing.T) {
	_ = writeRulesFixture(t, searchEventsRulesFixture)

	eventsJSON := `{
		"events": [
			{
				"id": "evt-001",
				"timestamp": "2026-04-10T02:00:00Z",
				"source": "azure",
				"event_type": "container_restart",
				"actor": "deploy-svc",
				"action": "restart",
				"target": "prod-api",
				"severity": "info",
				"metadata": {}
			}
		]
	}`
	dir := makeFixtureDir(t, "", eventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "deploy-svc",
			"--finding-family", "unusual-timing",
			"--finding-metadata-json", `{"maintenance_window":"true"}`,
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	var result struct {
		Events       []rawEvent       `json:"events"`
		MatchedRules []map[string]any `json:"matched_rules"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse wrapped output: %v\nraw=%s", err, out)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("want 1 matched rule (R-001) via finding metadata, got %d", len(result.MatchedRules))
	}
	if id, _ := result.MatchedRules[0]["id"].(string); id != "R-001" {
		t.Errorf("matched rule id: got %q, want R-001", id)
	}
}

// TestSearchEvents_WrappedEmptyWhenNoEvents verifies that wrapped mode emits a
// consistent empty {events,matched_rules} envelope when events.json is absent,
// rather than empty stdout (which would break JSON-array consumers).
func TestSearchEvents_WrappedEmptyWhenNoEvents(t *testing.T) {
	_ = writeRulesFixture(t, searchEventsRulesFixture)
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--finding-family", "auth-failure-burst",
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	var result struct {
		Events       []rawEvent       `json:"events"`
		MatchedRules []map[string]any `json:"matched_rules"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse wrapped output: %v\nraw=%s", err, out)
	}
	if len(result.Events) != 0 {
		t.Errorf("want empty events, got %d", len(result.Events))
	}
	if len(result.MatchedRules) != 0 {
		t.Errorf("want empty matched_rules, got %d", len(result.MatchedRules))
	}
}

// TestSearchEvents_JSONPositionalFindingFamily verifies the JSON-positional-arg
// path (used by the API tool executor) accepts finding_family / finding_metadata
// keys and switches into wrapped mode.
func TestSearchEvents_JSONPositionalFindingFamily(t *testing.T) {
	_ = writeRulesFixture(t, searchEventsRulesFixture)

	eventsJSON := `{
		"events": [
			{
				"id": "evt-001",
				"timestamp": "2026-04-10T02:15:00Z",
				"source": "azure",
				"event_type": "container_restart",
				"actor": "deploy-svc",
				"metadata": {"maintenance_window": "true"}
			}
		]
	}`
	dir := makeFixtureDir(t, "", eventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			`{"actor":"deploy-svc","finding_family":"unusual-timing"}`,
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	var result struct {
		Events       []rawEvent       `json:"events"`
		MatchedRules []map[string]any `json:"matched_rules"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse wrapped output: %v\nraw=%s", err, out)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("want 1 matched rule via JSON-positional finding_family, got %d", len(result.MatchedRules))
	}
	if id, _ := result.MatchedRules[0]["id"].(string); id != "R-001" {
		t.Errorf("matched rule id: got %q, want R-001", id)
	}
}

// TestSearchEvents_AutoPopulateFindingFamilyFromItemID verifies that when the
// caller does NOT pass --finding-family, search-events derives the family from
// MALLCOP_ITEM_ID by looking up the scenario YAML and reading finding.detector.
//
// This is the path the live worker takes: the model never passes finding_family
// (optional in schema), but MALLCOP_ITEM_ID is reliably set by legion's worker
// jail. Without auto-derivation, matched_rules is always empty — which is what
// bakeoff 5 measured (0 transcripts containing matched_rules in 55 scenarios).
func TestSearchEvents_AutoPopulateFindingFamilyFromItemID(t *testing.T) {
	// Seed the rules corpus AND a synthetic scenario YAML under the SAME
	// MALLCOP_REPO_ROOT so resolveFindingFamilyFromScenario and
	// loadOperatorRules walk the same fake tree.
	fakeRepo := writeRulesFixture(t, searchEventsRulesFixture)

	scenarioID := "TEST-autopop-unusual-timing"
	scenarioPath := filepath.Join(fakeRepo, "exams", "scenarios", "_test", scenarioID+".yaml")
	scenarioYAML := `id: TEST-autopop-unusual-timing
detector: unusual-timing
finding:
  id: fnd_autopop_001
  detector: unusual-timing
  title: "autopop test"
`
	if err := os.MkdirAll(filepath.Dir(scenarioPath), 0o755); err != nil {
		t.Fatalf("mkdir scenario _test: %v", err)
	}
	if err := os.WriteFile(scenarioPath, []byte(scenarioYAML), 0o644); err != nil {
		t.Fatalf("write scenario yaml: %v", err)
	}

	eventsJSON := `{
		"events": [
			{
				"id": "evt-001",
				"timestamp": "2026-04-10T02:15:00Z",
				"source": "azure",
				"event_type": "container_restart",
				"actor": "deploy-svc",
				"metadata": {"maintenance_window": "true"}
			}
		]
	}`
	dir := makeFixtureDir(t, "", eventsJSON, "")

	// MALLCOP_ITEM_ID format: academy-<run-id>-<scenario-id>. The resolver
	// strips the academy- prefix and walks the run-id prefix away until it
	// matches a scenario YAML basename.
	t.Setenv("MALLCOP_ITEM_ID", "academy-run-abc-"+scenarioID)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "deploy-svc",
			// Deliberately no --finding-family. Must be derived from item ID.
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	var result struct {
		Events       []rawEvent       `json:"events"`
		MatchedRules []map[string]any `json:"matched_rules"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse wrapped output: %v\nraw=%s", err, out)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("want 1 matched rule (R-001) via auto-derived finding_family, got %d\nraw=%s", len(result.MatchedRules), out)
	}
	if id, _ := result.MatchedRules[0]["id"].(string); id != "R-001" {
		t.Errorf("matched rule id: got %q, want R-001", id)
	}
}

// TestSearchEvents_WrappedEmptyWhenFamilyUnresolvable verifies the wrapped
// envelope is still emitted (with empty matched_rules) when neither
// --finding-family nor a resolvable MALLCOP_ITEM_ID is supplied. The wrap is
// non-negotiable: consumers must never see a non-wrapped shape.
func TestSearchEvents_WrappedEmptyWhenFamilyUnresolvable(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")
	t.Setenv("MALLCOP_ITEM_ID", "") // no item-id signal

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("expected wrapped envelope even without finding_family, got: %s", out)
	}
	result := decodeSearchEventsWrapped(t, out)
	if result.MatchedRules == nil {
		t.Errorf("matched_rules must be a non-nil slice (possibly empty)")
	}
	if len(result.MatchedRules) != 0 {
		t.Errorf("want zero matched_rules without family signal, got %d", len(result.MatchedRules))
	}
	if len(result.Events) == 0 {
		t.Errorf("events should still be populated; got 0")
	}
}

// TestCheckBaseline_FrequencyByType verifies that compound frequency-table
// keys are split into per-event-type buckets. This is the channel triage uses
// to answer "is this *action type* routine for this actor?" instead of
// conflating all event types into the aggregate Frequency field.
func TestCheckBaseline_FrequencyByType(t *testing.T) {
	root := t.TempDir()
	baselineJSON := `{
		"known_entities":{
			"actors":["deploy-svc"],
			"sources":["azure"]
		},
		"frequency_tables":{
			"azure:config_update:deploy-svc":48,
			"azure:container_restart:deploy-svc":156,
			"azure:container_restart:deploy-svc-2":13,
			"time:02:deploy-svc":24,
			"azure:login:admin-user":340
		}
	}`
	if err := os.WriteFile(filepath.Join(root, "baseline.json"), []byte(baselineJSON), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	captured := captureStdout(t, func() {
		if err := checkBaseline(root, "deploy-svc", "", "", 168); err != nil {
			t.Fatalf("checkBaseline: %v", err)
		}
	})
	var got baselineResult
	if err := json.Unmarshal([]byte(captured), &got); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, captured)
	}
	if got.FrequencyByType == nil {
		t.Fatalf("FrequencyByType missing from response")
	}
	// Substring-on-entity should pull in `deploy-svc` from config_update,
	// container_restart, AND container_restart:deploy-svc-2 (substring match).
	// time:02:deploy-svc is excluded because the first segment is "time".
	if got.FrequencyByType["config_update"] != 48 {
		t.Errorf("FrequencyByType[config_update] = %d, want 48", got.FrequencyByType["config_update"])
	}
	// container_restart: 156 (deploy-svc) + 13 (deploy-svc-2) = 169 (substring match)
	if got.FrequencyByType["container_restart"] != 169 {
		t.Errorf("FrequencyByType[container_restart] = %d, want 169 (156+13)", got.FrequencyByType["container_restart"])
	}
	// time-of-day bucket must NOT appear as an event_type.
	if _, ok := got.FrequencyByType["02"]; ok {
		t.Errorf("FrequencyByType must not contain time-of-day bucket key '02'")
	}
	// admin-user activity must not leak into deploy-svc's breakdown.
	if _, ok := got.FrequencyByType["login"]; ok {
		t.Errorf("FrequencyByType must not contain admin-user's 'login' bucket")
	}
	// Aggregate Frequency is preserved for back-compat: 48+156+13+24 = 241
	// (substring match also catches deploy-svc-2 and time:02:deploy-svc).
	if got.Frequency != 241 {
		t.Errorf("Frequency aggregate = %d, want 241 (48+156+13+24)", got.Frequency)
	}
	// EventType not requested → empty echo, FrequencyForType zero.
	if got.EventType != "" {
		t.Errorf("EventType = %q, want empty (caller did not pass event_type)", got.EventType)
	}
	if got.FrequencyForType != 0 {
		t.Errorf("FrequencyForType = %d, want 0 (no event_type passed)", got.FrequencyForType)
	}
}

// TestCheckBaseline_FrequencyForType_WhenEventTypePassed verifies that when
// the caller passes the finding's event_type, the response includes
// frequency_for_type populated from the matching frequency_by_type bucket.
// This is the path triage uses to answer "compare the action-specific count
// to the observed event volume" (POST.md Step 3 question A).
func TestCheckBaseline_FrequencyForType_WhenEventTypePassed(t *testing.T) {
	root := t.TempDir()
	// CO-02 shape: actor has heavy login activity but only 2 bulk_read events
	// in baseline. The conflated `frequency` field hides the 423x anomaly
	// when the observed volume is bulk_read=842.
	baselineJSON := `{
		"known_entities":{
			"actors":["co-svc"],
			"sources":["github"]
		},
		"frequency_tables":{
			"github:login:co-svc":840,
			"github:bulk_read:co-svc":2,
			"github:push:co-svc":300
		}
	}`
	if err := os.WriteFile(filepath.Join(root, "baseline.json"), []byte(baselineJSON), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	captured := captureStdout(t, func() {
		if err := checkBaseline(root, "co-svc", "", "bulk_read", 168); err != nil {
			t.Fatalf("checkBaseline: %v", err)
		}
	})
	var got baselineResult
	if err := json.Unmarshal([]byte(captured), &got); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, captured)
	}
	if got.FrequencyForType != 2 {
		t.Errorf("FrequencyForType for bulk_read = %d, want 2 (baseline buried under aggregate)", got.FrequencyForType)
	}
	if got.EventType != "bulk_read" {
		t.Errorf("EventType echo = %q, want \"bulk_read\"", got.EventType)
	}
	// Aggregate frequency still conflates: 840 + 2 + 300 = 1142.
	if got.Frequency != 1142 {
		t.Errorf("Frequency aggregate = %d, want 1142", got.Frequency)
	}
	if got.FrequencyByType["bulk_read"] != 2 {
		t.Errorf("FrequencyByType[bulk_read] = %d, want 2", got.FrequencyByType["bulk_read"])
	}
	if got.FrequencyByType["login"] != 840 {
		t.Errorf("FrequencyByType[login] = %d, want 840", got.FrequencyByType["login"])
	}
}

// TestCheckBaseline_EventTypeFromJSONPositional verifies that callers using
// the JSON-positional-argument convention (API tool executor path) can pass
// event_type alongside entity and source, and that the response includes
// frequency_for_type. This is the path the model uses at runtime.
func TestCheckBaseline_EventTypeFromJSONPositional(t *testing.T) {
	root := t.TempDir()
	baselineJSON := `{
		"known_entities":{
			"actors":["api-svc"],
			"sources":["azure"]
		},
		"frequency_tables":{
			"azure:resource_write:api-svc":100,
			"azure:resource_read:api-svc":5
		}
	}`
	if err := os.WriteFile(filepath.Join(root, "baseline.json"), []byte(baselineJSON), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	captured := captureStdout(t, func() {
		err := run([]string{
			"--tool", "check-baseline",
			"--mode", "exam",
			"--fixture-dir", root,
			`{"entity":"api-svc","source":"azure","event_type":"resource_read"}`,
		})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	})
	var got baselineResult
	if err := json.Unmarshal([]byte(captured), &got); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, captured)
	}
	if got.FrequencyForType != 5 {
		t.Errorf("FrequencyForType for resource_read = %d, want 5", got.FrequencyForType)
	}
	if got.EventType != "resource_read" {
		t.Errorf("EventType echo = %q, want \"resource_read\"", got.EventType)
	}
}

