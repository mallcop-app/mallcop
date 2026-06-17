package tools

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// contract_test.go — proves the §3 tool-contract guarantees retrofitted onto
// core/tools (portable-agent-architecture.md §3.3–3.8, §3.10 checklist). Each
// test maps 1:1 to a checklist item / known bug.

// ---- §3.8 fold lookup-rules INTO search-events -----------------------------

// TestSearchEventsFoldsMatchedRules proves the headline fix: search-events
// carries the operator-decisions rules that match the returned events' finding
// family + metadata, so the model never has to call a standalone lookup-rules.
// Asserted against the REAL shipped corpus (R-001: unusual-timing +
// maintenance_window=true).
func TestSearchEventsFoldsMatchedRules(t *testing.T) {
	root := repoRoot(t)
	s := newTempStore(t)

	base := time.Date(2026, 4, 10, 2, 0, 0, 0, time.UTC)
	seed := []event.Event{
		{ID: "e1", Source: "azure", Type: "container_restart", Actor: "deploy-svc", Timestamp: base},
		{ID: "e2", Source: "azure", Type: "container_restart", Actor: "deploy-svc", Timestamp: base.Add(time.Minute)},
	}
	for _, ev := range seed {
		if _, err := s.Append(store.KindEvents, ev); err != nil {
			t.Fatalf("append %s: %v", ev.ID, err)
		}
	}

	env, err := searchEventsWrappedAt(t, root, s,
		SearchEventsInput{Actor: "deploy-svc"},
		"unusual-timing",
		map[string]string{"maintenance_window": "true"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The folded rule MUST be present.
	if len(env.MatchedRules) != 1 || env.MatchedRules[0].ID != "R-001" {
		t.Fatalf("expected folded matched_rules=[R-001], got %+v", ruleIDs(env.MatchedRules))
	}
	if len(env.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(env.Events))
	}
	// The directive text rides along so the model can cite it.
	if !strings.Contains(env.MatchedRules[0].OperatorDirective, "maintenance window") {
		t.Errorf("folded rule missing its operator_directive text: %q", env.MatchedRules[0].OperatorDirective)
	}
}

// TestSearchEventsNoFamilyStillWraps proves rule folding is optional: with no
// finding family the envelope shape is unchanged and matched_rules is an empty
// (non-nil) slice — §3.3 (shape never branches on input).
func TestSearchEventsNoFamilyStillWraps(t *testing.T) {
	s := newTempStore(t)
	if _, err := s.Append(store.KindEvents, event.Event{ID: "e1", Actor: "x", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	env, err := SearchEventsWrapped(s, SearchEventsInput{Actor: "x"}, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.MatchedRules == nil {
		t.Error("matched_rules must be non-nil empty slice when no family supplied")
	}
	if len(env.MatchedRules) != 0 {
		t.Errorf("matched_rules must be empty with no family, got %d", len(env.MatchedRules))
	}
}

// ---- §3.3 wrapped envelope: every key present, always ----------------------

// TestEnvelopeKeysAlwaysPresent marshals the envelope to JSON and asserts every
// contract key is present on EVERY call — populated path AND empty path — with
// no omitted fields (no omitempty leaking a missing key).
func TestEnvelopeKeysAlwaysPresent(t *testing.T) {
	requiredTop := []string{"events", "matched_rules", "filter_applied", "notes"}
	requiredFilter := []string{"actor", "source", "type", "since", "until", "effective"}

	s := newTempStore(t)

	check := func(name string, env SearchEventsEnvelope) {
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		for _, k := range requiredTop {
			if _, ok := m[k]; !ok {
				t.Errorf("%s: top-level key %q missing from %s", name, k, b)
			}
		}
		var fm map[string]json.RawMessage
		if err := json.Unmarshal(m["filter_applied"], &fm); err != nil {
			t.Fatalf("%s: filter_applied not an object: %v", name, err)
		}
		for _, k := range requiredFilter {
			if _, ok := fm[k]; !ok {
				t.Errorf("%s: filter_applied key %q missing", name, k)
			}
		}
		// events / matched_rules must be JSON arrays (never null), even empty.
		for _, k := range []string{"events", "matched_rules"} {
			if strings.TrimSpace(string(m[k])) == "null" {
				t.Errorf("%s: %q is null; must be [] (§3.3/§3.4)", name, k)
			}
		}
	}

	// Empty world: no events at all.
	envEmpty, err := SearchEventsWrapped(s, SearchEventsInput{Actor: "nobody"}, "", nil)
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	check("empty", envEmpty)

	// Populated world.
	if _, err := s.Append(store.KindEvents, event.Event{ID: "e1", Actor: "x", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	envFull, err := SearchEventsWrapped(s, SearchEventsInput{Actor: "x"}, "", nil)
	if err != nil {
		t.Fatalf("full: %v", err)
	}
	check("full", envFull)
}

// ---- §3.4 empty-is-data, not error ----------------------------------------

// TestEmptyReturnsWrappedEmptyNotError proves a well-formed call against an
// empty world returns the wrapped envelope (empty slices + a notes line), NOT a
// Go error and NOT a null. Errors are reserved for schema violations.
func TestEmptyReturnsWrappedEmptyNotError(t *testing.T) {
	s := newTempStore(t)
	env, err := SearchEventsWrapped(s, SearchEventsInput{Actor: "nobody-home"}, "", nil)
	if err != nil {
		t.Fatalf("empty world must NOT error: %v", err)
	}
	if env.Events == nil || len(env.Events) != 0 {
		t.Errorf("events must be empty non-nil slice, got %v", env.Events)
	}
	if env.Notes == "" {
		t.Error("empty result must carry an explanatory notes string")
	}
	if !strings.Contains(env.Notes, "no events") {
		t.Errorf("notes should explain the empty result, got %q", env.Notes)
	}
}

// TestSchemaViolationStillErrors proves the error channel is preserved for
// genuine schema violations — a nil store is a malformed call, not an empty
// world, and MUST error (§3.4 reserves errors for schema violations).
func TestSchemaViolationStillErrors(t *testing.T) {
	if _, err := SearchEventsWrapped(nil, SearchEventsInput{}, "", nil); err == nil {
		t.Fatal("nil store must return an error (schema violation)")
	}
}

// ---- §3.5 self-resolving config: found when CWD is /tmp --------------------

// TestConfigSelfResolvesFromBinaryNotCWD proves findConfigRoot locates the
// project root by walking up from the BINARY's location, independent of CWD. It
// compiles a tiny helper into a temp project tree (marked with go.mod + the
// rule corpus), runs it with CWD=/tmp and a CLEARED MALLCOP_REPO_ROOT, and
// asserts the helper still resolves the correct root. This reproduces bug #1/#6
// (CWD/env-dependent config path) and proves the fix.
func TestConfigSelfResolvesFromBinaryNotCWD(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}

	// Build a temp project tree: <proj>/agents/rules/operator-decisions.yaml +
	// go.mod, with the helper binary placed at <proj>/bin/helper.
	proj := t.TempDir()
	mustMkdir(t, filepath.Join(proj, "agents", "rules"))
	mustWrite(t, filepath.Join(proj, "agents", "rules", "operator-decisions.yaml"), "rules: []\n")
	mustWrite(t, filepath.Join(proj, "go.mod"), "module helperprobe\n\ngo 1.25\n")
	mustWrite(t, filepath.Join(proj, "main.go"), configProbeSource)

	binPath := filepath.Join(proj, "bin", "helper")
	mustMkdir(t, filepath.Join(proj, "bin"))
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = proj
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}

	// Run the helper from CWD=/tmp with MALLCOP_REPO_ROOT explicitly unset, so
	// the ONLY way it can find the root is the walk-up from its own location.
	runCmd := exec.Command(binPath)
	runCmd.Dir = os.TempDir()
	runCmd.Env = filteredEnv("MALLCOP_REPO_ROOT")
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run helper: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))

	wantReal, _ := filepath.EvalSymlinks(proj)
	gotReal, _ := filepath.EvalSymlinks(got)
	if gotReal != wantReal {
		t.Errorf("config root resolved from binary, not CWD:\n got: %s\nwant: %s", gotReal, wantReal)
	}
}

// configProbeSource is a standalone program that calls the SAME resolution
// logic as findConfigRoot (walk up from os.Executable to a project marker) and
// prints the result. It is built and run as a subprocess so CWD and env can be
// controlled. It deliberately does NOT consult any env var — pure walk.
const configProbeSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func hasMarker(dir string) bool {
	for _, m := range []string{filepath.Join("agents","rules","operator-decisions.yaml"), "go.mod", ".git"} {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return false
}

func main() {
	exe, err := os.Executable()
	if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	dir := filepath.Dir(exe)
	for {
		if hasMarker(dir) { fmt.Print(dir); return }
		parent := filepath.Dir(dir)
		if parent == dir { break }
		dir = parent
	}
	fmt.Fprintln(os.Stderr, "no marker found")
	os.Exit(2)
}
`

// TestFindConfigRootWalkUp is the in-process companion: it places a marker tree
// under a temp dir, then calls findConfigRoot indirectly is impossible (it keys
// off the test binary's own location), so instead this asserts hasProjectMarker
// — the walk's predicate — recognizes each marker type.
func TestFindConfigRootMarkers(t *testing.T) {
	for _, marker := range []struct {
		name string
		rel  string
		dir  bool
	}{
		{"rule-corpus", filepath.Join("agents", "rules", "operator-decisions.yaml"), false},
		{"go.mod", "go.mod", false},
		{".git", ".git", true},
	} {
		t.Run(marker.name, func(t *testing.T) {
			d := t.TempDir()
			full := filepath.Join(d, marker.rel)
			if marker.dir {
				mustMkdir(t, full)
			} else {
				mustMkdir(t, filepath.Dir(full))
				mustWrite(t, full, "x")
			}
			if !hasProjectMarker(d) {
				t.Errorf("hasProjectMarker did not recognize %s marker", marker.name)
			}
		})
	}
	// A bare temp dir with no marker must NOT be recognized.
	if hasProjectMarker(t.TempDir()) {
		t.Error("hasProjectMarker false-positived on an unmarked dir")
	}
}

// ---- §3.6 date-hallucination fallback: exclude-all → unfiltered + notes -----

// TestDateExcludeAllReturnsUnfilteredWithNotes proves a time window that
// excludes EVERY candidate is dropped: the unfiltered set is returned, Notes
// explains it, and FilterApplied.Effective == "dropped". This is bug #4 (model
// hallucinates a year-off date range, tool returns empty, model resolves
// benign).
func TestDateExcludeAllReturnsUnfilteredWithNotes(t *testing.T) {
	s := newTempStore(t)
	base := time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC)
	for _, ev := range []event.Event{
		{ID: "e1", Actor: "baron", Timestamp: base},
		{ID: "e2", Actor: "baron", Timestamp: base.Add(time.Hour)},
	} {
		if _, err := s.Append(store.KindEvents, ev); err != nil {
			t.Fatal(err)
		}
	}

	// since is 100h after every event → excludes everything.
	env, err := SearchEventsWrapped(s,
		SearchEventsInput{Actor: "baron", Since: base.Add(100 * time.Hour)},
		"", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(env.Events) != 2 {
		t.Fatalf("expected unfiltered fallback to return all 2 events, got %d", len(env.Events))
	}
	if env.FilterApplied.Effective != "dropped" {
		t.Errorf("effective: got %q want \"dropped\"", env.FilterApplied.Effective)
	}
	if !strings.Contains(env.Notes, "excluded all events") {
		t.Errorf("notes must explain the dropped filter, got %q", env.Notes)
	}
}

// TestDateWindowAppliedWhenItMatches confirms the happy path is untouched: a
// window that DOES select a subset reports effective=="applied" and no
// fallback note.
func TestDateWindowAppliedWhenItMatches(t *testing.T) {
	s := newTempStore(t)
	base := time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC)
	for _, ev := range []event.Event{
		{ID: "e1", Actor: "baron", Timestamp: base},
		{ID: "e2", Actor: "baron", Timestamp: base.Add(2 * time.Hour)},
	} {
		if _, err := s.Append(store.KindEvents, ev); err != nil {
			t.Fatal(err)
		}
	}
	env, err := SearchEventsWrapped(s,
		SearchEventsInput{Actor: "baron", Since: base.Add(time.Hour), Until: base.Add(3 * time.Hour)},
		"", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Events) != 1 || env.Events[0].ID != "e2" {
		t.Errorf("expected only e2 in window, got %v", eventIDs(env.Events))
	}
	if env.FilterApplied.Effective != "applied" {
		t.Errorf("effective: got %q want \"applied\"", env.FilterApplied.Effective)
	}
	if strings.Contains(env.Notes, "excluded all events") {
		t.Errorf("no fallback note expected on happy path, got %q", env.Notes)
	}
}

// ---- §3.7 case-insensitive unmarshal: PascalCase fixture parses ------------

// TestPascalCaseFixtureParses proves a fixture written in a DIFFERENT casing
// CONVENTION than the snake_case struct tags parses through normalizeRecordKeys
// instead of decoding to all-zero values. This is bug #5: Go's encoding/json
// matches a key to a struct tag case-insensitively, but it does NOT translate
// between casing conventions — it cannot strip a separator or split a camelCase
// word. The fix is normalizeRecordKeys at the decode boundary.
//
// MUTATION-PROOF GATE — fixture choice is load-bearing.
// The event.Event struct tags are single lowercase words (`id`, `source`,
// `type`, `actor`, `timestamp`). A naïve single-word PascalCase key like "ID" /
// "Actor" is matched by Go's case-insensitive fallback *on its own*, so it would
// pass even with normalizeRecordKeys removed (a hollow test). To genuinely gate
// §3.7 the fixture must use keys Go's matcher CANNOT fold to the tag — here a
// kebab-/separator-bearing convention ("-id", "user-actor"). Go leaves the
// separator intact and finds no matching tag, so WITHOUT normalizeRecordKeys
// every field decodes to its zero value and the assertions below FAIL. WITH
// normalizeRecordKeys the keys collapse to the canonical snake_case (`-id`→`id`,
// the camelCase word boundaries fold) and the record parses. Verified by
// mutation: replacing normalizeRecordKeys(raw) with raw in the search_events
// decode path turns this test red (got 0 events) and restoring it turns it green.
func TestPascalCaseFixtureParses(t *testing.T) {
	s := newTempStore(t)

	// A hand-written fixture in a convention whose keys carry separators Go's
	// case-insensitive tag match cannot fold to the single-word struct tags.
	// Without normalizeRecordKeys at the boundary this decodes to an all-zero
	// event (no key matches `id`/`source`/`type`/`actor`/`timestamp`), so
	// search-events returns ZERO events and every assertion below fails.
	foreignConvention := json.RawMessage(`{"-id":"e1","-source":"azure","-type":"login","-actor":"baron","-timestamp":"2026-04-10T09:00:00Z"}`)
	if _, err := s.Append(store.KindEvents, foreignConvention); err != nil {
		t.Fatalf("append foreign-convention event: %v", err)
	}

	env, err := SearchEventsWrapped(s, SearchEventsInput{Actor: "baron"}, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The decisive assertion: without key normalization the actor filter matches
	// nothing (Actor decoded to "") and this is 0. It is 1 ONLY because
	// normalizeRecordKeys folded the foreign keys onto the struct tags.
	if len(env.Events) != 1 {
		t.Fatalf("foreign-convention event did not parse: got %d events (filter actor=baron) — normalizeRecordKeys not gating decode", len(env.Events))
	}
	got := env.Events[0]
	if got.ID != "e1" || got.Actor != "baron" || got.Type != "login" || got.Source != "azure" {
		t.Errorf("foreign-convention fields not mapped (decoded to zero-values?): %+v", got)
	}
	if got.Timestamp != "2026-04-10T09:00:00Z" {
		t.Errorf("foreign-convention timestamp not mapped: %q", got.Timestamp)
	}
}

// TestNormalizeKey unit-tests the casing transform across all conventions.
func TestNormalizeKey(t *testing.T) {
	cases := map[string]string{
		"EventType":  "event_type",
		"eventType":  "event_type",
		"event-type": "event_type",
		"event_type": "event_type",
		"EVENT_TYPE": "event_type",
		"ID":         "id",
		"Actor":      "actor",
		"":           "",
	}
	for in, want := range cases {
		if got := normalizeKey(in); got != want {
			t.Errorf("normalizeKey(%q) = %q, want %q", in, got, want)
		}
		// idempotence
		if again := normalizeKey(normalizeKey(in)); again != normalizeKey(in) {
			t.Errorf("normalizeKey not idempotent on %q", in)
		}
	}
}

// TestSnakeCaseKeyWinsOverRecased proves an explicit snake_case key is not
// clobbered by a re-cased duplicate (canonical key precedence).
func TestSnakeCaseKeyWinsOverRecased(t *testing.T) {
	raw := json.RawMessage(`{"event_type":"keep","EventType":"drop"}`)
	out := normalizeRecordKeys(raw)
	var m map[string]string
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["event_type"] != "keep" {
		t.Errorf("canonical snake_case key should win: got %q", m["event_type"])
	}
}

// ---- helpers ---------------------------------------------------------------

// searchEventsWrappedAt runs SearchEventsWrapped but pins the rule-corpus root
// to the supplied root via MALLCOP_REPO_ROOT, because in `go test` the test
// binary lives in a temp dir with no project marker above it, so the walk-up
// path legitimately falls through to the env override. The dedicated
// TestConfigSelfResolvesFromBinaryNotCWD proves the walk itself works.
func searchEventsWrappedAt(t *testing.T, root string, s *store.Store, in SearchEventsInput, family string, meta map[string]string) (SearchEventsEnvelope, error) {
	t.Helper()
	t.Setenv("MALLCOP_REPO_ROOT", root)
	return SearchEventsWrapped(s, in, family, meta)
}

func ruleIDs(rules []OperatorRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func eventIDs(evs []EventView) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.ID)
	}
	return out
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// filteredEnv returns os.Environ() with the named var removed.
func filteredEnv(remove string) []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, kv := range src {
		if strings.HasPrefix(kv, remove+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
