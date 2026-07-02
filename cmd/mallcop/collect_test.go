package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/collect"
	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// initCollectRepo creates a REAL git repo store with a seeded root commit — the
// collectors are proven against durable committed records, not stubs
// (invariant 10). Mirrors core/collect/collect_test.go's initRepo.
func initCollectRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	seed := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "root")
	seed.Dir = dir
	seed.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	return dir
}

func appendCollectRec(t *testing.T, st *store.Store, kind store.Kind, rec any) {
	t.Helper()
	if _, err := st.Append(kind, rec); err != nil {
		t.Fatalf("append %s: %v", kind, err)
	}
}

// seedCollectStore builds a fixture store carrying: (a) unmapped default-bucket
// events (a mapping gap), (b) a suppress directive whose human verb disagrees
// with the agent's stored escalate (an override_fp), and (c) a dissent-marked
// resolution (a dissent gap). Returns the store dir.
func seedCollectStore(t *testing.T) string {
	t.Helper()
	dir := initCollectRepo(t)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	unmapped := func(id, source, rawAction string) event.Event {
		pl, _ := json.Marshal(map[string]any{"unmapped_action": rawAction, "raw": map[string]any{"x": 1}})
		return event.Event{
			ID: id, Source: source, Type: source + "_other", Actor: "someone",
			Timestamp: time.Unix(1_700_000_000, 0).UTC(), Payload: pl,
		}
	}
	// (a) two repo.transfer + one org.rename unmapped github events → ranked gaps.
	appendCollectRec(t, st, store.KindEvents, unmapped("evt_b", "github", "repo.transfer"))
	appendCollectRec(t, st, store.KindEvents, unmapped("evt_a", "github", "repo.transfer"))
	appendCollectRec(t, st, store.KindEvents, unmapped("evt_c", "github", "org.rename"))
	// A MAPPED event that must NOT appear as a gap.
	appendCollectRec(t, st, store.KindEvents, event.Event{
		ID: "evt_mapped", Source: "github", Type: "push", Actor: "dev",
		Timestamp: time.Unix(1_700_000_001, 0).UTC(),
		Payload:   json.RawMessage(`{"action":"git.push"}`),
	})

	// Resolutions: an escalated finding (agent escalate) and a dissent-marked one.
	appendCollectRec(t, st, store.KindResolutions, resolution.Resolution{
		FindingID: "find-esc", Action: "escalate", Reason: "clean escalate, no dissent",
		Actor: "mallory", Severity: "high", Source: "detector:priv-escalation",
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
	})
	appendCollectRec(t, st, store.KindResolutions, resolution.Resolution{
		FindingID: "find-dis", Action: "resolve",
		Reason:    "deep panel majority RESOLVE (2 resolve / 1 escalate). Dissent (malicious) cited; confidence penalized 0.10.",
		Actor:     "dana", Severity: "medium", Source: "detector:unusual-login",
		Timestamp: time.Unix(1_700_000_001, 0).UTC(),
	})
	appendCollectRec(t, st, store.KindFindings, finding.Finding{
		ID: "find-esc", Source: "detector:priv-escalation", Severity: "high",
		Type: "priv-escalation", Actor: "mallory", Timestamp: time.Unix(1_700_000_000, 0).UTC(),
	})

	// (b) suppress directive whose human verb (resolve) disagrees with the agent's
	// escalate on find-esc → override_fp.
	meta, _ := json.Marshal(map[string]any{"finding_id": "find-esc", "verb": "resolve"})
	appendCollectRec(t, st, store.KindDirectives, store.Directive{
		Op: "suppress", Pattern: "detector:priv-escalation", Actor: "operator",
		Reason: "false positive on mallory", Meta: meta,
	})

	return dir
}

// TestRunCollect_EmitsVersionedEnvelopeWithGaps proves `mallcop collect --json`
// over a fixture store emits a valid, versioned envelope carrying the ranked
// mapping gaps and the store-pure gap candidates (override_fp + dissent). No
// network, no inference key.
func TestRunCollect_EmitsVersionedEnvelopeWithGaps(t *testing.T) {
	dir := seedCollectStore(t)

	out, err := withStdout(t, func() error {
		return runCollect([]string{"--store", dir, "--json"})
	})
	if err != nil {
		t.Fatalf("runCollect: %v", err)
	}

	var report collectReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output is not a valid collect envelope: %v\noutput: %s", err, out)
	}

	if report.SchemaVersion != CollectSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", report.SchemaVersion, CollectSchemaVersion)
	}

	// Mapping gaps: repo.transfer (count 2) ranked first, then org.rename; the
	// mapped "push" event never leaks in.
	if len(report.MappingGaps) != 2 {
		t.Fatalf("want 2 mapping gaps (repo.transfer, org.rename), got %d: %+v", len(report.MappingGaps), report.MappingGaps)
	}
	if g := report.MappingGaps[0]; g.RawAction != "repo.transfer" || g.Count != 2 {
		t.Fatalf("mapping_gaps[0] = %+v, want repo.transfer count 2", g)
	}
	if g := report.MappingGaps[1]; g.RawAction != "org.rename" || g.Count != 1 {
		t.Fatalf("mapping_gaps[1] = %+v, want org.rename count 1", g)
	}
	// Vocabulary crosses as DATA (detect.KnownEventTypes), never a live call from
	// the consumer — assert it is populated with a known gate literal.
	if !containsStr(report.MappingGaps[0].SuggestedVocabulary, "push") {
		t.Fatalf("suggested_vocabulary %v missing known literal 'push'", report.MappingGaps[0].SuggestedVocabulary)
	}

	// Gap candidates: exactly one override_fp + one dissent (store-pure kinds; no
	// --fidelity, so NO detect_miss).
	var overrideFP, dissent, detectMiss int
	for _, g := range report.GapCandidates {
		switch g.Kind {
		case collect.GapOverrideFP:
			overrideFP++
			if len(g.FindingIDs) != 1 || g.FindingIDs[0] != "find-esc" {
				t.Fatalf("override_fp wrong finding: %+v", g)
			}
			if g.Evidence.HumanVerb != "resolve" || g.Evidence.AgentAction != "escalate" {
				t.Fatalf("override_fp evidence = %+v, want human=resolve agent=escalate", g.Evidence)
			}
		case collect.GapDissent:
			dissent++
			if len(g.FindingIDs) != 1 || g.FindingIDs[0] != "find-dis" {
				t.Fatalf("dissent wrong finding: %+v", g)
			}
		case collect.GapDetectMiss:
			detectMiss++
		}
	}
	if overrideFP != 1 || dissent != 1 || detectMiss != 0 {
		t.Fatalf("want override_fp=1 dissent=1 detect_miss=0, got %d/%d/%d (all=%+v)",
			overrideFP, dissent, detectMiss, report.GapCandidates)
	}
}

// TestRunCollect_FidelityAddsDetectMiss proves the --fidelity opt-in decodes a
// []eval.DetectFidelityRow dump and surfaces the detect_miss gap kind the store
// alone cannot produce (D1).
func TestRunCollect_FidelityAddsDetectMiss(t *testing.T) {
	dir := seedCollectStore(t)

	rows := []eval.DetectFidelityRow{
		{
			ScenarioID: "PE-09", ExpectedDetector: "priv-escalation",
			ExpectedActor: "mallory", ExpectedAction: "escalate-or-stronger",
			Outcome: eval.OutcomeDetectMiss,
		},
		// A DETECT-MISS on an expected-RESOLVE scenario is the correct "nothing
		// flagged" outcome — must NOT surface as a detect_miss gap.
		{
			ScenarioID: "OK-01", ExpectedDetector: "unusual-login",
			ExpectedActor: "bob", ExpectedAction: "resolved",
			Outcome: eval.OutcomeDetectMiss,
		},
	}
	fidPath := filepath.Join(t.TempDir(), "fidelity.json")
	raw, _ := json.Marshal(rows)
	if err := os.WriteFile(fidPath, raw, 0o644); err != nil {
		t.Fatalf("write fidelity fixture: %v", err)
	}

	out, err := withStdout(t, func() error {
		return runCollect([]string{"--store", dir, "--fidelity", fidPath, "--json"})
	})
	if err != nil {
		t.Fatalf("runCollect with fidelity: %v", err)
	}

	var report collectReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output is not a valid collect envelope: %v\noutput: %s", err, out)
	}

	var detectMiss int
	for _, g := range report.GapCandidates {
		if g.Kind == collect.GapDetectMiss {
			detectMiss++
			if g.Evidence.ScenarioID != "PE-09" {
				t.Fatalf("detect_miss on wrong scenario: %+v", g)
			}
			if g.DetectorFamily != "priv-escalation" {
				t.Fatalf("detect_miss wrong family: %+v", g)
			}
		}
	}
	if detectMiss != 1 {
		t.Fatalf("want exactly one detect_miss gap (PE-09), got %d (all=%+v)", detectMiss, report.GapCandidates)
	}
}

// TestRunCollect_MissingStoreFailsLoud proves a missing/non-git --store fails
// loud (a real error → exit 2), not the findings sentinel.
func TestRunCollect_MissingStoreFailsLoud(t *testing.T) {
	err := runCollect([]string{"--store", filepath.Join(t.TempDir(), "nonexistent")})
	if err == nil {
		t.Fatal("expected an error for a missing store")
	}
	if isFindingsError(err) {
		t.Fatalf("missing store should be a real error (exit 2), not the findings sentinel: %v", err)
	}
}

// TestRunCollect_RequiresStore proves the --store flag is required.
func TestRunCollect_RequiresStore(t *testing.T) {
	if err := runCollect(nil); err == nil {
		t.Fatal("expected an error when --store is omitted")
	}
}

// --- helpers ----------------------------------------------------------------

// withStdout captures os.Stdout for the duration of fn.
func withStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	runErr := fn()
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return buf.String(), runErr
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
