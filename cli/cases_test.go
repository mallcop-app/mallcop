package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
	"github.com/mallcop-app/mallcop/pkg/baseline"
)

// writeKnownActorsBaseline writes a baseline naming actors as already-known,
// so the scan's OWN detector floor only fires the ONE detector each test
// targets (git-oops force-push, or new-external-access) — without it,
// new-actor additionally fires for every not-yet-seen actor, and unusual-
// timing fires once a DERIVED baseline (built from prior committed events,
// core/pipeline.Run's bl==nil path) sees a later scan's event land on an
// hour the actor hasn't used before. An EXPLICIT (non-nil) baseline is used
// as-is — no derivation — and its zero-value ActorHours keeps
// bl.HasActorHours() false for every scan in the sequence, so unusual-timing
// stays silent across all runs, not just the first.
func writeKnownActorsBaseline(t *testing.T, path string, actors ...string) {
	t.Helper()
	data, err := json.Marshal(&baseline.Baseline{KnownActors: actors})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// casesJSONPath is the on-disk path (inside the store's real work tree —
// syncWorkTree reconciles it after every commit, see core/store's doc) of the
// case-collapse projection, mirroring investigationRecordPath's pattern.
func casesJSONPath(storePath string) string {
	return filepath.Join(storePath, "cases.json")
}

func readCasesJSON(t *testing.T, storePath string) []cases.Case {
	t.Helper()
	data, err := os.ReadFile(casesJSONPath(storePath))
	if err != nil {
		t.Fatalf("read %s: %v", casesJSONPath(storePath), err)
	}
	var out []cases.Case
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", casesJSONPath(storePath), err)
	}
	return out
}

// gitOopsEventWithID is a deterministic force-push-to-main event (same rule as
// gitOopsEvent in scan_config_test.go) but with a caller-supplied event id and
// timestamp, so repeated scans over the SAME store produce DISTINCT findings
// that still cluster to the same (git-oops, dev, "") case key — reusing
// gitOopsEvent's id would falsely no-op scans 2/3 (pipeline event-level
// dedup), producing a false-negative count instead of the intended recurrence.
func gitOopsEventWithID(id, ts string) string {
	return `{"id":"` + id + `","source":"github","type":"push","actor":"dev","timestamp":"` + ts +
		`","payload":{"forced":true,"ref":"refs/heads/main"}}` + "\n"
}

// externalAccessEvent fires core/detect/new_external_access.go: an
// org.add_member grant with no approval signal, naming grantee as the
// collaborator added. Entity clusters on the "grantee" evidence key
// (core/cases.ExtractEntity's first fallback).
func externalAccessEvent(id, ts, grantee string) string {
	return `{"id":"` + id + `","source":"github","type":"org.add_member","actor":"admin","timestamp":"` + ts +
		`","payload":{"collaborator":"` + grantee + `"}}` + "\n"
}

// TestScanCases_ThreeRecurringEscalations_OneCaseCountThree proves 3 scans,
// each detecting a distinct-event-id force-push finding by the SAME actor on
// the SAME (unspecified) entity, collapse into ONE case in store/cases.json
// with count 3, status "recurring", and all 3 finding ids in arrival order.
func TestScanCases_ThreeRecurringEscalations_OneCaseCountThree(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store")
	baselinePath := filepath.Join(dir, "baseline.json")
	writeKnownActorsBaseline(t, baselinePath, "dev")

	ids := []string{"g1", "g2", "g3"}
	stamps := []string{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", "2026-01-01T02:00:00Z"}
	for i, id := range ids {
		eventsPath := filepath.Join(dir, "events-"+id+".jsonl")
		writeFile(t, eventsPath, gitOopsEventWithID(id, stamps[i]))
		err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath, "--baseline", baselinePath})
		if !isFindingsError(err) {
			t.Fatalf("scan %d (%s): want findings sentinel, got %v", i+1, id, err)
		}
	}

	got := readCasesJSON(t, storePath)
	if len(got) != 1 {
		t.Fatalf("want 1 case, got %d: %+v", len(got), got)
	}
	c := got[0]
	if c.Status != "recurring" {
		t.Errorf("status = %q, want recurring", c.Status)
	}
	if c.Count != 3 {
		t.Errorf("count = %d, want 3", c.Count)
	}
	if c.Key.Type != "git-oops" || c.Key.Actor != "dev" {
		t.Errorf("key = %+v, want type=git-oops actor=dev", c.Key)
	}
	wantIDs := []string{"finding-g1-force", "finding-g2-force", "finding-g3-force"}
	if len(c.FindingIDs) != len(wantIDs) {
		t.Fatalf("finding_ids = %v, want %v", c.FindingIDs, wantIDs)
	}
	for i, want := range wantIDs {
		if c.FindingIDs[i] != want {
			t.Errorf("finding_ids[%d] = %q, want %q (arrival order)", i, c.FindingIDs[i], want)
		}
	}
}

// TestScanCases_DistinctGrantee_TwoDistinctCases proves 2 scans naming
// distinct external-access grantees, same actor, produce 2 distinct cases
// with distinct case_id/key.entity.
func TestScanCases_DistinctGrantee_TwoDistinctCases(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store")
	baselinePath := filepath.Join(dir, "baseline.json")
	writeKnownActorsBaseline(t, baselinePath, "admin")

	grantees := []string{"alice", "bob"}
	for i, grantee := range grantees {
		id := "e" + string(rune('1'+i))
		eventsPath := filepath.Join(dir, "events-"+id+".jsonl")
		writeFile(t, eventsPath, externalAccessEvent(id, "2026-01-01T00:00:00Z", grantee))
		err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath, "--baseline", baselinePath})
		if !isFindingsError(err) {
			t.Fatalf("scan %d (%s): want findings sentinel, got %v", i+1, grantee, err)
		}
	}

	got := readCasesJSON(t, storePath)
	if len(got) != 2 {
		t.Fatalf("want 2 cases, got %d: %+v", len(got), got)
	}
	if got[0].CaseID == got[1].CaseID {
		t.Fatalf("want distinct case_ids, both = %q", got[0].CaseID)
	}
	entities := map[string]bool{got[0].Key.Entity: true, got[1].Key.Entity: true}
	for _, g := range grantees {
		if !entities[g] {
			t.Errorf("missing case with key.entity = %q; got entities %v", g, entities)
		}
	}
}

// TestScanCases_RerunSameEvent_NoOpCommit proves re-running a scan over the
// SAME store + SAME event id produces zero new findings (pipeline dedup) and
// leaves cases.json byte-identical — WriteSnapshot's no-op path, not a
// spurious mutation from an empty escalations batch.
func TestScanCases_RerunSameEvent_NoOpCommit(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store")
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEventWithID("g1", "2026-01-01T00:00:00Z"))

	err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath})
	if !isFindingsError(err) {
		t.Fatalf("first scan: want findings sentinel, got %v", err)
	}
	before, err := os.ReadFile(casesJSONPath(storePath))
	if err != nil {
		t.Fatalf("read cases.json after first scan: %v", err)
	}

	// Second scan: SAME event id, SAME store. The pipeline dedupes it to zero
	// new events/findings, so this scan finds nothing new — err is nil, NOT
	// the findings sentinel.
	err = runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath})
	if err != nil {
		t.Fatalf("second (duplicate) scan: want nil error (0 new findings), got %v", err)
	}

	after, err := os.ReadFile(casesJSONPath(storePath))
	if err != nil {
		t.Fatalf("read cases.json after second scan: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("cases.json changed on a duplicate-event rerun:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// mfaOnlyEvent fires ONLY core/detect/config_drift.go's mfa_disabled rule
// (severity high, no injection-probe finding alongside it) — the fixture
// TestScanCases_NoEscalation_NoCasesFile needs an evidence-rich resolve
// (never an escalate) with nothing else in the scan to escalate.
const mfaOnlyEvent = `{"id":"evt-mfa-001","source":"aws","type":"mfa_disabled","actor":"ops-bot","timestamp":"2026-06-18T14:22:00Z",` +
	`"payload":{"config_key":"mfa_required","old_value":"true","new_value":"false",` +
	`"change_description":"MFA requirement removed on the prod tenant","resource_name":"tenant-prod"}}` + "\n"

// TestScanCases_NoEscalation_NoCasesFile proves a scan whose only finding
// RESOLVES (never escalates) writes no cases.json at all. Per
// core/agent/cascade.go's documented nil-client fail-safe, an OFFLINE scan
// force-escalates unconditionally — a genuine "resolved, not escalated"
// scenario is not constructible without a live inference backend, so this
// test runs against a cannedbackend (same evidence-rich canned reply
// scan_e2e_test.go uses to clear the structural-confidence gate), exactly
// like the rest of this package's non-e2e cannedbackend-backed tests
// (see core/pipeline/pipeline_test.go for the same pattern).
func TestScanCases_NoEscalation_NoCasesFile(t *testing.T) {
	be := &cannedbackend.CannedBackend{
		CannedResolutionFunc: func(callIndex int) string {
			return `{"action":"resolve","confidence":5,"positive_evidence":true,` +
				`"reason":"ops-bot disabled MFA via the documented break-glass runbook RB-114 on 2026-06-18 ` +
				`at 14:40, consistent with ops-bot's known baseline maintenance frequency (first_seen 2026-01-02); ` +
				`reverted immediately, matching prior maintenance events. No standing exposure."}`
		},
	}
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	t.Cleanup(be.Stop)

	dir := t.TempDir()
	storePath := filepath.Join(dir, "store")
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, mfaOnlyEvent)

	t.Setenv(envInferenceURL, be.URL())
	t.Setenv(envInferenceKey, "mallcop-sk-test")
	t.Setenv(envInferenceModel, "test-model")
	t.Setenv(envInvestigate, "off")

	err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath})
	if !isFindingsError(err) {
		t.Fatalf("want findings sentinel (a resolved finding is still a finding), got %v", err)
	}

	if _, statErr := os.Stat(casesJSONPath(storePath)); !os.IsNotExist(statErr) {
		t.Fatalf("expected NO cases.json when nothing escalated, stat error: %v", statErr)
	}
}
