package pipeline_test

// churn_test.go — the REGRESSION coverage for mallcoppro-ee3: core/store used
// to commit every appended record as its own git commit, and each commit
// re-read + re-hashed the ENTIRE stream blob. With events.jsonl at 34MB a
// single 3,416-event scan produced thousands of commits (~3.6MB of loose
// objects EACH), exhausting CI runner disk. The fix is two-part:
//
//   - core/store.AppendBatch collapses a whole batch of records into ONE
//     commit (proven directly in core/store's own tests);
//   - core/pipeline drives Run's per-record Append loops through
//     AppendBatch, and DEDUPES pulled events against the store's already-
//     committed KindEvents stream so a connector without a durable pull
//     cursor (azure, github) does not regrow the stream every scan by
//     re-appending events it already committed.
//
// TestPipeline_ChurnRegression is the headline proof: driving 200 events
// through pipeline.Run must grow the commit log by a SMALL, BOUNDED number of
// commits (not one per event), and re-running over the SAME events must skip
// them entirely (EventsScanned==0, DuplicatesSkipped==200) while still costing
// only a couple of commits (the derived baseline record + the findings
// snapshot), never one per (deduped-to-zero) event.

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// fakeConnector is a connect.Connector over a fixed, caller-supplied event
// slice — it returns the SAME events on every Pull call, exactly like a cloud
// connector without a durable pull cursor re-pulling an overlapping window on
// every scan.
type fakeConnector struct {
	events []event.Event
}

func (f *fakeConnector) Pull(_ context.Context) ([]event.Event, error) {
	return f.events, nil
}

// repoCommitCount returns the total commit count reachable from HEAD in the
// store's underlying git repo.
func repoCommitCount(t *testing.T, st *store.Store) int {
	t.Helper()
	out, err := exec.Command("git", "-C", st.Path(), "rev-list", "--count", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-list --count: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("parse rev-list count %q: %v", out, err)
	}
	return n
}

// manyEventsSameActor builds n events sharing one actor (so the deterministic
// detector floor's new-actor dedup fires AT MOST once across the whole batch,
// keeping the finding/resolution commit count small and the assertion about
// commit growth meaningful) with distinct, stable IDs "evt-0".."evt-(n-1)" —
// stable across calls so a second call to this same helper reproduces the
// EXACT same IDs a re-pull would.
func manyEventsSameActor(n int) []event.Event {
	ts := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	out := make([]event.Event, n)
	for i := 0; i < n; i++ {
		out[i] = benignEvent(
			"evt-"+strconv.Itoa(i), "github", "api_request", "churn-actor", ts,
			map[string]any{"note": "routine", "seq": i},
		)
	}
	return out
}

// TestPipeline_ChurnRegression is THE commit-churn regression test
// (mallcoppro-ee3). Run 1 over 200 fresh events must cost only a HANDFUL of
// commits (events batch + baseline + findings batch + snapshot + resolutions
// batch + the KindScans register record, mallcoppro-e3c = at most 6), never
// one per event. Run 2 over the IDENTICAL events must dedupe every one of
// them (EventsScanned==0, DuplicatesSkipped==200) and cost at most 3 more
// commits (the re-derived baseline + the findings snapshot + the scan
// register record, all three of which run unconditionally on every scan) —
// never the ~200+ commits a naive per-record re-append would have cost.
func TestPipeline_ChurnRegression(t *testing.T) {
	const n = 200
	conn := &fakeConnector{events: manyEventsSameActor(n)}
	st := newGitStore(t)

	baseCommits := repoCommitCount(t, st)

	sum1, err := pipeline.Run(context.Background(), pipeline.Config{
		Connector: conn,
		Client:    nil, // fail-safe escalate; irrelevant to the churn assertion
		Store:     st,
	})
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if sum1.EventsScanned != n {
		t.Fatalf("run 1 EventsScanned = %d, want %d (all fresh)", sum1.EventsScanned, n)
	}
	if sum1.DuplicatesSkipped != 0 {
		t.Fatalf("run 1 DuplicatesSkipped = %d, want 0 (nothing pulled before)", sum1.DuplicatesSkipped)
	}

	afterRun1 := repoCommitCount(t, st)
	growth1 := afterRun1 - baseCommits
	if growth1 > 6 {
		t.Fatalf("run 1 grew the commit log by %d commits for %d events, want <= 6 "+
			"(events batch + baseline + findings batch + snapshot + resolutions batch + scan register) — "+
			"a per-record commit regression would grow this by ~%d", growth1, n, n)
	}
	if growth1 < 1 {
		t.Fatalf("run 1 grew the commit log by %d commits, want at least 1 (events were durably appended)", growth1)
	}

	// Run 2: the SAME connector, pulling the IDENTICAL 200 events again — the
	// exact re-pull-without-a-cursor scenario that regrew events.jsonl in
	// production. Every one of them must dedupe away.
	sum2, err := pipeline.Run(context.Background(), pipeline.Config{
		Connector: conn,
		Client:    nil,
		Store:     st,
	})
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if sum2.EventsScanned != 0 {
		t.Fatalf("run 2 EventsScanned = %d, want 0 (all %d events were re-pulled duplicates)", sum2.EventsScanned, n)
	}
	if sum2.DuplicatesSkipped != n {
		t.Fatalf("run 2 DuplicatesSkipped = %d, want %d", sum2.DuplicatesSkipped, n)
	}

	afterRun2 := repoCommitCount(t, st)
	growth2 := afterRun2 - afterRun1
	if growth2 > 3 {
		t.Fatalf("run 2 (all duplicates) grew the commit log by %d commits, want <= 3 "+
			"(the re-derived baseline record + the findings snapshot + the scan register record, "+
			"all three unconditional) — a broken dedupe would grow this by ~%d (re-appending every duplicate)", growth2, n)
	}
}

// TestPipeline_WithinBatchDuplicateIDCollapse proves a SINGLE pull batch that
// carries the same event ID twice collapses to the FIRST occurrence: the
// second (a different actor, so the two are trivially distinguishable) is
// dropped and counted in DuplicatesSkipped, never stored or detected on.
func TestPipeline_WithinBatchDuplicateIDCollapse(t *testing.T) {
	ts := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	events := []event.Event{
		benignEvent("dup-1", "github", "api_request", "alice", ts, map[string]any{"note": "first"}),
		benignEvent("dup-1", "github", "api_request", "bob", ts, map[string]any{"note": "second, same ID"}),
	}
	conn := &fakeConnector{events: events}
	st := newGitStore(t)

	sum, err := pipeline.Run(context.Background(), pipeline.Config{
		Connector: conn,
		Client:    nil,
		Store:     st,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if sum.EventsScanned != 1 {
		t.Fatalf("EventsScanned = %d, want 1 (the second event shares dup-1's ID and must collapse)", sum.EventsScanned)
	}
	if sum.DuplicatesSkipped != 1 {
		t.Fatalf("DuplicatesSkipped = %d, want 1", sum.DuplicatesSkipped)
	}

	stored := loadStoredEvents(t, st)
	if len(stored) != 1 {
		t.Fatalf("store holds %d events, want 1 (within-batch duplicate must not be persisted)", len(stored))
	}
	if stored[0].Actor != "alice" {
		t.Fatalf("stored event actor = %q, want %q (the FIRST occurrence of dup-1 must win)", stored[0].Actor, "alice")
	}
}

// TestPipeline_EmptyIDNeverDropped proves an event with an EMPTY ID is never
// treated as a duplicate of anything, even another empty-ID event in the same
// batch — an empty string is not an identity.
func TestPipeline_EmptyIDNeverDropped(t *testing.T) {
	ts := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	events := []event.Event{
		benignEvent("", "github", "api_request", "x1", ts, map[string]any{"note": "no id 1"}),
		benignEvent("", "github", "api_request", "x2", ts, map[string]any{"note": "no id 2"}),
	}
	conn := &fakeConnector{events: events}
	st := newGitStore(t)

	sum, err := pipeline.Run(context.Background(), pipeline.Config{
		Connector: conn,
		Client:    nil,
		Store:     st,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if sum.EventsScanned != 2 {
		t.Fatalf("EventsScanned = %d, want 2 (empty-ID events must never be dropped as duplicates)", sum.EventsScanned)
	}
	if sum.DuplicatesSkipped != 0 {
		t.Fatalf("DuplicatesSkipped = %d, want 0", sum.DuplicatesSkipped)
	}

	stored := loadStoredEvents(t, st)
	if len(stored) != 2 {
		t.Fatalf("store holds %d events, want 2", len(stored))
	}
}

// loadStoredEvents replays the KindEvents stream from the git store.
func loadStoredEvents(t *testing.T, st *store.Store) []event.Event {
	t.Helper()
	raws, err := st.Load(store.KindEvents)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	out := make([]event.Event, 0, len(raws))
	for _, raw := range raws {
		var ev event.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		out = append(out, ev)
	}
	return out
}
