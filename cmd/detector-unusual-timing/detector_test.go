package main

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// alice works 09-17 UTC; bob works 22-06 UTC (night shift).
var testBaseline = &baseline.Baseline{
	ActorHours: map[string][]int{
		"alice": {9, 10, 11, 12, 13, 14, 15, 16, 17},
		"bob":   {22, 23, 0, 1, 2, 3, 4, 5, 6},
	},
}

func makeEvent(id, actor string, hour int) event.Event {
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      "push",
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, hour, 0, 0, 0, time.UTC),
		Org:       "acme",
	}
}

// TestCollapseSingleEvent proves collapse's per-event gating (skip-gates: no
// actor-hours baseline, unknown actor, known hour) is unchanged from the old
// per-event evaluate — a batch of exactly one event behaves identically to
// the pre-collapse semantics.
func TestCollapseSingleEvent(t *testing.T) {
	tests := []struct {
		name         string
		ev           event.Event
		wantFinding  bool
		wantSeverity string
	}{
		{
			name:        "alice during business hours",
			ev:          makeEvent("evt-a", "alice", 10),
			wantFinding: false,
		},
		{
			name:         "alice at 3am — unusual",
			ev:           makeEvent("evt-b", "alice", 3),
			wantFinding:  true,
			wantSeverity: "low",
		},
		{
			name:        "bob at midnight — normal",
			ev:          makeEvent("evt-c", "bob", 23),
			wantFinding: false,
		},
		{
			name:         "bob at 14:00 — unusual",
			ev:           makeEvent("evt-d", "bob", 14),
			wantFinding:  true,
			wantSeverity: "low",
		},
		{
			name:        "unknown actor carol — skipped (new-actor handles)",
			ev:          makeEvent("evt-e", "carol", 3),
			wantFinding: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := collapse([]event.Event{tc.ev}, testBaseline)
			if tc.wantFinding && len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Fatalf("expected no finding but got: %+v", findings)
			}
			if tc.wantFinding && findings[0].Severity != tc.wantSeverity {
				t.Fatalf("severity: got %q want %q", findings[0].Severity, tc.wantSeverity)
			}
		})
	}
}

func TestNoBaselineData(t *testing.T) {
	bl := &baseline.Baseline{} // no actor hours
	ev := makeEvent("evt-x", "alice", 3)
	findings := collapse([]event.Event{ev}, bl)
	if findings != nil {
		t.Fatalf("expected no finding when no baseline data, got: %+v", findings)
	}
}

// TestCollapseGroupsMultipleEvents proves the fan-out fix (mallcoppro-d73):
// several events sharing one (actor, hour) group collapse into ONE finding,
// keyed on the first event, with evidence carrying the full group's event
// count, sampled event IDs, and distinct sorted sources/types.
func TestCollapseGroupsMultipleEvents(t *testing.T) {
	base := time.Date(2026, 4, 10, 3, 0, 0, 0, time.UTC)
	events := []event.Event{
		{ID: "evt-1", Source: "github", Type: "push", Actor: "alice", Timestamp: base},
		{ID: "evt-2", Source: "azure", Type: "login", Actor: "alice", Timestamp: base.Add(time.Minute)},
		{ID: "evt-3", Source: "github", Type: "push", Actor: "alice", Timestamp: base.Add(2 * time.Minute)},
	}

	findings := collapse(events, testBaseline)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 collapsed finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.ID != "finding-evt-1" {
		t.Errorf("ID: got %q, want finding-evt-1 (first event in the group)", f.ID)
	}

	var ev map[string]any
	if err := json.Unmarshal(f.Evidence, &ev); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if got := ev["event_count"]; got != float64(3) {
		t.Errorf("event_count: got %v, want 3", got)
	}
	eventIDs, _ := ev["event_ids"].([]any)
	if len(eventIDs) != 3 || eventIDs[0] != "evt-1" || eventIDs[1] != "evt-2" || eventIDs[2] != "evt-3" {
		t.Errorf("event_ids: got %v, want [evt-1 evt-2 evt-3] in order", eventIDs)
	}
	sources, _ := ev["sources"].([]any)
	if len(sources) != 2 || sources[0] != "azure" || sources[1] != "github" {
		t.Errorf("sources: got %v, want sorted [azure github]", sources)
	}
	types, _ := ev["event_types"].([]any)
	if len(types) != 2 || types[0] != "login" || types[1] != "push" {
		t.Errorf("event_types: got %v, want sorted [login push]", types)
	}
}

// TestGoldenFixture proves whole-batch parity against a fixed corpus, run
// through collapse EXACTLY as main() runs it (buffer the batch, collapse
// once) — not per-event. Every group in this fixture is a singleton, so the
// finding count matches the pre-collapse golden set; the golden file's
// evidence/reason strings reflect the new collapsed shape.
func TestGoldenFixture(t *testing.T) {
	bl, err := baseline.Load("testdata/baseline.json")
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}

	eventsFile, err := os.Open("testdata/events.jsonl")
	if err != nil {
		t.Fatalf("open events: %v", err)
	}
	defer eventsFile.Close()

	goldenFile, err := os.Open("testdata/findings.golden.jsonl")
	if err != nil {
		t.Fatalf("open golden: %v", err)
	}
	defer goldenFile.Close()

	var events []event.Event
	scanner := bufio.NewScanner(eventsFile)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		events = append(events, ev)
	}
	got := collapse(events, bl)

	var want []finding.Finding
	gScanner := bufio.NewScanner(goldenFile)
	for gScanner.Scan() {
		line := gScanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("unmarshal golden finding: %v", err)
		}
		want = append(want, f)
	}

	if len(got) != len(want) {
		t.Fatalf("finding count: got %d want %d", len(got), len(want))
	}

	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID {
			t.Errorf("[%d] ID: got %q want %q", i, g.ID, w.ID)
		}
		if g.Severity != w.Severity {
			t.Errorf("[%d] Severity: got %q want %q", i, g.Severity, w.Severity)
		}
		if g.Type != w.Type {
			t.Errorf("[%d] Type: got %q want %q", i, g.Type, w.Type)
		}
		if g.Actor != w.Actor {
			t.Errorf("[%d] Actor: got %q want %q", i, g.Actor, w.Actor)
		}
		if g.Reason != w.Reason {
			t.Errorf("[%d] Reason: got %q want %q", i, g.Reason, w.Reason)
		}
	}
}
