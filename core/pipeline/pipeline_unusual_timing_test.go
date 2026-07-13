package pipeline_test

// pipeline_unusual_timing_test.go — the REGRESSION TEST for mallcoppro-d73: a
// live 3dl-dev/mallcop-deploy scan produced 2010 unusual-timing findings that
// collapsed to only 145 distinct (actor, hour) BEHAVIORS (e.g. actor
// forge-relay at hour 16 alone produced 485 separate findings in one scan,
// each escalated to its own paid inference investigation). The root cause was
// core/detect/unusual_timing.go emitting one finding PER EVENT whose (actor,
// UTC hour) fell outside the actor's baseline — N events sharing one novel
// actor-hour meant N findings.
//
// This test drives the fix through the REAL pipeline (not a unit test on the
// detector): it seeds the store with a prior committed event so
// pipeline.Run's baseline-derivation path (Config.Baseline == nil →
// baseline.Build(priorEvents), see pipeline.go's (1a)) knows actor "svc-a" is
// active at hour 10 UTC, then pulls a batch with 5 events at the NOVEL hour 03
// and 2 events at the KNOWN hour 10. Before the fix this produced 5 separate
// unusual-timing findings for hour 03; after the fix it produces exactly one,
// carrying event_count=5 in its evidence.
import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestPipeline_UnusualTiming_CollapsesPerActorHour is the mallcoppro-d73
// regression test. It fails on the pre-fix detector (5 findings for the hour-3
// group) and passes on the fix (1 finding, event_count=5).
func TestPipeline_UnusualTiming_CollapsesPerActorHour(t *testing.T) {
	st := newGitStore(t)

	// Seed the store with ONE prior committed event for svc-a at hour 10 UTC —
	// simulating an earlier scan. pipeline.Run derives the baseline from the
	// store's prior KindEvents stream (Config.Baseline left nil below), so
	// baseline.Build sees svc-a active at hour 10 and NOT at hour 03.
	priorDay := time.Date(2026, 4, 9, 10, 0, 0, 0, time.UTC)
	priorEvent := event.Event{
		ID: "prior-svc-a-1", Source: "github", Type: "push", Actor: "svc-a",
		Timestamp: priorDay, Org: "acme",
	}
	if _, err := st.Append(store.KindEvents, priorEvent); err != nil {
		t.Fatalf("seed prior event: %v", err)
	}

	// The pulled batch: 5 events at the NOVEL hour 03, 2 events at the KNOWN
	// hour 10 — same actor, same source/type, so no OTHER detector (new-actor,
	// volume-anomaly) is exercised by this fixture; only unusual-timing should
	// fire, and only for the hour-03 group.
	day := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	var batch []event.Event
	for i := 0; i < 5; i++ {
		batch = append(batch, event.Event{
			ID:        "batch-h3-" + itoaLocal(i),
			Source:    "github",
			Type:      "push",
			Actor:     "svc-a",
			Timestamp: day.Add(3*time.Hour + time.Duration(i)*time.Minute),
			Org:       "acme",
		})
	}
	for i := 0; i < 2; i++ {
		batch = append(batch, event.Event{
			ID:        "batch-h10-" + itoaLocal(i),
			Source:    "github",
			Type:      "push",
			Actor:     "svc-a",
			Timestamp: day.Add(10*time.Hour + time.Duration(i)*time.Minute),
			Org:       "acme",
		})
	}

	eventsPath := writeEventsFile(t, batch)

	// baseCfg (baseline_gating_test.go) wires a nil Client (fires fail-safe,
	// no model call — irrelevant here since we assert on the DETECTOR's
	// output) and leaves Config.Baseline nil so Run derives it from the
	// store's prior events, exactly as the live scan does.
	cfg := baseCfg(t, st, eventsPath)

	if _, err := pipeline.Run(context.Background(), cfg); err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}

	findings := loadFindings(t, st)

	var unusualTiming []finding.Finding
	for _, f := range findings {
		if f.Type == "unusual-timing" {
			unusualTiming = append(unusualTiming, f)
		}
	}

	if len(unusualTiming) != 1 {
		t.Fatalf("expected EXACTLY ONE unusual-timing finding (the hour-03 group), got %d: %+v",
			len(unusualTiming), unusualTiming)
	}

	f := unusualTiming[0]
	if f.Actor != "svc-a" {
		t.Errorf("Actor = %q, want svc-a", f.Actor)
	}

	var ev map[string]any
	if err := json.Unmarshal(f.Evidence, &ev); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if ev["hour_utc"] != float64(3) {
		t.Errorf("evidence hour_utc = %v, want 3 (the novel hour; hour 10 must NOT fire)", ev["hour_utc"])
	}
	if ev["event_count"] != float64(5) {
		t.Errorf("evidence event_count = %v, want 5 (all 5 hour-03 events collapsed into this one finding)", ev["event_count"])
	}
}

// itoaLocal is a tiny strconv.Itoa replacement (avoids adding a new import
// just for small loop-index IDs, matching the style of core/detect's own
// itoa helper in detect_test.go).
func itoaLocal(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
