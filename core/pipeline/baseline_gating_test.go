package pipeline_test

// baseline_gating_test.go — proves the derived-baseline gate (mallcoppro-a7a):
// `mallcop scan` must investigate an actor/pattern ONCE (the first scan it
// appears) and NOT re-detect (or re-charge inference for) it on a steady-state
// re-scan. The pipeline derives the baseline from the store's PRIOR events, so a
// known actor is gated while a genuinely new actor/incident still fires.
//
// These drive the WHOLE public pipeline.Run over a REAL temp git store. They use
// a nil inference client: findings that DO fire fail safe to escalate (no model),
// which is irrelevant to what we assert — the DETECTED count (computed by the
// deterministic detector floor before any resolve) and the persisted baseline.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// benignEvent builds an event whose payload trips NO content detector — so only
// the baseline-dependent detectors (new-actor et al.) can fire.
func benignEvent(id, source, typ, actor string, ts time.Time, payload map[string]any) event.Event {
	pb, _ := json.Marshal(payload)
	return event.Event{
		ID: id, Source: source, Type: typ, Actor: actor,
		Timestamp: ts, Org: "atom", Payload: pb,
	}
}

// loadFindings replays the findings stream from the git store.
func loadFindings(t *testing.T, st *store.Store) []finding.Finding {
	t.Helper()
	raws, err := st.Load(store.KindFindings)
	if err != nil {
		t.Fatalf("load findings: %v", err)
	}
	out := make([]finding.Finding, 0, len(raws))
	for _, raw := range raws {
		var f finding.Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("unmarshal finding: %v", err)
		}
		out = append(out, f)
	}
	return out
}

// baseCfg wires a pipeline.Config over the given store + events file with a nil
// client (fires-fail-safe) and no explicit baseline (so Run derives one).
func baseCfg(t *testing.T, st *store.Store, eventsPath string) pipeline.Config {
	return pipeline.Config{
		Connector: connect.FromPath(eventsPath),
		Client:    nil, // findings that fire escalate via fail-safe; we assert on DETECTED count
		Store:     st,
	}
}

// TestPipeline_IdempotentReScan is THE regression test for the cost bug: a second
// scan over the SAME events must produce ZERO new findings and ZERO investigations.
// Against the pre-fix code (detect saw an always-empty baseline) the second run
// re-detected every actor — so this test FAILS pre-fix (the sabotage check).
func TestPipeline_IdempotentReScan(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	events := []event.Event{
		benignEvent("e1", "github", "api_request", "alice", ts, map[string]any{"note": "routine"}),
		benignEvent("e2", "github", "api_request", "bob", ts, map[string]any{"note": "routine"}),
		benignEvent("e3", "aws", "api_request", "carol", ts, map[string]any{"note": "routine"}),
	}
	path := writeEventsFile(t, events)
	st := newGitStore(t)

	// Run 1: three brand-new actors → three new-actor findings.
	sum1, err := pipeline.Run(context.Background(), baseCfg(t, st, path))
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if sum1.FindingsDetected != 3 {
		t.Fatalf("run 1 FindingsDetected = %d, want 3 (one new-actor each for alice/bob/carol)", sum1.FindingsDetected)
	}

	// Run 2: identical events. Every actor is now in the derived baseline → gated.
	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, path))
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if sum2.FindingsDetected != 0 {
		t.Errorf("run 2 FindingsDetected = %d, want 0 — the SAME actors were re-detected (cost bug not fixed)", sum2.FindingsDetected)
	}
	if sum2.Resolved+sum2.Escalated != 0 {
		t.Errorf("run 2 ran %d investigations, want 0 (no re-charged inference on a steady-state re-scan)",
			sum2.Resolved+sum2.Escalated)
	}
}

// TestPipeline_NewActorFiresOnce proves a genuinely new actor fires the FIRST scan
// it appears and is gated thereafter: absent in run 1, present in run 2 → fires in
// run 2, NOT run 3.
func TestPipeline_NewActorFiresOnce(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	run1 := []event.Event{
		benignEvent("a1", "github", "api_request", "alice", ts, map[string]any{"note": "routine"}),
	}
	run23 := []event.Event{
		benignEvent("a1", "github", "api_request", "alice", ts, map[string]any{"note": "routine"}),
		benignEvent("b1", "github", "api_request", "bob", ts, map[string]any{"note": "routine"}),
	}
	p1 := writeEventsFile(t, run1)
	p23 := writeEventsFile(t, run23)
	st := newGitStore(t)

	sum1, err := pipeline.Run(context.Background(), baseCfg(t, st, p1))
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if sum1.FindingsDetected != 1 {
		t.Fatalf("run 1 FindingsDetected = %d, want 1 (alice new)", sum1.FindingsDetected)
	}

	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, p23))
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if sum2.FindingsDetected != 1 {
		t.Fatalf("run 2 FindingsDetected = %d, want 1 (bob new; alice gated)", sum2.FindingsDetected)
	}
	// The run-2 finding must be for bob, not a re-detect of alice.
	last := loadFindings(t, st)
	got := last[len(last)-1]
	if got.Actor != "bob" || got.Type != "new-actor" {
		t.Errorf("run 2 finding = {actor=%q type=%q}, want {bob new-actor}", got.Actor, got.Type)
	}

	sum3, err := pipeline.Run(context.Background(), baseCfg(t, st, p23))
	if err != nil {
		t.Fatalf("run 3: %v", err)
	}
	if sum3.FindingsDetected != 0 {
		t.Errorf("run 3 FindingsDetected = %d, want 0 (alice+bob both baselined)", sum3.FindingsDetected)
	}
}

// TestPipeline_KnownActorNewIncidentStillFires proves the gate did NOT over-suppress:
// a KNOWN (baselined) actor performing a NEW privilege escalation still fires. The
// baseline gates actor-NOVELTY and per-ROLE novelty only; a new elevated role for a
// known actor is a new incident that must reach the human.
func TestPipeline_KnownActorNewIncidentStillFires(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)

	// Run 1: admin-user does benign activity → becomes a KNOWN actor with NO
	// baselined roles.
	run1 := []event.Event{
		benignEvent("p1", "github", "api_request", "admin-user", ts, map[string]any{"note": "routine"}),
	}
	// Run 2 (and 3): admin-user grants itself the "admin" role — a priv-escalation.
	escalation := []event.Event{
		benignEvent("p1", "github", "api_request", "admin-user", ts, map[string]any{"note": "routine"}),
		benignEvent("p2", "github", "role_assignment", "admin-user", ts, map[string]any{
			"role": "admin", "action": "add_role_assignment", "target_user": "victim",
		}),
	}
	p1 := writeEventsFile(t, run1)
	pEsc := writeEventsFile(t, escalation)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, p1)); err != nil {
		t.Fatalf("run 1: %v", err)
	}

	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, pEsc))
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if sum2.FindingsDetected != 1 {
		t.Fatalf("run 2 FindingsDetected = %d, want 1 (priv-escalation on a known actor; new-actor gated)", sum2.FindingsDetected)
	}
	last := loadFindings(t, st)
	got := last[len(last)-1]
	if got.Type != "priv-escalation" || got.Actor != "admin-user" {
		t.Fatalf("run 2 finding = {actor=%q type=%q}, want {admin-user priv-escalation}", got.Actor, got.Type)
	}

	// Run 3: the identical grant — "admin" is now a baselined role for admin-user,
	// so the SAME incident is gated (per-role idempotency). A DIFFERENT/higher role
	// would still fire; this proves the gate closes on the exact repeated incident.
	sum3, err := pipeline.Run(context.Background(), baseCfg(t, st, pEsc))
	if err != nil {
		t.Fatalf("run 3: %v", err)
	}
	if sum3.FindingsDetected != 0 {
		t.Errorf("run 3 FindingsDetected = %d, want 0 (admin role now baselined for admin-user)", sum3.FindingsDetected)
	}
}

// TestPipeline_ExplicitBaselineHonored proves an explicit Config.Baseline takes
// precedence over the derived one AND is NOT persisted. Over a FRESH store (the
// derived baseline would be empty → new-actor would fire), the explicit baseline
// marks the actor known → gated → zero findings.
func TestPipeline_ExplicitBaselineHonored(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	events := []event.Event{
		benignEvent("x1", "github", "api_request", "known-actor", ts, map[string]any{"note": "routine"}),
	}
	path := writeEventsFile(t, events)
	st := newGitStore(t)

	cfg := baseCfg(t, st, path)
	cfg.Baseline = &baseline.Baseline{KnownActors: []string{"known-actor"}}

	sum, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if sum.FindingsDetected != 0 {
		t.Errorf("FindingsDetected = %d, want 0 (explicit baseline gates known-actor; derived-empty would have fired)", sum.FindingsDetected)
	}

	// The explicit baseline must NOT be persisted to KindBaseline (only the derived
	// one is) — the explicit file is already durable.
	raws, err := st.Load(store.KindBaseline)
	if err != nil {
		t.Fatalf("load baseline stream: %v", err)
	}
	if len(raws) != 0 {
		t.Errorf("KindBaseline holds %d records, want 0 (explicit baseline must not be re-persisted)", len(raws))
	}
}

// TestPipeline_DerivedBaselinePersisted proves the DERIVED baseline is written to
// the KindBaseline stream so it is observable + portable + loadable by investigate.
func TestPipeline_DerivedBaselinePersisted(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	events := []event.Event{
		benignEvent("d1", "github", "api_request", "dave", ts, map[string]any{"note": "routine"}),
	}
	path := writeEventsFile(t, events)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, path)); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, path)); err != nil {
		t.Fatalf("run 2: %v", err)
	}

	raws, err := st.Load(store.KindBaseline)
	if err != nil {
		t.Fatalf("load baseline stream: %v", err)
	}
	if len(raws) != 2 {
		t.Fatalf("KindBaseline holds %d records, want 2 (one per derived scan)", len(raws))
	}
	// Run 2's baseline was derived from run 1's event → it must know "dave".
	var latest baseline.Baseline
	if err := json.Unmarshal(raws[len(raws)-1], &latest); err != nil {
		t.Fatalf("unmarshal persisted baseline: %v", err)
	}
	if !latest.IsKnownActor("dave") {
		t.Errorf("persisted baseline does not know dave; KnownActors=%v", latest.KnownActors)
	}
}
