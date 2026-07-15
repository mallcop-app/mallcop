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
	"os"
	"os/exec"
	"path/filepath"
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

// TestPipeline_PrivEscalationTargetAwareGate — mallcoppro-9af (ruled by Baron
// 2026-07-15): the priv-escalation baseline gate/dedup key is (actor, role,
// target), not (actor, role) alone. Before this fix, once admin-user's "admin"
// grant was baselined via ANY target, admin-user granting "admin" to a NEW
// principal in a later scan was silently gated forever — a compromised known
// admin re-granting privileges to a fresh attacker principal never re-fired.
// This drives the fix through the REAL derived-baseline path (pipeline.Run →
// baseline.Build → detect.Detect), proving both halves of the change agree:
//   - scan 2 grants "admin" to a NEW target (attacker) → MUST fire, where the
//     pre-fix (actor,role)-only gate would have suppressed it (the sabotage
//     check this test distinguishes).
//   - scan 3 repeats scan 2's exact grant → gated (idempotent, no churn).
func TestPipeline_PrivEscalationTargetAwareGate(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)

	// Scan 1: admin-user grants "admin" to "victim" — a real escalation, fires
	// and baselines (admin-user, admin, victim).
	grant1 := []event.Event{
		benignEvent("v1", "github", "role_assignment", "admin-user", ts, map[string]any{
			"role": "admin", "action": "add_role_assignment", "target_user": "victim",
		}),
	}
	// Scan 2: the SAME admin-user grants the SAME "admin" role to a DIFFERENT,
	// NEW target — a distinct incident (e.g. a compromised admin credential
	// handing privileges to a fresh attacker principal) that must reach the
	// human even though (actor, role) alone was already baselined.
	grant2 := []event.Event{
		benignEvent("v2", "github", "role_assignment", "admin-user", ts, map[string]any{
			"role": "admin", "action": "add_role_assignment", "target_user": "attacker",
		}),
	}
	pGrant1 := writeEventsFile(t, grant1)
	pGrant2 := writeEventsFile(t, grant2)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pGrant1)); err != nil {
		t.Fatalf("scan 1: %v", err)
	}

	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, pGrant2))
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if sum2.FindingsDetected != 1 {
		t.Fatalf("scan 2 FindingsDetected = %d, want 1 — the SAME role granted to a NEW target must fire, not be suppressed by the (actor,role)-only gate", sum2.FindingsDetected)
	}
	got := loadFindings(t, st)
	last := got[len(got)-1]
	if last.Type != "priv-escalation" || last.Actor != "admin-user" {
		t.Fatalf("scan 2 finding = {actor=%q type=%q}, want {admin-user priv-escalation}", last.Actor, last.Type)
	}

	// Scan 3: repeat scan 2's IDENTICAL grant (same actor, role, AND target).
	// The (actor, role, target) triple is now baselined → gated, no churn.
	sum3, err := pipeline.Run(context.Background(), baseCfg(t, st, pGrant2))
	if err != nil {
		t.Fatalf("scan 3: %v", err)
	}
	if sum3.FindingsDetected != 0 {
		t.Errorf("scan 3 FindingsDetected = %d, want 0 — the identical (actor,role,target) grant must be idempotent across re-scans", sum3.FindingsDetected)
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

// --- ADVERSARIAL FALSE-NEGATIVE REGRESSIONS (mallcoppro-a7a review) -----------
//
// These pin the three proven baseline-derivation holes the adversarial review
// found in ede6bcd: Build over-populated baseline fields off events the
// corresponding detector would NEVER fire on, so a benign prior event GATED
// (suppressed) a later REAL attack. Each test SABOTAGE-DISTINGUISHES the fix: it
// asserts the attack FIRES post-fix, where the pre-fix over-population would have
// suppressed it (0 findings). A test that passes both ways proves nothing.

// TestPipeline_RoleRemovalDoesNotPoisonLaterGrant — HOLE 1 (priv-escalation role
// poisoning). A benign role REMOVAL (which priv-escalation treats as NON-elevated
// via its removal guard) must NOT baseline that role. Pre-fix, Build recorded the
// role off the removal event ungated, so the LATER genuine admin GRANT of the same
// role was suppressed (IsKnownRole true). Post-fix, Build mirrors the detector's
// firing predicate, does not baseline the removed role, and the grant fires.
func TestPipeline_RoleRemovalDoesNotPoisonLaterGrant(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)

	// Scan 1: admin-user performs a benign role REMOVAL. priv-escalation does not
	// fire (removal is not elevation); admin-user becomes a KNOWN actor. The removed
	// "admin" role must NOT enter the baseline.
	removal := []event.Event{
		benignEvent("r1", "github", "role_assignment", "admin-user", ts, map[string]any{
			"role": "admin", "action": "remove_role_assignment", "target_user": "ex-employee",
		}),
	}
	// Scan 2: admin-user GRANTS the admin role to a fresh target — a real escalation
	// that MUST reach the human.
	grant := []event.Event{
		benignEvent("g1", "github", "role_assignment", "admin-user", ts, map[string]any{
			"role": "admin", "action": "add_role_assignment", "target_user": "attacker",
		}),
	}
	pRem := writeEventsFile(t, removal)
	pGrant := writeEventsFile(t, grant)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pRem)); err != nil {
		t.Fatalf("scan 1: %v", err)
	}

	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, pGrant))
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if sum2.FindingsDetected != 1 {
		t.Fatalf("scan 2 FindingsDetected = %d, want 1 — a benign prior role REMOVAL poisoned the baseline and suppressed the admin GRANT (false negative)", sum2.FindingsDetected)
	}
	got := loadFindings(t, st)
	last := got[len(got)-1]
	if last.Type != "priv-escalation" || last.Actor != "admin-user" {
		t.Fatalf("scan 2 finding = {actor=%q type=%q}, want {admin-user priv-escalation}", last.Actor, last.Type)
	}
}

// TestPipeline_RoleOnNonElevationEventDoesNotSuppressGrant — HOLE 1 variant. A
// role value that merely floats past on a NON-elevation event type (api_request)
// must not baseline that role: priv-escalation never fires on api_request, so it
// was never investigated. Pre-fix, Build recorded the role off ANY event carrying
// a role field, suppressing the later genuine grant. Post-fix it is gated to
// elevation event types and the grant fires.
func TestPipeline_RoleOnNonElevationEventDoesNotSuppressGrant(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)

	// Scan 1: svc-account makes an api_request that happens to carry a role field.
	// priv-escalation does not gate api_request → the role is NOT investigated and
	// must NOT be baselined. svc-account becomes a known actor.
	noise := []event.Event{
		benignEvent("n1", "github", "api_request", "svc-account", ts, map[string]any{
			"role": "admin", "note": "routine",
		}),
	}
	// Scan 2: svc-account GRANTS itself admin via a real role_assignment.
	grant := []event.Event{
		benignEvent("g1", "github", "role_assignment", "svc-account", ts, map[string]any{
			"role": "admin", "action": "add_role_assignment", "target_user": "attacker",
		}),
	}
	pNoise := writeEventsFile(t, noise)
	pGrant := writeEventsFile(t, grant)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pNoise)); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, pGrant))
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if sum2.FindingsDetected != 1 {
		t.Fatalf("scan 2 FindingsDetected = %d, want 1 — a role on a non-elevation event poisoned the baseline and suppressed the grant (false negative)", sum2.FindingsDetected)
	}
	got := loadFindings(t, st)
	last := got[len(got)-1]
	if last.Type != "priv-escalation" || last.Actor != "svc-account" {
		t.Fatalf("scan 2 finding = {actor=%q type=%q}, want {svc-account priv-escalation}", last.Actor, last.Type)
	}
}

// TestPipeline_WhitespaceRoleDoesNotPoisonCleanGrant — HOLE 1 variant (roleKey
// byte-fidelity). priv-escalation keys a role by lower-casing the RAW metadata
// value with NO whitespace trim; Build's buildPrivRoleKey must match byte-for-byte.
// If Build trims, a benign whitespace-padded grant (" admin ") baselines as "admin"
// and then SUPPRESSES a later clean-role attack grant ("admin") — a false negative
// in the highest-severity detector. Post-fix Build keys " admin " untrimmed, so the
// clean-role grant is a distinct key the detector still fires on.
func TestPipeline_WhitespaceRoleDoesNotPoisonCleanGrant(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)

	// Scan 1: admin-user grants a whitespace-padded "admin" role — a benign, already
	// reviewed change. It fires and admin-user + its role key enter the baseline.
	padded := []event.Event{
		benignEvent("p1", "github", "role_assignment", "admin-user", ts, map[string]any{
			"role": " admin ", "action": "add_role_assignment", "target_user": "contractor",
		}),
	}
	// Scan 2: admin-user grants a CLEAN "admin" role to a fresh target — a real
	// escalation that MUST reach the human. If Build trimmed the scan-1 key, this is
	// silently gated.
	clean := []event.Event{
		benignEvent("c1", "github", "role_assignment", "admin-user", ts, map[string]any{
			"role": "admin", "action": "add_role_assignment", "target_user": "attacker",
		}),
	}
	pPadded := writeEventsFile(t, padded)
	pClean := writeEventsFile(t, clean)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pPadded)); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, pClean))
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if sum2.FindingsDetected != 1 {
		t.Fatalf("scan 2 FindingsDetected = %d, want 1 — a whitespace-padded prior grant poisoned the baseline (buildPrivRoleKey trimmed) and suppressed the clean-role grant (false negative)", sum2.FindingsDetected)
	}
	got := loadFindings(t, st)
	last := got[len(got)-1]
	if last.Type != "priv-escalation" || last.Actor != "admin-user" {
		t.Fatalf("scan 2 finding = {actor=%q type=%q}, want {admin-user priv-escalation}", last.Actor, last.Type)
	}
}

// TestPipeline_CreatedPrincipalNameCollisionStillFires — HOLE 2 (created-principal
// name collision). Creating a brand-new principal whose display_name COLLIDES with
// an existing known ACTOR must still fire the "new principal created" finding on
// FIRST sight. Pre-fix, createdEntityEvaluate suppressed it because the name was a
// known actor (IsKnownActor). Post-fix the created-entity gate keys on
// IsKnownCreatedEntity — whether THAT creation was already seen — so the collision
// no longer hides the backdoor. A repeat scan of the same creation is still gated
// (no churn).
func TestPipeline_CreatedPrincipalNameCollisionStillFires(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)

	// Scan 1: establish "alice" (a real user) and "admin" as KNOWN actors.
	seed := []event.Event{
		benignEvent("s1", "github", "api_request", "alice", ts, map[string]any{"note": "routine"}),
		benignEvent("s2", "github", "api_request", "admin", ts, map[string]any{"note": "routine"}),
	}
	// Scan 2: admin creates a NEW service principal named "alice" — a backdoor whose
	// name collides with the existing known actor. This is a genuine new entity.
	collision := []event.Event{
		benignEvent("c1", "azure", "service_principal_created", "admin", ts, map[string]any{
			"display_name": "alice",
		}),
	}
	pSeed := writeEventsFile(t, seed)
	pColl := writeEventsFile(t, collision)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pSeed)); err != nil {
		t.Fatalf("scan 1: %v", err)
	}

	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, pColl))
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if sum2.FindingsDetected != 1 {
		t.Fatalf("scan 2 FindingsDetected = %d, want 1 — a created principal whose name collides with a known actor was suppressed (backdoor false negative)", sum2.FindingsDetected)
	}
	got := loadFindings(t, st)
	last := got[len(got)-1]
	if last.Type != "new-actor" || last.Actor != "alice" {
		t.Fatalf("scan 2 finding = {actor=%q type=%q}, want {alice new-actor (created principal)}", last.Actor, last.Type)
	}

	// Scan 3: identical creation — now that this specific creation was observed
	// (KnownCreatedEntities), it is gated. Proves the fix does not reintroduce churn.
	sum3, err := pipeline.Run(context.Background(), baseCfg(t, st, pColl))
	if err != nil {
		t.Fatalf("scan 3: %v", err)
	}
	if sum3.FindingsDetected != 0 {
		t.Errorf("scan 3 FindingsDetected = %d, want 0 (the same creation is now baselined — no re-investigation churn)", sum3.FindingsDetected)
	}
}

// TestPipeline_EmptyProfileLoginNewIPStillFires — HOLE 3 (unusual-login empty-
// profile blindness). A login carrying NO ip/geo must NOT create a KnownUsers
// entry, or the actor becomes "known" (HasUser true) yet HasLoginProfile stays
// false — permanently DEFERRING every future login. Pre-fix, a later login from a
// brand-new suspicious IP was silently suppressed. Post-fix, the empty-profile
// login leaves no entry, so the new-IP login still surfaces.
func TestPipeline_EmptyProfileLoginNewIPStillFires(t *testing.T) {
	ts := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)

	// Scan 1: eve logs in with NO ip/geo. Must not seed an empty login profile.
	blind := []event.Event{
		benignEvent("l1", "okta", "login", "eve", ts, map[string]any{"note": "no location data"}),
	}
	// Scan 2: eve logs in from a new suspicious IP/geo — must fire.
	newIP := []event.Event{
		benignEvent("l2", "okta", "login", "eve", ts, map[string]any{
			"ip": "203.0.113.9", "geo": "RU",
		}),
	}
	pBlind := writeEventsFile(t, blind)
	pNew := writeEventsFile(t, newIP)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pBlind)); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, pNew))
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if sum2.FindingsDetected != 1 {
		t.Fatalf("scan 2 FindingsDetected = %d, want 1 — an empty-profile prior login blinded unusual-login to the new-IP login (false negative)", sum2.FindingsDetected)
	}
	got := loadFindings(t, st)
	last := got[len(got)-1]
	if last.Type != "unusual-login" || last.Actor != "eve" {
		t.Fatalf("scan 2 finding = {actor=%q type=%q}, want {eve unusual-login}", last.Actor, last.Type)
	}
}

// --- STORE ROTATION SURVIVAL (mallcoppro-9e2) ---------------------------------
//
// mallcoppro-ee3 documented an OPERATIONAL store rotation: to bound git blob
// churn, the deployment archives events.jsonl to a gzip sidecar and truncates
// the LIVE events stream to empty, committing that truncation to the store.
// KindBaseline (a SEPARATE stream) is untouched by rotation. Pre-fix, Run's
// derived-baseline step read ONLY the (now-truncated) events stream, so a
// rotation silently forgot every actor/hour/role the system had already
// investigated — the next scan re-fired on all of them (the reported ~24h
// refire storm). These tests simulate that exact operational sequence against
// a REAL git store and assert the derived baseline survives it.

// simulateStoreRotation reproduces the mallcoppro-ee3 rotation operationally: it
// truncates the store's committed events.jsonl to empty and commits that
// truncation directly (mirroring the deployment's archive-then-truncate step),
// WITHOUT touching any other stream (baseline.jsonl, findings.jsonl, …) — the
// exact asymmetry that caused the bug.
func simulateStoreRotation(t *testing.T, st *store.Store) {
	t.Helper()
	dir := st.Path()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("rotate: truncate events.jsonl: %v", err)
	}
	for _, args := range [][]string{
		{"add", "events.jsonl"},
		{"-c", "user.email=test@mallcop.app", "-c", "user.name=mallcop-test",
			"commit", "-q", "-m", "rotate: archive events.jsonl"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// TestPipeline_BaselineSurvivesStoreRotation is THE regression test for
// mallcoppro-9e2: a previously-baselined actor/hour must NOT re-investigate on
// the first scan after a store rotation. Against pre-fix code (derivation read
// ONLY the truncated events stream) scan 3 below re-fires new-actor for alice —
// the sabotage check this test distinguishes.
func TestPipeline_BaselineSurvivesStoreRotation(t *testing.T) {
	ts := time.Date(2026, 6, 18, 9, 0, 0, 0, time.UTC) // hour 9 UTC

	seed := []event.Event{
		benignEvent("s1", "github", "api_request", "alice", ts, map[string]any{"note": "routine"}),
	}
	pSeed := writeEventsFile(t, seed)
	st := newGitStore(t)

	// Scan 1: alice, brand new, fires new-actor once (the baseline PERSISTED at
	// the end of this scan reflects events PRIOR to it — still empty, same as
	// TestPipeline_DerivedBaselinePersisted's first scan).
	sum1, err := pipeline.Run(context.Background(), baseCfg(t, st, pSeed))
	if err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	if sum1.FindingsDetected != 1 {
		t.Fatalf("scan 1 FindingsDetected = %d, want 1 (alice new)", sum1.FindingsDetected)
	}

	// Scan 2: steady-state re-scan of the SAME alice/hour-9 event. priorEvents now
	// includes scan 1's committed event, so THIS scan's derived+persisted baseline
	// carries KnownActors=[alice], ActorHours[alice]=[9] — and alice is gated (0
	// findings), proving the fixture is quiet before rotation is even introduced.
	sum2, err := pipeline.Run(context.Background(), baseCfg(t, st, pSeed))
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if sum2.FindingsDetected != 0 {
		t.Fatalf("scan 2 FindingsDetected = %d, want 0 (alice/hour-9 already baselined by scan 1's committed event)", sum2.FindingsDetected)
	}

	// ROTATE: the deployment archives + truncates events.jsonl. The events
	// stream now looks like a fresh store; KindBaseline (persisted at the end of
	// scan 2, which knows alice/hour-9) is untouched.
	simulateStoreRotation(t, st)

	raws, err := st.Load(store.KindEvents)
	if err != nil {
		t.Fatalf("load events post-rotation: %v", err)
	}
	if len(raws) != 0 {
		t.Fatalf("post-rotation events stream holds %d records, want 0 (rotation did not truncate as expected)", len(raws))
	}

	// Scan 3 (first post-rotation scan): alice appears AGAIN at the SAME known
	// hour (9). A previously-baselined actor/hour must NOT re-investigate.
	sum3, err := pipeline.Run(context.Background(), baseCfg(t, st, pSeed))
	if err != nil {
		t.Fatalf("scan 3 (post-rotation): %v", err)
	}
	if sum3.FindingsDetected != 0 {
		t.Fatalf("scan 3 (post-rotation) FindingsDetected = %d, want 0 — alice/hour-9 was already baselined before rotation and must not re-fire (the reported refire storm)", sum3.FindingsDetected)
	}

	// Scan 4: alice at a GENUINELY NEW hour (14) post-rotation → unusual-timing
	// must still fire. Proves the rotation-survival merge does not over-suppress
	// real novelty — only the ALREADY-KNOWN actor/hour is gated.
	newHour := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	novel := []event.Event{
		benignEvent("n1", "github", "api_request", "alice", newHour, map[string]any{"note": "routine"}),
	}
	pNovel := writeEventsFile(t, novel)
	sum4, err := pipeline.Run(context.Background(), baseCfg(t, st, pNovel))
	if err != nil {
		t.Fatalf("scan 4: %v", err)
	}
	if sum4.FindingsDetected != 1 {
		t.Fatalf("scan 4 FindingsDetected = %d, want 1 — alice at a genuinely NEW hour must still fire (rotation-survival must not over-suppress)", sum4.FindingsDetected)
	}
	got := loadFindings(t, st)
	last := got[len(got)-1]
	if last.Type != "unusual-timing" || last.Actor != "alice" {
		t.Fatalf("scan 4 finding = {actor=%q type=%q}, want {alice unusual-timing}", last.Actor, last.Type)
	}
}

// TestPipeline_DerivedBaselinePersistsRotationMerge proves the KindBaseline
// snapshot persisted AFTER a post-rotation scan carries the MERGED (pre + post
// rotation) knowledge — not just what the truncated events stream alone could
// derive — so a SECOND rotation would still find alice known.
func TestPipeline_DerivedBaselinePersistsRotationMerge(t *testing.T) {
	ts := time.Date(2026, 6, 18, 9, 0, 0, 0, time.UTC)
	seed := []event.Event{
		benignEvent("s1", "github", "api_request", "alice", ts, map[string]any{"note": "routine"}),
	}
	pSeed := writeEventsFile(t, seed)
	st := newGitStore(t)

	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pSeed)); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	// Scan 2: steady-state re-scan so the PERSISTED baseline actually carries
	// alice/hour-9 (scan 1's persisted snapshot reflects events PRIOR to it —
	// still empty; see TestPipeline_DerivedBaselinePersisted).
	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pSeed)); err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	simulateStoreRotation(t, st)

	// Post-rotation scan over a DIFFERENT, unrelated actor. The events stream
	// this scan derives from never mentions alice at all.
	otherTs := time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)
	other := []event.Event{
		benignEvent("o1", "github", "api_request", "bob", otherTs, map[string]any{"note": "routine"}),
	}
	pOther := writeEventsFile(t, other)
	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pOther)); err != nil {
		t.Fatalf("scan 3 (post-rotation, unrelated actor): %v", err)
	}
	// Scan 4: re-scan the same bob event so THIS scan's priorEvents (post-
	// rotation events.jsonl, which now holds scan 3's committed bob event)
	// derives a fresh baseline that knows bob — proving the LATEST persisted
	// snapshot carries BOTH the pre-rotation knowledge (alice, via the merge)
	// AND newly-learned post-rotation knowledge (bob, via fresh derivation).
	if _, err := pipeline.Run(context.Background(), baseCfg(t, st, pOther)); err != nil {
		t.Fatalf("scan 4 (post-rotation, re-scan): %v", err)
	}

	raws, err := st.Load(store.KindBaseline)
	if err != nil {
		t.Fatalf("load baseline stream: %v", err)
	}
	if len(raws) == 0 {
		t.Fatalf("KindBaseline holds 0 records after a derived scan")
	}
	var latest baseline.Baseline
	if err := json.Unmarshal(raws[len(raws)-1], &latest); err != nil {
		t.Fatalf("unmarshal persisted baseline: %v", err)
	}
	if !latest.IsKnownActor("alice") {
		t.Errorf("post-rotation persisted baseline forgot alice (KnownActors=%v) — the merge did not carry pre-rotation knowledge forward", latest.KnownActors)
	}
	if !latest.KnownHour("alice", 9) {
		t.Errorf("post-rotation persisted baseline forgot alice's hour 9 (ActorHours=%v)", latest.ActorHours)
	}
	if !latest.IsKnownActor("bob") {
		t.Errorf("post-rotation persisted baseline did not learn bob (KnownActors=%v)", latest.KnownActors)
	}
}
