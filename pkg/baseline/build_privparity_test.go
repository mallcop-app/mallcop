package baseline_test

// build_privparity_test.go — ANTI-DRIFT parity between baseline.Build's ActorRoles
// derivation and the REAL priv-escalation detector's firing predicate.
//
// Build cannot import core/detect (detect imports baseline — that would cycle), so
// Build mirrors the detector's isElevated / roleKey / elevation-type logic with a
// local copy (buildPriv* in build.go). Duplicated security logic is a false-
// negative hazard: if the detector's firing predicate changes and the mirror does
// not, Build would baseline a role the detector still fires on (suppressing a real
// attack) — or vice versa. This test forecloses that drift by driving the ACTUAL
// detector over a battery and asserting, for every case, that Build records a role
// IFF the detector both FIRES and derived the role from an EXPLICIT role/permission
// field (Build deliberately never baselines the event-type fallback — field-less
// escalations must fail safe and re-fire).
//
// It lives in the external baseline_test package so it may import core/detect.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func parityEvent(id, typ, actor string, payload map[string]any) event.Event {
	pb, _ := json.Marshal(payload)
	return event.Event{
		ID: id, Source: "github", Type: typ, Actor: actor,
		Timestamp: time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC), Payload: pb,
	}
}

// privEscalationFires runs the REAL registered detector set over a single event
// with an EMPTY baseline and returns the priv-escalation finding (or nil).
func privEscalationFires(t *testing.T, ev event.Event) *finding.Finding {
	t.Helper()
	for _, f := range detect.Detect([]event.Event{ev}, &baseline.Baseline{}) {
		if f.Type == "priv-escalation" {
			ff := f
			return &ff
		}
	}
	return nil
}

// TestBuild_ActorRoles_MirrorsPrivEscalationFiring pins Build's ActorRoles gate to
// the detector's real behavior. Each case uses a DISTINCT actor so Build's per-
// actor aggregation is unambiguous. wantFire is asserted against the REAL detector
// (so a detector predicate change breaks this test first), and wantRole records
// what Build must baseline: the explicit role key when the detector fires on an
// explicit field, or "" when Build must record NOTHING (non-firing, or a field-
// less/event-type-fallback firing that fails safe).
func TestBuild_ActorRoles_MirrorsPrivEscalationFiring(t *testing.T) {
	cases := []struct {
		name     string
		ev       event.Event
		wantFire bool   // does the REAL priv-escalation detector fire?
		wantRole string // role Build MUST baseline for this actor ("" = none)
	}{
		{
			name:     "explicit admin grant fires and is baselined",
			ev:       parityEvent("a1", "role_assignment", "a1", map[string]any{"role": "admin", "action": "add_role_assignment", "target_user": "t"}),
			wantFire: true, wantRole: "admin",
		},
		{
			name:     "explicit write permission fires and is baselined",
			ev:       parityEvent("a2", "permission_change", "a2", map[string]any{"permission": "write", "action": "grant"}),
			wantFire: true, wantRole: "write",
		},
		{
			name:     "role REMOVAL is not elevation → not fired, not baselined",
			ev:       parityEvent("a3", "role_assignment", "a3", map[string]any{"role": "admin", "action": "remove_role_assignment"}),
			wantFire: false, wantRole: "",
		},
		{
			name:     "role on a NON-elevation event type → not fired, not baselined",
			ev:       parityEvent("a4", "api_request", "a4", map[string]any{"role": "admin"}),
			wantFire: false, wantRole: "",
		},
		{
			name:     "admin_action field-less → fires (event-type fallback) but NOT baselined (fail safe)",
			ev:       parityEvent("a5", "admin_action", "a5", map[string]any{"action": "something"}),
			wantFire: true, wantRole: "",
		},
		{
			name:     "iam_change boundary removal → fires (action keyword) but NOT baselined (fail safe)",
			ev:       parityEvent("a6", "iam_change", "a6", map[string]any{"action": "DeleteRolePermissionsBoundary"}),
			wantFire: true, wantRole: "",
		},
		{
			name:     "non-elevated role value (reader) → not fired, not baselined",
			ev:       parityEvent("a7", "role_assignment", "a7", map[string]any{"role": "reader", "action": "add_role_assignment"}),
			wantFire: false, wantRole: "",
		},
		{
			name:     "collaborator_added maintainer → fires and is baselined",
			ev:       parityEvent("a8", "collaborator_added", "a8", map[string]any{"role": "maintainer"}),
			wantFire: true, wantRole: "maintainer",
		},
		{
			name:     "permission_level owner → fires and is baselined",
			ev:       parityEvent("a9", "permission_change", "a9", map[string]any{"permission_level": "owner"}),
			wantFire: true, wantRole: "owner",
		},
		{
			name:     "member_added mixed-case Admin → fires and is baselined lower-cased",
			ev:       parityEvent("a10", "member_added", "a10", map[string]any{"role": "Admin"}),
			wantFire: true, wantRole: "admin",
		},
		{
			// The detector's roleKey lower-cases the RAW value with NO trim, so Build
			// must baseline " admin " untrimmed. If buildPrivRoleKey trimmed, Build
			// would key "admin" here and a later clean-role grant would be suppressed
			// (false negative). wantRole carries the surrounding spaces deliberately.
			name:     "whitespace-padded admin role → fires and is baselined UNTRIMMED (byte-faithful roleKey)",
			ev:       parityEvent("a11", "role_assignment", "a11", map[string]any{"role": " admin ", "action": "add_role_assignment", "target_user": "t"}),
			wantFire: true, wantRole: " admin ",
		},
	}

	battery := make([]event.Event, 0, len(cases))
	for _, c := range cases {
		battery = append(battery, c.ev)
	}
	bl := baseline.Build(battery)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// (1) Pin the expectation against the REAL detector — this is what makes
			// the test a drift alarm: a predicate change flips wantFire here.
			gotFire := privEscalationFires(t, c.ev) != nil
			if gotFire != c.wantFire {
				t.Fatalf("REAL priv-escalation fired=%v, want %v — the detector's firing predicate changed; re-sync build.go's buildPriv* mirror and this battery", gotFire, c.wantFire)
			}

			actor := c.ev.Actor
			// (2) Build must record EXACTLY the role the detector would gate on.
			if c.wantRole != "" {
				if !bl.IsKnownRole(actor, c.wantRole) {
					t.Errorf("Build did NOT baseline (%s,%q) that the detector fires on → the SAME event would re-fire forever (churn), and a divergent mirror could suppress a real grant. ActorRoles[%s]=%v", actor, c.wantRole, actor, bl.ActorRoles[actor])
				}
			} else {
				if roles := bl.ActorRoles[actor]; len(roles) != 0 {
					t.Errorf("Build baselined %v for %s, want NONE — Build must not record a role off a non-firing or field-less event (that is the poisoning false-negative)", roles, actor)
				}
			}
		})
	}
}
