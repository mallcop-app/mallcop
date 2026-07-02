package detect

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// knobSnapshot captures the priv-escalation tuning knob sets so tests that call
// ApplyTuning (which mutates PACKAGE-GLOBAL state, process-wide) can restore
// them. Every mutating test registers restoreKnobs via t.Cleanup.
type knobSnapshot struct {
	keywords   map[string]bool
	actions    []string
	eventTypes map[string]bool
}

// saveKnobs deep-copies the current knob sets.
func saveKnobs() knobSnapshot {
	s := knobSnapshot{
		keywords:   make(map[string]bool, len(elevatedKeywords)),
		actions:    append([]string{}, elevatedActionKeywords...),
		eventTypes: make(map[string]bool, len(elevationEventTypes)),
	}
	for k, v := range elevatedKeywords {
		s.keywords[k] = v
	}
	for k, v := range elevationEventTypes {
		s.eventTypes[k] = v
	}
	return s
}

// restoreKnobs reinstates a snapshot (fresh copies, so a later mutation cannot
// corrupt the saved state).
func restoreKnobs(s knobSnapshot) {
	kw := make(map[string]bool, len(s.keywords))
	for k, v := range s.keywords {
		kw[k] = v
	}
	elevatedKeywords = kw
	elevatedActionKeywords = append([]string{}, s.actions...)
	et := make(map[string]bool, len(s.eventTypes))
	for k, v := range s.eventTypes {
		et[k] = v
	}
	elevationEventTypes = et
}

// tuningFixture returns a real events+baseline fixture spanning the
// priv-escalation surface: firing grants (bare, GCP, Okta, M365 formats), an
// admin_action, a boundary delete, and non-firing shapes (viewer grant, the
// PowerUserAccess grant the built-in keywords miss). Distinct actors so the
// (actor, role) dedup never hides a finding.
func tuningFixture(t *testing.T) ([]event.Event, *baseline.Baseline) {
	t.Helper()
	actors := []string{"a-owner", "b-gcp", "c-okta", "d-m365", "e-admin", "f-boundary", "g-viewer", "h-poweruser"}
	bl := &baseline.Baseline{
		KnownActors: actors,
		ActorRoles:  map[string][]string{},
	}
	for _, a := range actors {
		bl.ActorRoles[a] = []string{"viewer"}
	}
	roleEvent := func(id, actor, role string) event.Event {
		return event.Event{
			ID: id, Source: "cloud", Type: "role_assignment",
			Actor: actor, Timestamp: ts(15, 4),
			Payload: raw(t, map[string]string{"role_name": role, "target_user": "victim"}),
		}
	}
	events := []event.Event{
		roleEvent("tf-1", "a-owner", "owner"),
		roleEvent("tf-2", "b-gcp", "roles/owner"),
		roleEvent("tf-3", "c-okta", "Super Admin"),
		roleEvent("tf-4", "d-m365", "Sites.FullControl.All"),
		{ID: "tf-5", Source: "cloud", Type: "admin_action", Actor: "e-admin", Timestamp: ts(15, 5)},
		{ID: "tf-6", Source: "aws", Type: "iam_change", Actor: "f-boundary", Timestamp: ts(15, 6),
			Payload: raw(t, map[string]string{"action": "DeleteRolePermissionsBoundary"})},
		roleEvent("tf-7", "g-viewer", "roles/viewer"),
		roleEvent("tf-8", "h-poweruser", "PowerUserAccess"),
	}
	return events, bl
}

// privEscActors returns the set of actors the REAL Detect emitted a
// priv-escalation finding for.
func privEscActors(events []event.Event, bl *baseline.Baseline) map[string]bool {
	out := map[string]bool{}
	for _, f := range Detect(events, bl) {
		if f.Type == "priv-escalation" {
			out[f.Actor] = true
		}
	}
	return out
}

// TestTuningAbsentIsByteIdentical proves the zero-tuning contract: applying the
// tuning loaded from a NONEXISTENT path and from a PRESENT-BUT-EMPTY file both
// leave the REAL detector output byte-identical to the untouched run.
func TestTuningAbsentIsByteIdentical(t *testing.T) {
	snap := saveKnobs()
	t.Cleanup(func() { restoreKnobs(snap) })

	events, bl := tuningFixture(t)

	marshal := func() []byte {
		b, err := json.Marshal(Detect(events, bl))
		if err != nil {
			t.Fatalf("marshal findings: %v", err)
		}
		return b
	}
	before := marshal()
	if len(before) <= len("null") {
		t.Fatal("fixture produced no findings — the byte-identity comparison would be vacuous")
	}

	// (1) Nonexistent path: silent fall-through to zero tuning.
	tn, err := LoadTuningFile(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadTuningFile(nonexistent) must silently fall through, got %v", err)
	}
	ApplyTuning(tn)
	afterAbsent := marshal()

	// (2) Present but empty file: zero tuning, zero mutations.
	empty := filepath.Join(t.TempDir(), "tuning.yaml")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("write empty tuning: %v", err)
	}
	tn, err = LoadTuningFile(empty)
	if err != nil {
		t.Fatalf("LoadTuningFile(empty) must yield zero tuning, got %v", err)
	}
	ApplyTuning(tn)
	afterEmpty := marshal()

	if !bytes.Equal(before, afterAbsent) {
		t.Errorf("output changed after applying tuning from a nonexistent file:\nbefore: %s\nafter:  %s", before, afterAbsent)
	}
	if !bytes.Equal(before, afterEmpty) {
		t.Errorf("output changed after applying tuning from an empty file:\nbefore: %s\nafter:  %s", before, afterEmpty)
	}
}

// TestTuningAddWidensOnly proves the add-only contract end to end with the REAL
// detector: an extra_elevated_keywords entry makes a previously-missed grant
// fire, and EVERY previously-firing shape still fires (no narrowing).
func TestTuningAddWidensOnly(t *testing.T) {
	snap := saveKnobs()
	t.Cleanup(func() { restoreKnobs(snap) })

	events, bl := tuningFixture(t)

	// Precondition: no CURRENT keyword matches the poweruser role — otherwise
	// this test proves nothing.
	if containsElevatedKeyword("PowerUserAccess") {
		t.Fatal("precondition broken: a built-in keyword already matches PowerUserAccess — pick a different missed role for this test")
	}
	before := privEscActors(events, bl)
	if before["h-poweruser"] {
		t.Fatal("precondition broken: PowerUserAccess grant already fires without tuning")
	}
	if before["g-viewer"] {
		t.Fatal("precondition broken: viewer grant fires without tuning")
	}
	wantFiring := []string{"a-owner", "b-gcp", "c-okta", "d-m365", "e-admin", "f-boundary"}
	for _, a := range wantFiring {
		if !before[a] {
			t.Fatalf("fixture sanity: %s must fire priv-escalation before tuning (got %v)", a, before)
		}
	}

	path := filepath.Join(t.TempDir(), "tuning.yaml")
	if err := os.WriteFile(path, []byte("priv_escalation:\n  extra_elevated_keywords:\n    - poweruser\n"), 0o644); err != nil {
		t.Fatalf("write tuning: %v", err)
	}
	tn, err := LoadTuningFile(path)
	if err != nil {
		t.Fatalf("LoadTuningFile: %v", err)
	}
	ApplyTuning(tn)

	after := privEscActors(events, bl)
	// WIDENED: the missed grant now fires through the REAL Detect path.
	if !after["h-poweruser"] {
		t.Fatalf("PowerUserAccess grant did NOT fire after tuning (fired: %v)", after)
	}
	// NO NARROWING: everything that fired before still fires.
	for _, a := range wantFiring {
		if !after[a] {
			t.Errorf("NARROWING: %s fired before tuning but not after (after: %v)", a, after)
		}
	}
	// The non-elevated grant still does not fire.
	if after["g-viewer"] {
		t.Errorf("viewer grant fires after tuning — the extra keyword leaked beyond its match")
	}
}

// TestTuningUnknownKeyRejected proves the strict-decode gate: an unknown yaml
// key (a typo, or a smuggled non-additive field) is a LOUD load error, never a
// silent no-op.
func TestTuningUnknownKeyRejected(t *testing.T) {
	cases := map[string]string{
		// Typo of extra_elevated_keywords — the exact footgun strict decode catches.
		"typo-field": "priv_escalation:\n  extra_elevated_keyword:\n    - poweruser\n",
		// A hypothetical narrowing field: MUST be inexpressible.
		"narrowing-field": "priv_escalation:\n  remove_elevated_keywords:\n    - admin\n",
		// Unknown top-level section.
		"unknown-section": "priv_escalatoin:\n  extra_elevated_keywords:\n    - poweruser\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tuning.yaml")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatalf("write tuning: %v", err)
			}
			tn, err := LoadTuningFile(path)
			if err == nil {
				t.Fatalf("unknown key accepted silently; got tuning %+v", tn)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error should name the offending file %s; got %v", path, err)
			}
		})
	}
}

// TestTuningParseErrorLoud proves a malformed tuning file is a loud error —
// a corrupt file must never degrade to "partially applied".
func TestTuningParseErrorLoud(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tuning.yaml")
	if err := os.WriteFile(path, []byte("priv_escalation: [unclosed\n\t: garbage"), 0o644); err != nil {
		t.Fatalf("write tuning: %v", err)
	}
	tn, err := LoadTuningFile(path)
	if err == nil {
		t.Fatalf("malformed yaml accepted; got tuning %+v", tn)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("parse error should name the offending file %s; got %v", path, err)
	}
}
