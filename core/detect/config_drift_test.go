package detect

import (
	"encoding/json"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// nestedPayload builds an event payload in the CORPUS/eval-seeder shape: the
// discriminating fields live under payload.metadata (mirrors eventRecord in
// core/eval/scenario_tools.go — every exam scenario's `metadata:` block
// projects this way). This is the shape TestConfigDrift_InfraSubversionClasses
// exercises, because it is the shape the new eval-corpus scenarios
// (exams/scenarios/infra_subversion/) use, and because config_drift.go used to
// silently drop every field in this shape before readConfigPayload's
// payloadMeta fix.
func nestedPayload(t *testing.T, meta map[string]string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"action":   "update",
		"target":   "irrelevant",
		"severity": "info",
		"metadata": meta,
	})
	if err != nil {
		t.Fatalf("marshal nested payload: %v", err)
	}
	return b
}

// flatPayload builds an event payload in the PRODUCTION connector shape: the
// discriminating fields sit flat at the payload root (normalizeEntry's
// contract). readConfigPayload must resolve both shapes identically.
func flatPayload(t *testing.T, fields map[string]string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal flat payload: %v", err)
	}
	return b
}

// TestConfigDrift_InfraSubversionClasses is the direct-unit-level half of
// mallcoppro-192's proof: for each of the 5 infra-subversion classes, the
// DANGEROUS direction/shape fires config-drift and the ROUTINE-AUTHORIZED
// counterpart (same event type, opposite direction) does not — checked
// against BOTH the corpus-nested and production-flat payload shapes so the
// readConfigPayload fix is pinned from both sides. The corpus-level
// regression (TestExamDetect_InfraSubversionCorpus, tuning_exam_regression
// style) additionally proves this through the full exam-detect grader over
// the committed eval-corpus scenarios.
func TestConfigDrift_InfraSubversionClasses(t *testing.T) {
	type tc struct {
		name      string
		eventType string
		nested    map[string]string
		wantFire  bool
		wantSev   string // only checked when wantFire
	}

	cases := []tc{
		// --- disableLocalAuth: weakening (false = local auth re-enabled) fires.
		{
			name:      "disable-local-auth-weakened",
			eventType: "disable_local_auth_change",
			nested: map[string]string{
				"resource_name": "prod-cosmos",
				"config_key":    "disableLocalAuth",
				"old_value":     "true",
				"new_value":     "false",
			},
			wantFire: true,
			wantSev:  "high",
		},
		// --- disableLocalAuth: hardening (true = local auth disabled) is quiet.
		{
			name:      "disable-local-auth-hardened-benign",
			eventType: "disable_local_auth_change",
			nested: map[string]string{
				"resource_name": "prod-cosmos",
				"config_key":    "disableLocalAuth",
				"old_value":     "false",
				"new_value":     "true",
			},
			wantFire: false,
		},
		// --- diagnosticSettings delete: always dangerous (audit-blinding).
		{
			name:      "diagnostic-settings-delete",
			eventType: "diagnostic_settings_delete",
			nested: map[string]string{
				"resource_name": "prod-app-gateway",
			},
			wantFire: true,
			wantSev:  "critical",
		},
		// --- diagnosticSettings update (routine, different event type entirely):
		// config_drift has no rule at all for this type — quiet by construction.
		{
			name:      "diagnostic-settings-update-benign",
			eventType: "diagnostic_settings_update",
			nested: map[string]string{
				"resource_name": "prod-app-gateway",
			},
			wantFire: false,
		},
		// --- DNS zone delete: always dangerous (domain hijack).
		{
			name:      "dns-zone-delete",
			eventType: "dns_zone_delete",
			nested: map[string]string{
				"resource_name": "prod.example.com",
			},
			wantFire: true,
			wantSev:  "critical",
		},
		// --- DNS record change within an existing zone (routine, different type).
		{
			name:      "dns-record-change-benign",
			eventType: "dns_record_change",
			nested: map[string]string{
				"resource_name": "www.prod.example.com",
			},
			wantFire: false,
		},
		// --- Cosmos container delete: always dangerous (store destruction).
		{
			name:      "cosmos-container-delete",
			eventType: "cosmos_container_delete",
			nested: map[string]string{
				"resource_name": "findings-store",
			},
			wantFire: true,
			wantSev:  "critical",
		},
		// --- Cosmos container create (routine, different event type).
		{
			name:      "cosmos-container-create-benign",
			eventType: "cosmos_container_create",
			nested: map[string]string{
				"resource_name": "audit-archive-2026",
			},
			wantFire: false,
		},
		// --- Consistency level weakened: Strong -> Eventual fires.
		{
			name:      "consistency-level-weakened",
			eventType: "consistency_level_change",
			nested: map[string]string{
				"resource_name": "prod-cosmos",
				"old_value":     "Strong",
				"new_value":     "Eventual",
			},
			wantFire: true,
			wantSev:  "high",
		},
		// --- Consistency level strengthened (routine hardening): quiet.
		{
			name:      "consistency-level-strengthened-benign",
			eventType: "consistency_level_change",
			nested: map[string]string{
				"resource_name": "prod-cosmos",
				"old_value":     "Eventual",
				"new_value":     "Session",
			},
			wantFire: false,
		},
		// --- Consistency level unchanged (same value both sides): quiet.
		{
			name:      "consistency-level-unchanged-benign",
			eventType: "consistency_level_change",
			nested: map[string]string{
				"resource_name": "prod-cosmos",
				"old_value":     "Session",
				"new_value":     "Session",
			},
			wantFire: false,
		},
		// --- iam_policy_attach: undocumented policy/permission-surface attach
		// (e.g. the LAW relay's NIP-86 allowpubkey fan-out to an unexpected
		// principal, mallcoppro-956) fires — no approval signal present.
		{
			name:      "iam-policy-attach-undocumented",
			eventType: "iam_policy_attach",
			nested: map[string]string{
				"policy_name": "relay-write-allowlist",
				"target_user": "npub1unexpectedstranger",
			},
			wantFire: true,
			wantSev:  "high",
		},
		// --- iam_policy_attach: documented onboarding (a ticket/approval signal
		// present) is quiet — same event type, approved-grant shape.
		{
			name:      "iam-policy-attach-documented-onboarding-benign",
			eventType: "iam_policy_attach",
			nested: map[string]string{
				"policy_name": "relay-write-allowlist",
				"target_user": "npub1newteammember",
				"ticket":      "ONBOARD-3301",
			},
			wantFire: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name+"/nested", func(t *testing.T) {
			ev := event.Event{
				ID: "cd-" + c.name, Source: "azure", Type: c.eventType,
				Actor: "some-actor", Timestamp: ts(16, 0),
				Payload: nestedPayload(t, c.nested),
			}
			f := configDriftEvaluate(ev, &baseline.Baseline{})
			if c.wantFire && f == nil {
				t.Fatalf("expected config-drift to fire for %s (nested shape), got nil", c.eventType)
			}
			if !c.wantFire && f != nil {
				t.Fatalf("expected config-drift to stay QUIET for %s (nested shape, routine case), got finding: %+v", c.eventType, f)
			}
			if c.wantFire && f.Severity != c.wantSev {
				t.Fatalf("severity = %q, want %q", f.Severity, c.wantSev)
			}
		})

		// Flat-shape mirror: same discriminators, production top-level layout.
		t.Run(c.name+"/flat", func(t *testing.T) {
			ev := event.Event{
				ID: "cd-flat-" + c.name, Source: "azure", Type: c.eventType,
				Actor: "some-actor", Timestamp: ts(16, 0),
				Payload: flatPayload(t, c.nested),
			}
			f := configDriftEvaluate(ev, &baseline.Baseline{})
			if c.wantFire && f == nil {
				t.Fatalf("expected config-drift to fire for %s (flat shape), got nil", c.eventType)
			}
			if !c.wantFire && f != nil {
				t.Fatalf("expected config-drift to stay QUIET for %s (flat shape, routine case), got finding: %+v", c.eventType, f)
			}
		})
	}
}

// TestConsistencyRank pins the strength ordering and the fail-closed behavior
// on unrecognized/empty input (applies must treat "cannot parse" as "does not
// apply", never as "escalate").
func TestConsistencyRank(t *testing.T) {
	cases := []struct {
		level    string
		wantRank int
		wantOK   bool
	}{
		{"Strong", 4, true},
		{"Bounded Staleness", 3, true},
		{"bounded-staleness", 3, true},
		{"Session", 2, true},
		{"Consistent Prefix", 1, true},
		{"eventual", 0, true},
		{"", 0, false},
		{"quantum-consistency", 0, false},
	}
	for _, c := range cases {
		rank, ok := consistencyRank(c.level)
		if ok != c.wantOK || (ok && rank != c.wantRank) {
			t.Errorf("consistencyRank(%q) = (%d, %v), want (%d, %v)", c.level, rank, ok, c.wantRank, c.wantOK)
		}
	}
}
