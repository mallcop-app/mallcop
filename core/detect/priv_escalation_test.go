package detect

import (
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// TestContainsElevatedKeyword covers the substring match that lets priv-escalation
// recognize cloud-specific privileged role formats, not just the bare
// "owner"/"admin" GitHub/Azure form. Regression guard for mallcoppro-9dd: the old
// exact map lookup silently missed GCP "roles/owner" and Okta "Super Admin".
func TestContainsElevatedKeyword(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{"owner", true},                 // Azure / GitHub bare form (exact, still works)
		{"admin", true},                 //
		{"roles/owner", true},           // GCP — missed by the old exact match
		{"roles/editor", true},          // GCP primitive: broad write (GAP-1)
		{"Super Admin", true},           // Okta — missed by old exact match (case-insensitive)
		{"Org Administrator", true},     // contains "admin"
		{"Sites.FullControl.All", true}, // M365 Graph app role (GAP-2)
		{"write", true},                 // a write grant is elevated
		{"viewer", false},
		{"readonly", false},
		{"roles/viewer", false},
		{"", false},
	}
	for _, c := range cases {
		if got := containsElevatedKeyword(c.role); got != c.want {
			t.Errorf("containsElevatedKeyword(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

// TestPrivEscalationFiresOnCloudRoles proves the detector FIRES and marks critical
// on GCP- and Okta-format privileged role grants, exercised through the real
// Detect path. Before the substring fix these produced no priv-escalation finding
// even though the connector emitted the correct role_assignment Type + payload.
func TestPrivEscalationFiresOnCloudRoles(t *testing.T) {
	cases := []struct {
		name, source, actor, role, wantSev string
	}{
		{"gcp-roles-owner", "gcp", "deployer", "roles/owner", "critical"},
		{"okta-super-admin", "okta", "rogue", "Super Admin", "critical"},
		{"gcp-roles-editor", "gcp", "deployer2", "roles/editor", "high"},       // GAP-1: broad write, not owner/admin → high
		{"m365-fullcontrol", "m365", "appsp", "Sites.FullControl.All", "high"}, // GAP-2
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bl := &baseline.Baseline{
				KnownActors: []string{c.actor}, // suppress new-actor so we isolate priv-escalation
				ActorRoles:  map[string][]string{c.actor: {"viewer"}},
			}
			ev := event.Event{
				ID: "pe-" + c.name, Source: c.source, Type: "role_assignment",
				Actor: c.actor, Timestamp: ts(16, 8),
				Payload: raw(t, map[string]string{
					"role_name":   c.role,
					"target_user": "victim",
				}),
			}
			found := false
			var sev string
			for _, f := range Detect([]event.Event{ev}, bl) {
				if f.Type == "priv-escalation" {
					found, sev = true, f.Severity
				}
			}
			if !found {
				t.Fatalf("priv-escalation did NOT fire on %s role %q", c.source, c.role)
			}
			if sev != c.wantSev {
				t.Errorf("priv-escalation severity = %q, want %q (role %q)", sev, c.wantSev, c.role)
			}
		})
	}
}
