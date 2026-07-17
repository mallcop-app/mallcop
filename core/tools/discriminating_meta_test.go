// discriminating_meta_test.go — proves the promoted identity fields
// (mallcoppro-37d's search_events coordination item) are in the
// discriminatingMetaKeys allowlist and actually surface through the ordinary
// search_events projection, not just get_raw_event.
package tools

import (
	"encoding/json"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/event"
)

// TestDiscriminatingMetaKeys_IncludesIdentityFields is a direct membership
// check: "caller", "session_name", "source_ip" must be in the allowlist
// search_events' projection consults.
func TestDiscriminatingMetaKeys_IncludesIdentityFields(t *testing.T) {
	want := []string{"caller", "session_name", "source_ip"}
	for _, k := range want {
		found := false
		for _, have := range discriminatingMetaKeys {
			if have == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("discriminatingMetaKeys missing %q; got %v", k, discriminatingMetaKeys)
		}
	}
}

// TestEventViewsFor_SurfacesIdentityMetadata proves the allowlist entries
// actually reach the model-facing EventView.Metadata projection: a promoted
// caller/session_name/source_ip triple under an event's payload.metadata
// shows up in the ordinary search_events view, not just get_raw_event.
func TestEventViewsFor_SurfacesIdentityMetadata(t *testing.T) {
	ev := event.Event{
		ID:     "e-identity",
		Source: "aws",
		Type:   "assume_role",
		Actor:  "forge-proxy",
		Payload: json.RawMessage(`{
			"target": "arn:aws:iam::111122223333:role/forge-proxy",
			"action": "AssumeRole",
			"metadata": {
				"caller": "arn:aws:sts::111122223333:assumed-role/forge-proxy/session-abc",
				"session_name": "session-abc",
				"source_ip": "203.0.113.7"
			}
		}`),
	}

	views := EventViewsFor([]event.Event{ev})
	if len(views) != 1 {
		t.Fatalf("EventViewsFor returned %d views, want 1", len(views))
	}
	got := views[0].Metadata
	want := map[string]string{
		"caller":       "arn:aws:sts::111122223333:assumed-role/forge-proxy/session-abc",
		"session_name": "session-abc",
		"source_ip":    "203.0.113.7",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("Metadata[%q] = %q, want %q", k, got[k], v)
		}
	}
}
