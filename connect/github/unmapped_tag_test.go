package github

import (
	"encoding/json"
	"testing"
)

// TestUnmappedActionTagged proves the connector writes the "unmapped_action"
// mapping-gap tag into the flat payload EXACTLY when an action falls through to
// the "github_other" default bucket — and never on a classified event. This is
// the feedstock the offline core/collect.UnmappedActions collector mines.
func TestUnmappedActionTagged(t *testing.T) {
	readTag := func(payload json.RawMessage) (string, bool) {
		var pl struct {
			UnmappedAction string `json:"unmapped_action"`
		}
		if err := json.Unmarshal(payload, &pl); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		return pl.UnmappedAction, pl.UnmappedAction != ""
	}

	// (a) An audit action with no classifier match → github_other + tagged.
	unmappedAudit := `{"action":"repo.transfer","actor":"mallory","org":"acme","repo":"acme/x","@timestamp":1700000000000}`
	ev, ok := normalizeAuditEntry(json.RawMessage(unmappedAudit), "acme", nil)
	if !ok {
		t.Fatal("normalizeAuditEntry ok=false")
	}
	if ev.Type != defaultEventTy {
		t.Fatalf("want default bucket %q, got %q", defaultEventTy, ev.Type)
	}
	if tag, tagged := readTag(ev.Payload); !tagged || tag != "repo.transfer" {
		t.Fatalf("unmapped audit: want unmapped_action=repo.transfer, got %q (tagged=%v)", tag, tagged)
	}

	// (b) A CLASSIFIED audit action (git.push → push) must NOT carry the tag.
	mappedAudit := `{"action":"git.push","actor":"dev","org":"acme","repo":"acme/x","@timestamp":1700000000000}`
	ev, ok = normalizeAuditEntry(json.RawMessage(mappedAudit), "acme", nil)
	if !ok {
		t.Fatal("normalizeAuditEntry ok=false for mapped")
	}
	if ev.Type != "push" {
		t.Fatalf("want push, got %q", ev.Type)
	}
	if tag, tagged := readTag(ev.Payload); tagged {
		t.Fatalf("classified event must not carry unmapped_action, got %q", tag)
	}

	// (c) An events-feed event of an unknown type → github_other + tagged with the
	// GitHub event "type".
	unmappedEvt := `{"id":"1","type":"GollumEvent","created_at":"2023-11-14T00:00:00Z","actor":{"login":"mallory"},"repo":{"name":"acme/x"},"payload":{}}`
	ev, ok = normalizeEvent(json.RawMessage(unmappedEvt), "acme", nil)
	if !ok {
		t.Fatal("normalizeEvent ok=false")
	}
	if ev.Type != defaultEventTy {
		t.Fatalf("want default bucket %q, got %q", defaultEventTy, ev.Type)
	}
	if tag, tagged := readTag(ev.Payload); !tagged || tag != "GollumEvent" {
		t.Fatalf("unmapped event: want unmapped_action=GollumEvent, got %q (tagged=%v)", tag, tagged)
	}

	// (d) A CLASSIFIED events-feed event (PushEvent → push) must NOT carry the tag.
	mappedEvt := `{"id":"2","type":"PushEvent","created_at":"2023-11-14T00:00:00Z","actor":{"login":"dev"},"repo":{"name":"acme/x"},"payload":{}}`
	ev, ok = normalizeEvent(json.RawMessage(mappedEvt), "acme", nil)
	if !ok {
		t.Fatal("normalizeEvent ok=false for mapped")
	}
	if ev.Type != "push" {
		t.Fatalf("want push, got %q", ev.Type)
	}
	if tag, tagged := readTag(ev.Payload); tagged {
		t.Fatalf("classified event must not carry unmapped_action, got %q", tag)
	}
}
