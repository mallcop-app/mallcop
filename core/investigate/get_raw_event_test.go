// get_raw_event_test.go — proves the investigate loop actually advertises
// get_raw_event to the model and routes a tool_use for it to
// tools.GetRawEvent (mallcoppro-37d).
package investigate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/tools"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// TestToolDefs_IncludesGetRawEvent proves ToolDefs() actually advertises
// get_raw_event — a model never told a tool exists can never call it.
func TestToolDefs_IncludesGetRawEvent(t *testing.T) {
	defs := ToolDefs()
	var found *struct {
		hasIDProp bool
		required  []string
	}
	for _, d := range defs {
		if d.Name != "get_raw_event" {
			continue
		}
		schema, ok := d.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("get_raw_event InputSchema is not a map[string]any: %T", d.InputSchema)
		}
		props, _ := schema["properties"].(map[string]any)
		_, hasID := props["id"]
		req, _ := schema["required"].([]string)
		found = &struct {
			hasIDProp bool
			required  []string
		}{hasIDProp: hasID, required: req}
	}
	if found == nil {
		t.Fatalf("ToolDefs() does not include get_raw_event; got tool names: %v", toolNames(defs))
	}
	if !found.hasIDProp {
		t.Error("get_raw_event InputSchema.properties has no \"id\" field")
	}
	if len(found.required) != 1 || found.required[0] != "id" {
		t.Errorf("get_raw_event InputSchema.required = %v, want [\"id\"]", found.required)
	}
}

// TestExecuteTool_DispatchesGetRawEvent proves ExecuteTool routes a
// "get_raw_event" tool_use to tools.GetRawEvent against the REAL store and
// returns the full raw payload (the provenance fields search_events never
// projects) via the SAME dispatch path the model-driven loop uses.
func TestExecuteTool_DispatchesGetRawEvent(t *testing.T) {
	dir := initRepo(t)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	ev := event.Event{
		ID:        "cafe1234",
		Source:    "aws",
		Type:      "assume_role",
		Actor:     "forge-proxy",
		Timestamp: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		Payload: json.RawMessage(`{
			"sourceIPAddress": "203.0.113.7",
			"userIdentity": {"arn": "arn:aws:sts::111122223333:assumed-role/forge-proxy/session-abc"},
			"requestParameters": {"roleSessionName": "session-abc"}
		}`),
	}
	if _, err := st.Append(store.KindEvents, ev); err != nil {
		t.Fatalf("append event: %v", err)
	}

	out, err := ExecuteTool(Options{Store: st}, "get_raw_event", map[string]any{"id": "finding-cafe1234"})
	if err != nil {
		t.Fatalf("ExecuteTool(get_raw_event) returned error: %v", err)
	}
	res, ok := out.(tools.GetRawEventOutput)
	if !ok {
		t.Fatalf("ExecuteTool(get_raw_event) returned %T, want tools.GetRawEventOutput", out)
	}
	if !res.Found {
		t.Fatal("Found = false, want true (id leniency should strip the finding- prefix)")
	}
	if res.ID != "cafe1234" {
		t.Errorf("ID = %q, want the stored event id %q", res.ID, "cafe1234")
	}

	var decoded map[string]any
	if err := json.Unmarshal(res.Payload, &decoded); err != nil {
		t.Fatalf("Payload is not valid JSON: %v", err)
	}
	if decoded["sourceIPAddress"] != "203.0.113.7" {
		t.Errorf("sourceIPAddress = %v, want 203.0.113.7 (the raw provenance field get_raw_event exists to expose)", decoded["sourceIPAddress"])
	}
}
