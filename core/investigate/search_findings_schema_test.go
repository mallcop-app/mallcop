package investigate

import "testing"

// TestSearchFindingsSchemaExposesTypeAndIDs guards the mallcoppro-a8b fix: the
// search_findings tool schema advertised to the chat model must expose every
// filter the handler (tools.SearchFindingsInput) accepts. Before the fix the
// schema advertised only actor/source/since, so a model that (correctly) scoped
// a finding lookup with {"type":"forge"} or {"ids":[<on-screen id>]} had those
// unknown keys silently dropped by the JSON decoder and got the ENTIRE findings
// stream back — the 2000+-finding "garbage" result the live analyst punted on.
// Keep wantFields in sync with core/tools/search_findings.go SearchFindingsInput.
func TestSearchFindingsSchemaExposesTypeAndIDs(t *testing.T) {
	wantFields := []string{"actor", "source", "type", "ids", "since"}

	var props map[string]any
	for _, td := range ToolDefs() {
		if td.Name != "search_findings" {
			continue
		}
		schema, ok := td.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("search_findings InputSchema is %T, want map[string]any", td.InputSchema)
		}
		props, ok = schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("search_findings schema properties is %T, want map[string]any", schema["properties"])
		}
	}
	if props == nil {
		t.Fatal("no search_findings tool in ToolDefs()")
	}
	for _, f := range wantFields {
		if _, present := props[f]; !present {
			t.Errorf("search_findings schema is missing filter %q — a model cannot scope by it, so an unknown key is dropped and the whole stream returns (mallcoppro-a8b)", f)
		}
	}
}
