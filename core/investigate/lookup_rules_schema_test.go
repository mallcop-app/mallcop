package investigate

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mallcop-app/mallcop/core/tools"
)

// corpusRepoRoot resolves the repo root (where agents/rules/operator-decisions.yaml
// lives) from this test file's location — the same trick core/tools' repoRoot uses.
func corpusRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

// TestLookupRulesSchemaExposesMetadataPredicates guards the mallcoppro-118 fix:
// the lookup_rules tool schema advertised to the chat model must expose every
// metadata predicate field the handler (tools.LookupRulesInput) accepts, or a
// rule with a metadata_match block is unreachable via chat because the model
// never sees the field to populate it.
func TestLookupRulesSchemaExposesMetadataPredicates(t *testing.T) {
	// The flat predicate fields ExecuteTool unmarshals into LookupRulesInput.
	// Keep in sync with core/tools/lookup_rules.go's LookupRulesInput json tags.
	wantFields := []string{
		"finding_id", "finding_family",
		"maintenance_window", "scheduled", "resolution_event", "location_change",
		"automation_provenance", "deploy_release", "sensitive_bulk_read",
		"hr_provisioning", "scenario_pattern", "actor_role",
	}

	var props map[string]any
	for _, td := range ToolDefs() {
		if td.Name != "lookup_rules" {
			continue
		}
		schema, ok := td.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("lookup_rules InputSchema is %T, want map[string]any", td.InputSchema)
		}
		props, ok = schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("lookup_rules schema properties is %T, want map[string]any", schema["properties"])
		}
	}
	if props == nil {
		t.Fatal("no lookup_rules tool in ToolDefs()")
	}
	for _, f := range wantFields {
		if _, present := props[f]; !present {
			t.Errorf("lookup_rules schema is missing predicate field %q — metadata_match rules using it are unreachable via chat", f)
		}
	}
}

// TestLookupRulesMetadataPredicateReachable proves end to end (through
// ExecuteTool, the exact path the chat loop uses) that supplying a metadata
// predicate now surfaces a rule that has a metadata_match block, and that the
// predicate is load-bearing: without it, the rule does not match.
func TestLookupRulesMetadataPredicateReachable(t *testing.T) {
	opts := Options{RepoRoot: corpusRepoRoot(t)}

	// R-001 (family unusual-timing) requires metadata_match maintenance_window="true".
	withPredicate, err := ExecuteTool(opts, "lookup_rules", map[string]any{
		"finding_id":         "f-1",
		"finding_family":     "unusual-timing",
		"maintenance_window": "true",
	})
	if err != nil {
		t.Fatalf("lookup_rules with predicate: %v", err)
	}
	out, ok := withPredicate.(tools.LookupRulesOutput)
	if !ok {
		t.Fatalf("result is %T, want tools.LookupRulesOutput", withPredicate)
	}
	if !containsRule(out, "R-001") {
		t.Fatalf("R-001 not returned when maintenance_window=true supplied; got %+v", ruleIDs(out))
	}

	// Without the predicate, R-001's metadata_match fails → not returned.
	without, err := ExecuteTool(opts, "lookup_rules", map[string]any{
		"finding_id":     "f-1",
		"finding_family": "unusual-timing",
	})
	if err != nil {
		t.Fatalf("lookup_rules without predicate: %v", err)
	}
	outNoPred := without.(tools.LookupRulesOutput)
	if containsRule(outNoPred, "R-001") {
		t.Errorf("R-001 returned WITHOUT maintenance_window — the metadata predicate is not load-bearing; got %+v", ruleIDs(outNoPred))
	}
}

func containsRule(out tools.LookupRulesOutput, id string) bool {
	for _, r := range out.Rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

func ruleIDs(out tools.LookupRulesOutput) []string {
	ids := make([]string, 0, len(out.Rules))
	for _, r := range out.Rules {
		ids = append(ids, r.ID)
	}
	return ids
}
