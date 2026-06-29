// observe_test.go — unit tests for the SHARED observable predicates, moved here
// from core/eval/scenario_tools_test.go when the predicates were extracted. They
// reference the package-internal helper relationshipCountFor directly, so they
// must live in this package. Their PASSING UNCHANGED is the proof that the
// extraction preserved behavior byte-for-byte: the same assertions that guarded
// the eval-internal helper now guard the shared free function, with identical
// inputs and identical expected outputs.
package observe

import (
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
)

// TestRelationshipCountFor_GroupCreditDiscriminator unit-tests the predicate core:
// an EXPLICIT established group-level relationship covers a sibling leaf; a LEAF-only
// relationship in the same group does NOT grant group-wide credit; a below-floor
// group touch does NOT; and a sibling resource group the actor never touched is NOT
// covered.
func TestRelationshipCountFor_GroupCreditDiscriminator(t *testing.T) {
	const grp = "sub-1/resourcegroups/atom-rg"
	const newLeaf = "sub-1/resourcegroups/atom-rg/flexibleservers/atom-db-staging"
	const foreignLeaf = "sub-1/resourcegroups/other-rg/flexibleservers/x"

	mk := func(entries map[string]int) map[string]baseline.Relationship {
		m := map[string]baseline.Relationship{}
		for k, v := range entries {
			m[k] = baseline.Relationship{Count: v}
		}
		return m
	}

	// Established group-level relationship → covers the new sibling leaf.
	if got := relationshipCountFor(mk(map[string]int{"infra-admin:" + grp: 892}), "infra-admin", newLeaf); got != 892 {
		t.Fatalf("established group relationship must cover a sibling leaf; got %d want 892", got)
	}
	// Leaf-only relationships in the same group → NO group-wide credit for a NEW leaf.
	leafOnly := mk(map[string]int{
		"ci-bot:sub-1/resourcegroups/atom-rg/containerapps/atom-api": 380,
		"ci-bot:sub-1/resourcegroups/atom-rg/containerapps/atom-bot": 280,
	})
	if got := relationshipCountFor(leafOnly, "ci-bot", newLeaf); got != 0 {
		t.Fatalf("leaf-only history must NOT grant group-wide credit (lateral movement); got %d want 0", got)
	}
	// Below-floor group touch → not established → no credit.
	if got := relationshipCountFor(mk(map[string]int{"x:" + grp: 3}), "x", newLeaf); got != 0 {
		t.Fatalf("a below-floor group touch must not manufacture group trust; got %d want 0", got)
	}
	// Established group relationship does not cover a DIFFERENT group's resource.
	if got := relationshipCountFor(mk(map[string]int{"infra-admin:" + grp: 892}), "infra-admin", foreignLeaf); got != 0 {
		t.Fatalf("group credit must not cross into a group the actor never touched; got %d want 0", got)
	}
}
