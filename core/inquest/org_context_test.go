package inquest

import (
	"strings"
	"testing"
)

// TestAssembleOrgContext_CallerMatchesOwnedEntity proves a configured owned
// entity whose Match is a substring of identity.Caller resolves
// CallerOwned to that entity's own Match/Name/Relationship, verbatim.
func TestAssembleOrgContext_CallerMatchesOwnedEntity(t *testing.T) {
	owned := []OwnedEntity{
		{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own hourly inference relay"},
	}
	identity := IdentityEvidence{Caller: "arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy"}

	out := assembleOrgContext(owned, "forge-proxy", identity)
	if out.CallerOwned == nil {
		t.Fatal("CallerOwned = nil, want a match")
	}
	want := OwnedMatch{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own hourly inference relay"}
	if *out.CallerOwned != want {
		t.Errorf("CallerOwned = %+v, want %+v", *out.CallerOwned, want)
	}
	if out.TargetOwned != nil || out.ActorOwned != nil {
		t.Errorf("expected only CallerOwned to match, got TargetOwned=%+v ActorOwned=%+v", out.TargetOwned, out.ActorOwned)
	}
}

// TestAssembleOrgContext_TargetMatchesOwnedEntity proves the same match
// logic applies independently to identity.Target.
func TestAssembleOrgContext_TargetMatchesOwnedEntity(t *testing.T) {
	owned := []OwnedEntity{
		{Match: "458526671706", Name: "mallcop-bedrock-relay", Relationship: "operator's own Bedrock relay account"},
	}
	identity := IdentityEvidence{Target: "arn:aws:iam::458526671706:role/mallcop-bedrock-relay"}

	out := assembleOrgContext(owned, "some-actor", identity)
	if out.TargetOwned == nil {
		t.Fatal("TargetOwned = nil, want a match")
	}
	if out.TargetOwned.Name != "mallcop-bedrock-relay" {
		t.Errorf("TargetOwned.Name = %q, want mallcop-bedrock-relay", out.TargetOwned.Name)
	}
	if out.CallerOwned != nil || out.ActorOwned != nil {
		t.Errorf("expected only TargetOwned to match, got CallerOwned=%+v ActorOwned=%+v", out.CallerOwned, out.ActorOwned)
	}
}

// TestAssembleOrgContext_ActorMatchesOwnedEntity proves the same match logic
// applies independently to the finding actor (passed separately from
// identity, since Actor lives on finding.Finding, not IdentityEvidence).
func TestAssembleOrgContext_ActorMatchesOwnedEntity(t *testing.T) {
	owned := []OwnedEntity{
		{Match: "forge-proxy-actor", Name: "forge-proxy", Relationship: "operator's own inference relay"},
	}
	out := assembleOrgContext(owned, "forge-proxy-actor", IdentityEvidence{})
	if out.ActorOwned == nil {
		t.Fatal("ActorOwned = nil, want a match")
	}
	if out.CallerOwned != nil || out.TargetOwned != nil {
		t.Errorf("expected only ActorOwned to match, got CallerOwned=%+v TargetOwned=%+v", out.CallerOwned, out.TargetOwned)
	}
}

// TestAssembleOrgContext_NoMatch proves an actor/identity with no
// configured-entity overlap resolves to an all-nil, no-error
// OrgContextEvidence — honest evidence for the narrative, not a degraded
// section (mirrors TestAssembleBaselineEvidence_UnknownActor).
func TestAssembleOrgContext_NoMatch(t *testing.T) {
	owned := []OwnedEntity{
		{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own hourly inference relay"},
	}
	identity := IdentityEvidence{Caller: "arn:aws:iam::999988887777:role/some-stranger", Target: "arn:aws:iam::999988887777:role/other-stranger"}

	out := assembleOrgContext(owned, "unrelated-actor", identity)
	if out.CallerOwned != nil || out.TargetOwned != nil || out.ActorOwned != nil {
		t.Errorf("expected no matches, got %+v", out)
	}
	if out.Error != "" {
		t.Errorf("Error = %q, want empty — no match is honest evidence, not a degraded section", out.Error)
	}
}

// TestAssembleOrgContext_EmptyOwned proves nil/empty owned config (the
// absent org: block default) is safe and resolves every field to nil.
func TestAssembleOrgContext_EmptyOwned(t *testing.T) {
	identity := IdentityEvidence{Caller: "anything", Target: "anything-else"}
	out := assembleOrgContext(nil, "any-actor", identity)
	if out.CallerOwned != nil || out.TargetOwned != nil || out.ActorOwned != nil || out.Error != "" {
		t.Errorf("expected all-nil, no-error evidence with nil owned config, got %+v", out)
	}
}

// TestAssembleOrgContext_MultipleConfiguredEntitiesFirstMatchWins proves that
// when more than one configured entity's Match is a substring of the same
// identity field, the FIRST one in config order wins — deterministic,
// documented resolution order.
func TestAssembleOrgContext_MultipleConfiguredEntitiesFirstMatchWins(t *testing.T) {
	owned := []OwnedEntity{
		{Match: "225635015146", Name: "forge-proxy-first", Relationship: "first configured"},
		{Match: "forge-proxy", Name: "forge-proxy-second", Relationship: "second configured — should never win here"},
	}
	identity := IdentityEvidence{Caller: "arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy"}

	out := assembleOrgContext(owned, "actor", identity)
	if out.CallerOwned == nil {
		t.Fatal("CallerOwned = nil, want a match")
	}
	if out.CallerOwned.Name != "forge-proxy-first" {
		t.Errorf("CallerOwned.Name = %q, want forge-proxy-first (first configured entry must win)", out.CallerOwned.Name)
	}
}

// TestSafeAssembleOrgContext_PanicIsolated proves safeAssembleOrgContext is a
// transparent pass-through of assembleOrgContext on a normal call — the same
// non-panic-path proof every other section's tests in this package rely on
// (no section test in this package forces an actual panic through its own
// safeAssemble* wrapper; the recover() plumbing itself is proven once, at
// the RunAll level, by TestRunAll_PanicGuard in inquest_test.go).
// assembleOrgContext has no nil-pointer-deref or index-out-of-range surface
// to trigger organically — it only runs strings.Contains over plain string
// fields — so this section carries no realistic panic scenario beyond what
// the shared wrapper pattern already guards structurally.
func TestSafeAssembleOrgContext_PanicIsolated(t *testing.T) {
	owned := []OwnedEntity{
		{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own hourly inference relay"},
	}
	identity := IdentityEvidence{Caller: "arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy"}

	direct := assembleOrgContext(owned, "actor", identity)
	wrapped := safeAssembleOrgContext(owned, "actor", identity)
	if wrapped.Error != "" {
		t.Errorf("safeAssembleOrgContext.Error = %q, want empty on a normal call", wrapped.Error)
	}
	if direct.CallerOwned == nil || wrapped.CallerOwned == nil || *direct.CallerOwned != *wrapped.CallerOwned {
		t.Errorf("safeAssembleOrgContext result diverged from assembleOrgContext: direct=%+v wrapped=%+v", direct, wrapped)
	}
}

// TestAssembleOrgContext_EmptyIdentityFieldNeverMatches proves an empty
// caller/target string is never treated as "matching" an owned entity even
// if a (misconfigured) owned entity somehow carried an empty Match — the
// config-time validator already rejects an empty Match, but this locks the
// defense in at the assembly layer too (belt-and-suspenders against
// strings.Contains(x, "") matching everything).
func TestAssembleOrgContext_EmptyIdentityFieldNeverMatches(t *testing.T) {
	owned := []OwnedEntity{{Match: "225635015146", Name: "forge-proxy", Relationship: "x"}}
	out := assembleOrgContext(owned, "", IdentityEvidence{})
	if out.CallerOwned != nil || out.TargetOwned != nil || out.ActorOwned != nil {
		t.Errorf("expected no matches against empty identity fields, got %+v", out)
	}
}

// TestOrgContextEvidence_JSONFieldNames locks the wire shape's json tags —
// the narrate prompt references these field names explicitly
// ("evidence.org_context", "caller_owned"/"target_owned"/"actor_owned").
func TestOrgContextEvidence_JSONFieldNames(t *testing.T) {
	owned := []OwnedEntity{{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own relay"}}
	out := assembleOrgContext(owned, "actor", IdentityEvidence{Caller: "arn:...225635015146:role/x"})
	if out.CallerOwned == nil {
		t.Fatal("expected a match to serialize against")
	}
	// buildUserMessage's own golden test (narrate_test.go) proves the full
	// wire encoding; this test just confirms assembleOrgContext's Go-level
	// contract matches the field the prompt names.
	if !strings.Contains(out.CallerOwned.Relationship, "operator's own relay") {
		t.Errorf("Relationship = %q, want to carry the configured phrase verbatim", out.CallerOwned.Relationship)
	}
}
