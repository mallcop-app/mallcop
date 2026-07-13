package baseline

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/event"
)

// ev is a terse event constructor for the Build tests.
func ev(id, source, typ, actor string, ts time.Time, payload map[string]any) event.Event {
	pb, _ := json.Marshal(payload)
	return event.Event{ID: id, Source: source, Type: typ, Actor: actor, Timestamp: ts, Payload: pb}
}

// TestBuild_PopulatesDetectorFields checks Build populates exactly the fields the
// baseline-dependent detectors read, from a fixed event set.
func TestBuild_PopulatesDetectorFields(t *testing.T) {
	utc := time.UTC
	events := []event.Event{
		// alice: two api_requests at hours 9 and 10 on github.
		ev("e1", "github", "api_request", "alice", time.Date(2026, 6, 18, 9, 0, 0, 0, utc), map[string]any{"note": "x"}),
		ev("e2", "github", "api_request", "alice", time.Date(2026, 6, 18, 10, 30, 0, 0, utc), map[string]any{"note": "y"}),
		// alice: an explicit role grant (nested metadata shape) + a flat permission.
		ev("e3", "github", "role_assignment", "alice", time.Date(2026, 6, 18, 9, 15, 0, 0, utc), map[string]any{
			"metadata": map[string]any{"role": "Admin"},
		}),
		ev("e4", "github", "permission_change", "alice", time.Date(2026, 6, 18, 9, 20, 0, 0, utc), map[string]any{
			"permission": "write",
		}),
		// bob: a login carrying ip + geo at hour 22 on okta.
		ev("e5", "okta", "login", "bob", time.Date(2026, 6, 18, 22, 5, 0, 0, utc), map[string]any{
			"metadata": map[string]any{"ip": "1.2.3.4", "geo": "US"},
		}),
	}

	b := Build(events)

	// KnownActors — distinct, sorted.
	if got, want := b.KnownActors, []string{"alice", "bob"}; !reflect.DeepEqual(got, want) {
		t.Errorf("KnownActors = %v, want %v", got, want)
	}

	// FrequencyTables — 3-segment "source:event_type:actor" counts.
	wantFreq := map[string]int{
		"github:api_request:alice":       2,
		"github:role_assignment:alice":   1,
		"github:permission_change:alice": 1,
		"okta:login:bob":                 1,
	}
	if !reflect.DeepEqual(b.FrequencyTables, wantFreq) {
		t.Errorf("FrequencyTables = %v, want %v", b.FrequencyTables, wantFreq)
	}
	// The volume-anomaly reader agrees with the raw table.
	if got := b.FreqCountActor("github", "api_request", "alice"); got != 2 {
		t.Errorf("FreqCountActor(github,api_request,alice) = %d, want 2", got)
	}

	// ActorHours — sorted distinct UTC hours.
	if got, want := b.ActorHours["alice"], []int{9, 10}; !reflect.DeepEqual(got, want) {
		t.Errorf("ActorHours[alice] = %v, want %v", got, want)
	}
	if got, want := b.ActorHours["bob"], []int{22}; !reflect.DeepEqual(got, want) {
		t.Errorf("ActorHours[bob] = %v, want %v", got, want)
	}
	if !b.HasActorHours() || !b.KnownHour("alice", 9) || b.KnownHour("alice", 3) {
		t.Errorf("ActorHours reader disagrees: HasActorHours=%v knownHour9=%v knownHour3=%v",
			b.HasActorHours(), b.KnownHour("alice", 9), b.KnownHour("alice", 3))
	}

	// ActorRoles — lower-cased, sorted, EXPLICIT role + permission only.
	if got, want := b.ActorRoles["alice"], []string{"admin", "write"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ActorRoles[alice] = %v, want %v", got, want)
	}
	if !b.IsKnownRole("alice", "admin") || b.IsKnownRole("alice", "owner") {
		t.Errorf("IsKnownRole reader disagrees: admin=%v owner=%v",
			b.IsKnownRole("alice", "admin"), b.IsKnownRole("alice", "owner"))
	}

	// KnownUsers — built from the login; ip/geo captured; last-seen set.
	bob, ok := b.KnownUsers["bob"]
	if !ok {
		t.Fatalf("KnownUsers has no bob; got %v", b.KnownUsers)
	}
	if !reflect.DeepEqual(bob.KnownIPs, []string{"1.2.3.4"}) || !reflect.DeepEqual(bob.KnownGeos, []string{"US"}) {
		t.Errorf("bob profile = {ips=%v geos=%v}, want {[1.2.3.4] [US]}", bob.KnownIPs, bob.KnownGeos)
	}
	if bob.LastSeen.IsZero() {
		t.Errorf("bob LastSeen is zero, want the login timestamp")
	}
	if _, ok := b.KnownUsers["alice"]; ok {
		t.Errorf("alice has no login → must NOT be in KnownUsers, but is")
	}
	// unusual-login readers agree.
	if !b.HasUser("bob") || !b.HasLoginProfile("bob") || !b.KnownIP("bob", "1.2.3.4") || !b.KnownGeo("bob", "US") {
		t.Errorf("unusual-login readers disagree for bob")
	}
}

// TestBuild_Deterministic proves the same event set yields byte-identical JSON
// regardless of input ordering — the persisted KindBaseline snapshot is reproducible.
func TestBuild_Deterministic(t *testing.T) {
	utc := time.UTC
	events := []event.Event{
		ev("e1", "github", "api_request", "bob", time.Date(2026, 6, 18, 11, 0, 0, 0, utc), map[string]any{"n": 1}),
		ev("e2", "aws", "api_request", "alice", time.Date(2026, 6, 18, 9, 0, 0, 0, utc), map[string]any{"n": 2}),
		ev("e3", "github", "login", "carol", time.Date(2026, 6, 18, 3, 0, 0, 0, utc), map[string]any{
			"metadata": map[string]any{"ip": "9.9.9.9"},
		}),
	}
	reordered := []event.Event{events[2], events[0], events[1]}

	a, _ := json.Marshal(Build(events))
	b, _ := json.Marshal(Build(reordered))
	if string(a) != string(b) {
		t.Errorf("Build is not deterministic:\n a=%s\n b=%s", a, b)
	}
}

// TestBuild_EntityCreationBaselinesCreatedPrincipal proves a principal NAMED in an
// entity-creation event is baselined as a KNOWN actor even though it never authors
// an event — otherwise new-actor's createdEntityEvaluate re-flags it every scan.
func TestBuild_EntityCreationBaselinesCreatedPrincipal(t *testing.T) {
	utc := time.UTC
	events := []event.Event{
		ev("e1", "azure", "service_principal_created", "admin", time.Date(2026, 6, 18, 9, 0, 0, 0, utc),
			map[string]any{"metadata": map[string]any{"display_name": "deploy-svc-new"}}),
	}
	b := Build(events)
	if !b.IsKnownActor("admin") {
		t.Errorf("performing actor admin not baselined")
	}
	if !b.IsKnownActor("deploy-svc-new") {
		t.Errorf("created principal deploy-svc-new not baselined; KnownActors=%v", b.KnownActors)
	}
	// The created principal also enters KnownCreatedEntities (the created-entity gate)
	// so a repeat scan of the same creation is suppressed.
	if !b.IsKnownCreatedEntity("deploy-svc-new") {
		t.Errorf("created principal deploy-svc-new not in KnownCreatedEntities; got %v", b.KnownCreatedEntities)
	}
}

// TestBuild_CreatedEntityDistinctFromKnownActor proves KnownCreatedEntities and
// KnownActors are SEPARATE (the fix for the created-principal name-collision false
// negative). A plain actor that was never CREATED must NOT be a known created
// entity — otherwise creating a backdoor principal named after an existing actor
// would be silently gated on first sight.
func TestBuild_CreatedEntityDistinctFromKnownActor(t *testing.T) {
	utc := time.UTC
	events := []event.Event{
		// realuser is only ever an ACTOR — never created.
		ev("e1", "github", "api_request", "realuser", time.Date(2026, 6, 18, 9, 0, 0, 0, utc), map[string]any{"n": 1}),
		// admin CREATES a distinct principal "backdoor".
		ev("e2", "azure", "service_principal_created", "admin", time.Date(2026, 6, 18, 9, 5, 0, 0, utc),
			map[string]any{"metadata": map[string]any{"display_name": "backdoor"}}),
	}
	b := Build(events)

	// realuser is a known actor but NOT a known created entity.
	if !b.IsKnownActor("realuser") {
		t.Errorf("realuser should be a known actor")
	}
	if b.IsKnownCreatedEntity("realuser") {
		t.Errorf("realuser was never CREATED — must not be a known created entity (name-collision gate would suppress a real backdoor)")
	}
	// backdoor is both a known created entity (gate for repeat creations) AND a known
	// actor (so its later activity does not churn new-actor).
	if !b.IsKnownCreatedEntity("backdoor") {
		t.Errorf("backdoor creation not recorded in KnownCreatedEntities; got %v", b.KnownCreatedEntities)
	}
	if !b.IsKnownActor("backdoor") {
		t.Errorf("created principal backdoor should also be a known actor (actor-novelty gate); KnownActors=%v", b.KnownActors)
	}
}

// TestBuild_EmptyCorpus proves an empty event set yields an empty (all-unknown)
// baseline — the first-scan case where every actor must fire.
func TestBuild_EmptyCorpus(t *testing.T) {
	b := Build(nil)
	if b == nil {
		t.Fatal("Build(nil) returned nil, want empty baseline")
	}
	if b.IsKnownActor("anyone") || b.HasActorHours() || len(b.KnownUsers) != 0 {
		t.Errorf("empty-corpus baseline is not empty: %+v", b)
	}
}

// --- Merge (mallcoppro-9e2: store-rotation baseline persistence) --------------

// TestMerge_NilReceiverAndArgument proves Merge treats a nil receiver and/or a
// nil argument as an empty baseline rather than panicking — the store-rotation
// caller passes a nil lastPersisted on a store's very first derived scan.
func TestMerge_NilReceiverAndArgument(t *testing.T) {
	var nilB *Baseline
	other := &Baseline{KnownActors: []string{"alice"}}

	got := nilB.Merge(other)
	if !got.IsKnownActor("alice") {
		t.Errorf("nil.Merge(other) lost other's data: %+v", got)
	}

	got2 := other.Merge(nil)
	if !got2.IsKnownActor("alice") {
		t.Errorf("other.Merge(nil) lost receiver's data: %+v", got2)
	}

	got3 := nilB.Merge(nil)
	if got3 == nil || got3.IsKnownActor("anyone") {
		t.Errorf("nil.Merge(nil) = %+v, want a non-nil empty baseline", got3)
	}
}

// TestMerge_UnionsSetValuedFields proves KnownActors, KnownCreatedEntities,
// ActorHours, and ActorRoles are the UNION of both inputs — the property the
// store-rotation fix depends on: an actor/hour/role known on EITHER side of a
// rotation stays known in the merged result.
func TestMerge_UnionsSetValuedFields(t *testing.T) {
	a := &Baseline{
		KnownActors:          []string{"alice"},
		KnownCreatedEntities: []string{"svc-a"},
		ActorHours:           map[string][]int{"alice": {9}},
		ActorRoles:           map[string][]string{"alice": {"admin"}},
	}
	b := &Baseline{
		KnownActors:          []string{"bob"},
		KnownCreatedEntities: []string{"svc-b"},
		ActorHours:           map[string][]int{"alice": {14}, "bob": {22}},
		ActorRoles:           map[string][]string{"bob": {"contributor"}},
	}

	got := a.Merge(b)

	if !got.IsKnownActor("alice") || !got.IsKnownActor("bob") {
		t.Errorf("KnownActors = %v, want union [alice bob]", got.KnownActors)
	}
	if !got.IsKnownCreatedEntity("svc-a") || !got.IsKnownCreatedEntity("svc-b") {
		t.Errorf("KnownCreatedEntities = %v, want union [svc-a svc-b]", got.KnownCreatedEntities)
	}
	if !got.KnownHour("alice", 9) || !got.KnownHour("alice", 14) {
		t.Errorf("alice's merged hours = %v, want union [9 14]", got.ActorHours["alice"])
	}
	if !got.KnownHour("bob", 22) {
		t.Errorf("bob's merged hours = %v, want [22]", got.ActorHours["bob"])
	}
	if !got.IsKnownRole("alice", "admin") || !got.IsKnownRole("bob", "contributor") {
		t.Errorf("merged roles missing an input side: alice=%v bob=%v", got.ActorRoles["alice"], got.ActorRoles["bob"])
	}

	// Neither input was mutated.
	if len(a.KnownActors) != 1 || len(b.KnownActors) != 1 {
		t.Errorf("Merge mutated an input: a.KnownActors=%v b.KnownActors=%v", a.KnownActors, b.KnownActors)
	}
}

// TestMerge_FrequencyTablesTakeMax proves FrequencyTables merge by MAX, not
// sum. This is the correctness-critical property documented on Merge: Build
// recomputes FRESH from the full available corpus every scan (not
// incrementally), so under normal non-rotated operation the freshly-derived
// count is already >= the previously-persisted count for the same key — a sum
// would double-count every steady-state scan, while max is a no-op there and
// correctly falls back to the larger (persisted) value when the fresh corpus
// was truncated by a rotation.
func TestMerge_FrequencyTablesTakeMax(t *testing.T) {
	persisted := &Baseline{FrequencyTables: map[string]int{"github:api_request:alice": 500}}
	freshFullCorpus := &Baseline{FrequencyTables: map[string]int{"github:api_request:alice": 503}} // 3 new events, non-rotated
	freshPostRotation := &Baseline{FrequencyTables: map[string]int{"github:api_request:alice": 2}} // rotation truncated the corpus

	if got := persisted.Merge(freshFullCorpus).FreqCountActor("github", "api_request", "alice"); got != 503 {
		t.Errorf("non-rotated merge FreqCount = %d, want 503 (fresh already superset — sum would double-count to 1003)", got)
	}
	if got := persisted.Merge(freshPostRotation).FreqCountActor("github", "api_request", "alice"); got != 500 {
		t.Errorf("post-rotation merge FreqCount = %d, want 500 (persisted count must survive a truncated fresh corpus)", got)
	}
}

// TestMerge_KnownUsersUnionsIPsGeosAndLatestLastSeen proves KnownUsers profiles
// merge per-actor: IPs/geos union, LastSeen takes the later timestamp.
func TestMerge_KnownUsersUnionsIPsGeosAndLatestLastSeen(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	a := &Baseline{KnownUsers: map[string]UserProfile{
		"alice": {KnownIPs: []string{"1.1.1.1"}, KnownGeos: []string{"US"}, LastSeen: early},
	}}
	b := &Baseline{KnownUsers: map[string]UserProfile{
		"alice": {KnownIPs: []string{"2.2.2.2"}, KnownGeos: []string{"CA"}, LastSeen: late},
	}}

	got := a.Merge(b)
	if !got.KnownIP("alice", "1.1.1.1") || !got.KnownIP("alice", "2.2.2.2") {
		t.Errorf("merged IPs = %v, want union of both sides", got.KnownUsers["alice"].KnownIPs)
	}
	if !got.KnownGeo("alice", "US") || !got.KnownGeo("alice", "CA") {
		t.Errorf("merged geos = %v, want union of both sides", got.KnownUsers["alice"].KnownGeos)
	}
	if !got.KnownUsers["alice"].LastSeen.Equal(late) {
		t.Errorf("merged LastSeen = %v, want the LATER timestamp %v", got.KnownUsers["alice"].LastSeen, late)
	}
}
