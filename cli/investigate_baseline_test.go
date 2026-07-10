package cli

// investigate_baseline_test.go — proves `mallcop investigate` can load the
// baseline the scan pipeline persisted (mallcoppro-a7a step 3): with no explicit
// --baseline, the investigate runner falls back to the store's KindBaseline
// snapshot, so check_baseline sees the SAME actor/role context the scan gated on.

import (
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
)

func TestLoadPersistedBaseline_ReturnsLatest(t *testing.T) {
	st, err := openOrInitStore(t.TempDir())
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}

	// Empty store: no persisted baseline → nil (check_baseline degrades gracefully).
	if bl, err := loadPersistedBaseline(st); err != nil || bl != nil {
		t.Fatalf("empty store: got (%v, %v), want (nil, nil)", bl, err)
	}

	// Persist two baselines (the append-only history the scan writes each derive run).
	if _, err := st.Append(store.KindBaseline, &baseline.Baseline{KnownActors: []string{"alice"}}); err != nil {
		t.Fatalf("append baseline 1: %v", err)
	}
	if _, err := st.Append(store.KindBaseline, &baseline.Baseline{KnownActors: []string{"alice", "bob"}}); err != nil {
		t.Fatalf("append baseline 2: %v", err)
	}

	// The MOST RECENT record is the current baseline.
	bl, err := loadPersistedBaseline(st)
	if err != nil {
		t.Fatalf("loadPersistedBaseline: %v", err)
	}
	if bl == nil {
		t.Fatal("loadPersistedBaseline returned nil after two appends")
	}
	if !bl.IsKnownActor("alice") || !bl.IsKnownActor("bob") {
		t.Errorf("latest baseline = %v, want the {alice,bob} record (most recent)", bl.KnownActors)
	}
}
