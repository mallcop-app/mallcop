package connect

import (
	"context"
	"errors"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/event"
)

// fakeConnector is a test double: it returns a fixed batch and/or error, and
// records whether Pull was called (to prove fail-loud short-circuits later
// sources). It lives in the test file so it never crosses the purity lint.
type fakeConnector struct {
	events []event.Event
	err    error
	called *bool
}

func (f *fakeConnector) Pull(ctx context.Context) ([]event.Event, error) {
	if f.called != nil {
		*f.called = true
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.events, nil
}

func evs(ids ...string) []event.Event {
	out := make([]event.Event, 0, len(ids))
	for _, id := range ids {
		out = append(out, event.Event{ID: id})
	}
	return out
}

func ids(events []event.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.ID)
	}
	return out
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestMulti_ConcatenatesInDeclarationOrder proves a Multi over two fake
// connectors returns the concatenated event set, in sub-connector declaration
// order (whole-corpus floor makes concat sufficient).
func TestMulti_ConcatenatesInDeclarationOrder(t *testing.T) {
	a := &fakeConnector{events: evs("a1", "a2")}
	b := &fakeConnector{events: evs("b1")}
	got, err := Multi(a, b).Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	want := []string{"a1", "a2", "b1"}
	if !equalIDs(ids(got), want) {
		t.Fatalf("got %v, want %v", ids(got), want)
	}
}

// TestMulti_FailLoudOnSubError proves one failing sub-connector makes Multi fail
// entirely (not a partial batch) — a configured source that errors HALTS the
// scan rather than silently under-reporting.
func TestMulti_FailLoudOnSubError(t *testing.T) {
	boom := errors.New("aws: credentials expired")
	thirdCalled := false
	a := &fakeConnector{events: evs("a1")}
	b := &fakeConnector{err: boom}
	c := &fakeConnector{events: evs("c1"), called: &thirdCalled}

	got, err := Multi(a, b, c).Pull(context.Background())
	if err == nil {
		t.Fatal("expected a hard error from the failing sub-connector; got nil")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error should be the sub-connector's error; got %v", err)
	}
	if got != nil {
		t.Errorf("failing scan must return no events (no partial batch); got %v", ids(got))
	}
	if thirdCalled {
		t.Error("fail-loud must short-circuit: the connector after the failure must not run")
	}
}

// TestMulti_HonorsCancellation proves a cancelled context aborts before pulling
// any sub-connector, propagating the cancellation error.
func TestMulti_HonorsCancellation(t *testing.T) {
	firstCalled := false
	a := &fakeConnector{events: evs("a1"), called: &firstCalled}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the pull

	_, err := Multi(a).Pull(ctx)
	if err == nil {
		t.Fatal("expected a cancellation error; got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should be context.Canceled; got %v", err)
	}
	if firstCalled {
		t.Error("a pre-cancelled context must abort before running any sub-connector")
	}
}

// TestMulti_CancellationPropagatesToSubs proves ctx is threaded into each
// sub-connector so a source doing I/O sees the deadline/cancellation.
func TestMulti_CancellationPropagatesToSubs(t *testing.T) {
	var seen context.Context
	spy := connectorFunc(func(ctx context.Context) ([]event.Event, error) {
		seen = ctx
		return nil, nil
	})
	type ctxKey string
	key := ctxKey("k")
	ctx := context.WithValue(context.Background(), key, "v")
	if _, err := Multi(spy).Pull(ctx); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if seen == nil || seen.Value(key) != "v" {
		t.Fatal("Multi must thread its ctx into each sub-connector's Pull")
	}
}

// TestMulti_EmptyIsCleanScan proves a Multi with no sub-connectors is a clean
// scan over zero events, not a failure.
func TestMulti_EmptyIsCleanScan(t *testing.T) {
	got, err := Multi().Pull(context.Background())
	if err != nil {
		t.Fatalf("empty Multi should not error; got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty Multi should yield 0 events; got %d", len(got))
	}
}

// connectorFunc adapts a func to the Connector interface for tests.
type connectorFunc func(ctx context.Context) ([]event.Event, error)

func (f connectorFunc) Pull(ctx context.Context) ([]event.Event, error) { return f(ctx) }
