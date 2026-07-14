package pipeline_test

// actor_store_invariant_test.go — the store-invariant guard for mallcoppro-ae4.
//
// THE INVARIANT: a real scan (connect → detect → pipeline persist → git store)
// stores the RAW actor name on disk. The [USER_DATA_BEGIN]/[USER_DATA_END]
// sanitize sentinels are a PROMPT-CONSTRUCTION concern (see core/agent/
// untrusted.go: WrapUntrusted, applied only in core/agent/tier.go and
// core/investigate at prompt-build time) — they must NEVER be baked into the
// persisted record. If they were, an actor-exact tool query
// (tools.SearchFindings / tools.SearchEvents actor=X, which compares with
// strings.EqualFold) could never match a natural actor name: a query for
// "ghost" would miss a finding stored as "[USER_DATA_BEGIN]ghost[USER_DATA_END]".
//
// mallcoppro-ae4 root-caused the observed on-disk sentinels (mallcop-e2e's
// findings.jsonl; the legacy Python-authored records still resident in
// mallcop-deploy) to STALE DATA — the deprecated Python scanner sanitized at
// ingest, a pattern the Go rewrite deliberately moved to prompt-build time. The
// Go write path (core/detect copies ev.Actor verbatim; core/pipeline appends it
// unmodified) does NOT wrap actors. This test locks that in so a regression that
// re-introduces ingest-/persist-time sanitization is caught by CI, and so the
// actor-exact query the investigate agent depends on keeps working end to end.
//
// It lives in the external pipeline_test package and reuses that suite's helpers
// (newGitStore, writeEventsFile, useShippedCorpus).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/tools"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// TestPipeline_StoresRawActor_ActorExactQueryMatches drives the full scan
// pipeline over a single event whose actor is a natural name ("ghost") absent
// from the baseline, so the new-actor detector fires with Actor == "ghost". It
// then proves the two halves of the ae4 invariant:
//
//  1. ON DISK: neither the committed findings stream nor the committed events
//     stream contains a [USER_DATA_BEGIN]/[USER_DATA_END] sentinel — the raw
//     actor is persisted verbatim.
//  2. QUERYABLE: an actor-exact tools.SearchFindings / tools.SearchEvents query
//     for "ghost" MATCHES the stored record. (Against a sentinel-wrapped store
//     this query returns nothing — the exact failure mallcoppro-ae4 reported.)
func TestPipeline_StoresRawActor_ActorExactQueryMatches(t *testing.T) {
	root := useShippedCorpus(t)

	// Every model round-trip resolves cleanly; this test asserts the STORE
	// invariant, not the cascade disposition, so the canned reply just has to be
	// well-formed and let Run complete.
	be := &cannedbackend.CannedBackend{
		CannedResolutionFunc: func(int) string {
			return `{"action":"resolve","confidence":5,"positive_evidence":true,` +
				`"reason":"first-seen automation account ghost provisioned via the ` +
				`documented onboarding runbook; benign."}`
		},
	}
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	t.Cleanup(be.Stop)

	st := newGitStore(t)

	// A single benign event with a natural, baseline-absent actor. A mid-day
	// timestamp keeps timing-based detectors quiet; the "heartbeat" type is not a
	// content-detector trigger — so new-actor is the detector that fires, with
	// Actor set verbatim to "ghost".
	payload, _ := json.Marshal(map[string]string{"note": "routine heartbeat"})
	events := []event.Event{{
		ID:        "evt-ghost-001",
		Source:    "github",
		Type:      "heartbeat",
		Actor:     "ghost",
		Timestamp: time.Date(2026, 6, 18, 14, 22, 0, 0, time.UTC),
		Org:       "atom",
		Payload:   payload,
	}}

	cfg := pipeline.Config{
		Connector: connect.FromPath(writeEventsFile(t, events)),
		Client:    &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"},
		Store:     st,
		// "ghost" is deliberately NOT in KnownActors, so new-actor fires on it.
		Baseline: &baseline.Baseline{KnownActors: []string{"ops-bot"}},
		Cascade:  agent.CascadeOptions{RepoRoot: root},
		Workers:  2,
	}

	if _, err := pipeline.Run(context.Background(), cfg); err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}

	// (1) ON-DISK INVARIANT: the committed findings and events streams must carry
	// NO sanitize sentinel. Load reads the committed git blob — i.e. exactly the
	// bytes on disk — so a substring scan here is a scan of the persisted record.
	const (
		begin = "[USER_DATA_BEGIN]"
		end   = "[USER_DATA_END]"
	)
	for _, kind := range []store.Kind{store.KindFindings, store.KindEvents} {
		raws, err := st.Load(kind)
		if err != nil {
			t.Fatalf("load %s: %v", kind, err)
		}
		if len(raws) == 0 {
			t.Fatalf("store holds zero %s records; the scan did not persist the stream", kind)
		}
		for i, raw := range raws {
			if s := string(raw); strings.Contains(s, begin) || strings.Contains(s, end) {
				t.Errorf("%s record %d persists a sanitize sentinel on disk (sentinels belong at "+
					"prompt-build only, per core/agent/untrusted.go): %s", kind, i, s)
			}
		}
	}

	// (2) ACTOR-EXACT QUERY: the raw actor is queryable. Against a sentinel-wrapped
	// store both of these return nothing — that is the mallcoppro-ae4 symptom.
	fnds, err := tools.SearchFindings(st, tools.SearchFindingsInput{Actor: "ghost"})
	if err != nil {
		t.Fatalf("SearchFindings actor=ghost: %v", err)
	}
	if len(fnds) == 0 {
		t.Fatalf("SearchFindings actor=ghost matched nothing; the raw actor is not queryable")
	}
	for _, f := range fnds {
		if f.Actor != "ghost" {
			t.Errorf("stored finding actor = %q, want the raw %q (no sentinels)", f.Actor, "ghost")
		}
	}

	evs, _, err := tools.SearchEvents(st, tools.SearchEventsInput{Actor: "ghost"})
	if err != nil {
		t.Fatalf("SearchEvents actor=ghost: %v", err)
	}
	if len(evs) == 0 {
		t.Fatalf("SearchEvents actor=ghost matched nothing; the raw event actor is not queryable")
	}
	for _, e := range evs {
		if e.Actor != "ghost" {
			t.Errorf("stored event actor = %q, want the raw %q (no sentinels)", e.Actor, "ghost")
		}
	}
}
