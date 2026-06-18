package pipeline_test

// latency_test.go — measures the ORCHESTRATION overhead of the scan pipeline.
//
// Real per-finding latency is dominated by MODEL latency (the live backend round
// trip). Against the cannedbackend the model reply is near-instant, so the
// wall-clock of a full scan is ~= the pipeline's own overhead: connect parse +
// detect floor + the resolve fan-out scheduling + the git store appends. This
// test runs the full scan over a multi-finding fixture N times, computes the p50,
// and asserts it stays small — i.e. the pipeline adds little on top of the
// (here ~0) model latency.
//
// The assertion bound is deliberately generous (the git store does real disk +
// fork-exec git plumbing per append, which dominates the canned-backend run);
// the POINT is to catch a regression that adds an order of magnitude of
// orchestration overhead, not to micro-benchmark git. The measured p50 is logged
// so the harness/report can surface scan_latency.

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
)

// TestPipeline_ScanLatency_P50OrchestrationOverheadIsSmall measures p50 scan
// latency over a multi-finding fixture against the cannedbackend and asserts the
// orchestration overhead is bounded.
func TestPipeline_ScanLatency_P50OrchestrationOverheadIsSmall(t *testing.T) {
	root := useShippedCorpus(t)

	be := &cannedbackend.CannedBackend{
		CannedResolutionFunc: func(callIndex int) string {
			return `{"action":"resolve","confidence":5,"positive_evidence":true,` +
				`"reason":"ops-bot disabled MFA via documented break-glass runbook RB-114 during the approved window."}`
		},
	}
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	t.Cleanup(be.Stop)
	client := &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"}

	const runs = 15
	durations := make([]time.Duration, 0, runs)
	for i := 0; i < runs; i++ {
		// Fresh store per run so we measure a clean scan, not a growing log.
		st := newGitStore(t)
		eventsPath := writeEventsFile(t, multiFindingFixture(t))
		cfg := pipeline.Config{
			Connector: connect.FromPath(eventsPath),
			Client:    client,
			Store:     st,
			Baseline:  knownActorsBaseline(),
			Cascade: agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{
				text:      "events: evt-mfa-001 mfa_disabled ops-bot; baseline: ops-bot known, break-glass runbook RB-114 on file",
				toolCalls: 2, distinctTools: 2,
			}},
			Workers: 4,
		}
		start := time.Now()
		sum, err := pipeline.Run(context.Background(), cfg)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("run %d: pipeline.Run: %v", i, err)
		}
		if sum.FindingsDetected != 2 {
			t.Fatalf("run %d: FindingsDetected = %d, want 2", i, sum.FindingsDetected)
		}
		durations = append(durations, elapsed)
	}

	sort.Slice(durations, func(a, b int) bool { return durations[a] < durations[b] })
	p50 := durations[len(durations)/2]
	t.Logf("scan_latency p50 (orchestration, canned model): %v over %d runs (min=%v max=%v)",
		p50, runs, durations[0], durations[len(durations)-1])

	// A multi-finding canned scan must complete well under a second. A real model
	// adds seconds of network/inference latency PER finding on top of this; the
	// pipeline itself contributes only this bounded overhead. A p50 over the bound
	// means the orchestrator regressed (e.g. lost concurrency, added a sync stall).
	const bound = 750 * time.Millisecond
	if p50 > bound {
		t.Errorf("p50 scan latency %v exceeds orchestration bound %v — the pipeline added "+
			"non-trivial overhead on top of (here ~0) model latency", p50, bound)
	}
}
