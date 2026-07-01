// Package pipeline is the ORCHESTRATOR that assembles the four core seams into
// one agentic scan cycle:
//
//	core/connect  →  core/detect  →  core/agent (cascade)  →  core/store
//	  (Pull)          (Detect)        (ResolveFinding)         (Append)
//
// Run is the single entry point. It pulls events through a Connector, runs the
// deterministic detector floor, then resolves EACH finding through the tiered
// triage→investigate→escalate cascade (core/agent.ResolveFindingWith), and
// durably appends both the findings and their resolutions to the git-backed
// store. It returns a Summary of what happened.
//
// CONCURRENCY: findings are resolved through a bounded worker pool (Config.Workers,
// default modest). This is safe because the two shared collaborators are
// concurrency-safe by construction:
//
//   - the inference client (core/agent.Client, in practice inference.DirectClient)
//     is a stateless net/http POSTer — every Messages call builds its own request;
//     there is no shared mutable state, so N goroutines may call it at once.
//   - the store serializes every Append behind its per-repo Serializer lock and a
//     git compare-and-swap, so concurrent appends linearize with no lost write.
//
// The pipeline adds NOTHING to that floor: it never bypasses the cascade (the
// untrusted-data handling, the hard-constraint floor, the structural gate, and
// the fail-safe all live INSIDE ResolveFindingWith — the pipeline calls it and
// honors whatever it returns). A finding the floor force-escalates never reaches
// the model; a finding the cascade escalates is recorded as escalated; the
// pipeline cannot and does not re-decide.
//
// IMPORT DISCIPLINE: this package imports core/connect, core/detect, core/agent,
// core/store, and pkg/* — and NOTHING that talks to a model directly. It reaches
// inference ONLY through the core/agent.Client interface threaded in by the
// caller (the cmd layer hands it an inference.DirectClient). The core import-lint
// (core/lint) and this package's imports_test.go forbid any framework / transport
// / vendor-SDK import here.
package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// defaultWorkers is the bounded resolve-pool size when Config.Workers <= 0. Modest
// on purpose: per-finding cost is dominated by model latency (real backend) or is
// near-instant (canned backend), so a small pool keeps memory + connection
// pressure low while still overlapping the per-finding model round-trips.
const defaultWorkers = 4

// Config is the immutable input to one Run. The {Client, ...} the pipeline needs
// are injected — the pipeline constructs none of them, so the import-lint floor
// holds (no inference, no transport built here).
type Config struct {
	// Connector is the event source (FILE/STDIN by default; a cloud connector in a
	// later wave). Required.
	Connector connect.Connector

	// Client is the inference seam the cascade reaches the model through. A nil
	// Client makes EVERY finding fail safe to escalate (the cascade's documented
	// nil-client behavior) — a scan still runs and records escalations, it just
	// never resolves anything benign. Typically an *inference.DirectClient.
	Client agent.Client

	// Store is the git-backed sink for findings + resolutions. Required: a scan
	// with nowhere to durably write its output is a misconfiguration, not a
	// silent no-op.
	Store *store.Store

	// Baseline supplies historical context to the baseline-dependent detectors
	// (new-actor, priv-escalation, unusual-login, …). Nil is treated as an empty
	// baseline (content-only detectors still fire).
	Baseline *baseline.Baseline

	// Cascade carries the model tiers + (optional) live tools for ResolveFindingWith.
	// The zero value uses the cascade's documented defaults and no live tools.
	Cascade agent.CascadeOptions

	// Workers bounds the concurrent resolve pool. <= 0 uses defaultWorkers. The
	// pool never exceeds the number of findings.
	Workers int
}

// Summary is the result of one completed scan cycle. The four counts answer the
// operator's questions: how much did we look at, how much did we flag, how much
// did the agent close on its own, and how much needs a human.
//
// Invariant: Resolved + Escalated == FindingsDetected (every finding terminates
// in exactly one of the two dispositions — the cascade has no third outcome).
type Summary struct {
	// EventsScanned is the number of events the connector pulled and the detector
	// floor evaluated.
	EventsScanned int `json:"events_scanned"`
	// FindingsDetected is the number of findings the detector floor produced.
	FindingsDetected int `json:"findings_detected"`
	// Resolved is the number of findings the cascade closed as benign
	// (ActionProceed) — agent-handled, no human needed.
	Resolved int `json:"resolved"`
	// Escalated is the number of findings the cascade routed to a human
	// (ActionEscalated), whether by the pre-LLM floor or a tier verdict.
	Escalated int `json:"escalated"`
	// Duration is the wall-clock time the whole Run took, for latency reporting.
	Duration time.Duration `json:"duration_ms"`
}

// resolved is one finding paired with its cascade resolution, carried out of a
// worker goroutine so the store writes and counting happen on the main goroutine
// in a deterministic order (sorted by finding ID) — the store linearizes anyway,
// but ordering the writes keeps the on-disk log reproducible for a fixed input.
type resolved struct {
	finding    finding.Finding
	resolution agent.Resolution
}

// Run executes one scan cycle and returns its Summary. The order is load-bearing
// and mirrors the architecture topology exactly:
//
//  1. CONNECT: cfg.Connector.Pull(ctx) — pull the normalized event batch. A pull
//     error aborts the scan (we will not detect over a partial/corrupt source).
//  2. DETECT: detect.Detect(events, baseline) — the deterministic floor. No
//     inference key, no network. Findings are appended to the store FIRST so the
//     durable record of "what we flagged" exists even if a later resolve panics
//     or the process is killed mid-scan.
//  3. RESOLVE: for each finding, agent.ResolveFindingWith(ctx, client, f, opts)
//     through a bounded worker pool. The cascade owns the hard-constraint floor,
//     the untrusted-data boxing, the structural gate, and the fail-safe — the
//     pipeline does not reach around any of it.
//  4. STORE: each resolution is appended to the store as a pkg/resolution.Resolution
//     so the notification binaries and the git audit trail see a uniform record.
//
// Run is safe to call once per Config. A non-nil error means the scan could not
// complete (connector, detector-input, or a store write failed); a nil error with
// a Summary means the scan completed and the counts are authoritative.
func Run(ctx context.Context, cfg Config) (Summary, error) {
	start := time.Now()

	if cfg.Connector == nil {
		return Summary{}, fmt.Errorf("pipeline: nil Connector")
	}
	if cfg.Store == nil {
		return Summary{}, fmt.Errorf("pipeline: nil Store")
	}

	// (1) CONNECT.
	events, err := cfg.Connector.Pull(ctx)
	if err != nil {
		return Summary{}, fmt.Errorf("pipeline: connect: %w", err)
	}

	// Append every pulled event to the durable store so the scan's input corpus is
	// itself reconstructable from the git log (the store is the one brain).
	for i := range events {
		if _, err := cfg.Store.Append(store.KindEvents, events[i]); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store event %s: %w", events[i].ID, err)
		}
	}

	// (2) DETECT — deterministic, offline.
	bl := cfg.Baseline
	if bl == nil {
		bl = &baseline.Baseline{}
	}
	findings := detect.Detect(events, bl)

	// OPERATOR FEEDBACK: replay the directives stream and DROP any finding an
	// operator has suppressed (via `mallcop feedback <id> dismiss`). This is the
	// keystone that makes persisted feedback honored by the NEXT scan: without
	// it the directives stream is inert. The drop happens BEFORE the
	// findings-append below, so a suppressed finding is neither recorded nor
	// resolved — the operator's decision persists and the next scan obeys it.
	directives, err := cfg.Store.LoadDirectives()
	if err != nil {
		return Summary{}, fmt.Errorf("pipeline: load directives: %w", err)
	}
	findings = applyDirectives(findings, directives)

	summary := Summary{
		EventsScanned:    len(events),
		FindingsDetected: len(findings),
	}

	// Persist the findings BEFORE resolving them. The findings stream is the
	// durable record of "what the floor flagged"; it must survive a crash during
	// resolution. Append is the only path; the store linearizes.
	for i := range findings {
		if _, err := cfg.Store.Append(store.KindFindings, findings[i]); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store finding %s: %w", findings[i].ID, err)
		}
	}

	// Publish the browser-readable snapshot: the current, deduped, non-suppressed
	// findings as a single JSON document. The web chat reads this instead of the
	// append-only findings.jsonl, which accumulates history + suppressed records
	// across scans. Written on every scan (including the empty set, so a cleared
	// scan overwrites a stale snapshot).
	if _, err := cfg.Store.WriteSnapshot("findings.json", findings); err != nil {
		return Summary{}, fmt.Errorf("pipeline: write findings snapshot: %w", err)
	}

	if len(findings) == 0 {
		summary.Duration = time.Since(start)
		return summary, nil
	}

	// (3) RESOLVE through a bounded worker pool. The cascade is the security floor;
	// the pool only parallelizes the per-finding model round-trips.
	results, err := resolveAll(ctx, cfg, findings)
	if err != nil {
		return Summary{}, err
	}

	// (4) STORE resolutions + count. Writes happen here, in finding order, on one
	// goroutine — deterministic on-disk ordering for a fixed input. The store
	// would linearize concurrent writes anyway; ordering them keeps the log
	// reproducible.
	for _, r := range results {
		res := toResolutionRecord(r.finding, r.resolution)
		if _, err := cfg.Store.Append(store.KindResolutions, res); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store resolution for %s: %w", r.finding.ID, err)
		}
		if r.resolution.Action == agent.ActionEscalated {
			summary.Escalated++
		} else {
			summary.Resolved++
		}
	}

	summary.Duration = time.Since(start)
	return summary, nil
}

// resolveAll runs ResolveFindingWith over every finding through a bounded pool of
// at most cfg.Workers goroutines (never more than len(findings)). Results are
// collected into a slice indexed by input position, so the caller sees them in
// the SAME order as the (name-sorted, deterministic) detector output regardless
// of which worker finished first.
//
// The inference client and the store are concurrency-safe (see package doc), so
// the only shared state the pool touches is the pre-allocated results slice —
// and each goroutine writes a DISTINCT index, so there is no data race (proven by
// -race in the package tests).
func resolveAll(ctx context.Context, cfg Config, findings []finding.Finding) ([]resolved, error) {
	workers := cfg.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	if workers > len(findings) {
		workers = len(findings)
	}

	results := make([]resolved, len(findings))
	jobs := make(chan int)

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				f := findings[idx]
				// ResolveFindingWith carries the ENTIRE security floor: the
				// hard-constraint pre-LLM router, untrusted-data boxing, the
				// structural gate, and the fail-safe. The pipeline does not reach
				// around any of it — it records exactly what the cascade returns.
				res := agent.ResolveFindingWith(ctx, cfg.Client, f, cfg.Cascade)
				results[idx] = resolved{finding: f, resolution: res}
			}
		}()
	}

	for idx := range findings {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()

	return results, nil
}

// toResolutionRecord maps the cascade's internal agent.Resolution onto the
// shared pkg/resolution.Resolution wire record the store streams and the
// notification binaries consume. The mapping is mechanical:
//
//   - ActionEscalated → "escalate"; anything else (ActionProceed) → "resolve".
//   - Reason, Actor, Severity, Source carry through from the cascade resolution
//     and the originating finding so the record is self-describing on the wire.
//
// The cascade never reports a numeric confidence on its terminal Resolution, so
// Confidence is left zero — the disposition (escalate vs resolve) is the
// authoritative signal, not a self-reported score.
func toResolutionRecord(f finding.Finding, r agent.Resolution) resolution.Resolution {
	action := "resolve"
	if r.Action == agent.ActionEscalated {
		action = "escalate"
	}
	return resolution.Resolution{
		FindingID: f.ID,
		Action:    action,
		Reason:    r.Reason,
		Actor:     f.Actor,
		Severity:  f.Severity,
		Source:    f.Source,
		Timestamp: time.Now().UTC(),
	}
}
