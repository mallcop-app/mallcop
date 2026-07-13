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
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// defaultWorkers is the bounded resolve-pool size when Config.Workers <= 0. Modest
// on purpose: per-finding cost is dominated by model latency (real backend) or is
// near-instant (canned backend), so a small pool keeps memory + connection
// pressure low while still overlapping the per-finding model round-trips.
const defaultWorkers = 4

// defaultMaxFindingsForActors is the volume circuit-breaker ceiling applied when
// Config.Budget.MaxFindingsForActors <= 0. A run whose detector floor produces
// strictly MORE findings than this trips the breaker (agent.CheckCircuitBreaker),
// which appends a synthetic critical meta-finding that force-escalates to a human.
// It mirrors src/mallcop/budget.py BudgetConfig.max_findings_for_actors (= 25) —
// the legacy default, kept in exactly one place so the flag/env only OVERRIDE it.
const defaultMaxFindingsForActors = 25

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

	// Budget carries the volume circuit-breaker ceiling (MaxFindingsForActors).
	// A run whose (post-suppression) detector floor produces strictly MORE
	// findings than the ceiling trips the breaker: a synthetic critical
	// meta-finding (family "mallcop-budget") is appended to the finding set and
	// force-escalated to a human via the seeded E-006 route (see Run). The zero
	// value applies defaultMaxFindingsForActors — the caller only sets this to
	// OVERRIDE the default (scan.go threads a --max-findings flag through here).
	Budget agent.BudgetConfig
}

// Summary is the result of one completed scan cycle. The four counts answer the
// operator's questions: how much did we look at, how much did we flag, how much
// did the agent close on its own, and how much needs a human.
//
// Invariant: Resolved + Escalated == FindingsDetected (every finding terminates
// in exactly one of the two dispositions — the cascade has no third outcome).
type Summary struct {
	// EventsScanned is the number of events the detector floor actually
	// evaluated this scan — i.e. the connector's pull count MINUS any events
	// dropped by the ID-based dedupe (see DuplicatesSkipped) because they were
	// already committed by an earlier scan, or repeated within this same pull.
	// A connector without a durable pull cursor (azure, github) can re-pull an
	// overlapping window every scan; EventsScanned reflects only the NEW events
	// this scan processed, not the raw pull size.
	EventsScanned int `json:"events_scanned"`
	// FindingsDetected is the number of findings the detector floor produced.
	FindingsDetected int `json:"findings_detected"`
	// Resolved is the number of findings the cascade closed as benign
	// (ActionProceed) — agent-handled, no human needed.
	Resolved int `json:"resolved"`
	// Escalated is the number of findings the cascade routed to a human
	// (ActionEscalated), whether by the pre-LLM floor or a tier verdict.
	Escalated int `json:"escalated"`
	// DuplicatesSkipped is the number of pulled events dropped by the dedupe:
	// events whose ID already exists in the store's committed KindEvents
	// stream, plus any repeat IDs within this scan's own pulled batch. Omitted
	// from the JSON encoding when zero (the common case: a connector with a
	// durable cursor never re-pulls).
	DuplicatesSkipped int `json:"duplicates_skipped,omitempty"`
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

	// (1a) DERIVE THE BASELINE FROM PRIOR HISTORY — the idempotency keystone.
	// Read the store's ALREADY-committed events (everything earlier scans saw)
	// BEFORE appending THIS scan's batch below, then derive the baseline the
	// baseline-dependent detectors gate on. The ordering is load-bearing: an actor
	// or pattern first seen in THIS scan must NOT already be in the baseline (it is
	// investigated exactly once — now), so the prior-events read MUST precede the
	// KindEvents append. An explicit Config.Baseline (the eval/academy pre-built
	// corpus, or a --baseline file) ALWAYS wins — the derived baseline is used only
	// when none was supplied, so the explicit-override path is unchanged. On the
	// first scan the store holds no prior events → an empty baseline → every actor
	// fires (correct). This is the fix for the steady-state re-investigation cost
	// bug: without it cfg.Baseline was nil, detect saw an EMPTY baseline, and
	// new-actor re-flagged (and the cascade re-charged inference for) every actor on
	// every scan.
	//
	// This SAME prior-events read also feeds the DEDUPE below (a second, load-
	// bearing reason the ordering must not move): a connector without a durable
	// pull cursor (azure, github) can re-pull events its OWN earlier scan already
	// committed, and without a dedupe the events stream only grows — regrowing
	// exactly the O(N * filesize) commit-churn problem AppendBatch fixes on the
	// write side. On the derived-baseline path (bl == nil) priorEvents is already
	// being loaded for baseline.Build, so the dedupe ID set reuses that EXACT
	// slice — zero extra I/O. On the explicit-Config.Baseline path priorEvents is
	// NOT otherwise loaded (the explicit baseline needs no history), so we load it
	// here purely to build the dedupe ID set; it is never fed to baseline.Build in
	// that branch.
	bl := cfg.Baseline
	derived := false
	var priorEvents []event.Event
	if bl == nil {
		var perr error
		priorEvents, perr = loadPriorEvents(cfg.Store)
		if perr != nil {
			return Summary{}, fmt.Errorf("pipeline: load prior events for baseline: %w", perr)
		}
		fresh := baseline.Build(priorEvents)

		// STORE-ROTATION SURVIVAL (mallcoppro-9e2): merge in the LAST persisted
		// KindBaseline snapshot before gating. An operational store rotation
		// (mallcoppro-ee3: the events stream is archived and truncated to bound git
		// blob churn) empties priorEvents WITHOUT touching the separately persisted
		// KindBaseline stream — so `fresh` alone would forget every actor/hour/role
		// this system already investigated and re-fire on all of them. Baseline.Merge
		// unions the two (MAX on counts, so a normal non-rotated scan — where fresh is
		// already a superset — is unaffected; see Merge's doc comment). A store that
		// was never scanned in derive mode has no persisted snapshot, so
		// lastPersisted is nil and the merge is a no-op.
		lastPersisted, perr := loadPersistedBaseline(cfg.Store)
		if perr != nil {
			return Summary{}, fmt.Errorf("pipeline: load persisted baseline: %w", perr)
		}
		bl = lastPersisted.Merge(fresh)
		derived = true
	} else {
		var perr error
		priorEvents, perr = loadPriorEvents(cfg.Store)
		if perr != nil {
			return Summary{}, fmt.Errorf("pipeline: load prior events for dedupe: %w", perr)
		}
	}

	// DEDUPE-ON-APPEND (mallcoppro-ee3): drop every pulled event whose ID already
	// exists in the store's committed KindEvents stream (priorEvents, read above
	// — BEFORE this scan's batch is appended), and collapse duplicate IDs WITHIN
	// the pulled batch itself (keep the first). An event with an EMPTY ID is
	// NEVER dropped — an empty-string ID is not an identity, and a connector or
	// test fixture that never assigns one must not have its events silently
	// discarded. detect MUST see this DEDUPED slice (not the raw pull), so a
	// re-pulled duplicate is neither re-detected nor re-appended.
	var duplicatesSkipped int
	events, duplicatesSkipped = dedupeEvents(events, priorEvents)

	// Append every (deduped) pulled event to the durable store, in ONE commit
	// instead of one commit per event, so the scan's input corpus is itself
	// reconstructable from the git log (the store is the one brain) without
	// paying a per-event commit's whole-file re-hash cost (see
	// store.AppendBatch's doc comment). This runs AFTER the prior-events read
	// above so this scan's events never baseline (or dedupe) themselves.
	if len(events) > 0 {
		batch := make([]any, len(events))
		for i := range events {
			batch[i] = events[i]
		}
		if _, err := cfg.Store.AppendBatch(store.KindEvents, batch); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store events batch: %w", err)
		}
	}

	// (2) DETECT — deterministic, offline. Gated on the baseline derived from prior
	// history (or the explicit override), so a KNOWN actor/pattern is not re-detected
	// on a steady-state re-scan, while a genuinely new actor/pattern still fires once.
	findings := detect.Detect(events, bl)

	// Persist the DERIVED baseline as a KindBaseline snapshot: it is otherwise
	// ephemeral (built in-memory each scan), so recording it makes it observable in
	// the git log, portable (a fresh clone reconstructs it), and loadable by the
	// investigate path so check-baseline can see the same baseline the scan gated on.
	// Only the derived baseline is persisted — an explicit Config.Baseline is already
	// a durable file, and re-appending it would only add noise to the eval/academy
	// path. Append (not overwrite): KindBaseline is the append-only history stream.
	if derived {
		if _, err := cfg.Store.Append(store.KindBaseline, bl); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store baseline snapshot: %w", err)
		}
	}

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

	// VOLUME CIRCUIT BREAKER (L4 resource floor, ports src/mallcop/budget.py
	// check_circuit_breaker). A flood of findings — e.g. an attacker generating
	// noise to drown a single real boundary violation — must NOT be quietly
	// auto-handled. When the (post-suppression) finding count exceeds the budget
	// ceiling, CheckCircuitBreaker returns a synthetic CRITICAL meta-finding
	// (family "mallcop-budget"). We APPEND it to the finding set HERE, before the
	// count and the store-append below, so that:
	//   - it is counted in FindingsDetected (the Resolved+Escalated invariant holds),
	//   - it is durably stored like any other finding, and
	//   - it flows through the SAME resolve loop, where checkHardConstraints matches
	//     the seeded E-006 escalate_route and force-escalates it to a HUMAN with no
	//     model call. We do NOT merely log the trip: it becomes a first-class,
	//     escalated finding an operator sees. At or under the ceiling, nothing is
	//     appended (CheckCircuitBreaker returns nil).
	budget := cfg.Budget
	if budget.MaxFindingsForActors <= 0 {
		budget.MaxFindingsForActors = defaultMaxFindingsForActors
	}
	if mf := agent.CheckCircuitBreaker(findings, budget); mf != nil {
		findings = append(findings, *mf)
	}

	summary := Summary{
		EventsScanned:     len(events),
		FindingsDetected:  len(findings),
		DuplicatesSkipped: duplicatesSkipped,
	}

	// Persist the findings BEFORE resolving them, in ONE commit. The findings
	// stream is the durable record of "what the floor flagged"; it must survive
	// a crash during resolution. AppendBatch is the only path; the store
	// linearizes.
	if len(findings) > 0 {
		batch := make([]any, len(findings))
		for i := range findings {
			batch[i] = findings[i]
		}
		if _, err := cfg.Store.AppendBatch(store.KindFindings, batch); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store findings batch: %w", err)
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

	// (4) STORE resolutions + count. Build every resolution record and tally
	// Escalated/Resolved in the SAME deterministic finding-order loop as before,
	// then persist the whole set as ONE commit (instead of one commit per
	// resolution) — deterministic on-disk ordering for a fixed input is
	// unchanged; only the number of commits it costs to get there drops.
	resRecords := make([]any, len(results))
	for i, r := range results {
		resRecords[i] = toResolutionRecord(r.finding, r.resolution)
		if r.resolution.Action == agent.ActionEscalated {
			summary.Escalated++
		} else {
			summary.Resolved++
		}
	}
	if len(resRecords) > 0 {
		if _, err := cfg.Store.AppendBatch(store.KindResolutions, resRecords); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store resolutions batch: %w", err)
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

// loadPriorEvents replays the store's committed KindEvents stream (everything
// earlier scans durably recorded at HEAD) and unmarshals it to []event.Event —
// the corpus baseline.Build derives the derived baseline from. A stream with no
// records (a first scan, or a fresh store) is not an error: it yields nil, which
// Build turns into an empty baseline (every actor fires — correct for scan one).
// A malformed record is a hard error: a corrupt event history must not silently
// degrade the baseline into re-investigating everything.
func loadPriorEvents(st *store.Store) ([]event.Event, error) {
	raws, err := st.Load(store.KindEvents)
	if err != nil {
		return nil, err
	}
	if len(raws) == 0 {
		return nil, nil
	}
	out := make([]event.Event, 0, len(raws))
	for i, raw := range raws {
		var ev event.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("decode prior event %d: %w", i, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

// loadPersistedBaseline returns the MOST RECENT baseline the pipeline persisted
// to the store's KindBaseline stream on an earlier derived scan, or nil when the
// stream is empty (a fresh store, or one whose every scan supplied an explicit
// Config.Baseline — never persisted, see the derived-only Append below). KindBaseline
// is append-only history, so the LAST record is the most current snapshot. Used by
// the (1a) derivation step to survive a store rotation (mallcoppro-9e2): mirrors
// cli/investigate.go's loadPersistedBaseline (duplicated, not imported — cli
// depends on core/pipeline's sibling packages, not the reverse, and this package's
// import-lint forbids reaching into cli). A nil result is not an error; Merge
// treats a nil receiver as an empty baseline.
func loadPersistedBaseline(st *store.Store) (*baseline.Baseline, error) {
	raws, err := st.Load(store.KindBaseline)
	if err != nil {
		return nil, err
	}
	if len(raws) == 0 {
		return nil, nil
	}
	var b baseline.Baseline
	if err := json.Unmarshal(raws[len(raws)-1], &b); err != nil {
		return nil, fmt.Errorf("decode persisted baseline: %w", err)
	}
	return &b, nil
}

// dedupeEvents drops every event in pulled whose ID already appears in prior
// (the store's already-committed KindEvents stream, read BEFORE this scan's
// batch is appended — see the (1a) ordering invariant in Run) and collapses
// duplicate IDs WITHIN pulled itself, keeping the first occurrence. An event
// with an EMPTY ID is NEVER dropped, by either rule: an empty string is not an
// identity, so it can never be a "duplicate" of anything, and treating it as
// one would silently discard events from a connector (or test fixture) that
// assigns no ID. Order is preserved. Returns the deduped slice and the count
// of events dropped (for Summary.DuplicatesSkipped).
func dedupeEvents(pulled, prior []event.Event) ([]event.Event, int) {
	priorIDs := make(map[string]bool, len(prior))
	for _, ev := range prior {
		if ev.ID != "" {
			priorIDs[ev.ID] = true
		}
	}

	seen := make(map[string]bool, len(pulled))
	out := make([]event.Event, 0, len(pulled))
	skipped := 0
	for _, ev := range pulled {
		if ev.ID == "" {
			out = append(out, ev)
			continue
		}
		if priorIDs[ev.ID] || seen[ev.ID] {
			skipped++
			continue
		}
		seen[ev.ID] = true
		out = append(out, ev)
	}
	return out, skipped
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
