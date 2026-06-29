// scenario_tools.go — the PER-SCENARIO live ToolRunner that backs the ModeReal
// parity run with REAL telemetry (portable-agent-architecture.md §3.8, §4.1).
//
// THE GAP THIS CLOSES: RunScenario drives the portable cascade
// (agent.ResolveFindingWith) which reaches tools ONLY through the injected
// agent.ToolRunner seam (CascadeOptions.Tools). Before this file the runner
// passed whatever single ToolRunner the caller set — nil for the merge-gate — so
// on ModeReal the live agent investigated with NO scenario evidence: search-events
// returned nothing scenario-specific, check-baseline returned nothing, and the
// parity number measured a model staring at an empty toolbox. That number is
// meaningless.
//
// THE FIX: for EACH scenario, scenarioToolRunner seeds a per-scenario evidence
// source from the exam.Scenario (its events, baseline, finding) and dispatches
// tool calls to the REAL core/tools over THAT data — the SAME tool surface the
// agent gets in production:
//
//   - search-events  → tools.SearchEventsWrapped over a git-backed store seeded
//     with the scenario's events, FOLDING the operator-decisions matched_rules
//     (§3.8) keyed on the finding family + the finding's flat metadata.
//   - check-baseline → tools.CheckBaseline over a baseline.Baseline reconstructed
//     from the scenario's known_entities + frequency_tables (so the agent can
//     answer "is this routine for this actor").
//   - search-findings → tools.SearchFindings over the same store (seeded with the
//     scenario's finding) so the deeper sweep has the finding stream.
//
// Each scenario gets its OWN runner over its OWN store + baseline: scenario A's
// agent sees ONLY scenario A's telemetry. That per-scenario isolation is what
// makes the eval reproducible (§4.1) — the baseline the gate scores is the
// scenario's, not a shared/static fixture.
//
// core/eval is the harness layer (not the shipped runtime), so importing the
// real core/tools + core/store here is the intended seam — the import-lint bans
// only vendor SDKs / orchestration / dropped transport, none of which this adds.
package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/observe"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/tools"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// scenarioToolRunner is the per-scenario live ToolRunner. It holds a git-backed
// store seeded with the scenario's events + finding and a baseline reconstructed
// from the scenario's baseline block, and dispatches RunTools to the REAL
// core/tools over that data. It implements agent.ToolRunner.
//
// CONCURRENCY (the recurring -race flake class, fix #3). The cascade's deep-panel
// fan-out (core/agent/fanout.go) issues THREE RunTools calls CONCURRENTLY against
// the SAME runner. The earlier design re-ran every tool on every call — each call
// re-shelled `git rev-parse HEAD` + `git cat-file` over the per-scenario store and
// re-walked the operator-decisions corpus (os.Executable walk + file read). That
// is shared MUTABLE EXTERNAL state (one git repo, the process temp dir, the binary
// walk) read concurrently: it produces NO Go data race (every call has its own Go
// locals) yet can DIVERGE — a concurrent call can observe a transiently empty /
// partial git read and compute the role-grant / zero-history predicate on
// INCOMPLETE events, flipping a terminal escalate to a resolve ~2% of the time.
// This is the same class as the repoRoot-global and backend-content-routing flakes
// already closed in this harness.
//
// THE FIX (systemic, not a symptom patch): all per-scenario telemetry is read from
// the store EXACTLY ONCE, up front, into an IMMUTABLE snapshot (events, matched
// rules, findings, and the two observable predicates). RunTools never touches the
// git store, the corpus walk, or any shared map after construction — it only reads
// frozen fields and writes to its own local strings.Builders. The predicates are
// computed once and returned identically on every call, so the role-grant /
// zero-history forces compute the SAME regardless of goroutine scheduling. Nothing
// the runner reads during RunTools is mutated after newScenarioToolRunner returns,
// so concurrent RunTools calls are trivially safe.
type scenarioToolRunner struct {
	baseline *baseline.Baseline

	// family + meta drive the §3.8 rule fold and the check-baseline lookup. meta
	// is the OBSERVABLE predicate: the finding metadata UNIONED with the metadata
	// the scenario's events carry (maintenance_window, scheduled, location_change,
	// …). The operator rules' metadata_match predicates key on those OBSERVABLE
	// event fields — "Worker passes this after search-events surfaces the flag" —
	// so folding against finding metadata alone would miss every rule whose
	// predicate lives on the events. Unioning the event metadata in is what makes
	// the §3.8 matched_rules fold fire exactly as it does once a production agent
	// has seen the events.
	family string
	actor  string
	source string
	meta   map[string]string

	// snap is the IMMUTABLE per-scenario evidence snapshot, computed ONCE in
	// newScenarioToolRunner. RunTools reads ONLY these frozen fields (plus the
	// immutable baseline/meta above) — never the git store — so concurrent calls
	// from the deep-panel fan-out cannot observe a partial read. Treat every field
	// as read-only after construction.
	snap scenarioSnapshot
}

// scenarioSnapshot is the frozen evidence one scenario yields. Every field is
// computed once (over a single, committed git read) and then read-only: RunTools
// renders subsets of it per tier but never mutates it and never re-reads the
// store. The slices are never appended to after construction; the predicate
// booleans + details are the §4.3 observable forces computed from the SAME
// surfaced events the model sees, so they are byte-stable across calls.
type scenarioSnapshot struct {
	// events is the surfaced event set the model and the predicates BOTH read:
	// the actor/source-filtered read, with the new-actor fallback already folded
	// in (FIX 2). Computed once so all three deep goroutines render identical
	// events.
	events []tools.EventView
	// matchedRules is the §3.8 operator-decisions fold (corpus walk OR the
	// explicit-repoRoot LookupRules fallback), resolved once.
	matchedRules []tools.OperatorRule
	// findings is the seeded findings stream (investigate tier only).
	findings []finding.Finding
	// searchEmpty mirrors the old ToolEmpty: the relied-on search-events surfaced
	// no events. An empty read is data, not a dismissal (§3.4 / §2.5).
	searchEmpty bool

	// The observable force-escalate predicates (§4.3), computed ONCE over the
	// frozen events + the typed baseline. roleGrant terminal-escalates a privilege
	// grant by the finding actor with no precedent; zeroHist hands a zero-history
	// access to investigate; bulkExport terminal-escalates an unjustified bulk/PII
	// export. Frozen here so every RunTools call returns the same force regardless
	// of which goroutine runs it.
	zeroHist   bool
	zeroDetail string
	roleGrant  bool
	roleDetail string
	bulkExport bool
	bulkDetail string
}

// newScenarioToolRunner builds a live ToolRunner over one scenario's telemetry.
// It seeds a fresh git-backed store under tmpDir (the caller owns tmpDir's
// lifetime) with the scenario's events + finding, reconstructs the baseline, and
// records the finding family + metadata for the §3.8 rule fold. repoRoot locates
// the operator-decisions corpus so search-events can fold matched_rules exactly
// as production does.
//
// Returns an error only on a genuine seeding failure (cannot init the store,
// cannot append a record) — never for an empty scenario (a scenario with no
// events/baseline yields a runner whose tools return the canonical empty
// envelope, which is itself valid evidence, §3.4).
func newScenarioToolRunner(tmpDir, repoRoot string, s *exam.Scenario) (*scenarioToolRunner, error) {
	st, err := seedScenarioStore(tmpDir, s)
	if err != nil {
		return nil, err
	}
	r := &scenarioToolRunner{
		baseline: baselineFromScenario(s),
		family:   scenarioFamily(s),
		actor:    scenarioActor(s),
		source:   scenarioSource(s),
		meta:     scenarioObservableMeta(s),
	}
	// Read the per-scenario telemetry from the store EXACTLY ONCE into an
	// immutable snapshot. After this returns, RunTools never touches the store —
	// it reads only frozen fields — so the deep-panel fan-out's concurrent RunTools
	// calls cannot race on a partial git read (the recurring -race flake class).
	snap, err := r.seedSnapshot(st, repoRoot, finding.Finding{})
	if err != nil {
		return nil, err
	}
	r.snap = snap
	return r, nil
}

// seedSnapshot performs the SINGLE store read + rule fold + predicate computation
// that backs every RunTools call. It is invoked once from newScenarioToolRunner
// (the only place that holds the *store.Store) and its result is frozen into
// r.snap. It mutates no shared state; it reads the seeded store and the
// operator-decisions corpus and returns an immutable snapshot.
//
// f carries only the finding id/family for the §3.8 LookupRules fallback; the
// surfaced events, the actor/source filter, and the two predicates are identical
// for every tier, so they are computed once here and rendered per-tier later.
func (r *scenarioToolRunner) seedSnapshot(st *store.Store, repoRoot string, f finding.Finding) (scenarioSnapshot, error) {
	var snap scenarioSnapshot

	// --- search-events: the one read the predicates + the model both consume. ---
	// Filter by the finding's actor + source so the snapshot scopes to the entity
	// under investigation (production scopes the read the same way; an empty
	// actor/source yields the full stream, the unfiltered read).
	in := tools.SearchEventsInput{Actor: r.actor, Source: r.source}
	env, err := tools.SearchEventsWrapped(st, in, r.family, r.meta)
	if err != nil {
		// A genuine schema violation (unreadable store, malformed record). The
		// cascade treats a tool ERROR as a fail-safe escalate, so surface it.
		return scenarioSnapshot{}, fmt.Errorf("search-events: %w", err)
	}
	// FIX 2 (EVAL FIDELITY): when the actor-filter returns NO events for a finding
	// about a NEW actor, the creation events are authored by a DIFFERENT principal
	// (ID-01). Surface events whose target / principal_id / display_name names the
	// finding actor so triage can resolve ID-01 as designed. This only ADDS
	// resolving evidence when the direct read was empty; it never suppresses events.
	if len(env.Events) == 0 && r.actor != "" {
		if alt := r.eventsNamingActor(st); len(alt) > 0 {
			env.Events = alt
		}
	}
	// §3.8 matched_rules fold. SearchEventsWrapped resolves the corpus via the
	// binary-walk (the PRODUCTION path); under the eval harness that walk can miss
	// the corpus, so fall back to the explicit-repoRoot LookupRules. Either way the
	// model sees the SAME matched_rules production folds in, reproducibly (§4.1).
	if len(env.MatchedRules) == 0 && repoRoot != "" && r.family != "" {
		if out, lErr := tools.LookupRules(repoRoot, lookupInput(f, r.family, r.meta)); lErr == nil {
			env.MatchedRules = out.Rules
		}
	}
	snap.events = env.Events
	snap.matchedRules = env.MatchedRules
	snap.searchEmpty = len(env.Events) == 0

	// --- the observable forces, computed ONCE over the frozen events. -----------
	// SHARED IMPLEMENTATION: the three predicates are the FREE functions in
	// core/observe — the SAME functions the production core/toolrun.Runner calls —
	// so the eval and the prod runner emit byte-identical booleans + details
	// (closing the eval-vs-prod divergence veracity flagged). The inputs are exactly
	// what both runners hold: the finding actor, the typed baseline, the frozen
	// surfaced events.
	snap.zeroHist, snap.zeroDetail = observe.ZeroHistoryAccess(r.actor, r.baseline, snap.events)
	snap.roleGrant, snap.roleDetail = observe.RoleGrantByActor(r.actor, r.baseline, snap.events)
	snap.bulkExport, snap.bulkDetail = observe.BulkExportNoJustification(r.actor, snap.events)

	// --- search-findings (investigate tier renders this; read once). ------------
	if fs, fErr := tools.SearchFindings(st, tools.SearchFindingsInput{Actor: r.actor}); fErr == nil {
		snap.findings = fs
	}

	return snap, nil
}

// RunTools gathers evidence for one tier over THIS scenario's telemetry and
// returns the boxed tool transcript + structural signals. The cascade boxes the
// Text as UNTRUSTED before it reaches the model (tier.go). tier scopes the
// toolset: triage runs search-events + check-baseline; investigate adds
// search-findings (the deeper sweep).
//
// ToolEmpty is set when the relied-on search-events returned no events: an empty
// read is data, not a dismissal — the fail-safe force-escalates a resolve built
// on it (§3.4 / §2.5).
func (r *scenarioToolRunner) RunTools(ctx context.Context, tier string, f finding.Finding) (agent.ToolEvidence, error) {
	// CONCURRENCY-SAFE BY CONSTRUCTION. RunTools reads ONLY the immutable snapshot
	// (r.snap, frozen in newScenarioToolRunner) and the immutable baseline/meta,
	// and writes ONLY to its own local strings.Builders. It does NOT touch the git
	// store, the corpus walk, or any shared map — so the deep-panel fan-out's three
	// concurrent RunTools calls render IDENTICAL evidence and IDENTICAL predicates
	// regardless of goroutine scheduling. The earlier design re-read the store on
	// every call; a concurrent partial git read could flip the role-grant /
	// zero-history force (the recurring -race flake). The single up-front read kills
	// that class.
	//
	// FIX 1: build ONE text section PER TOOL (baseline / events / findings) so the
	// cascade boxes each as its OWN WrapUntrusted field, each independently 1024-
	// capped — the high-signal check-baseline + relationship evidence (VA-03's
	// zero-history discriminator) survives the cap instead of being truncated
	// inside one concatenated blob.
	var eventsB, baselineB, findingsB strings.Builder
	calls := 0
	distinct := 0

	// --- search-events (every tier) — rendered from the frozen snapshot. ------
	// COMPACT rendering, not the full JSON envelope: each per-tool field is still
	// 1024-capped by the cascade's per-field sanitizer (sanitize.go) — the SAME cap
	// the production model sees. We render the high-signal facts (event ids, matched
	// rule ids+family, per-event discriminating metadata) so the salient evidence
	// survives the cap. The envelope is reconstructed from the snapshot's frozen
	// events + matched rules so writeSearchEvents renders exactly as before.
	calls++
	distinct++
	writeSearchEvents(&eventsB, SearchEventsEnvelopeFromSnapshot(r.snap.events, r.snap.matchedRules))

	// --- check-baseline (every tier) — "is this routine for this actor". ------
	// CheckBaseline is a PURE function over the immutable baseline (no store I/O,
	// no shared mutation), so it stays inline; its result is deterministic.
	if r.actor != "" {
		bl, err := tools.CheckBaseline(r.baseline, tools.CheckBaselineInput{
			Entity:    r.actor,
			Source:    r.source,
			EventType: r.eventType(),
		})
		if err == nil {
			calls++
			distinct++
			writeCheckBaseline(&baselineB, r.actor, bl)
		}
		// A check-baseline error is only "entity is required" (we guard actor !=
		// "" above), so it cannot fire here; if it ever did, we omit the block
		// rather than fail the whole evidence gather — search-events still ran.
	}

	// --- search-findings (investigate tier only) — rendered from the snapshot. -
	if strings.EqualFold(tier, "investigate") {
		calls++
		distinct++
		writeSearchFindings(&findingsB, r.snap.findings)
	}

	return agent.ToolEvidence{
		// FIX 1: per-tool boxed fields. Text is left empty so the cascade boxes the
		// per-tool fields individually (each independently 1024-capped).
		BaselineText:  baselineB.String(),
		EventsText:    eventsB.String(),
		FindingsText:  findingsB.String(),
		ToolCalls:     calls,
		DistinctTools: distinct,
		ToolEmpty:     r.snap.searchEmpty,
		// FIX 3 (OBSERVABLE FORCE-ESCALATE, event-keyed): the two structural
		// predicates, computed ONCE in seedSnapshot over the REAL surfaced events +
		// the typed baseline (never the model). Returned identically on every call.
		ZeroHistoryAccess:         r.snap.zeroHist,
		ZeroHistoryDetail:         r.snap.zeroDetail,
		RoleGrantByActor:          r.snap.roleGrant,
		RoleGrantDetail:           r.snap.roleDetail,
		BulkExportNoJustification: r.snap.bulkExport,
		BulkExportDetail:          r.snap.bulkDetail,
	}, nil
}

// eventsNamingActor (FIX 2) returns the events whose TARGET / principal_id /
// display_name names the finding actor — the events that CREATED a new actor,
// authored by a different principal. It is the empty-actor-filter fallback for a
// NEW-actor finding: search-events keyed on the finding actor returns nothing
// because the new actor authored no events yet, but it appears as the object of
// its own creation. Returns the matching EventView set (empty when none match), so
// triage sees the benign creation context (ID-01) instead of an empty read.
// eventsNamingActor is called ONCE from seedSnapshot (which holds the store)
// while building the immutable snapshot — never from the concurrent RunTools path
// — so it takes the store explicitly rather than from a runner field.
func (r *scenarioToolRunner) eventsNamingActor(st *store.Store) []tools.EventView {
	if r.actor == "" {
		return nil
	}
	full, _, err := tools.SearchEvents(st, tools.SearchEventsInput{})
	if err != nil {
		return nil
	}
	al := strings.ToLower(strings.TrimSpace(r.actor))
	out := []tools.EventView{}
	for _, ev := range projectEventViews(full) {
		named := false
		// The new actor appears as the TARGET of its creation (a service-principal
		// path ending in the actor name) ...
		if tl := strings.ToLower(ev.Target); strings.Contains(tl, al) {
			named = true
		}
		// ... or as the principal_id / display_name in the grant/creation metadata.
		if !named {
			for _, k := range []string{"principal_id", "display_name"} {
				if v, ok := ev.Metadata[k]; ok && strings.Contains(strings.ToLower(v), al) {
					named = true
					break
				}
			}
		}
		if named {
			out = append(out, ev)
		}
	}
	return out
}

// projectEventViews projects typed events into the flat EventView the runner
// reasons over, reusing the EXACT projection the envelope uses (target/action +
// the FIX 1 discriminating metadata, each sanitized individually) so the runner's
// force-escalate predicates read the same EventView the model sees.
func projectEventViews(events []event.Event) []tools.EventView {
	return tools.EventViewsFor(events)
}

// lookupInput builds the LookupRules input from the finding + observable metadata
// predicate. FindingID/FindingFamily are required by the tool; the observable
// metadata rides in the legacy nested FindingMetadata shim (the rule matcher
// reads it case-insensitively, exactly as the §3.8 fold does).
func lookupInput(f finding.Finding, family string, meta map[string]string) tools.LookupRulesInput {
	id := f.ID
	if id == "" {
		id = "eval-finding"
	}
	md := map[string]string{}
	for k, v := range meta {
		md[k] = v
	}
	return tools.LookupRulesInput{
		FindingID:       id,
		FindingFamily:   family,
		FindingMetadata: md,
	}
}

// eventType returns the finding's event_type metadata (the bucket check-baseline
// reports FrequencyForType against), or "".
func (r *scenarioToolRunner) eventType() string {
	if r.meta == nil {
		return ""
	}
	return r.meta["event_type"]
}

// seedScenarioStore creates a fresh git-backed store under tmpDir and appends the
// scenario's events + finding into it. tmpDir must be empty (the caller owns it,
// typically t.TempDir or a per-scenario os.MkdirTemp). The store IS the same
// git-backed source of truth core/tools reads in production — so the tools run
// over real committed records, not a mock.
func seedScenarioStore(tmpDir string, s *exam.Scenario) (*store.Store, error) {
	if err := gitInit(tmpDir); err != nil {
		return nil, err
	}
	st, err := store.Open(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("seed store: open: %w", err)
	}
	for i, ev := range s.Events {
		rec := eventRecord(ev)
		if _, err := st.Append(store.KindEvents, rec); err != nil {
			return nil, fmt.Errorf("seed store: append event[%d]: %w", i, err)
		}
	}
	if s.Finding != nil {
		if _, err := st.Append(store.KindFindings, findingRecord(s)); err != nil {
			return nil, fmt.Errorf("seed store: append finding: %w", err)
		}
	}
	return st, nil
}

// eventRecord projects an exam.Event into the on-disk event.Event JSON shape the
// store persists and tools.SearchEvents replays. The rich exam metadata is
// carried in Payload so it survives the round-trip (the tool projects only the
// flat EventView fields, but the payload keeps the record self-describing).
func eventRecord(ev exam.Event) event.Event {
	out := event.Event{
		ID:     ev.ID,
		Source: ev.Source,
		Type:   ev.EventType,
		Actor:  ev.Actor,
	}
	if ts := parseScenarioTime(ev.Timestamp); !ts.IsZero() {
		out.Timestamp = ts
	}
	payload := map[string]any{
		"action":   ev.Action,
		"target":   ev.Target,
		"severity": ev.Severity,
	}
	if len(ev.Metadata) > 0 {
		payload["metadata"] = map[string]any(ev.Metadata)
	}
	if raw, err := json.Marshal(payload); err == nil {
		out.Payload = raw
	}
	return out
}

// findingRecord projects the scenario's finding block into a finding.Finding the
// store persists and tools.SearchFindings replays — same field mapping as the
// runner's findingFromScenario, kept here so the seeded stream matches what the
// cascade resolves.
func findingRecord(s *exam.Scenario) finding.Finding {
	return findingFromScenario(s)
}

// eventMetaRenderOrder is the deterministic order the discriminating per-event
// metadata (FIX 1) is rendered in the compact transcript, so the transcript is
// reproducible (§4.1). It is the same key set EventView.Metadata carries; rendering
// in a fixed order (not map iteration order) keeps the boxed text byte-stable.
var eventMetaRenderOrder = []string{
	"operation_count",
	"blobs_accessed",
	"bytes_read",
	"resource_count",
	"rows_affected",
	"export_format",
	"includes_pii",
	"role",
	"principal_id",
	"ip",
	"location",
	"user_agent",
	"job_id",
	"ticket_id",
	"schedule",
	"scheduled",
	"maintenance_window",
	"window_id",
	"post_deploy",
}

// SearchEventsEnvelopeFromSnapshot reconstructs the minimal SearchEventsEnvelope
// writeSearchEvents renders — its Events and MatchedRules — from the frozen
// snapshot slices. It exists so RunTools renders the SAME compact transcript it
// always did while reading ONLY immutable snapshot data (no store re-read). Only
// the two fields writeSearchEvents consumes are populated; the rest of the
// envelope (FilterApplied, Notes) is not rendered by writeSearchEvents and is left
// at its zero value deliberately. The input slices are treated as read-only.
func SearchEventsEnvelopeFromSnapshot(events []tools.EventView, rules []tools.OperatorRule) tools.SearchEventsEnvelope {
	return tools.SearchEventsEnvelope{
		Events:       events,
		MatchedRules: rules,
	}
}

// writeSearchEvents renders the search-events result COMPACTLY: one line listing
// the matched event ids (the model's anchor to "which events"), one line per
// event with the salient fields, and the §3.8 matched rules as id+family (NOT the
// full multi-line operator_directive, which would blow the 1024-char field cap).
// The event metadata that drove the rule fold (maintenance_window, scheduled, …)
// is surfaced so the model can see WHY a rule applies.
func writeSearchEvents(b *strings.Builder, env tools.SearchEventsEnvelope) {
	b.WriteString("search-events: ")
	if len(env.Events) == 0 {
		b.WriteString("no events matched the filter (empty read).\n")
	} else {
		ids := make([]string, 0, len(env.Events))
		for _, e := range env.Events {
			ids = append(ids, e.ID)
		}
		b.WriteString(fmt.Sprintf("%d events [%s]\n", len(env.Events), strings.Join(ids, ", ")))
		for _, e := range env.Events {
			// EVAL FIDELITY (FIX 4): surface target + action so the model sees WHAT each
			// event did and to WHAT — the per-event relationship detail legion's academy
			// fed its agent. Both are already sanitized at projection (sanitizeEventField).
			b.WriteString(fmt.Sprintf("  - %s %s/%s actor=%s", e.ID, e.Source, e.Type, e.Actor))
			if e.Action != "" {
				b.WriteString(" action=" + e.Action)
			}
			if e.Target != "" {
				b.WriteString(" target=" + e.Target)
			}
			// FIX 1: the discriminating per-event metadata (volume magnitude, origin,
			// grant shape) the model needs to tell an attack apart from benign load —
			// rendered in a deterministic key order (§4.1 reproducibility). Each value
			// is already sanitized individually at projection.
			for _, k := range eventMetaRenderOrder {
				if v, ok := e.Metadata[k]; ok && v != "" {
					b.WriteString(" " + k + "=" + v)
				}
			}
			b.WriteString(" " + e.Timestamp + "\n")
		}
	}
	if len(env.MatchedRules) > 0 {
		parts := make([]string, 0, len(env.MatchedRules))
		for _, ru := range env.MatchedRules {
			parts = append(parts, ru.ID+"("+ru.AppliesTo.Family+")")
		}
		b.WriteString("matched_rules: " + strings.Join(parts, ", ") + "\n")
	}
}

// writeCheckBaseline renders the check-baseline result COMPACTLY: known?, the
// aggregate frequency, the per-type frequency the finding asked about (so the
// model can answer "is this routine for this actor at this volume?"), and the
// per-type breakdown. This is the evidence the structural gate scores for
// "routine activity".
func writeCheckBaseline(b *strings.Builder, actor string, bl tools.CheckBaselineResult) {
	b.WriteString(fmt.Sprintf("check-baseline: actor=%s known=%t frequency=%d", actor, bl.Known, bl.Frequency))
	if bl.EventType != "" {
		b.WriteString(fmt.Sprintf(" frequency_for_%s=%d", bl.EventType, bl.FrequencyForType))
	}
	b.WriteString("\n")
	if len(bl.FrequencyByType) > 0 {
		// Deterministic key order so the transcript is reproducible (§4.1).
		keys := make([]string, 0, len(bl.FrequencyByType))
		for k := range bl.FrequencyByType {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, bl.FrequencyByType[k]))
		}
		b.WriteString("  by_type: " + strings.Join(parts, " ") + "\n")
	}
	// EVAL FIDELITY (FIX 4): surface the actor↔target relationships so the model can
	// answer "has this actor touched this target before, and how often" — the
	// academy's relationship evidence. Deterministic key order (§4.1 reproducibility).
	if len(bl.Relationships) > 0 {
		keys := make([]string, 0, len(bl.Relationships))
		for k := range bl.Relationships {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			rel := bl.Relationships[k]
			seg := fmt.Sprintf("%s(count=%d", k, rel.Count)
			if rel.FirstSeen != "" {
				seg += " first_seen=" + rel.FirstSeen
			}
			if rel.LastSeen != "" {
				seg += " last_seen=" + rel.LastSeen
			}
			seg += ")"
			parts = append(parts, seg)
		}
		b.WriteString("  relationships: " + strings.Join(parts, " ") + "\n")
	}
}

// writeSearchFindings renders the findings stream COMPACTLY: one line per finding
// (id/type/actor). The deeper-sweep evidence the investigate tier reads.
func writeSearchFindings(b *strings.Builder, fs []finding.Finding) {
	b.WriteString(fmt.Sprintf("search-findings: %d findings\n", len(fs)))
	for _, f := range fs {
		b.WriteString(fmt.Sprintf("  - %s type=%s actor=%s\n", f.ID, f.Type, f.Actor))
	}
}

// baselineFromScenario reconstructs a pkg/baseline.Baseline from the scenario's
// baseline block so tools.CheckBaseline answers over the scenario's OWN history:
//
//   - known_entities.actors → KnownActors (drives Known=true)
//   - frequency_tables       → FrequencyTables (drives Frequency / FrequencyByType
//     / FrequencyForType — "is this routine for this actor")
//
// A scenario with no baseline yields nil; CheckBaseline treats a nil baseline as
// "unknown entity, zero frequency", which is itself valid evidence.
func baselineFromScenario(s *exam.Scenario) *baseline.Baseline {
	if s.Baseline == nil {
		return nil
	}
	b := &baseline.Baseline{
		KnownUsers:      map[string]baseline.UserProfile{},
		KnownActors:     append([]string{}, s.Baseline.KnownEntities.Actors...),
		FrequencyTables: map[string]int{},
		Relationships:   map[string]baseline.Relationship{},
		ActorHours:      map[string][]int{},
	}
	for k, v := range s.Baseline.FrequencyTables {
		b.FrequencyTables[k] = v
	}
	// CLASS D (timing baseline): the corpus encodes an actor's KNOWN active hours
	// NOT as actor_hours but as 5-segment frequency keys
	// "source:event_type:actor:N:partofday" (UT-03 / UT-05 carry these). Derive
	// ActorHours from those keys so unusual-timing has a profile to compare an
	// event's UTC hour against. Only the part-of-day token's hour set is known —
	// the index segment (N) is a window ordinal, not an hour. ActorRoles is
	// deliberately NOT populated (priv-escalation must still escalate a known-role
	// grant — the PE-05 Known-Actor-Trust trap).
	deriveActorHours(b, s.Baseline.FrequencyTables)
	// EVAL FIDELITY (FIX 4): reconstruct the scenario's relationships table into the
	// typed baseline so check-baseline can surface the actor↔target history legion's
	// academy fed its agent. The scenario keys an "actor:target" pair → {count,
	// first_seen, last_seen}; mirror it verbatim.
	for k, rel := range s.Baseline.Relationships {
		b.Relationships[k] = baseline.Relationship{
			Count:     rel.Count,
			FirstSeen: rel.FirstSeen,
			LastSeen:  rel.LastSeen,
		}
	}
	// Surface known actors as profiles too, so entityKnown (which checks
	// KnownUsers as well as KnownActors) resolves them and a last-seen lookup has
	// a home. last_seen is left zero (the scenario baseline carries no per-actor
	// last-seen; relationships are not consumed by CheckBaseline).
	for _, a := range s.Baseline.KnownEntities.Actors {
		b.KnownUsers[a] = baseline.UserProfile{}
	}
	return b
}

// partOfDayHours maps a corpus part-of-day token to the set of UTC hours it
// covers. The corpus encodes an actor's active windows as these tokens in its
// 5-segment frequency keys; unusual-timing compares an event's UTC hour against
// the union of hours for the tokens the actor carries. Boundaries follow the
// conventional quartering of the day (night 0-5, morning 6-11, afternoon 12-17,
// evening 18-23).
func partOfDayHours(token string) []int {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "night":
		return []int{0, 1, 2, 3, 4, 5}
	case "morning":
		return []int{6, 7, 8, 9, 10, 11}
	case "afternoon":
		return []int{12, 13, 14, 15, 16, 17}
	case "evening":
		return []int{18, 19, 20, 21, 22, 23}
	default:
		return nil
	}
}

// deriveActorHours scans the frequency_tables for 5-segment timing keys
// "source:event_type:actor:N:partofday" and populates b.ActorHours[actor] with the
// union of UTC hours implied by the part-of-day tokens present. Actors with no
// 5-segment keys get no entry (HasActorHours stays false for them → unusual-timing
// has nothing to compare and correctly stays silent — the corpus-data limit the
// design documents for UT-01/02/04/06/07).
func deriveActorHours(b *baseline.Baseline, freq map[string]int) {
	seen := map[string]map[int]bool{}
	for key := range freq {
		segs := strings.Split(key, ":")
		if len(segs) != 5 {
			continue
		}
		actor := segs[2]
		hours := partOfDayHours(segs[4])
		if len(hours) == 0 {
			continue
		}
		if seen[actor] == nil {
			seen[actor] = map[int]bool{}
		}
		for _, h := range hours {
			seen[actor][h] = true
		}
	}
	for actor, hs := range seen {
		out := make([]int, 0, len(hs))
		for h := range hs {
			out = append(out, h)
		}
		sort.Ints(out)
		b.ActorHours[actor] = out
	}
}

// --- scenario field extractors (shared by the runner + the rule fold) ---------

// scenarioFamily is the §3.8 rule-fold family: the finding's detector (the
// canonical family). Falls back to the scenario top-level detector.
func scenarioFamily(s *exam.Scenario) string {
	if s.Finding != nil && s.Finding.Detector != "" {
		return s.Finding.Detector
	}
	return s.Detector
}

// scenarioActor is the entity under investigation: the finding metadata actor,
// falling back to the first event's actor.
func scenarioActor(s *exam.Scenario) string {
	if s.Finding != nil {
		if a := metaString(s.Finding.Metadata, "actor"); a != "" {
			return a
		}
	}
	if len(s.Events) > 0 {
		return s.Events[0].Actor
	}
	return ""
}

// scenarioSource is the finding's source metadata, falling back to the first
// event's source.
func scenarioSource(s *exam.Scenario) string {
	if s.Finding != nil {
		if src := metaString(s.Finding.Metadata, "source"); src != "" {
			return src
		}
	}
	if len(s.Events) > 0 {
		return s.Events[0].Source
	}
	return ""
}

// scenarioObservableMeta builds the flat string predicate the §3.8 rule matcher
// evaluates: the finding's metadata UNIONED with the metadata carried on the
// scenario's events (maintenance_window, scheduled, location_change, …). Event
// metadata takes precedence on a key collision — the observable event field is
// the ground truth the operator rules key on; the finding metadata seeds the
// less-observable fields (actor, source, event_type). Non-string values are
// rendered with %v so a numeric/boolean flag still matches a string predicate.
//
// Folding against this union — not the finding metadata alone — is what makes the
// matched_rules fold fire: R-001 (maintenance_window) / R-002 (scheduled) and
// their kin key on event fields, and a real agent only learns those after
// search-events surfaces them. The runner surfaces the same evidence proactively.
func scenarioObservableMeta(s *exam.Scenario) map[string]string {
	out := map[string]string{}
	if s == nil {
		return out
	}
	// Seed from finding metadata first.
	if s.Finding != nil {
		for k, v := range s.Finding.Metadata {
			out[k] = metaValueString(v)
		}
	}
	// Union event metadata over it (observable fields win).
	for _, ev := range s.Events {
		for k, v := range ev.Metadata {
			out[k] = metaValueString(v)
		}
	}
	return out
}

// metaValueString renders a metadata value as the string the rule matcher
// compares (case-insensitively). Strings pass through; everything else is %v so a
// numeric or boolean flag still matches a string predicate (e.g. true → "true").
func metaValueString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// --- helpers ------------------------------------------------------------------

// parseScenarioTime parses a scenario RFC3339 timestamp, returning the zero time
// on empty/unparseable input (the tools treat a zero timestamp as "unbounded").
func parseScenarioTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// gitInit initializes a bare-minimum git work tree at dir so store.Open accepts
// it (the store requires an existing .git and runs hermetically). We set a
// deterministic identity and disable global/system config bleed, matching the
// store's own hermetic git invocations.
func gitInit(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("git init: mkdir: %w", err)
	}
	if out, err := runGit(dir, "init", "-q"); err != nil {
		return fmt.Errorf("git init: %v: %s", err, out)
	}
	return nil
}

// runGit runs a git subcommand in dir with a deterministic identity and no
// global/system config bleed — the same hermetic discipline core/store uses, so
// a freshly seeded scenario store is reproducible regardless of the operator's
// git environment.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=mallcop-eval",
		"GIT_AUTHOR_EMAIL=eval@mallcop.app",
		"GIT_COMMITTER_NAME=mallcop-eval",
		"GIT_COMMITTER_EMAIL=eval@mallcop.app",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}
