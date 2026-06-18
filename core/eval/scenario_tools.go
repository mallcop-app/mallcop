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
	"context"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
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
type scenarioToolRunner struct {
	store    *store.Store
	baseline *baseline.Baseline
	repoRoot string // for the §3.8 operator-decisions rule corpus (matched_rules)

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
	return &scenarioToolRunner{
		store:    st,
		baseline: baselineFromScenario(s),
		repoRoot: repoRoot,
		family:   scenarioFamily(s),
		actor:    scenarioActor(s),
		source:   scenarioSource(s),
		meta:     scenarioObservableMeta(s),
	}, nil
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
	var b strings.Builder
	calls := 0
	distinct := 0
	searchEmpty := false

	// --- search-events (every tier) — folds §3.8 matched_rules. ---------------
	// Filter by the finding's actor + source so the model sees the events for the
	// entity under investigation (production scopes the read the same way; an
	// empty actor/source yields the full stream, which is the unfiltered read).
	in := tools.SearchEventsInput{Actor: r.actor, Source: r.source}
	env, err := tools.SearchEventsWrapped(r.store, in, r.family, r.meta)
	if err != nil {
		// A genuine schema violation (unreadable store, malformed record) — the
		// cascade treats a tool ERROR as a fail-safe escalate. Surface it.
		return agent.ToolEvidence{}, fmt.Errorf("search-events: %w", err)
	}
	// §3.8 matched_rules fold. SearchEventsWrapped resolves the operator-decisions
	// corpus via the binary-walk (findConfigRoot) — the PRODUCTION path. Under the
	// eval harness the "binary" is the test/harness binary, so the walk can miss
	// the corpus; we then fold the rules DETERMINISTICALLY through the real
	// tools.LookupRules, which takes our explicit repoRoot. Either way the model
	// sees the SAME matched_rules production folds in (§3.8), reproducibly (§4.1).
	if len(env.MatchedRules) == 0 && r.repoRoot != "" && r.family != "" {
		if out, lErr := tools.LookupRules(r.repoRoot, lookupInput(f, r.family, r.meta)); lErr == nil {
			env.MatchedRules = out.Rules
		}
	}
	calls++
	distinct++
	// COMPACT rendering, not the full JSON envelope: the cascade boxes this whole
	// transcript as ONE untrusted field and the sanitizer caps a field at 1024
	// chars (sanitize.go) — the SAME cap the production model sees. A verbose
	// envelope dump would be truncated mid-evidence, dropping check-baseline and
	// the matched rules. We render the high-signal facts (event ids, matched rule
	// ids+family, baseline frequencies) so the salient evidence survives the cap.
	writeSearchEvents(&b, env)
	if len(env.Events) == 0 {
		searchEmpty = true
	}

	// --- check-baseline (every tier) — "is this routine for this actor". ------
	if r.actor != "" {
		bl, err := tools.CheckBaseline(r.baseline, tools.CheckBaselineInput{
			Entity:    r.actor,
			Source:    r.source,
			EventType: r.eventType(),
		})
		if err == nil {
			calls++
			distinct++
			writeCheckBaseline(&b, r.actor, bl)
		}
		// A check-baseline error is only "entity is required" (we guard actor !=
		// "" above), so it cannot fire here; if it ever did, we omit the block
		// rather than fail the whole evidence gather — search-events still ran.
	}

	// --- search-findings (investigate tier only) — the deeper sweep. ----------
	if strings.EqualFold(tier, "investigate") {
		fs, err := tools.SearchFindings(r.store, tools.SearchFindingsInput{Actor: r.actor})
		if err == nil {
			calls++
			distinct++
			writeSearchFindings(&b, fs)
		}
	}

	return agent.ToolEvidence{
		Text:          b.String(),
		ToolCalls:     calls,
		DistinctTools: distinct,
		ToolEmpty:     searchEmpty,
	}, nil
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
			b.WriteString(fmt.Sprintf("  - %s %s/%s actor=%s %s\n", e.ID, e.Source, e.Type, e.Actor, e.Timestamp))
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
	}
	for k, v := range s.Baseline.FrequencyTables {
		b.FrequencyTables[k] = v
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
