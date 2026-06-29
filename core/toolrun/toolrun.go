// Package toolrun is the PRODUCTION ToolRunner — the live agent.ToolRunner the
// scan pipeline wires into the cascade (CascadeOptions.Tools). It lives OUTSIDE
// core/agent so the dependency-injection seam and the import-lint hold: core/agent
// defines the ToolRunner interface and imports NEITHER this package nor core/observe;
// the concrete implementation is wired only at the cmd layer (scan.go).
//
// WHAT IT IS: the prod counterpart of core/eval's per-scenario scenarioToolRunner.
// Both reach the REAL core/tools (search-events folding operator rules §3.8,
// check-baseline, search-findings) over a git-backed store + typed baseline, and
// both compute the THREE observable force-escalate predicates via the SHARED
// core/observe package — so the eval and prod runners emit BYTE-IDENTICAL
// observables, closing the eval-vs-prod divergence veracity flagged. The validated
// 83.9% / 2-missed-attacks transfers because the gate-relevant signals are computed
// by one shared implementation fed identical inputs.
//
// THE KEY DIFFERENCE FROM EVAL: eval builds ONE runner per scenario over a frozen
// snapshot (one immutable read, because the deep-panel fan-out calls RunTools
// concurrently against the same runner). The PROD runner serves MANY findings from
// one Runner constructed once in scan.go, so it CANNOT freeze a single snapshot —
// RunTools derives the per-finding read from the LIVE finding on every call. That is
// concurrency-safe by construction: each RunTools reads the Store independently
// (Store.Load reads committed HEAD via git cat-file) and writes only local builders;
// there is no shared mutable snapshot.
//
// IMPORT DISCIPLINE: core/toolrun may import core/store, core/tools, pkg/baseline,
// pkg/finding, and core/observe — none repo-wide banned. It is NOT core/agent, so
// the stricter core/agent bans (inference/net/http/net/url) do not apply, and it
// imports no campfire/legion/agent-framework/vendor SDK (see imports_test.go).
package toolrun

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/observe"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/tools"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// Runner is the production agent.ToolRunner. It is constructed ONCE (in scan.go)
// and serves every finding the cascade resolves. Store + Baseline are the live
// production read sources; RepoRoot pins the §3.8 operator-decisions corpus (pass
// "" to let SearchEventsWrapped resolve it via the os.Executable binary-walk, the
// production path).
type Runner struct {
	Store    *store.Store
	Baseline *baseline.Baseline
	RepoRoot string
}

// compile-time assertion that Runner satisfies the cascade's tool seam.
var _ agent.ToolRunner = (*Runner)(nil)

// RunTools gathers evidence for one finding at one tier over the LIVE store +
// baseline and returns the boxed (untrusted) tool transcript + the structural
// observable signals the cascade's force-escalate gate scores. tier scopes the
// toolset: triage runs search-events + check-baseline; investigate adds
// search-findings.
//
// It mirrors the eval scenarioToolRunner's RunTools EXACTLY so the two emit
// identical observables: same filter derivation, same SearchEventsWrapped wrapper,
// same FIX-2 new-actor fallback, same searchEmpty ordering, same predicate inputs,
// same per-tool boxing. The only divergence is the source of the derivation inputs
// (a live finding.Finding here, an exam.Scenario in eval) — and the parity test
// feeds the prod runner a finding built FROM the scenario so that derivation is
// proven equivalent.
func (r *Runner) RunTools(ctx context.Context, tier string, f finding.Finding) (agent.ToolEvidence, error) {
	// (1) Derive the filters from the live finding, as eval derives them from the
	// scenario. actor/source scope the search-events read; family drives the §3.8
	// rule fold; eventType is the check-baseline bucket.
	actor := strings.TrimSpace(f.Actor)
	source := findingSource(f)
	family := findingFamily(f)

	// meta is the OBSERVABLE predicate the §3.8 fold + transcript key on: the finding
	// metadata UNIONED with the metadata carried on the store's events (event values
	// WIN), replicating eval's scenarioObservableMeta EXACTLY — eval unions over ALL
	// the scenario's events (not the actor-filtered read), so we union over the FULL
	// event stream here, BEFORE the search, so the very first SearchEventsWrapped call
	// folds matched_rules on the observable event fields just as eval does.
	meta := findingObservableMeta(f, r.allEventViews())
	eventType := meta["event_type"]

	// (2) search-events over the SAME wrapper eval uses: casefold + time-fallback +
	// §3.8 matched-rules fold via the binary-walk corpus (RepoRoot = production
	// os.Executable walk when r.RepoRoot == "").
	in := tools.SearchEventsInput{Actor: actor, Source: source}
	env, err := tools.SearchEventsWrapped(r.Store, in, family, meta)
	if err != nil {
		return agent.ToolEvidence{}, fmt.Errorf("search-events: %w", err)
	}
	// FIX-2 new-actor fallback: when the actor-filtered read is empty for a finding
	// about a NEW actor, surface the events that NAME the actor (its creation events,
	// authored by a different principal — ID-01). Lifted from eval's eventsNamingActor;
	// it needs the LIVE store so it lives here, sharing the algorithm so eval + prod
	// stay identical. Applied BEFORE the §3.8 fallback + searchEmpty, matching eval's
	// ordering in seedSnapshot.
	if len(env.Events) == 0 && actor != "" {
		if alt := r.eventsNamingActor(actor); len(alt) > 0 {
			env.Events = alt
		}
	}
	// §3.8 fallback: if the binary-walk did not resolve the corpus but an explicit
	// RepoRoot is set, fold via LookupRules (the explicit-root path eval uses under
	// test). Production passes RepoRoot="" and relies on the binary-walk inside
	// SearchEventsWrapped, so this only fires when a caller pins the root. Uses the
	// SAME event-unioned meta eval passes (r.meta), so the fold is identical.
	if len(env.MatchedRules) == 0 && r.RepoRoot != "" && family != "" {
		if out, lErr := tools.LookupRules(r.RepoRoot, lookupInput(f, family, meta)); lErr == nil {
			env.MatchedRules = out.Rules
		}
	}

	// searchEmpty mirrors eval ToolEmpty EXACTLY: computed AFTER the FIX-2 fallback
	// folds in any naming events (eval's seedSnapshot sets searchEmpty at the SAME
	// point — post-fallback). A relied-on empty read is a finding, not a dismissal.
	searchEmpty := len(env.Events) == 0

	// (5) The observable force-escalate predicates over the REAL store + baseline,
	// computed via the SHARED core/observe functions — byte-identical to eval.
	zeroHist, zeroDetail := observe.ZeroHistoryAccess(actor, r.Baseline, env.Events)
	roleGrant, roleDetail := observe.RoleGrantByActor(actor, r.Baseline, env.Events)
	bulkExport, bulkDetail := observe.BulkExportNoJustification(actor, env.Events)

	// (6/7/8) Render the per-tier toolset into the three per-tool boxed fields.
	var eventsB, baselineB, findingsB strings.Builder
	calls := 0
	distinct := 0

	// search-events (every tier).
	calls++
	distinct++
	writeSearchEvents(&eventsB, env.Events, env.MatchedRules)

	// check-baseline (every tier).
	if actor != "" {
		if bl, bErr := tools.CheckBaseline(r.Baseline, tools.CheckBaselineInput{
			Entity:    actor,
			Source:    source,
			EventType: eventType,
		}); bErr == nil {
			calls++
			distinct++
			writeCheckBaseline(&baselineB, actor, bl)
		}
	}

	// search-findings (investigate tier only).
	if strings.EqualFold(tier, "investigate") {
		if fs, fErr := tools.SearchFindings(r.Store, tools.SearchFindingsInput{Actor: actor}); fErr == nil {
			calls++
			distinct++
			writeSearchFindings(&findingsB, fs)
		}
	}

	return agent.ToolEvidence{
		BaselineText:              baselineB.String(),
		EventsText:                eventsB.String(),
		FindingsText:              findingsB.String(),
		ToolCalls:                 calls,
		DistinctTools:             distinct,
		ToolEmpty:                 searchEmpty,
		ZeroHistoryAccess:         zeroHist,
		ZeroHistoryDetail:         zeroDetail,
		RoleGrantByActor:          roleGrant,
		RoleGrantDetail:           roleDetail,
		BulkExportNoJustification: bulkExport,
		BulkExportDetail:          bulkDetail,
	}, nil
}

// eventsNamingActor (FIX 2, lifted from eval) returns the events whose TARGET /
// principal_id / display_name names the finding actor — the empty-actor-filter
// fallback for a NEW-actor finding (the new actor authored no events yet but appears
// as the object of its own creation). It reads the FULL stream from the LIVE store,
// which is why it lives in core/toolrun (eval's copy is identical); sharing the
// algorithm keeps eval + prod byte-identical.
func (r *Runner) eventsNamingActor(actor string) []tools.EventView {
	if actor == "" {
		return nil
	}
	full, _, err := tools.SearchEvents(r.Store, tools.SearchEventsInput{})
	if err != nil {
		return nil
	}
	al := strings.ToLower(strings.TrimSpace(actor))
	out := []tools.EventView{}
	for _, ev := range tools.EventViewsFor(full) {
		named := false
		if tl := strings.ToLower(ev.Target); strings.Contains(tl, al) {
			named = true
		}
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

// allEventViews reads the FULL event stream from the live store and projects it to
// EventViews. It backs the observable-meta union (§3.8): eval unions event metadata
// over the finding metadata from ALL the scenario's events, so prod must union over
// the whole stream too — not the actor-filtered surfaced set — or a rule keyed on an
// event field the filter excluded would fail to fold and the transcript would drift.
// Returns nil on a read error (the union degrades to finding metadata alone).
func (r *Runner) allEventViews() []tools.EventView {
	full, _, err := tools.SearchEvents(r.Store, tools.SearchEventsInput{})
	if err != nil {
		return nil
	}
	return tools.EventViewsFor(full)
}

// --- derivation: live finding.Finding → the filters eval derives from a scenario.

// findingSource is the finding's source filter. finding.Source is shaped
// "detector:<family>"; the source the events are keyed on is the bare family OR an
// explicit source carried in the finding evidence/metadata. We prefer an explicit
// "source" meta (the production detector populates it), else strip the "detector:"
// prefix — matching scenarioSource, which reads the finding's source metadata.
func findingSource(f finding.Finding) string {
	if s := evidenceMeta(f)["source"]; s != "" {
		return s
	}
	return strings.TrimPrefix(strings.TrimSpace(f.Source), "detector:")
}

// findingFamily is the §3.8 rule-fold family: the finding's detector family. It is
// finding.Type (the canonical family the cascade floor keys on), matching
// scenarioFamily which returns the finding detector.
func findingFamily(f finding.Finding) string {
	return strings.TrimSpace(f.Type)
}

// findingObservableMeta builds the flat string predicate the §3.8 rule matcher
// evaluates: the finding's metadata UNIONED with the metadata carried on the
// surfaced events (event fields WIN on a collision), mirroring eval's
// scenarioObservableMeta exactly. The finding metadata seeds the less-observable
// fields (actor, source, event_type); the event metadata is the ground truth the
// operator rules key on. When events is nil the union is the finding metadata alone
// (the pre-read pass used for the initial rule fold).
func findingObservableMeta(f finding.Finding, events []tools.EventView) map[string]string {
	out := map[string]string{}
	// Seed from finding metadata (its evidence object + the canonical scalar fields).
	for k, v := range evidenceMeta(f) {
		out[k] = v
	}
	if out["actor"] == "" && strings.TrimSpace(f.Actor) != "" {
		out["actor"] = f.Actor
	}
	if out["source"] == "" {
		if s := findingSource(f); s != "" {
			out["source"] = s
		}
	}
	if out["event_type"] == "" && strings.TrimSpace(f.Type) != "" {
		out["event_type"] = f.Type
	}
	// Union event metadata OVER it (observable fields win).
	for _, ev := range events {
		for k, v := range ev.Metadata {
			out[k] = v
		}
	}
	return out
}

// evidenceMeta extracts a flat string map from the finding's Evidence JSON. The
// production detector stashes the finding's observable metadata in Evidence; we read
// any top-level string/scalar fields plus a nested "metadata" object (the legacy
// shape). Non-string scalars render with %v so a numeric/boolean flag still matches a
// string predicate. Returns an empty map (never nil) when Evidence is absent/opaque.
func evidenceMeta(f finding.Finding) map[string]string {
	out := map[string]string{}
	if len(f.Evidence) == 0 {
		return out
	}
	var raw map[string]any
	if err := json.Unmarshal(f.Evidence, &raw); err != nil {
		return out
	}
	absorb := func(m map[string]any) {
		for k, v := range m {
			switch vv := v.(type) {
			case string:
				out[k] = vv
			case map[string]any, []any:
				// nested objects/arrays are not flat predicate fields; skip.
			default:
				out[k] = fmt.Sprintf("%v", vv)
			}
		}
	}
	absorb(raw)
	if nested, ok := raw["metadata"].(map[string]any); ok {
		absorb(nested)
	}
	return out
}

// lookupInput builds the LookupRules input from the finding + observable metadata
// predicate, identical to eval's lookupInput so the explicit-root fold path matches.
func lookupInput(f finding.Finding, family string, meta map[string]string) tools.LookupRulesInput {
	id := f.ID
	if id == "" {
		id = "prod-finding"
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

// --- transcript renderers (replicated from eval, byte-identical output) ---------
//
// These mirror core/eval's writeSearchEvents / writeCheckBaseline /
// writeSearchFindings + eventMetaRenderOrder EXACTLY. They are replicated (not
// imported) because the eval renderers are unexported and importing core/eval into
// the runtime would pull the harness into the shipped binary and break the DI / lint
// discipline. The parity test asserts byte-equality of EventsText/BaselineText/
// FindingsText between the two runners, guarding against any drift in this copy.

// eventMetaRenderOrder is the deterministic order the discriminating per-event
// metadata is rendered, so the transcript is reproducible (§4.1). Identical to eval.
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

func writeSearchEvents(b *strings.Builder, events []tools.EventView, rules []tools.OperatorRule) {
	b.WriteString("search-events: ")
	if len(events) == 0 {
		b.WriteString("no events matched the filter (empty read).\n")
	} else {
		ids := make([]string, 0, len(events))
		for _, e := range events {
			ids = append(ids, e.ID)
		}
		b.WriteString(fmt.Sprintf("%d events [%s]\n", len(events), strings.Join(ids, ", ")))
		for _, e := range events {
			b.WriteString(fmt.Sprintf("  - %s %s/%s actor=%s", e.ID, e.Source, e.Type, e.Actor))
			if e.Action != "" {
				b.WriteString(" action=" + e.Action)
			}
			if e.Target != "" {
				b.WriteString(" target=" + e.Target)
			}
			for _, k := range eventMetaRenderOrder {
				if v, ok := e.Metadata[k]; ok && v != "" {
					b.WriteString(" " + k + "=" + v)
				}
			}
			b.WriteString(" " + e.Timestamp + "\n")
		}
	}
	if len(rules) > 0 {
		parts := make([]string, 0, len(rules))
		for _, ru := range rules {
			parts = append(parts, ru.ID+"("+ru.AppliesTo.Family+")")
		}
		b.WriteString("matched_rules: " + strings.Join(parts, ", ") + "\n")
	}
}

func writeCheckBaseline(b *strings.Builder, actor string, bl tools.CheckBaselineResult) {
	b.WriteString(fmt.Sprintf("check-baseline: actor=%s known=%t frequency=%d", actor, bl.Known, bl.Frequency))
	if bl.EventType != "" {
		b.WriteString(fmt.Sprintf(" frequency_for_%s=%d", bl.EventType, bl.FrequencyForType))
	}
	b.WriteString("\n")
	if len(bl.FrequencyByType) > 0 {
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

func writeSearchFindings(b *strings.Builder, fs []finding.Finding) {
	b.WriteString(fmt.Sprintf("search-findings: %d findings\n", len(fs)))
	for _, f := range fs {
		b.WriteString(fmt.Sprintf("  - %s type=%s actor=%s\n", f.ID, f.Type, f.Actor))
	}
}
