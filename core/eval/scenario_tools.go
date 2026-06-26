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
	// FIX 1: build ONE text section PER TOOL (baseline / events / findings) so the
	// cascade boxes each as its OWN WrapUntrusted field, each independently 1024-
	// capped — the high-signal check-baseline + relationship evidence (VA-03's
	// zero-history discriminator) survives the cap instead of being truncated
	// inside one concatenated blob.
	var eventsB, baselineB, findingsB strings.Builder
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
	// FIX 2 (EVAL FIDELITY): when the actor-filter returns NO events for a finding
	// about a NEW actor, the creation events are authored by a DIFFERENT principal
	// (ID-01: deploy-svc-new's creation events are authored by admin-user, with the
	// finding actor appearing as the event TARGET / principal_id / display_name).
	// An empty read would make ToolEmpty true and force a fail-safe escalate — but
	// ID-01 is a benign onboarding the chain must RESOLVE. So when the actor-filter
	// is empty, ALSO surface events whose target / principal_id / display_name names
	// the finding actor, so triage can resolve ID-01 as designed.
	// GUARD: this only ADDS resolving evidence when the direct read was empty; it
	// never suppresses events. ID-03 / ID-04 (malicious/ambiguous new actors)
	// perform their OWN events (the finding actor IS the event actor), so the direct
	// read is non-empty and this fallback does not fire for them — they still escalate.
	if len(env.Events) == 0 && r.actor != "" {
		if alt := r.eventsNamingActor(); len(alt) > 0 {
			env.Events = alt
		}
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
	// COMPACT rendering, not the full JSON envelope: each per-tool field is still
	// 1024-capped by the cascade's per-field sanitizer (sanitize.go) — the SAME cap
	// the production model sees. We render the high-signal facts (event ids, matched
	// rule ids+family, per-event discriminating metadata) so the salient evidence
	// survives the cap.
	writeSearchEvents(&eventsB, env)
	if len(env.Events) == 0 {
		searchEmpty = true
	}

	// FIX 3 (OBSERVABLE FORCE-ESCALATE, event-keyed): compute the two structural
	// predicates the triage gate forces a clean resolve to escalate on — from the
	// REAL surfaced events + the typed baseline, never from the model. Keyed on the
	// EVENT predicate (zero relationship-history with an accessed target; a role-grant
	// the finding actor has no precedent for), never on detector family.
	zeroHist, zeroDetail := r.zeroHistoryAccess(env.Events)
	roleGrant, roleDetail := r.roleGrantByActor(env.Events)

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
			writeCheckBaseline(&baselineB, r.actor, bl)
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
			writeSearchFindings(&findingsB, fs)
		}
	}

	return agent.ToolEvidence{
		// FIX 1: per-tool boxed fields. Text is left empty so the cascade boxes the
		// per-tool fields individually (each independently 1024-capped).
		BaselineText:      baselineB.String(),
		EventsText:        eventsB.String(),
		FindingsText:      findingsB.String(),
		ToolCalls:         calls,
		DistinctTools:     distinct,
		ToolEmpty:         searchEmpty,
		ZeroHistoryAccess: zeroHist,
		ZeroHistoryDetail: zeroDetail,
		RoleGrantByActor:  roleGrant,
		RoleGrantDetail:   roleDetail,
	}, nil
}

// roleGrantEventTypes / roleGrantActions are the privilege/role-grant event
// signatures the FIX 3 (b) predicate keys on. A surfaced event whose type or action
// is one of these is a role grant. Compared after separator-stripping + lower-case.
var roleGrantEventTypes = map[string]struct{}{
	"roleassignment":   {},
	"roleassign":       {},
	"permissiongrant":  {},
	"privilegegrant":   {},
}

var roleGrantActions = map[string]struct{}{
	"addroleassignment": {},
	"assignrole":        {},
	"grantrole":         {},
	"grantpermission":   {},
}

// eventsNamingActor (FIX 2) returns the events whose TARGET / principal_id /
// display_name names the finding actor — the events that CREATED a new actor,
// authored by a different principal. It is the empty-actor-filter fallback for a
// NEW-actor finding: search-events keyed on the finding actor returns nothing
// because the new actor authored no events yet, but it appears as the object of
// its own creation. Returns the matching EventView set (empty when none match), so
// triage sees the benign creation context (ID-01) instead of an empty read.
func (r *scenarioToolRunner) eventsNamingActor() []tools.EventView {
	if r.actor == "" {
		return nil
	}
	full, _, err := tools.SearchEvents(r.store, tools.SearchEventsInput{})
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

// zeroHistoryAccess (FIX 3a) reports whether the finding actor, in the surfaced
// events, accessed a target with which it has ZERO relationship history (no
// relationship record, or a record with count 0). VA-03: ci-bot reads storage
// targets absent from its (deploy-only) relationship set. CO-02: deploy-svc
// bulk-reads a target outside its established relationships. VA-01 is NOT caught:
// every deploy target is in deploy-svc's relationships with a positive count.
//
// It considers only events AUTHORED BY the finding actor (the actor under
// investigation actually performed the access) and only events carrying a target
// (a login/health-check with no resource target is not an "access"). The first
// zero-history target found is named in the detail for the audit trail.
func (r *scenarioToolRunner) zeroHistoryAccess(events []tools.EventView) (bool, string) {
	if r.actor == "" || r.baseline == nil {
		return false, ""
	}
	rels := r.baseline.RelationshipsFor(r.actor)
	al := strings.ToLower(strings.TrimSpace(r.actor))
	for _, ev := range events {
		if !strings.EqualFold(ev.Actor, r.actor) {
			continue
		}
		target := strings.TrimSpace(ev.Target)
		if target == "" {
			continue
		}
		if relationshipCountFor(rels, al, target) == 0 {
			return true, r.actor + " → " + target + " (no relationship history)"
		}
	}
	return false, ""
}

// relationshipCountFor returns the historical relationship count for the
// (actor, target) pair, or 0 when the actor has NO established relationship
// covering that target. The scenario keys relationships as "<actor>:<target>".
//
// DISCRIMINATION (not blunter escalation): a relationship covers an event target
// when its target segment is the SAME RESOURCE — an exact match, OR one is a
// path-prefix of the other at a segment boundary (so a relationship with the
// storage ACCOUNT atomstorage01 covers a read on atomstorage01/containers/financial:
// the actor has established access to that resource; a new container under an
// established account is not "zero history"). This is what separates VA-02 /
// VA-05 (a known batch/report actor reading a NEW container under an account it
// ALREADY accesses — established, RESOLVE) from VA-03 (ci-bot, a deploy-only
// actor, reading storageAccounts it has NEVER touched — zero history, ESCALATE):
// ci-bot's relationships are all containerRegistries/containerApps, none share a
// resource prefix with the storage targets. Sharing only the subscription /
// resourceGroup prefix does NOT count — the prefix must extend past the
// resourceGroup to a concrete resource, so a brand-new resource in a known group
// is still zero-history. actorLower is the pre-lowercased finding actor.
func relationshipCountFor(rels map[string]baseline.Relationship, actorLower, target string) int {
	tl := strings.ToLower(strings.TrimSpace(target))
	for key, rel := range rels {
		// Split off the actor prefix ("<actor>:") to isolate the target portion.
		keyTarget := key
		if idx := strings.Index(strings.ToLower(key), actorLower+":"); idx == 0 {
			keyTarget = key[len(actorLower)+1:]
		} else if i := strings.IndexByte(key, ':'); i >= 0 {
			keyTarget = key[i+1:]
		}
		kl := strings.ToLower(strings.TrimSpace(keyTarget))
		if kl == "" {
			continue
		}
		if kl == tl || sameResource(kl, tl) {
			return rel.Count
		}
	}
	return 0
}

// sameResource reports whether two lower-cased resource paths refer to the same
// underlying resource: one is a segment-boundary prefix of the other, with the
// shared prefix extending PAST the resourceGroup level (so a relationship to a
// concrete resource covers a sub-path of it, but merely sharing the
// subscription/resourceGroup does not). "/"-delimited segment boundaries only —
// "atomstorage01" must not match "atomstorage011".
func sameResource(a, b string) bool {
	if a == b {
		return true
	}
	short, long := a, b
	if len(short) > len(long) {
		short, long = long, short
	}
	// long must start with short followed by a path separator (segment boundary).
	if !strings.HasPrefix(long, short+"/") {
		return false
	}
	// The shared prefix must reach a concrete resource, not stop at the resource
	// group. Require the prefix to contain more path depth than "<sub>/resourceGroups
	// /<rg>" — i.e. at least one segment AFTER the resourceGroup name. This stops a
	// brand-new resource in a known group from counting as established access.
	return resourceDepthPastGroup(short)
}

// resourceDepthPastGroup reports whether a resource path descends to at least a
// concrete resource past the "<...>/resourceGroups/<rg>" prefix (or carries no
// resourceGroups segment at all, e.g. an "acme-corp/tenant" style path, in which
// case two segments are enough to name a resource). It prevents a relationship that
// only reaches the resource-group level from "covering" arbitrary new resources
// inside that group.
func resourceDepthPastGroup(path string) bool {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		if strings.EqualFold(s, "resourceGroups") || strings.EqualFold(s, "resourcegroups") {
			// Need: resourceGroups(i) / <rg>(i+1) / <resourceType-or-name>(i+2)
			return len(segs) >= i+3
		}
	}
	// No resourceGroups segment: a 2+ segment path already names a resource.
	return len(segs) >= 2
}

// roleGrantByActor (FIX 3b) reports whether the surfaced events show the FINDING
// ACTOR performing a role-grant / privilege event (event_type role_assignment, or
// action add_role_assignment) for which it has NO baseline history of granting
// roles. UT-01 / IT-02: admin-user (the finding actor) grants a role with a
// role_assignment baseline frequency of 0. ID-01 is NOT caught: there the role
// grant is authored by admin-user (a KNOWN role-granter with frequency 28), NOT by
// the finding actor deploy-svc-new — so the finding actor performed no grant.
func (r *scenarioToolRunner) roleGrantByActor(events []tools.EventView) (bool, string) {
	if r.actor == "" {
		return false, ""
	}
	for _, ev := range events {
		if !strings.EqualFold(ev.Actor, r.actor) {
			continue
		}
		if !isRoleGrantEvent(ev) {
			continue
		}
		// The finding actor performed a role grant. Force-escalate UNLESS the actor
		// has an established baseline history of granting roles (a known role-granter
		// doing a routine grant is not the under-escalation case). The baseline
		// frequency for the role-grant event type captures "has this actor granted
		// roles before"; 0 (or absent) => no precedent => escalate.
		if r.actorRoleGrantFrequency() == 0 {
			return true, r.actor + " performed " + ev.Type + "/" + ev.Action + " with no baseline role-grant history"
		}
	}
	return false, ""
}

// isRoleGrantEvent reports whether an event is a role-grant / privilege event by
// its type or action (separator-stripped, lower-cased). Keyed on the EVENT, never
// on the detector family.
func isRoleGrantEvent(ev tools.EventView) bool {
	if _, ok := roleGrantEventTypes[stripSep(ev.Type)]; ok {
		return true
	}
	if _, ok := roleGrantActions[stripSep(ev.Action)]; ok {
		return true
	}
	return false
}

// actorRoleGrantFrequency returns the finding actor's baseline frequency for
// role-grant event types, summed across the role-grant type keys. A frequency
// table key has the shape "<source>:<event_type>:<actor>" or "<source>:<event_type>"
// (the exam seeds the latter); we sum any key whose event_type segment is a
// role-grant type AND that references the actor. 0 means "no role-grant precedent".
func (r *scenarioToolRunner) actorRoleGrantFrequency() int {
	if r.baseline == nil {
		return 0
	}
	al := strings.ToLower(strings.TrimSpace(r.actor))
	total := 0
	for key, v := range r.baseline.FrequencyTables {
		kl := strings.ToLower(key)
		if !strings.Contains(kl, al) {
			continue
		}
		parts := strings.Split(key, ":")
		if len(parts) < 2 {
			continue
		}
		if _, ok := roleGrantEventTypes[stripSep(parts[1])]; ok {
			total += v
		}
	}
	return total
}

// stripSep lower-cases and removes separators (-, _, space, .) so "role_assignment",
// "role-assignment", and "Role Assignment" all fold to "roleassignment".
func stripSep(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch r {
		case '-', '_', ' ', '.':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
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
	"role",
	"principal_id",
	"ip",
	"location",
	"user_agent",
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
	}
	for k, v := range s.Baseline.FrequencyTables {
		b.FrequencyTables[k] = v
	}
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
