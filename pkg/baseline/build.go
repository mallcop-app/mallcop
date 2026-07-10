package baseline

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/pkg/event"
)

// Build derives a *Baseline from a corpus of historical events — the store's
// PRIOR accumulated event stream. It is the keystone that makes `mallcop scan`
// idempotent across runs: the pipeline gates the baseline-dependent detectors
// (new-actor, volume-anomaly, unusual-timing, priv-escalation, unusual-login) on
// the baseline Build produces from the events already seen, so an actor/pattern
// is investigated ONCE — the first scan it appears — and NOT re-investigated (and
// re-charged for inference) on every subsequent steady-state scan.
//
// It populates ONLY the fields the shipped baseline-dependent detectors actually
// read (audited against every core/detect/*.go baseline access):
//
//   - KnownActors     — every distinct non-empty actor, PLUS the principals NAMED
//     in entity-creation events (so new-actor's ACTOR-novelty gate does not re-fire
//     when a created principal later authors its own events). Read by new-actor
//     (IsKnownActor).
//   - KnownCreatedEntities — the identities already OBSERVED being created via an
//     entity-creation event. Read by new-actor's created-entity gate
//     (createdEntityEvaluate → IsKnownCreatedEntity), kept SEPARATE from KnownActors
//     so a brand-new created principal whose display_name collides with a known
//     actor still fires the first time it is created.
//   - FrequencyTables — "source:event_type:actor" → prior count. Read by
//     volume-anomaly (FreqCountActor) and surfaced by check-baseline.
//   - ActorHours      — actor → sorted distinct UTC hours seen. Read by
//     unusual-timing (HasActorHours / ActorHours / KnownHour).
//   - ActorRoles      — actor → sorted distinct role keys the priv-escalation
//     detector would actually FIRE (and gate) on: the event type is an elevation
//     type, the event isElevated (with the removal guard), and the role key came
//     from an EXPLICIT role/permission field. Recorded only when the detector would
//     genuinely investigate it — never off a non-firing event. Read by
//     priv-escalation (IsKnownRole). See the SECURITY note below.
//   - KnownUsers      — actor → UserProfile{KnownIPs, KnownGeos, LastSeen} built
//     from the actor's LOGIN events that carried at least one ip or geo (so
//     HasLoginProfile stays meaningful). Read by unusual-login (HasUser /
//     HasLoginProfile / KnownIP / KnownGeo).
//
// It deliberately does NOT populate the 2-segment "source:event_type" frequency
// keys (exfil-pattern / rate-anomaly's FreqCount) nor Relationships
// (unusual-resource-access / the observe force-escalate predicates): those
// detectors judge the EVENT (content / magnitude / lateral-movement), not actor
// novelty, so leaving them unset keeps their behavior byte-identical to the
// current empty-baseline production path — no new activation, no regression.
//
// SECURITY (does not hide a real attack): the baseline gates NEW-ACTOR-ness and
// PER-ROLE novelty only. A genuinely new actor, a genuinely new role for a known
// actor, a login from a new IP, a genuine volume spike — each still fires the
// first time it is seen. Detectors that judge the event itself (priv-escalation on
// admin_action / boundary-removal, exfil, secrets, injection, …) are NOT gated by
// the fields Build sets, so a known actor committing a NEW incident still fires.
// ActorRoles records ONLY explicit role/permission fields — never priv-escalation's
// event-type fallback (admin_action, boundary-delete keywords) — so the highest-
// severity field-less escalations fail SAFE (re-fire and re-escalate) rather than
// risk being suppressed by a baselined event type.
//
// Output is deterministic: every slice is sorted, so the same event set always
// yields byte-identical JSON (the persisted KindBaseline snapshot is reproducible).
func Build(events []event.Event) *Baseline {
	actorSet := map[string]struct{}{}
	createdSet := map[string]struct{}{}
	freq := map[string]int{}
	hourSet := map[string]map[int]struct{}{}
	roleSet := map[string]map[string]struct{}{}
	ipSet := map[string]map[string]struct{}{}
	geoSet := map[string]map[string]struct{}{}
	loginActors := map[string]struct{}{}
	lastSeen := map[string]time.Time{}

	for i := range events {
		ev := events[i]
		actor := strings.TrimSpace(ev.Actor)

		// Principals NAMED in entity-creation events are baselined TWO ways, keyed on
		// two DIFFERENT novelty questions (SECURITY — do not conflate them):
		//   - KnownActors (actorSet): stops new-actor's ACTOR-novelty gate re-firing
		//     when the created principal later AUTHORS its own events.
		//   - KnownCreatedEntities (createdSet): the set new-actor's created-entity
		//     gate (createdEntityEvaluate) keys on, so a repeat scan of the SAME
		//     creation is gated — WITHOUT suppressing a brand-new created principal
		//     whose display_name merely COLLIDES with an existing known ACTOR name.
		//     Keying the created-entity gate on KnownActors (the prior bug) let an
		//     attacker evade the "new principal created" finding by naming a backdoor
		//     principal after any known actor. The two sets are populated together
		//     here but consumed by separate gates so neither masks the other.
		if buildEntityCreationEventTypes[ev.Type] {
			meta := buildMetaBlock(ev.Payload)
			if created := buildFirstNonEmpty(meta, "display_name", "principal_id", "member", "new_principal"); created != "" {
				c := strings.TrimSpace(created)
				actorSet[c] = struct{}{}
				createdSet[c] = struct{}{}
			}
		}

		if actor == "" {
			continue
		}
		actorSet[actor] = struct{}{}

		// FrequencyTables: the actor-aware 3-segment key volume-anomaly reads.
		freq[ev.Source+":"+ev.Type+":"+actor]++

		// ActorHours: distinct UTC hours the actor was active.
		h := ev.Timestamp.UTC().Hour()
		if hourSet[actor] == nil {
			hourSet[actor] = map[int]struct{}{}
		}
		hourSet[actor][h] = struct{}{}

		// ActorRoles: record a role ONLY when priv-escalation would ACTUALLY FIRE
		// (and therefore GATE) on it — i.e. mirror the detector's full FIRING
		// predicate, not just its field read. The prior bug recorded a role/permission
		// value off ANY event, ungated: so a benign role REMOVAL (which priv-escalation
		// treats as NON-elevated), or a role that merely floated past on a
		// non-elevation event, seeded ActorRoles and then SUPPRESSED a later genuine
		// GRANT of that role. Gate here exactly as the detector does:
		//   (1) event type ∈ the elevation set,
		//   (2) buildPrivIsElevated true (admin_action / boundary-removal keyword /
		//       elevated role|permission keyword — with the SAME removal guard that
		//       makes remove_role_assignment non-elevated), and
		//   (3) the role key came from an EXPLICIT role/permission field (never the
		//       event-type fallback — field-less escalations must fail SAFE and
		//       re-fire, per the SECURITY note above).
		// buildPriv* mirror core/detect/priv_escalation.go; TestBuild_ActorRoles_
		// MirrorsPrivEscalationFiring drives the REAL detector to prove no drift.
		meta := buildMetaBlock(ev.Payload)
		if buildElevationEventTypes[ev.Type] {
			roleName := buildFirstNonEmpty(meta, "role", "role_name")
			perm := buildFirstNonEmpty(meta, "permission", "permission_level")
			action := buildTopAction(ev.Payload)
			if buildPrivIsElevated(ev.Type, roleName, perm, action) && (roleName != "" || perm != "") {
				addBuildSet(roleSet, actor, buildPrivRoleKey(roleName, perm))
			}
		}

		// KnownUsers: built from LOGIN events (the only shape carrying IP/geo). A
		// login becomes a profile ONLY when it carried at least one ip or geo — an
		// empty-profile entry makes the actor a "known user" (HasUser true) yet leaves
		// HasLoginProfile false, which makes unusual-login DEFER forever, permanently
		// blinding it to a later new-IP / new-geo login (a false negative). By only
		// recording a profile when there IS location history to compare against,
		// HasLoginProfile stays meaningful: a genuinely new/suspicious login by an
		// actor we have no location baseline for still fires (via the HasUser gate)
		// rather than being silently deferred.
		if ev.Type == buildLoginEventType {
			ip := buildFirstNonEmpty(meta, "ip", "source_ip", "client_ip")
			geo := buildFirstNonEmpty(meta, "geo", "location", "region")
			if ip != "" || geo != "" {
				loginActors[actor] = struct{}{}
				if t := ev.Timestamp.UTC(); t.After(lastSeen[actor]) {
					lastSeen[actor] = t
				}
				if ip != "" {
					addBuildSet(ipSet, actor, strings.TrimSpace(ip))
				}
				if geo != "" {
					addBuildSet(geoSet, actor, strings.TrimSpace(geo))
				}
			}
		}
	}

	b := &Baseline{}

	// KnownActors (sorted).
	if len(actorSet) > 0 {
		b.KnownActors = sortedKeys(actorSet)
	}

	// KnownCreatedEntities (sorted) — the identities already OBSERVED being created.
	// new-actor's created-entity gate keys on this set (NOT KnownActors) so a repeat
	// scan of the same creation is gated while a brand-new created principal that
	// collides with a known actor name still fires.
	if len(createdSet) > 0 {
		b.KnownCreatedEntities = sortedKeys(createdSet)
	}

	// FrequencyTables.
	if len(freq) > 0 {
		b.FrequencyTables = freq
	}

	// ActorHours (each actor's hours sorted ascending).
	if len(hourSet) > 0 {
		b.ActorHours = make(map[string][]int, len(hourSet))
		for actor, hs := range hourSet {
			hours := make([]int, 0, len(hs))
			for h := range hs {
				hours = append(hours, h)
			}
			sort.Ints(hours)
			b.ActorHours[actor] = hours
		}
	}

	// ActorRoles (each actor's roles sorted).
	if len(roleSet) > 0 {
		b.ActorRoles = make(map[string][]string, len(roleSet))
		for actor, rs := range roleSet {
			b.ActorRoles[actor] = sortedKeys(rs)
		}
	}

	// KnownUsers (one entry per login actor; sorted IPs/geos; last-seen).
	if len(loginActors) > 0 {
		b.KnownUsers = make(map[string]UserProfile, len(loginActors))
		for actor := range loginActors {
			p := UserProfile{LastSeen: lastSeen[actor]}
			if ips := ipSet[actor]; len(ips) > 0 {
				p.KnownIPs = sortedKeys(ips)
			}
			if geos := geoSet[actor]; len(geos) > 0 {
				p.KnownGeos = sortedKeys(geos)
			}
			b.KnownUsers[actor] = p
		}
	}

	return b
}

// buildEntityCreationEventTypes mirrors core/detect/new_actor.go's
// entityCreationEventTypes: event types that CREATE a new principal named in
// metadata while the performing actor is an existing admin. Duplicated here
// because pkg/baseline cannot import core/detect (detect imports baseline — the
// dependency would cycle). Kept in sync by TestBuild_EntityCreationBaselinesCreatedPrincipal.
var buildEntityCreationEventTypes = map[string]bool{
	"service_principal_created": true,
	"user_created":              true,
	"member_added":              true,
	"user_provisioned":          true,
}

// buildLoginEventType is the event type unusual-login keys on.
const buildLoginEventType = "login"

// --- priv-escalation FIRING-predicate mirror -------------------------------
//
// These mirror core/detect/priv_escalation.go so Build records into ActorRoles
// EXACTLY the (actor, role) pairs the priv-escalation detector would fire — and
// therefore gate — on, and NOTHING it would not. They are duplicated here (not
// imported) because core/detect imports pkg/baseline — importing back would
// cycle. Duplication is a false-negative hazard for a security monitor, so it is
// pinned to the detector's REAL behavior by TestBuild_ActorRoles_MirrorsPriv
// EscalationFiring, which drives the actual detector over a battery and asserts
// Build's recorded roles equal the detector's explicit-field gate keys. If the
// detector's predicate ever changes, that parity test fails until these are
// re-synced. (The elevation event-type SET must also stay a map literal in
// core/detect for vocab.go's AST invariant, so it necessarily lives in both
// places — same as buildEntityCreationEventTypes mirrors entityCreationEventTypes.)

// buildElevationEventTypes mirrors priv_escalation.go's builtinElevationEventTypes:
// the event types that may carry a privilege escalation.
var buildElevationEventTypes = map[string]bool{
	"role_assignment":    true,
	"collaborator_added": true,
	"permission_change":  true,
	"admin_action":       true,
	"member_added":       true,
	"iam_change":         true,
}

// buildElevatedActionKeywords mirrors priv_escalation.go's
// builtinElevatedActionKeywords: action substrings that elevate privilege even
// with no role/permission field (e.g. deleting an IAM permissions boundary).
var buildElevatedActionKeywords = []string{
	"deleterolepermissionsboundary",
	"deletepermissionsboundary",
	"removepermissionsboundary",
	"putrolepermissionsboundary",
}

// buildElevatedKeywords mirrors priv_escalation.go's builtinElevatedKeywords:
// role/permission values that indicate elevated access. Matched case-insensitively
// as SUBSTRINGS (see buildContainsElevatedKeyword).
var buildElevatedKeywords = map[string]bool{
	"admin":       true,
	"owner":       true,
	"write":       true,
	"contributor": true,
	"maintainer":  true,
	"editor":      true,
	"fullcontrol": true,
}

// buildPrivIsElevated mirrors priv_escalation.go's isElevated: admin_action is
// always elevated; a boundary-removal action keyword elevates regardless of role
// fields; a role/permission REMOVAL is NOT elevated (the removal guard that makes
// remove_role_assignment benign); otherwise an elevated role/permission keyword
// elevates.
func buildPrivIsElevated(evType, roleName, permissionLevel, action string) bool {
	if evType == "admin_action" {
		return true
	}
	a := strings.ToLower(action)
	for _, kw := range buildElevatedActionKeywords {
		if a != "" && strings.Contains(a, kw) {
			return true
		}
	}
	if strings.HasPrefix(a, "remove") || strings.HasPrefix(a, "revoke") || strings.HasPrefix(a, "delete_role") {
		return false
	}
	for _, val := range []string{roleName, permissionLevel} {
		if buildContainsElevatedKeyword(val) {
			return true
		}
	}
	return false
}

// buildContainsElevatedKeyword mirrors priv_escalation.go's containsElevatedKeyword:
// case-insensitive SUBSTRING match against the elevated-keyword set.
func buildContainsElevatedKeyword(val string) bool {
	lowered := strings.ToLower(val)
	if lowered == "" {
		return false
	}
	for kw := range buildElevatedKeywords {
		if strings.Contains(lowered, kw) {
			return true
		}
	}
	return false
}

// buildPrivRoleKey mirrors priv_escalation.go's roleKey for the EXPLICIT-field
// case: lower-cased role_name, else lower-cased permission_level. Build calls it
// only when one of those fields is present, so the event-type fallback (never
// baselined — field-less escalations fail safe) is intentionally not reached here.
func buildPrivRoleKey(roleName, permissionLevel string) string {
	if roleName != "" {
		return strings.ToLower(strings.TrimSpace(roleName))
	}
	return strings.ToLower(strings.TrimSpace(permissionLevel))
}

// buildTopAction reads the TOP-LEVEL "action" string from an event payload,
// mirroring priv_escalation.go's readPrivPayload (which reads action from the
// payload root, not from the metadata block). Returns "" when absent/malformed.
func buildTopAction(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var top map[string]any
	if err := json.Unmarshal(payload, &top); err != nil {
		return ""
	}
	if s, ok := top["action"].(string); ok {
		return s
	}
	return ""
}

// buildMetaBlock returns the discriminating metadata block from an event payload,
// handling BOTH on-disk layouts the same way core/detect's payloadMeta does: the
// nested corpus shape (payload.metadata.{role,ip,…}) and the flat production
// connector shape (fields at the payload root). A nil/empty/malformed payload
// yields an empty (never nil) map. Replicated here rather than imported for the
// same no-cycle reason as buildEntityCreationEventTypes.
func buildMetaBlock(payload json.RawMessage) map[string]any {
	out := map[string]any{}
	if len(payload) == 0 {
		return out
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return out
	}
	if meta, ok := m["metadata"].(map[string]any); ok {
		return meta
	}
	return m
}

// buildFirstNonEmpty returns the first present, non-empty STRING value among the
// aliases (mirrors core/detect's metaStr).
func buildFirstNonEmpty(meta map[string]any, aliases ...string) string {
	for _, k := range aliases {
		if v, ok := meta[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// addBuildSet records value v in the per-actor set m[actor].
func addBuildSet(m map[string]map[string]struct{}, actor, v string) {
	if m[actor] == nil {
		m[actor] = map[string]struct{}{}
	}
	m[actor][v] = struct{}{}
}

// sortedKeys returns the map's keys as a sorted slice (deterministic output).
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
