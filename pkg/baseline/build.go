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
//     in entity-creation events (new-actor's createdEntityEvaluate flags the
//     created principal, which never authors its own events, so it must be
//     baselined by name or it re-fires forever). Read by new-actor
//     (IsKnownActor).
//   - FrequencyTables — "source:event_type:actor" → prior count. Read by
//     volume-anomaly (FreqCountActor) and surfaced by check-baseline.
//   - ActorHours      — actor → sorted distinct UTC hours seen. Read by
//     unusual-timing (HasActorHours / ActorHours / KnownHour).
//   - ActorRoles      — actor → sorted distinct EXPLICIT role/permission values
//     (metadata role/role_name/permission/permission_level, lower-cased). Read by
//     priv-escalation (IsKnownRole). See the SECURITY note below on why only
//     explicit role fields are baselined and the event-type fallback is not.
//   - KnownUsers      — actor → UserProfile{KnownIPs, KnownGeos, LastSeen} built
//     from the actor's LOGIN events. Read by unusual-login (HasUser /
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

		// Principals NAMED in entity-creation events are baselined by name even when
		// they never author an event (new-actor's createdEntityEvaluate keys on them).
		if buildEntityCreationEventTypes[ev.Type] {
			meta := buildMetaBlock(ev.Payload)
			if created := buildFirstNonEmpty(meta, "display_name", "principal_id", "member", "new_principal"); created != "" {
				actorSet[strings.TrimSpace(created)] = struct{}{}
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

		// ActorRoles: EXPLICIT role/permission fields only (never the event-type
		// fallback — see the SECURITY note above). Mirrors priv-escalation's
		// roleKey primary derivation (lower-cased role_name, else permission_level).
		meta := buildMetaBlock(ev.Payload)
		if role := buildFirstNonEmpty(meta, "role", "role_name"); role != "" {
			addBuildSet(roleSet, actor, strings.ToLower(strings.TrimSpace(role)))
		}
		if perm := buildFirstNonEmpty(meta, "permission", "permission_level"); perm != "" {
			addBuildSet(roleSet, actor, strings.ToLower(strings.TrimSpace(perm)))
		}

		// KnownUsers: built from LOGIN events (the only shape carrying IP/geo). An
		// actor with a login becomes a KNOWN user; its login IP/geo become the
		// profile unusual-login compares future logins against.
		if ev.Type == buildLoginEventType {
			loginActors[actor] = struct{}{}
			if t := ev.Timestamp.UTC(); t.After(lastSeen[actor]) {
				lastSeen[actor] = t
			}
			if ip := buildFirstNonEmpty(meta, "ip", "source_ip", "client_ip"); ip != "" {
				addBuildSet(ipSet, actor, strings.TrimSpace(ip))
			}
			if geo := buildFirstNonEmpty(meta, "geo", "location", "region"); geo != "" {
				addBuildSet(geoSet, actor, strings.TrimSpace(geo))
			}
		}
	}

	b := &Baseline{}

	// KnownActors (sorted).
	if len(actorSet) > 0 {
		b.KnownActors = sortedKeys(actorSet)
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
