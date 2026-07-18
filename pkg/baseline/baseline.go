package baseline

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Baseline holds historical patterns for known users and entities.
type Baseline struct {
	KnownUsers map[string]UserProfile `json:"known_users"`

	// KnownActors is the set of actors seen during the baseline window.
	// Used by detector-new-actor.
	KnownActors []string `json:"known_actors,omitempty"`

	// KnownCreatedEntities is the set of principal identities (display_name /
	// principal_id / member) already OBSERVED being created via an entity-creation
	// event during the baseline window. detector-new-actor's created-entity gate
	// (createdEntityEvaluate) keys on THIS set — NOT KnownActors — so a genuinely
	// new created principal whose display_name collides with an existing known ACTOR
	// name still fires the first time it is created, while a repeat scan of the same
	// creation is gated. Kept distinct from KnownActors precisely so "this name is a
	// known actor" and "this created-principal entity was already seen" cannot be
	// conflated (the fix for the created-principal name-collision false negative).
	KnownCreatedEntities []string `json:"known_created_entities,omitempty"`

	// FrequencyTables maps "source:event_type" → baseline event count.
	// Used by detector-volume-anomaly.
	FrequencyTables map[string]int `json:"frequency_tables,omitempty"`

	// ActorHours maps actor → list of UTC hours (0-23) seen during baseline.
	// Used by detector-unusual-timing.
	ActorHours map[string][]int `json:"actor_hours,omitempty"`

	// ActorRoles maps actor → list of known role/permission keys.
	// Used by detector-priv-escalation.
	ActorRoles map[string][]string `json:"actor_roles,omitempty"`

	// Relationships maps a relationship key (the scenario's "actor:target" shape,
	// or any caller convention) → the historical actor↔target relationship record.
	// EVAL FIDELITY (FIX 4): legion's academy fed its agent the scenario's
	// relationships table so the model could answer "has this actor touched this
	// target before, and how often". Reconstructing it here lets check-baseline
	// surface the same relationship evidence the academy showed — without it the
	// portable eval projected only aggregate frequencies and the parity number
	// measured a model blind to actor↔target history.
	Relationships map[string]Relationship `json:"relationships,omitempty"`
}

// Relationship is a historical actor↔target relationship record: how many times an
// actor has acted on a target and the first/last time it did. Mirrors the scenario
// baseline's relationships entry so check-baseline can surface the academy's
// relationship evidence (FIX 4). FirstSeen/LastSeen are kept as the raw scenario
// strings (RFC3339 in the corpus) — the tool surfaces them verbatim as evidence.
type Relationship struct {
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
}

// UserProfile captures the expected behaviour for a single actor.
type UserProfile struct {
	KnownIPs  []string  `json:"known_ips"`
	KnownGeos []string  `json:"known_geos"` // e.g. "US", "GB"
	LastSeen  time.Time `json:"last_seen"`
}

// Load reads and parses a baseline JSON file from disk.
func Load(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var b Baseline
	if err := json.NewDecoder(f).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// HasUser returns true when the actor appears in the baseline.
func (b *Baseline) HasUser(actor string) bool {
	_, ok := b.KnownUsers[actor]
	return ok
}

// KnownIP returns true when the IP is in the actor's profile.
func (b *Baseline) KnownIP(actor, ip string) bool {
	p, ok := b.KnownUsers[actor]
	if !ok {
		return false
	}
	for _, known := range p.KnownIPs {
		if known == ip {
			return true
		}
	}
	return false
}

// KnownGeo returns true when the geo is in the actor's profile.
func (b *Baseline) KnownGeo(actor, geo string) bool {
	p, ok := b.KnownUsers[actor]
	if !ok {
		return false
	}
	for _, known := range p.KnownGeos {
		if known == geo {
			return true
		}
	}
	return false
}

// IsKnownActor returns true when the actor appears in KnownActors.
func (b *Baseline) IsKnownActor(actor string) bool {
	for _, a := range b.KnownActors {
		if a == actor {
			return true
		}
	}
	return false
}

// IsKnownCreatedEntity returns true when the identity was already observed being
// CREATED (via an entity-creation event) during the baseline window. This is the
// gate detector-new-actor's created-entity check uses so a repeat scan of the same
// principal creation is suppressed while a brand-new created principal — even one
// whose name collides with a known actor — still fires the first time.
func (b *Baseline) IsKnownCreatedEntity(name string) bool {
	for _, c := range b.KnownCreatedEntities {
		if c == name {
			return true
		}
	}
	return false
}

// HasLoginProfile returns true when the actor has a baseline UserProfile carrying
// at least one known IP or known geo — i.e. there is login-location history to
// compare a new login against. A known actor with an empty profile (no IPs, no
// geos) returns false: unusual-login has no basis to flag the login as unusual
// and must not over-fire (eval-fidelity gate).
func (b *Baseline) HasLoginProfile(actor string) bool {
	p, ok := b.KnownUsers[actor]
	if !ok {
		return false
	}
	return len(p.KnownIPs) > 0 || len(p.KnownGeos) > 0
}

// FreqCount returns the baseline event count for "source:event_type".
func (b *Baseline) FreqCount(source, eventType string) int {
	if b.FrequencyTables == nil {
		return 0
	}
	return b.FrequencyTables[source+":"+eventType]
}

// FreqCountActor returns the baseline event count for the 3-segment key
// "source:event_type:actor" — the actor-aware shape the corpus frequency_tables
// use. volume-anomaly keys on this so the per-actor baseline (not a 2-segment
// aggregate) drives the spike ratio, matching the corpus key shape exactly.
func (b *Baseline) FreqCountActor(source, eventType, actor string) int {
	if b.FrequencyTables == nil {
		return 0
	}
	return b.FrequencyTables[source+":"+eventType+":"+actor]
}

// KnownHour returns true when the given UTC hour is in the actor's known hours.
func (b *Baseline) KnownHour(actor string, hour int) bool {
	hours, ok := b.ActorHours[actor]
	if !ok {
		return false
	}
	for _, h := range hours {
		if h == hour {
			return true
		}
	}
	return false
}

// HasActorHours returns true when there is any timing baseline data.
func (b *Baseline) HasActorHours() bool {
	return len(b.ActorHours) > 0
}

// HasActorHoursFor returns true when THIS actor has any recorded baseline hours.
// It distinguishes "the hour is off-baseline" (actor has hours, this one isn't
// among them) from "there is no timing baseline for this actor at all" — the
// two states KnownHour==false conflates. Callers that treat an unknown hour as a
// timing DEVIATION must gate on this, or an actor with no hour history would read
// as perpetually off-hours.
func (b *Baseline) HasActorHoursFor(actor string) bool {
	return len(b.ActorHours[actor]) > 0
}

// RelationshipsFor returns the relationship records whose key references the given
// entity — the scenario keys an "actor:target" pair, so a key whose actor segment
// (before the first ':') equals the entity, OR any key that contains the entity as
// a segment, is returned. The result maps the matching relationship KEY → record
// (empty map, never nil, when there is no relationship data). Case-insensitive.
// This is the query check-baseline uses to surface actor↔target history (FIX 4).
func (b *Baseline) RelationshipsFor(entity string) map[string]Relationship {
	out := map[string]Relationship{}
	if b == nil || len(b.Relationships) == 0 || entity == "" {
		return out
	}
	el := strings.ToLower(entity)
	for key, rel := range b.Relationships {
		// Match the actor segment (before the first ':') exactly, or any ':'-segment.
		matched := false
		for _, seg := range strings.Split(key, ":") {
			if strings.EqualFold(strings.TrimSpace(seg), entity) {
				matched = true
				break
			}
		}
		if !matched && strings.Contains(strings.ToLower(key), el) {
			matched = true
		}
		if matched {
			out[key] = rel
		}
	}
	return out
}

// Clone returns a DEEP copy of the baseline: every map and slice is reallocated
// so a caller that mutates the returned value (or any nested slice/map inside it)
// cannot corrupt the original or any other holder of the original. Scalar,
// string, and time.Time fields are value-copied. A nil receiver clones to a
// fresh empty &Baseline{} so callers always get a usable, isolated value.
//
// This is the per-detector input-isolation primitive (K7 HOLE 1a): detect.Detect
// threads ONE *Baseline through every registered detector, so a detector that
// mutated it would silently narrow what every later detector sees. Handing each
// detector its own clone makes that structurally impossible.
func (b *Baseline) Clone() *Baseline {
	if b == nil {
		return &Baseline{}
	}
	out := &Baseline{}

	if b.KnownUsers != nil {
		out.KnownUsers = make(map[string]UserProfile, len(b.KnownUsers))
		for k, p := range b.KnownUsers {
			out.KnownUsers[k] = UserProfile{
				KnownIPs:  cloneStrings(p.KnownIPs),
				KnownGeos: cloneStrings(p.KnownGeos),
				LastSeen:  p.LastSeen,
			}
		}
	}

	out.KnownActors = cloneStrings(b.KnownActors)
	out.KnownCreatedEntities = cloneStrings(b.KnownCreatedEntities)

	if b.FrequencyTables != nil {
		out.FrequencyTables = make(map[string]int, len(b.FrequencyTables))
		for k, v := range b.FrequencyTables {
			out.FrequencyTables[k] = v
		}
	}

	if b.ActorHours != nil {
		out.ActorHours = make(map[string][]int, len(b.ActorHours))
		for k, hrs := range b.ActorHours {
			cp := make([]int, len(hrs))
			copy(cp, hrs)
			out.ActorHours[k] = cp
		}
	}

	if b.ActorRoles != nil {
		out.ActorRoles = make(map[string][]string, len(b.ActorRoles))
		for k, roles := range b.ActorRoles {
			out.ActorRoles[k] = cloneStrings(roles)
		}
	}

	if b.Relationships != nil {
		out.Relationships = make(map[string]Relationship, len(b.Relationships))
		for k, r := range b.Relationships {
			out.Relationships[k] = r // Relationship is all value fields (int + strings)
		}
	}

	return out
}

// cloneStrings returns a reallocated copy of s, preserving nil (a nil slice
// clones to nil, not an empty slice, so a round-tripped baseline is unchanged).
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}

// IsKnownRole returns true when actor+role is in the actor roles baseline.
// Since mallcoppro-9af, priv-escalation's gate passes a composite "role:target"
// string as role (see core/detect/priv_escalation.go's roleTargetKey) so the
// gate is aware of WHO received the grant, not just the role — this method
// itself is unchanged, it just compares whatever string the caller passes.
func (b *Baseline) IsKnownRole(actor, role string) bool {
	roles, ok := b.ActorRoles[actor]
	if !ok {
		return false
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
