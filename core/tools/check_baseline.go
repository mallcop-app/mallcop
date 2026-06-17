// check_baseline.go — the check-baseline pure read tool, reusing pkg/baseline.
//
// CheckBaseline answers "is this entity known to the baseline, and what do we
// know about it?" It is a PURE function over an already-loaded *baseline.Baseline
// — no disk access, no inference, no side effects. Callers load the baseline
// (baseline.Load, or reconstruction from core/store) and pass the typed value.
package tools

import (
	"errors"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/baseline"
)

// CheckBaselineInput is the input for CheckBaseline.
//
// Entity is the actor ID / email to look up (required). Source, when set,
// additionally requires the actor's profile to carry that source-derived
// signal — currently a known geo, the only source-shaped field the typed
// baseline exposes. EventType, when set, selects the frequency bucket reported
// in FrequencyForType.
type CheckBaselineInput struct {
	Entity    string `json:"entity"`
	Source    string `json:"source,omitempty"`
	EventType string `json:"event_type,omitempty"`
}

// CheckBaselineResult is the output contract for check-baseline.
//
// Known reports whether the entity appears in the baseline. LastSeen is the
// actor's last-seen timestamp (RFC3339, empty when unknown). Frequency is the
// aggregate baseline event count across all event types for the entity;
// FrequencyByType breaks that aggregate down per event type. FrequencyForType
// is the count for the specific EventType the caller asked about (zero when the
// caller omits EventType or no events of that type are baselined). Roles is the
// actor's known role/permission keys.
type CheckBaselineResult struct {
	Known            bool           `json:"known"`
	LastSeen         string         `json:"last_seen"`
	Frequency        int            `json:"frequency"`
	FrequencyByType  map[string]int `json:"frequency_by_type"`
	FrequencyForType int            `json:"frequency_for_type"`
	EventType        string         `json:"event_type,omitempty"`
	Roles            []string       `json:"roles"`
}

// CheckBaseline reports what the baseline knows about an entity.
//
// A nil baseline is treated as "no baseline data": the entity is unknown,
// frequencies are zero, roles empty. This mirrors the original tool's
// graceful-not-found behaviour (a missing baseline file means "unknown entity",
// never an error). CheckBaseline returns an error only when Entity is empty.
func CheckBaseline(b *baseline.Baseline, in CheckBaselineInput) (CheckBaselineResult, error) {
	if in.Entity == "" {
		return CheckBaselineResult{}, errors.New("check-baseline: entity is required")
	}

	res := CheckBaselineResult{
		FrequencyByType: map[string]int{},
		EventType:       in.EventType,
		Roles:           []string{},
	}
	if b == nil {
		return res, nil
	}

	// Known: the entity appears in the baseline's user profiles or known-actor
	// list (case-insensitive).
	known := entityKnown(b, in.Entity)

	// If a source is supplied, also require the source to be known for this
	// actor. The typed baseline exposes source-derived signal as known geos;
	// require the source string to appear there (case-insensitive). When the
	// actor carries no geo data we do not downgrade — absence of geo data is
	// not evidence the source is unknown.
	if known && in.Source != "" {
		if p, ok := profileFor(b, in.Entity); ok && len(p.KnownGeos) > 0 {
			sourceKnown := false
			for _, g := range p.KnownGeos {
				if strings.EqualFold(g, in.Source) {
					sourceKnown = true
					break
				}
			}
			if !sourceKnown {
				known = false
			}
		}
	}
	res.Known = known

	// LastSeen from the actor's profile (zero time → empty string).
	if p, ok := profileFor(b, in.Entity); ok && !p.LastSeen.IsZero() {
		res.LastSeen = p.LastSeen.UTC().Format("2006-01-02T15:04:05Z07:00")
	}

	// Frequency: sum FrequencyTables entries whose compound key contains the
	// entity (case-insensitive substring), bucketing per event type from the
	// `<source>:<event_type>` key shape. This matches the original tool: a bare
	// entity lookup never hits the compound exam-seed keys.
	entityLower := strings.ToLower(in.Entity)
	for key, v := range b.FrequencyTables {
		if !strings.Contains(strings.ToLower(key), entityLower) {
			continue
		}
		res.Frequency += v
		parts := strings.Split(key, ":")
		// Compound shapes:
		//   <source>:<event_type>            (e.g. azure:container_restart)
		//   <source>:<event_type>:<actor>    (e.g. azure:container_restart:svc)
		//   time:<hour>:<actor>              (skip — not an event_type bucket)
		if len(parts) >= 2 && parts[0] != "time" {
			res.FrequencyByType[parts[1]] += v
		}
	}
	// A curated bare-entity key, if present, overrides the substring sum.
	if v, ok := b.FrequencyTables[in.Entity]; ok {
		res.Frequency = v
	}

	if in.EventType != "" {
		res.FrequencyForType = res.FrequencyByType[in.EventType]
	}

	// Roles: the actor's known role/permission keys from the baseline.
	for actor, roles := range b.ActorRoles {
		if strings.EqualFold(actor, in.Entity) {
			res.Roles = append([]string{}, roles...)
			break
		}
	}

	return res, nil
}

// entityKnown reports whether the entity appears anywhere the baseline records
// known actors: the user profile map or the KnownActors slice.
func entityKnown(b *baseline.Baseline, entity string) bool {
	for actor := range b.KnownUsers {
		if strings.EqualFold(actor, entity) {
			return true
		}
	}
	for _, a := range b.KnownActors {
		if strings.EqualFold(a, entity) {
			return true
		}
	}
	return false
}

// profileFor returns the UserProfile for the entity (case-insensitive) and
// whether one exists.
func profileFor(b *baseline.Baseline, entity string) (baseline.UserProfile, bool) {
	for actor, p := range b.KnownUsers {
		if strings.EqualFold(actor, entity) {
			return p, true
		}
	}
	return baseline.UserProfile{}, false
}
