package detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(unusualResourceAccessDetector{}) }

type unusualResourceAccessDetector struct{}

func (unusualResourceAccessDetector) Name() string { return "unusual-resource-access" }

// resourceAccessEventTypes are the data/resource access event types this detector
// inspects.
// NOTE: storage_access is deliberately EXCLUDED. A pure storage_access burst is a
// VOLUME signal (the volume-anomaly family owns it — VA-03 data-exfil), not a
// novel-resource-class signal. Lateral-movement scenarios that DO touch storage
// (URA-02) still fire here via their secret/database/vm/registry accesses, so the
// exclusion costs no reproduction while preventing URA from stealing VA-03.
var resourceAccessEventTypes = map[string]bool{
	"database_access": true,
	"secret_access":   true,
	"bulk_read":       true,
	"resource_access": true,
	"vm_access":       true,
	"registry_access": true,
}

// Detect fires when an actor accesses a resource whose CLASS within its parent
// resource group the actor has no prior relationship to. The relationship baseline
// keys an "actor:target" pair; the gate compares the access target's
// "<rg>/<resource-class>" prefix against the actor's known relationship targets.
// A sibling rotation (the actor already touches the SAME resource class in the
// SAME group, just a different instance — URA-04 prod→staging) is NOT flagged.
// Fires on ev.Actor.
func (unusualResourceAccessDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	emitted := make(map[string]bool)
	var out []finding.Finding
	for _, ev := range events {
		if f := unusualResourceAccessEvaluate(ev, bl, emitted); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func unusualResourceAccessEvaluate(ev event.Event, bl *baseline.Baseline, emitted map[string]bool) *finding.Finding {
	if !resourceAccessEventTypes[ev.Type] {
		return nil
	}
	meta := payloadMeta(ev.Payload)
	target := metaStr(meta, "target", "resource", "resource_id")
	if target == "" {
		// eventRecord writes target at the top of the payload, not under metadata.
		target = topLevelString(ev.Payload, "target")
	}
	if target == "" {
		return nil
	}

	if actorHasResourceClassRelationship(bl, ev.Actor, target) {
		// The actor already operates on this resource class in this group —
		// a sibling/instance rotation, not a novel access. Benign.
		return nil
	}

	dedupKey := ev.Actor + ":" + resourceClassPrefix(target)
	if emitted[dedupKey] {
		return nil
	}
	emitted[dedupKey] = true

	evidence, _ := json.Marshal(map[string]string{
		"actor":      ev.Actor,
		"target":     target,
		"event_type": ev.Type,
		"event_id":   ev.ID,
	})

	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:unusual-resource-access",
		Severity:  "high",
		Type:      "unusual-resource-access",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason: fmt.Sprintf(
			"unusual resource access: %q accessed %q with no prior relationship to this resource class",
			ev.Actor, target,
		),
		Evidence: evidence,
		EventIDs: []string{ev.ID},
	}
}

// resourceClassPrefix reduces an ARM-style resource path to its
// "<resourceGroup>/<resourceClass>" identity — the granularity at which a prior
// relationship counts. For
// "sub-x/resourceGroups/atom-rg/flexibleServers/atom-db-prod" it returns
// "atom-rg/flexibleServers". A path with no recognizable RG/class structure
// returns the whole target (so an unstructured target still keys deterministically).
func resourceClassPrefix(target string) string {
	segs := strings.Split(target, "/")
	rg := ""
	for i := 0; i+1 < len(segs); i++ {
		if strings.EqualFold(segs[i], "resourceGroups") {
			rg = segs[i+1]
			// The resource class is the segment after the RG name (if present).
			if i+2 < len(segs) {
				return rg + "/" + segs[i+2]
			}
			return rg
		}
	}
	return target
}

// actorHasResourceClassRelationship reports whether the actor's relationship
// baseline references the target's "<rg>/<resource-class>" prefix — i.e. the actor
// already operates on this class of resource in this group. The relationship keys
// are "<actor>:<target-path>"; a key whose path contains the prefix counts.
func actorHasResourceClassRelationship(bl *baseline.Baseline, actor, target string) bool {
	if bl == nil {
		return false
	}
	prefix := strings.ToLower(resourceClassPrefix(target))
	if prefix == "" {
		return false
	}
	for key := range bl.RelationshipsFor(actor) {
		if strings.Contains(strings.ToLower(key), prefix) {
			return true
		}
	}
	return false
}

// topLevelString reads a top-level string field from a raw JSON payload (the
// eventRecord projection writes action/target/severity at the payload root).
func topLevelString(payload []byte, key string) string {
	if len(payload) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}
