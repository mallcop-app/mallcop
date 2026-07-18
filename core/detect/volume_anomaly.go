package detect

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(volumeAnomalyDetector{}) }

type volumeAnomalyDetector struct{}

func (volumeAnomalyDetector) Name() string { return "volume-anomaly" }

// Detect is whole-corpus: it counts events per (source, event_type) group and
// flags groups exceeding the anomaly ratio over baseline.
func (volumeAnomalyDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	return volumeAnomalyEvaluateAll(events, bl)
}

const (
	// volumeAnomalyRatio is the multiplier over baseline that triggers a finding.
	volumeAnomalyRatio = 3.0
	// volumeMinBaselineCount is the minimum baseline count to be meaningful.
	// Groups with fewer baseline events are skipped to avoid false positives
	// on rarely-seen event types — UNLESS the observed volume clears
	// volumeAbsoluteFloor (a genuinely large burst is meaningful even against a
	// tiny baseline, e.g. a service account that has done a bulk read twice ever
	// suddenly reading 1600 objects).
	volumeMinBaselineCount = 5
	// volumeAbsoluteFloor is the observed-volume magnitude above which a spike is
	// significant regardless of how small the baseline is (but the event type must
	// still be KNOWN — baseline 0 is new-actor's job, never volume-anomaly's). This
	// is what lets a tiny-baseline exfil (baseline 2, 1600 operations) fire without
	// lowering the ratio for rarely-seen benign bursts (a handful of operations
	// against a small baseline stays below the floor and is skipped).
	volumeAbsoluteFloor = 50.0
)

// volumeMagnitudeAliases are the canonical event-metadata fields that carry the
// UNDERLYING operation/object count an event stands for. The corpus (and real
// connectors) emit a REPRESENTATIVE slice of events, each carrying the size of the
// batch it represents (a single storage_access event with blobs_accessed=120, a
// bulk_read with operation_count=847) rather than one event per underlying
// operation. Counting event RECORDS therefore undercounts the true volume by orders
// of magnitude — the field/unit contract mismatch that made every metadata-carried
// volume spike a false negative. volumeAnomalyEventWeight reads the first present
// alias as the event's weight so the detector measures volume in the SAME unit the
// baseline frequency tables count (operations), not event records.
//
// bytes_read is deliberately EXCLUDED: it is a data-size unit (bytes), not an
// operation count, so summing it into an operations baseline would compare unlike
// units. distinct_api_count lives on the finding, not the events, so it never
// appears here.
var volumeMagnitudeAliases = []string{
	"operation_count",
	"blobs_accessed",
	"objects_accessed",
	"object_count",
	"resource_count",
	"results_count",
	"rows_affected",
	"record_count",
}

// volumeAnomalyEventWeight returns how many underlying operations one event
// represents: the first present canonical magnitude field (volumeMagnitudeAliases),
// or 1 when the event carries none (one operation per record — the legacy
// event-count behavior, unchanged for events without a magnitude field). A
// non-positive magnitude falls back to 1 so a malformed/zero field never erases the
// event from the count.
func volumeAnomalyEventWeight(ev event.Event) float64 {
	meta := payloadMeta(ev.Payload)
	if v, ok := metaFloat(meta, volumeMagnitudeAliases...); ok && v > 0 {
		return v
	}
	return 1
}

type volumeGroupKey struct {
	source    string
	eventType string
	actor     string
}

// volumeAnomalyEvaluateAll counts events per (source, event_type) group and
// returns findings for groups that exceed volumeAnomalyRatio × baseline count.
// Results are ordered deterministically by source then event_type.
// This is a pure function: no I/O, no globals mutated.
func volumeAnomalyEvaluateAll(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	// Sum the OPERATION VOLUME per group (not event records): each event
	// contributes its magnitude-field weight (volumeAnomalyEventWeight), so a
	// representative event carrying blobs_accessed=120 counts as 120 operations,
	// matching the unit the baseline frequency tables count. events is also tallied
	// so the finding can report both the volume and how many records carried it.
	volumes := make(map[volumeGroupKey]float64)
	records := make(map[volumeGroupKey]int)

	type groupMeta struct {
		firstEventID string
		firstEvent   event.Event
		// eventIDs is the FULL contributing set of event ids in this group
		// (mallcoppro-323) — volume-anomaly is an aggregate detector (one
		// finding per (source,event_type,actor) group), so Finding.EventIDs
		// must carry every event that fed the volume total, not just
		// firstEventID.
		eventIDs []string
	}
	meta := make(map[volumeGroupKey]groupMeta)

	for _, ev := range events {
		k := volumeGroupKey{ev.Source, ev.Type, ev.Actor}
		volumes[k] += volumeAnomalyEventWeight(ev)
		records[k]++
		m, seen := meta[k]
		if !seen {
			m = groupMeta{firstEventID: ev.ID, firstEvent: ev}
		}
		if ev.ID != "" {
			m.eventIDs = append(m.eventIDs, ev.ID)
		}
		meta[k] = m
	}

	// Sort groups for deterministic output.
	keys := make([]volumeGroupKey, 0, len(volumes))
	for k := range volumes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		if keys[i].eventType != keys[j].eventType {
			return keys[i].eventType < keys[j].eventType
		}
		return keys[i].actor < keys[j].actor
	})

	var findings []finding.Finding
	for _, k := range keys {
		currentVolume := volumes[k]
		// Key on the 3-segment "source:event_type:actor" baseline (the corpus
		// frequency_tables shape). FreqCountActor reads the per-actor count so the
		// spike ratio is measured against THIS actor's history, not a cross-actor
		// aggregate.
		baselineCount := bl.FreqCountActor(k.source, k.eventType, k.actor)

		// An unknown event type (no per-actor baseline at all) has no volume basis:
		// a brand-new actor/behavior is new-actor's job, never volume-anomaly's.
		if baselineCount == 0 {
			continue
		}
		// A tiny baseline is skipped to avoid false positives on rarely-seen event
		// types — UNLESS the observed volume itself clears the absolute floor (a
		// genuinely large burst is meaningful even against a 2-event baseline).
		if baselineCount < volumeMinBaselineCount && currentVolume < volumeAbsoluteFloor {
			continue
		}

		if currentVolume <= volumeAnomalyRatio*float64(baselineCount) {
			continue
		}

		m := meta[k]
		ratio := currentVolume / float64(baselineCount)

		evidence, _ := json.Marshal(map[string]interface{}{
			"source":         k.source,
			"event_type":     k.eventType,
			"current_volume": currentVolume,
			"event_records":  records[k],
			"baseline_count": baselineCount,
			"ratio":          fmt.Sprintf("%.1f", ratio),
		})

		findings = append(findings, finding.Finding{
			ID:        "finding-" + m.firstEventID,
			Source:    "detector:volume-anomaly",
			Severity:  "medium",
			Type:      "volume-anomaly",
			Actor:     m.firstEvent.Actor,
			Timestamp: m.firstEvent.Timestamp,
			Reason: fmt.Sprintf(
				"%s:%s volume spike: %.0f operations across %d event(s) vs baseline %d (%.1f×)",
				k.source, k.eventType, currentVolume, records[k], baselineCount, ratio,
			),
			Evidence: evidence,
			EventIDs: m.eventIDs,
		})
	}

	return findings
}
