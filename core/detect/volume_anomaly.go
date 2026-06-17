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
	// on rarely-seen event types.
	volumeMinBaselineCount = 5
)

type volumeGroupKey struct {
	source    string
	eventType string
}

// volumeAnomalyEvaluateAll counts events per (source, event_type) group and
// returns findings for groups that exceed volumeAnomalyRatio × baseline count.
// Results are ordered deterministically by source then event_type.
// This is a pure function: no I/O, no globals mutated.
func volumeAnomalyEvaluateAll(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	// Count current events per group; track first event per group for finding ID.
	counts := make(map[volumeGroupKey]int)

	type groupMeta struct {
		firstEventID string
		firstEvent   event.Event
	}
	meta := make(map[volumeGroupKey]groupMeta)

	for _, ev := range events {
		k := volumeGroupKey{ev.Source, ev.Type}
		counts[k]++
		if _, seen := meta[k]; !seen {
			meta[k] = groupMeta{firstEventID: ev.ID, firstEvent: ev}
		}
	}

	// Sort groups for deterministic output.
	keys := make([]volumeGroupKey, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		return keys[i].eventType < keys[j].eventType
	})

	var findings []finding.Finding
	for _, k := range keys {
		currentCount := counts[k]
		baselineCount := bl.FreqCount(k.source, k.eventType)

		if baselineCount < volumeMinBaselineCount {
			continue
		}

		if float64(currentCount) <= volumeAnomalyRatio*float64(baselineCount) {
			continue
		}

		m := meta[k]
		ratio := float64(currentCount) / float64(baselineCount)

		evidence, _ := json.Marshal(map[string]interface{}{
			"source":         k.source,
			"event_type":     k.eventType,
			"current_count":  currentCount,
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
				"%s:%s volume spike: %d events vs baseline %d (%.1f×)",
				k.source, k.eventType, currentCount, baselineCount, ratio,
			),
			Evidence: evidence,
		})
	}

	return findings
}
