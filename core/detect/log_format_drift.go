package detect

import (
	"encoding/json"
	"fmt"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(logFormatDriftDetector{}) }

type logFormatDriftDetector struct{}

func (logFormatDriftDetector) Name() string { return "log-format-drift" }

// logDriftThreshold is the unmatched-line percentage above which a log_format_drift
// event is flagged. A parser that suddenly fails to match a meaningful fraction of
// log lines indicates either a service update that changed the log shape or active
// log tampering — both warrant surfacing. The corpus drift events carry
// unmatched_percent of 15/25/40 (LFD-01/03/02), so a threshold of 10 surfaces all.
const logDriftThreshold = 10.0

// Detect fires on a log_format_drift event whose unmatched_percent exceeds the
// threshold. Fires on ev.Actor (the service/component emitting the drifting logs,
// which the scenario finding metadata names).
func (logFormatDriftDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type != "log_format_drift" {
			continue
		}
		meta := payloadMeta(ev.Payload)
		pct, ok := metaFloat(meta, "unmatched_percent")
		if !ok || pct < logDriftThreshold {
			continue
		}
		evidence, _ := json.Marshal(map[string]any{
			"actor":             ev.Actor,
			"unmatched_percent": pct,
			"event_type":        ev.Type,
			"event_id":          ev.ID,
		})
		out = append(out, finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:log-format-drift",
			Severity:  "high",
			Type:      "log-format-drift",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason: fmt.Sprintf(
				"log format drift: %q logs %.0f%% unmatched by the parser (possible tampering or unsignaled service change)",
				ev.Actor, pct,
			),
			Evidence: evidence,
		})
	}
	return out
}
