// Package exampledetector is the trivial rule used to PROVE the wasip1 sidecar
// delivery path end to end (mallcoppro-f70): the same detect.Detector
// implementation is run two ways — in-process (an ordinary Go call) and
// wrapped by detecthost as a real, compiled .wasm sidecar — and the two runs
// must produce byte-identical findings. It is not a real security rule; it
// exists only as the example + proof fixture the spec requires.
//
// It is a plain package (not `main`) so it can be imported both by the wasip1
// sidecar main (../main.go) and directly, in-process, by host-side tests —
// proving "sidecar findings == in-process findings" requires calling the SAME
// Go code both ways.
package exampledetector

import (
	"encoding/json"
	"fmt"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// EventType is the marker event.Type this trivial rule fires on.
const EventType = "sidecar-example-trigger"

// Detector fires one "low" severity finding for every event whose Type is
// EventType. It is intentionally the simplest possible rule: no baseline use,
// no regex, no per-actor state — anything more elaborate would make the
// in-process-vs-sidecar equality proof harder to eyeball.
type Detector struct{}

var _ detect.Detector = Detector{}

// Name implements detect.Detector.
func (Detector) Name() string { return "sidecar-example" }

// Detect implements detect.Detector.
func (Detector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type != EventType {
			continue
		}
		evidence, _ := json.Marshal(map[string]string{"rule": "sidecar-example-trigger"})
		out = append(out, finding.Finding{
			ID:        "finding-" + ev.ID + "-sidecar-example",
			Source:    "detector:sidecar-example",
			Severity:  "low",
			Type:      "sidecar-example",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("event %q from actor %q matched the sidecar-example trigger", ev.ID, ev.Actor),
			Evidence:  evidence,
		})
	}
	return out
}
