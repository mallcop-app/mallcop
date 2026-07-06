// Package deployflood is an agent-authored detector that fires on
// github.deployment events — a tell-tale of a flood of deployments that may
// indicate automated or coerced deploy activity. It mirrors the reference
// authored detector (synthmarker) in shape, kept tight so a benign look-alike
// event (one whose Type is not exactly "github.deployment") does NOT fire.
package deployflood

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(detector{}) }

const detectorName = "authored-deploy-flood"

type detector struct{}

func (detector) Name() string { return "authored-deploy-flood" }

func (detector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type != "github.deployment" {
			continue
		}
		out = append(out, finding.Finding{
			ID:        "finding-" + ev.ID + "-deploy-flood",
			Source:    "detector:" + detectorName,
			Severity:  "high",
			Type:      "authored-deploy-flood",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    "github.deployment event observed by the authored deploy-flood detector",
		})
	}
	return out
}