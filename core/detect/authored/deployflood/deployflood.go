// Package deployflood is an agent-authored detector that fires on a genuine
// VOLUME anomaly in github.deployment events — a real flood of deployments by
// one actor, not the mere presence of a deployment.
//
// mallcoppro-8ac9 (2026-07-15, Baron): the original version of this detector
// fired severity:high on EVERY single github.deployment event, with no
// counting, no window, and no baseline comparison — a false-positive cannon
// that would have escalated every normal deploy on every customer repo. This
// rewrite gives it real flood semantics: it counts github.deployment events
// per actor within the given event set (the scenario/scan's own event window
// — the same "whole-slice" model the framework's volume-anomaly detector uses,
// see core/detect/volume_anomaly.go) and compares the count against the
// actor's baseline deployment frequency (pkg/baseline.Baseline.FreqCountActor,
// keyed "github:github.deployment:<actor>", the identical 3-segment shape the
// corpus's frequency_tables and volume-anomaly both use). It fires ONLY when
// that count is a genuine burst: well above the actor's established baseline,
// or — when the baseline is thin or absent — above an absolute floor, so a
// flood with no history still fires. A single deployment, or a volume the
// baseline already explains, never fires.
package deployflood

import (
	"fmt"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(detector{}) }

const detectorName = "authored-deploy-flood"

// deployEventType is the github connector event type this detector watches.
const deployEventType = "github.deployment"

// Flood thresholds. Mirrors the shape of the framework's volume-anomaly
// detector (core/detect/volume_anomaly.go): a dual gate where either a strong
// ratio over an established baseline, or a large absolute count regardless of
// baseline, marks the observed volume a flood.
const (
	// deployFloodRatio is the multiplier over the actor's baseline deployment
	// count that marks the observed count a flood, once the baseline is large
	// enough to trust (see deployFloodMinBaselineForRatio).
	deployFloodRatio = 3.0

	// deployFloodMinBaselineForRatio is the minimum baseline count required
	// before the ratio comparison is trusted. A baseline of 1 or 2 makes even
	// a 3rd or 4th ordinary deployment look like "3x baseline" — too noisy to
	// mean anything — so the ratio path only engages once there is enough
	// history to make a ratio meaningful.
	deployFloodMinBaselineForRatio = 3

	// deployFloodAbsoluteFloor is the observed per-actor deployment count
	// within the event set above which the volume is a flood REGARDLESS of
	// baseline — a genuine burst with a thin-or-zero baseline (a brand-new
	// actor, or one whose deployment history was never established) is still
	// a flood; it must not be waved through just because there is nothing to
	// compute a ratio against.
	deployFloodAbsoluteFloor = 8
)

type detector struct{}

func (detector) Name() string { return "authored-deploy-flood" }

// Detect is pure: it reads events and the baseline, allocates local findings,
// and returns them. It mutates no package-level state and treats events/bl as
// read-only (per-detector isolation the framework enforces around every
// registered detector). It counts github.deployment events per actor across
// the given event set, compares each actor's count against that actor's
// baseline deployment frequency, and emits one finding per actor whose count
// is a genuine flood — never for a lone deployment or a baseline-consistent
// volume.
func (detector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	counts := make(map[string]int)
	for _, ev := range events {
		if ev.Type != deployEventType {
			continue
		}
		counts[ev.Actor]++
	}

	fired := make(map[string]bool, len(counts))
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type != deployEventType || fired[ev.Actor] {
			continue
		}
		count := counts[ev.Actor]
		baselineCount := bl.FreqCountActor("github", deployEventType, ev.Actor)

		isFlood := count >= deployFloodAbsoluteFloor
		if !isFlood && baselineCount >= deployFloodMinBaselineForRatio {
			isFlood = float64(count) > deployFloodRatio*float64(baselineCount)
		}
		if !isFlood {
			continue
		}
		fired[ev.Actor] = true

		out = append(out, finding.Finding{
			ID:        "finding-" + ev.ID + "-deploy-flood",
			Source:    "detector:" + detectorName,
			Severity:  "high",
			Type:      detectorName,
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason: fmt.Sprintf(
				"github.deployment flood by %q: %d deployment events observed vs baseline %d",
				ev.Actor, count, baselineCount),
		})
	}
	return out
}
