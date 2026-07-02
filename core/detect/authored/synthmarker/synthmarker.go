// Package synthmarker is the REFERENCE agent-authored detector. It exists to
// prove the own-package authored-detector mechanism (K7 L1) end-to-end: it is
// its OWN Go package that imports the detector framework and registers itself
// via init(); it is reachable by detect.Detect once the aggregator
// (core/detect/authored) is linked into the binary; and it is shaped to pass
// the K2a import allow-list (L2) and the K7 additive-shape AST gate (L3).
//
// WHY OWN-PACKAGE ISOLATION MATTERS (the §5 L1 hazard it closes): every
// framework detector lives in the single shared package `detect`
// (core/detect/*.go), so a new file added directly under core/detect/ would be
// `package detect` and its init() could mutate a sibling detector's unexported
// package state (e.g. injectionPatterns in injection_probe.go), silently
// narrowing a security-critical detector. An authored detector lives in its
// OWN package under core/detect/authored/<name>/, so its init() sees only its
// own file scope — it cannot see, let alone assign, another detector's package
// vars. The isolation is STRUCTURAL, not policed.
//
// BENIGN BY CONSTRUCTION (corpus-safety): this detector fires only on the
// synthetic event type below, a marker that never appears in the labeled exam
// corpus. Registering it therefore cannot perturb any existing scenario's
// outcome — exam-detect emits nothing new for it — so the reference detector is
// additive at every layer (guard, allow-list, shape gate, and the exam-detect
// no-new-firings contract).
package synthmarker

import (
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// init is the sole registration hook: own-package init() runs only when this
// package is linked (via the aggregator's blank import), and it can reach
// nothing but this package's own scope.
func init() { detect.Register(detector{}) }

// markerType is the synthetic event type this reference detector recognizes. It
// is namespaced so it cannot collide with any real connector event type present
// in the corpus.
const markerType = "mallcop.synthetic-marker"

// detectorName is the stable, unique detector identifier.
const detectorName = "authored-synthetic-marker"

type detector struct{}

func (detector) Name() string { return "authored-synthetic-marker" }

// Detect is pure: it reads events, allocates local findings, and returns them.
// It mutates no package-level state (the shape gate forbids it) and touches no
// I/O, network, or process. It fires exactly once per synthetic-marker event.
func (detector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type != markerType {
			continue
		}
		out = append(out, finding.Finding{
			ID:        "finding-" + ev.ID + "-synthetic-marker",
			Source:    "detector:" + detectorName,
			Severity:  "low",
			Type:      detectorName,
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    "synthetic marker event observed by the reference authored detector",
		})
	}
	return out
}
