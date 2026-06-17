// Package detect provides offline, deterministic security detection over a
// corpus of normalized events. It exposes a Detector registry and a single
// Detect entry point that runs every registered detector and aggregates the
// findings.
//
// The detection logic is lifted, unchanged, from the standalone
// cmd/detector-* binaries. Each detector implementation here is the source of
// truth; the standalone binaries remain as thin stdin/stdout wrappers. No
// inference key, network access, or external service is required — detection
// is pure, in-process, and reproducible.
package detect

import (
	"sort"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// Detector evaluates a corpus of events against a baseline and returns zero or
// more findings. Implementations are pure: no I/O, no network, no shared
// mutable state across calls. A detector that is naturally per-event simply
// loops over the corpus internally; a detector that needs whole-corpus context
// (e.g. volume-anomaly) consumes the full slice.
type Detector interface {
	// Name is the stable detector identifier, e.g. "config-drift".
	Name() string

	// Detect returns findings for the given events. bl is never nil; callers
	// that have no baseline pass an empty &baseline.Baseline{}.
	Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding
}

// registry holds all detectors keyed by Name. Populated by Register, typically
// from each detector file's init().
var registry = map[string]Detector{}

// Register adds a detector to the package registry. It panics on a duplicate
// name so registration collisions surface at startup rather than silently
// dropping a detector. Intended to be called from init().
func Register(d Detector) {
	name := d.Name()
	if _, exists := registry[name]; exists {
		panic("detect: duplicate detector registered: " + name)
	}
	registry[name] = d
}

// Detectors returns the registered detectors ordered by name. The slice is a
// fresh copy; mutating it does not affect the registry.
func Detectors() []Detector {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Detector, 0, len(names))
	for _, n := range names {
		out = append(out, registry[n])
	}
	return out
}

// Detect runs every registered detector over the events and returns the
// aggregated findings. Detectors run in deterministic (name-sorted) order, and
// each detector's findings are appended in the order it produces them, so the
// overall output is reproducible for a fixed input.
//
// bl may be nil; a nil baseline is treated as an empty baseline so detectors
// that only need event content (injection-probe, secrets-exposure, git-oops,
// config-drift, dependency-tamper, malicious-skill) work with no baseline at
// all. No inference key is required.
func Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	if bl == nil {
		bl = &baseline.Baseline{}
	}
	var all []finding.Finding
	for _, d := range Detectors() {
		all = append(all, d.Detect(events, bl)...)
	}
	return all
}
