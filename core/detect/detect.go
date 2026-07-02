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
	"fmt"
	"log"
	"sort"
	"time"

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

// frameworkDetectorNames is the checked-in set of BUILT-IN ("framework")
// detector Names — the detectors declared in core/detect/*.go and registered by
// their own files' init(). It is maintained by hand and kept honest by
// TestFrameworkDetectorNamesMatchRegistry (the detect package test binary links
// no authored detectors, so the live registry there is exactly this set).
//
// Why a checked-in list and not the live registry: the K7 shape gate
// (core/selfgate) seeds its detector-Name-uniqueness set with these to reject —
// BEFORE merge — an authored detector whose Name collides with a built-in, which
// would otherwise be an unrecovered detect.Register panic that crashes
// cmd/mallcop at init. The gate must return the SAME framework set regardless of
// whether the process running it ALSO links authored detectors (cmd/mallcop
// does): reading the live registry there would re-discover an already-merged
// authored detector that is present both in the registry AND on disk in the head
// tree, and the tree walk would flag it as colliding with itself. A
// process-independent list avoids that false positive.
var frameworkDetectorNames = []string{
	"auth-failure-burst",
	"config-drift",
	"dependency-tamper",
	"exfil-pattern",
	"git-oops",
	"injection-probe",
	"log-format-drift",
	"malicious-skill",
	"new-actor",
	"new-external-access",
	"priv-escalation",
	"rate-anomaly",
	"secrets-exposure",
	"unusual-login",
	"unusual-resource-access",
	"unusual-timing",
	"volume-anomaly",
}

// FrameworkDetectorNames returns a fresh, sorted copy of the built-in detector
// Names. The K7 shape gate seeds its Name-uniqueness set with these so an
// authored Name colliding with a framework detector is a deterministic pre-merge
// rejection rather than a startup panic. Independent of the live registry so it
// is stable no matter what a given binary links (see frameworkDetectorNames).
func FrameworkDetectorNames() []string {
	out := make([]string, len(frameworkDetectorNames))
	copy(out, frameworkDetectorNames)
	return out
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

// detectorTimeout bounds ONE detector's wall-clock runtime inside Detect. A
// detector that panics OR exceeds this deadline is QUARANTINED: only its own
// output is dropped and a diagnostic is recorded; every OTHER detector's
// findings survive and the scan completes. This is the L4 resource floor for
// agent-authored detectors — the shared-package framework detectors are pure
// and fast by contract, but an authored detector (core/detect/authored/<name>/)
// is code the self-extension loop produced, so a runaway or panicking one must
// not be able to hang or crash a whole scan.
//
// TRADEOFF (documented, load-bearing): Go cannot forcibly kill a goroutine, so
// a detector stuck in a pure CPU loop or a blocking call LEAKS its goroutine for
// the life of the process even after Detect stops waiting for it. We accept the
// leak because the alternative — letting one detector hang the entire scan — is
// strictly worse: Detect returns with every healthy detector's findings intact.
// mallcop is a one-shot CLI, so a leaked goroutine lives only until the scan
// process exits, and a well-behaved detector never times out. The recover()
// side has no such caveat: a panic is fully contained.
const detectorTimeout = 5 * time.Second

// quarantineReporter records that a detector was QUARANTINED (panicked or blew
// its deadline) and its output dropped. It defaults to a stderr log line;
// detectsafe_test.go swaps it to observe quarantines deterministically without
// depending on log capture. It is package-level indirection for the diagnostic
// sink, NOT shared scan state — Detect passes no mutable accumulator between
// detectors.
var quarantineReporter = func(name, reason string) {
	log.Printf("detect: QUARANTINED detector %q (its output dropped; scan continues with the other detectors): %s", name, reason)
}

// Detect runs every registered detector over the events and returns the
// aggregated findings. Detectors run in deterministic (name-sorted) order, and
// each detector's findings are appended in the order it produces them, so the
// overall output is reproducible for a fixed input.
//
// Each detector runs under runDetectorSafely: a per-detector recover() + a
// wall-clock deadline (detectorTimeout). A detector that panics or times out is
// QUARANTINED — its output is dropped and a diagnostic recorded — and Detect
// continues with the remaining detectors. Detect itself therefore NEVER panics
// and NEVER hangs on one bad detector; the healthy detectors' findings always
// come back.
//
// bl may be nil; a nil baseline is treated as an empty baseline so detectors
// that only need event content (injection-probe, secrets-exposure, git-oops,
// config-drift, dependency-tamper, malicious-skill) work with no baseline at
// all. No inference key is required.
func Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	if bl == nil {
		bl = &baseline.Baseline{}
	}
	return detectAll(Detectors(), detectorTimeout, events, bl)
}

// detectAll is the aggregation core: it runs each detector in order under
// runDetectorSafely with the given per-detector deadline and appends the output
// of every detector that completes cleanly. A quarantined detector contributes
// nothing (its output dropped) but does not stop the others. Split out from
// Detect so tests can drive it with an explicit detector slice + a short timeout
// WITHOUT mutating the process-wide registry (which would break the exact
// registered-detector-count assertions).
func detectAll(detectors []Detector, timeout time.Duration, events []event.Event, bl *baseline.Baseline) []finding.Finding {
	var all []finding.Finding
	for _, d := range detectors {
		// INPUT ISOLATION (K7 HOLE 1a — framework defence-in-depth). Every
		// detector gets a FRESH, DEEP copy of the events (each event's mutable
		// Payload []byte reallocated) and its own baseline clone, so no
		// detector — a framework bug OR a malicious authored one that mutates
		// its arguments (events[i].Payload = nil, bl.KnownActors = nil) — can
		// corrupt what any OTHER detector sees. The 17 framework detectors are
		// pure readers, so this is behaviour-identical for them; it is a floor
		// for agent-authored code. It also removes the data race the previous
		// shared-slice threading had: a timed-out detector's LEAKED goroutine
		// now mutates only its own copy, never the input the next detector reads.
		out, ok := runDetectorSafely(d, timeout, cloneEventsForDetector(events), bl.Clone())
		if !ok {
			continue // quarantined; diagnostic already recorded by runDetectorSafely
		}
		all = append(all, out...)
	}
	return all
}

// runDetectorSafely runs one detector's Detect under a recover() AND a
// per-detector wall-clock deadline. It returns (findings, true) when the
// detector completes cleanly within timeout, or (nil, false) when it PANICS or
// exceeds the deadline — in which case the detector is quarantined (its output
// dropped) and a diagnostic is recorded via quarantineReporter. It never panics
// and never blocks longer than timeout.
//
// The detector runs in its own goroutine; the done channel is BUFFERED (cap 1)
// so that a timed-out detector's goroutine can still send its (ignored) result
// and exit cleanly rather than blocking forever on the send — the only way it
// leaks is if it never returns at all (the documented tradeoff on detectorTimeout).
func runDetectorSafely(d Detector, timeout time.Duration, events []event.Event, bl *baseline.Baseline) ([]finding.Finding, bool) {
	type outcome struct {
		findings []finding.Finding
		panicked bool
		panicVal any
	}
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if p := recover(); p != nil {
				o.panicked = true
				o.panicVal = p
				o.findings = nil
			}
			done <- o
		}()
		o.findings = d.Detect(events, bl)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case o := <-done:
		if o.panicked {
			quarantineReporter(d.Name(), fmt.Sprintf("panic recovered: %v", o.panicVal))
			return nil, false
		}
		return o.findings, true
	case <-timer.C:
		quarantineReporter(d.Name(), fmt.Sprintf("exceeded the %s per-detector deadline", timeout))
		return nil, false
	}
}
