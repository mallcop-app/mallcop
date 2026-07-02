package detect

// detectsafe_test.go — PROOF that the L4 per-detector resource floor QUARANTINES
// a panicking or timing-out detector: its output is dropped and a diagnostic is
// recorded, but every OTHER detector's findings survive and the aggregation
// completes. A panicking/hung authored detector must never crash or hang a scan.
//
// The tests drive the internal detectAll seam with an explicit detector slice
// and a short deadline so a "runaway" detector proves the timeout path in
// milliseconds and WITHOUT registering into the process-wide registry (which
// would break the exact registered-detector-count assertions in detect_test.go).
// The public Detect delegates to detectAll over the live registry, so the path
// under test is the same one production runs.

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// healthyDetector emits exactly one finding per call — the survivor whose output
// must come back even when a sibling detector panics or hangs.
type healthyDetector struct{ name, fam string }

func (h healthyDetector) Name() string { return h.name }
func (h healthyDetector) Detect(_ []event.Event, _ *baseline.Baseline) []finding.Finding {
	return []finding.Finding{{ID: "f-" + h.name, Type: h.fam, Source: "detector:" + h.name}}
}

// panickingDetector panics inside Detect — the recover() path.
type panickingDetector struct{}

func (panickingDetector) Name() string { return "test-panicker" }
func (panickingDetector) Detect(_ []event.Event, _ *baseline.Baseline) []finding.Finding {
	panic("authored detector blew up")
}

// sleepingDetector blocks past the deadline — the timeout path.
type sleepingDetector struct{ d time.Duration }

func (s sleepingDetector) Name() string { return "test-sleeper" }
func (s sleepingDetector) Detect(_ []event.Event, _ *baseline.Baseline) []finding.Finding {
	time.Sleep(s.d)
	return []finding.Finding{{ID: "f-sleeper", Type: "should-be-dropped"}}
}

// captureQuarantines swaps quarantineReporter for a recording sink for the
// duration of the test and returns the recorded (name→reason) map + a restore.
// Not parallel-safe (mutates a package var) — these tests do not call
// t.Parallel().
func captureQuarantines(t *testing.T) map[string]string {
	t.Helper()
	var mu sync.Mutex
	got := map[string]string{}
	prev := quarantineReporter
	quarantineReporter = func(name, reason string) {
		mu.Lock()
		defer mu.Unlock()
		got[name] = reason
	}
	t.Cleanup(func() { quarantineReporter = prev })
	return got
}

// familiesOf collects the family (Type) of every finding for assertions.
func familiesOf(findings []finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		out[f.Type] = true
	}
	return out
}

// TestDetect_QuarantinesPanickingDetector proves a detector that PANICS is
// quarantined (its output dropped, a diagnostic recorded) while the healthy
// detectors on either side of it still contribute their findings — the scan
// never crashes.
func TestDetect_QuarantinesPanickingDetector(t *testing.T) {
	got := captureQuarantines(t)

	detectors := []Detector{
		healthyDetector{name: "aaa-healthy", fam: "fam-a"},
		panickingDetector{},
		healthyDetector{name: "zzz-healthy", fam: "fam-z"},
	}

	findings := detectAll(detectors, detectorTimeout, nil, &baseline.Baseline{})

	fams := familiesOf(findings)
	if !fams["fam-a"] || !fams["fam-z"] {
		t.Fatalf("healthy detectors' findings were dropped: got families %v, want fam-a and fam-z", fams)
	}
	if len(findings) != 2 {
		t.Fatalf("expected exactly the 2 healthy findings, got %d: %+v", len(findings), findings)
	}
	if reason, ok := got["test-panicker"]; !ok {
		t.Fatalf("panicking detector was not recorded as quarantined; recorded=%v", got)
	} else if reason == "" {
		t.Fatalf("quarantine diagnostic for the panicker is empty")
	}
}

// TestDetect_QuarantinesTimingOutDetector proves a detector that BLOWS THE
// per-detector deadline is quarantined (its output dropped, a diagnostic
// recorded) while the healthy detector still fires — the scan never hangs. It
// runs with a short deadline so the hung goroutine is bounded to a few
// milliseconds of test time.
func TestDetect_QuarantinesTimingOutDetector(t *testing.T) {
	got := captureQuarantines(t)

	const shortDeadline = 30 * time.Millisecond
	detectors := []Detector{
		healthyDetector{name: "aaa-healthy", fam: "fam-a"},
		sleepingDetector{d: 5 * time.Second}, // far past the short deadline
	}

	start := time.Now()
	findings := detectAll(detectors, shortDeadline, nil, &baseline.Baseline{})
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("detectAll blocked %s on the sleeping detector; the deadline must cap it near %s", elapsed, shortDeadline)
	}
	fams := familiesOf(findings)
	if !fams["fam-a"] {
		t.Fatalf("healthy detector's finding was dropped when the sibling timed out: got %v", fams)
	}
	if fams["should-be-dropped"] {
		t.Fatalf("timed-out detector's output leaked into the result: %+v", findings)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly the 1 healthy finding, got %d: %+v", len(findings), findings)
	}
	if _, ok := got["test-sleeper"]; !ok {
		t.Fatalf("timing-out detector was not recorded as quarantined; recorded=%v", got)
	}
}

// mutatingDetector is a MALICIOUS authored-style detector: it writes THROUGH its
// arguments — nil-ing every event Payload and clearing the baseline — then emits
// nothing. Its Name sorts FIRST, so absent input isolation it runs before and
// SILENCES the reader below. This is exactly the K7 HOLE 1 shared-input mutation.
type mutatingDetector struct{}

func (mutatingDetector) Name() string { return "aaa-mutator" }
func (mutatingDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	for i := range events {
		events[i].Payload = nil
	}
	bl.KnownActors = nil
	for k := range bl.KnownUsers {
		delete(bl.KnownUsers, k)
	}
	return nil
}

// payloadReaderDetector fires one finding per event that STILL carries a
// non-empty Payload, but only when the baseline STILL lists a known actor — so
// it fires IFF its input was NOT silenced by the mutating sibling. Its Name sorts
// LAST, so it runs after the mutator.
type payloadReaderDetector struct{}

func (payloadReaderDetector) Name() string { return "zzz-reader" }
func (payloadReaderDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	if len(bl.KnownActors) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, ev := range events {
		if len(ev.Payload) > 0 {
			out = append(out, finding.Finding{ID: "read-" + ev.ID, Type: "read"})
		}
	}
	return out
}

// TestDetectAll_IsolatesInputFromMutatingSibling is the framework half of the K7
// HOLE 1a proof: a first-running (name-sorted-earliest) detector that mutates its
// events/baseline arguments CANNOT silence a later sibling, because detectAll
// hands each detector its own DEEP copy of the input. It also proves detectAll
// never mutates the CALLER's original events slice or baseline.
func TestDetectAll_IsolatesInputFromMutatingSibling(t *testing.T) {
	events := []event.Event{
		{ID: "e1", Actor: "alice", Payload: json.RawMessage(`{"k":"v"}`)},
		{ID: "e2", Actor: "bob", Payload: json.RawMessage(`{"k":"w"}`)},
	}
	bl := &baseline.Baseline{
		KnownActors: []string{"alice", "bob"},
		KnownUsers:  map[string]baseline.UserProfile{"alice": {}},
	}

	// aaa-mutator sorts before zzz-reader; detectAll runs them in that order.
	findings := detectAll(
		[]Detector{mutatingDetector{}, payloadReaderDetector{}},
		detectorTimeout, events, bl,
	)

	if fams := familiesOf(findings); !fams["read"] {
		t.Fatalf("the reader was SILENCED by a mutating sibling — per-detector input isolation failed: got %+v", findings)
	}
	if n := len(findings); n != 2 {
		t.Fatalf("reader should fire once per event that kept its payload (want 2), got %d: %+v", n, findings)
	}
	// The caller's original input must survive intact — detectAll clones, so the
	// mutator only ever touched its own copy.
	if events[0].Payload == nil || events[1].Payload == nil {
		t.Fatalf("detectAll mutated the caller's event payloads: %+v", events)
	}
	if len(bl.KnownActors) != 2 || len(bl.KnownUsers) != 1 {
		t.Fatalf("detectAll mutated the caller's baseline: KnownActors=%v KnownUsers=%v", bl.KnownActors, bl.KnownUsers)
	}
}

// TestDetect_CleanDetectorsAllFire is the negative control: with no bad
// detector, detectAll returns every detector's output and records NO quarantine.
func TestDetect_CleanDetectorsAllFire(t *testing.T) {
	got := captureQuarantines(t)

	detectors := []Detector{
		healthyDetector{name: "one", fam: "fam-1"},
		healthyDetector{name: "two", fam: "fam-2"},
	}
	findings := detectAll(detectors, detectorTimeout, nil, &baseline.Baseline{})
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings from 2 clean detectors, got %d", len(findings))
	}
	if len(got) != 0 {
		t.Fatalf("clean run recorded quarantines: %v", got)
	}
}
