// registry_test.go — PROOF that the own-package authored-detector mechanism
// works end-to-end (K7 L1). This test file is part of package `authored`, so
// building the test binary links `authored`, which blank-imports every
// authored detector package (registry.go). Each authored package's init()
// therefore runs and calls detect.Register BEFORE this test executes — exactly
// the linkage cmd/mallcop gets in production.
package authored

import (
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/event"
)

const referenceDetectorName = "authored-synthetic-marker"
const syntheticMarkerType = "mallcop.synthetic-marker"

// TestReferenceDetectorRegisters proves the reference authored detector is
// reachable through the framework registry once the aggregator is linked —
// i.e. its own-package init() ran and detect.Register succeeded.
func TestReferenceDetectorRegisters(t *testing.T) {
	found := false
	for _, d := range detect.Detectors() {
		if d.Name() == referenceDetectorName {
			found = true
			break
		}
	}
	if !found {
		var names []string
		for _, d := range detect.Detectors() {
			names = append(names, d.Name())
		}
		t.Fatalf("reference authored detector %q not registered via the aggregator; registered: %v",
			referenceDetectorName, names)
	}
}

// TestReferenceDetectorDetects proves the reference detector is actually run by
// detect.Detect and fires on its synthetic marker — and, critically, that it
// does NOT fire on an ordinary event, so linking it cannot perturb the corpus.
func TestReferenceDetectorDetects(t *testing.T) {
	marker := event.Event{
		ID:        "ev-marker",
		Type:      syntheticMarkerType,
		Actor:     "tester",
		Timestamp: time.Now(),
	}
	findings := detect.Detect([]event.Event{marker}, nil)
	hits := 0
	for _, f := range findings {
		if f.Type == referenceDetectorName {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("reference detector fired %d times on the synthetic marker, want exactly 1 (findings: %+v)", hits, findings)
	}

	// Corpus-safety: on an ordinary (non-marker) event the reference detector
	// must emit nothing, so registering it changes no existing scenario outcome.
	ordinary := event.Event{
		ID:        "ev-ordinary",
		Type:      "login",
		Actor:     "tester",
		Timestamp: time.Now(),
	}
	findings = detect.Detect([]event.Event{ordinary}, nil)
	for _, f := range findings {
		if f.Type == referenceDetectorName {
			t.Fatalf("reference detector fired on an ordinary event — it must fire only on the synthetic marker (finding: %+v)", f)
		}
	}
}
