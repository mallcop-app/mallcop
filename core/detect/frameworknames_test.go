package detect

import (
	"sort"
	"testing"
)

// TestFrameworkDetectorNamesMatchRegistry keeps the checked-in
// frameworkDetectorNames list honest. The detect package test binary links NO
// authored detectors (core/detect/authored imports this package, so an internal
// detect test cannot link it without a cycle), so the live registry here is
// exactly the framework set. If someone adds or removes a framework detector
// without updating FrameworkDetectorNames, this fails — which matters because
// the K7 shape gate seeds its Name-collision set from that list to reject an
// authored Name that would otherwise panic detect.Register at startup.
func TestFrameworkDetectorNamesMatchRegistry(t *testing.T) {
	registered := map[string]bool{}
	for _, d := range Detectors() {
		registered[d.Name()] = true
	}

	listed := FrameworkDetectorNames()

	// The list must be sorted and duplicate-free (it is seeded into a set, and a
	// sorted list is easiest to review in diffs).
	if !sort.StringsAreSorted(listed) {
		t.Errorf("FrameworkDetectorNames() is not sorted: %v", listed)
	}
	seen := map[string]bool{}
	for _, n := range listed {
		if seen[n] {
			t.Errorf("FrameworkDetectorNames() lists %q more than once", n)
		}
		seen[n] = true
	}

	if len(listed) != len(registered) {
		t.Errorf("FrameworkDetectorNames() has %d names, live framework registry has %d", len(listed), len(registered))
	}
	for n := range registered {
		if !seen[n] {
			t.Errorf("registered framework detector %q is missing from FrameworkDetectorNames()", n)
		}
	}
	for n := range seen {
		if !registered[n] {
			t.Errorf("FrameworkDetectorNames() lists %q, which is not a registered framework detector", n)
		}
	}
}
