package detect

// SnapshotTuningKnobsForTest snapshots the priv-escalation tuning knob sets and
// returns a restore func. It exists ONLY for tests (this file is _test.go and is
// never linked into shipped binaries): ApplyTuning mutates package-global state
// process-wide, so any test that applies tuning — including the external
// detect_test exam-detect regression — must restore the knobs via t.Cleanup.
//
// This is NOT a production narrowing surface: the shipped package exposes no
// removal/override API; the tuning schema itself is add-only by construction.
func SnapshotTuningKnobsForTest() (restore func()) {
	s := saveKnobs()
	return func() { restoreKnobs(s) }
}

// SnapshotRegistryForTest snapshots the detector registry and returns a restore
// func. It exists ONLY for tests (this file is _test.go, never linked into
// shipped binaries): LoadRules registers decl-rule detectors into the
// package-global registry process-wide, so any test that loads rules must
// restore the registry via t.Cleanup, or it would leak decl detectors into the
// framework-count assertions (TestRegistryHasAllSeventeen) and the
// every-detector-has-a-fixture cross-check.
//
// The shipped package exposes NO unregister API — a one-shot CLI registers once
// at startup and exits. This is purely a test seam.
func SnapshotRegistryForTest() (restore func()) {
	saved := make(map[string]Detector, len(registry))
	for k, v := range registry {
		saved[k] = v
	}
	return func() {
		registry = make(map[string]Detector, len(saved))
		for k, v := range saved {
			registry[k] = v
		}
	}
}
