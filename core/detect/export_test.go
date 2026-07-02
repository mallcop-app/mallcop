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
