// synthdemo_invariant_test.go — the vocab-lint INVARIANT guarding the synthetic
// gap-close demo fixture (exams/synthetic/, rd mallcoppro-a07 / S1 ruling).
//
// The self-extension gate tests demonstrate a tuning gap-close END-TO-END by
// injecting a PURPOSE-BUILT synthetic pair into a throwaway corpus:
//
//	SYNTH-PE-01 (must_fire) — role "MallcopSyntheticElevatedRole"
//	SYNTH-PE-02 (must_not_fire benign twin) — role "MallcopSyntheticBaselineRole"
//
// closed by exams/synthetic/tuning.yaml's synthetic keyword
// "mallcopsyntheticelevated". The WHOLE POINT of that fixture is that the gap is
// UNCLOSABLE WITHOUT TUNING — the elevated role carries none of priv-escalation's
// built-in elevation vocabulary, so only the synthetic knob can make it fire.
// That property is what lets every REAL corpus scenario (PE-08, IP-01, ...) be
// fixed for good instead of being held RED-able just to demonstrate a gap-close.
//
// This test is the tripwire that keeps the property true. It FAILS if:
//   - the synthetic keyword ever becomes a built-in elevated keyword (the demo
//     would then "close" with no tuning — the treadmill returns), or
//   - either synthetic role is edited to carry a built-in keyword substring
//     (SYNTH-PE-01 would fire untuned; SYNTH-PE-02 would fire always), or
//   - the synthetic tuning file stops closing the gap it is paired with.
//
// It lives in the EXTERNAL detect_test package (like tuning_exam_regression_test.go,
// whose repoRootFromHere helper it reuses) so it can drive the real
// ApplyTuning / snapshot-restore seam without leaking a narrowing API.
package detect_test

import (
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// Synthetic-fixture constants — kept in lockstep with exams/synthetic/*. The
// role values are ASSERTED against the on-disk scenario files below (so a drift
// in either direction fails), and the keyword is ASSERTED to be exactly what
// exams/synthetic/tuning.yaml carries.
const (
	synthElevatedRole = "MallcopSyntheticElevatedRole"
	synthBaselineRole = "MallcopSyntheticBaselineRole"
	synthKeyword      = "mallcopsyntheticelevated"

	synthMustFireFile = "exams/synthetic/SYNTH-PE-01-elevated-must-fire.yaml"
	synthTwinFile     = "exams/synthetic/SYNTH-PE-02-baseline-benign-twin.yaml"
	synthTuningFile   = "exams/synthetic/tuning.yaml"
)

// scenarioRole loads a synthetic scenario file and returns the role value of its
// first event's metadata — the discriminator priv-escalation keys on.
func scenarioRole(t *testing.T, root, rel string) string {
	t.Helper()
	s, err := exam.Load(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("load %s: %v", rel, err)
	}
	if len(s.Events) == 0 {
		t.Fatalf("%s has no events", rel)
	}
	role, _ := s.Events[0].Metadata["role"].(string)
	if role == "" {
		t.Fatalf("%s event[0] carries no metadata.role", rel)
	}
	return role
}

// TestSynthDemoKeywordNeverBuiltin is the core invariant: with ONLY the built-in
// priv-escalation vocabulary published (no tuning), the synthetic elevated role
// must NOT match — proving the demo gap is real and requires the synthetic knob.
// If the synthetic keyword is ever promoted into builtinElevatedKeywords (or the
// role is edited to carry a built-in keyword), this assertion flips and fails.
func TestSynthDemoKeywordNeverBuiltin(t *testing.T) {
	root := repoRootFromHere(t)

	// The on-disk fixture must carry exactly the roles this invariant reasons
	// about — pin the constants to the files so neither can drift silently.
	if got := scenarioRole(t, root, synthMustFireFile); got != synthElevatedRole {
		t.Fatalf("%s role = %q, want %q (fixture/constant drift)", synthMustFireFile, got, synthElevatedRole)
	}
	if got := scenarioRole(t, root, synthTwinFile); got != synthBaselineRole {
		t.Fatalf("%s role = %q, want %q (fixture/constant drift)", synthTwinFile, got, synthBaselineRole)
	}

	// Restore the built-in snapshot after this test — ApplyTuning below mutates
	// process-global knobs.
	restore := detect.SnapshotTuningKnobsForTest()
	defer restore()

	// With built-ins ONLY, neither synthetic role may match. The elevated role
	// matching here would mean the synthetic keyword became a built-in (or a
	// built-in keyword is now a substring of the role) — the treadmill returning.
	if detect.ContainsElevatedKeywordForTest(synthElevatedRole) {
		t.Fatalf("built-in priv-escalation vocabulary matches the synthetic elevated role %q — "+
			"the synthetic gap-close keyword must NEVER be a built-in (it is the demo's whole reason to exist). "+
			"Either %q was added to builtinElevatedKeywords or the fixture role was changed to carry a built-in keyword.",
			synthElevatedRole, synthKeyword)
	}
	if detect.ContainsElevatedKeywordForTest(synthBaselineRole) {
		t.Fatalf("built-in priv-escalation vocabulary matches the synthetic BENIGN-TWIN role %q — "+
			"the twin must stay silent under every tuning; a built-in match here breaks the false-positive floor",
			synthBaselineRole)
	}
}

// TestSynthDemoTuningClosesTheGap proves the paired synthetic tuning file
// actually closes the gap it is designed to close, and ONLY that gap: applying
// exams/synthetic/tuning.yaml makes the elevated role match while the benign
// twin stays silent. This is the positive half of the invariant — the fixture is
// a genuine, closable-only-by-tuning gap, not a permanently-dead one.
func TestSynthDemoTuningClosesTheGap(t *testing.T) {
	root := repoRootFromHere(t)

	tuning, err := detect.LoadTuningFile(filepath.Join(root, filepath.FromSlash(synthTuningFile)))
	if err != nil {
		t.Fatalf("load %s: %v", synthTuningFile, err)
	}
	// The synthetic tuning file must carry exactly the keyword this invariant
	// reasons about.
	found := false
	for _, kw := range tuning.PrivEscalation.ExtraElevatedKeywords {
		if kw == synthKeyword {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s does not carry the synthetic keyword %q; got %v",
			synthTuningFile, synthKeyword, tuning.PrivEscalation.ExtraElevatedKeywords)
	}

	restore := detect.SnapshotTuningKnobsForTest()
	defer restore()

	detect.ApplyTuning(tuning)

	if !detect.ContainsElevatedKeywordForTest(synthElevatedRole) {
		t.Fatalf("after applying %s, the synthetic elevated role %q still does not match — "+
			"the paired tuning no longer closes its gap", synthTuningFile, synthElevatedRole)
	}
	if detect.ContainsElevatedKeywordForTest(synthBaselineRole) {
		t.Fatalf("after applying %s, the synthetic BENIGN-TWIN role %q matches — "+
			"the synthetic keyword widened onto the twin (false-positive floor broken)",
			synthTuningFile, synthBaselineRole)
	}
}
