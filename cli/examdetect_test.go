package cli

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mallcop-app/mallcop/core/detect"
)

// repoRootForExamTest resolves the repo root from this test file's location
// (cli/ is one level below the root). Inside `go test` os.Executable lands in
// a temp build dir, so the RepoRoot walk finds no marker; the test pins
// MALLCOP_REPO_ROOT (the documented production fallback) instead.
func repoRootForExamTest(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), ".."))
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	return root
}

// TestRunExamDetect_RemainingGapExitsRed proves the CLI surfaces a
// labeled-and-unfixed detection gap as the errFindings sentinel (exit code 1).
//
// Every labeled gap that used to anchor this test is now CLOSED — VA-03 (the
// volume field/unit contract, mallcoppro-3c9), IP-01 (the SQLi-in-User-Agent
// injection probe, injection-probe's classic-injection signatures), and PE-08
// (the AWS PowerUserAccess grant, now a built-in priv-escalation keyword,
// mallcoppro-a07) all show PASS out of the box — the REAL pinned corpus has
// ZERO remaining labeled gaps. That is the fix landing, not a regression: an
// always-green corpus can no longer demonstrate "the CLI surfaces a gap as
// exit 1" at all, so this test injects the PURPOSE-BUILT synthetic pair
// (SYNTH-PE-01 must-fire + SYNTH-PE-02 benign twin, exams/synthetic/) into a
// throwaway clone of the pinned corpus via injectSyntheticCorpus (same helper
// TestRunExamDetect_ConfigTuningClosesPE uses, cli/detect_config_test.go) — a
// gap that is UNCLOSABLE without tuning BY CONSTRUCTION
// (core/detect/synthdemo_invariant_test.go), so this regression can never
// again be invalidated by a future promotion into the builtin vocabulary.
//
// detect.ResetTuning restores the pristine (untuned) snapshot first, so
// SYNTH-PE-01 is reliably RED regardless of test run order (a sibling test,
// TestRunExamDetect_ConfigTuningClosesPE, publishes a tuning overlay into the
// same process-global detector state).
func TestRunExamDetect_RemainingGapExitsRed(t *testing.T) {
	detect.ResetTuning()
	t.Cleanup(detect.ResetTuning)
	root := injectSyntheticCorpus(t)
	t.Setenv("MALLCOP_REPO_ROOT", root)

	out, err := withStdio(t, "", func() error { return runExamDetect(nil) })

	// Detection gaps present → errFindings sentinel (exit code 1), not a real error.
	if !isFindingsError(err) {
		t.Fatalf("expected findings sentinel error while %s is labeled-and-unfixed, got %v\noutput:\n%s", synthMustFireID, err, out)
	}
	for _, want := range []string{
		"FAIL " + synthMustFireID,
		"PASS PE-08-aws-poweruser-grant",
		"PASS IP-01-sqli-user-agent",
		"PASS VA-03-data-exfil",
		"PASS AC-01-external-access-stolen-cred",
		"exam-detect:",
	} {
		if !containsLine(out, want) {
			t.Errorf("human output missing %q; got:\n%s", want, out)
		}
	}
}

// containsLine reports whether any output line starts with prefix (after the
// fixed-width status column the renderer emits).
func containsLine(out, prefix string) bool {
	for _, line := range splitLines(out) {
		if len(line) >= len(prefix) && line[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// TestRunExamDetect_JSONShape asserts the --json report shape: rows with
// {scenario_id, must_fire, must_not_fire, emitted, pass} and totals with
// {labeled, unlabeled, passed, failed} — the machine contract the self-extension
// loop reads.
//
// Uses the injected synthetic gap (see TestRunExamDetect_RemainingGapExitsRed's
// doc comment) as its "still failing" row: the real pinned corpus has zero
// labeled gaps on its own now that PE-08 is a built-in (mallcoppro-a07).
func TestRunExamDetect_JSONShape(t *testing.T) {
	detect.ResetTuning()
	t.Cleanup(detect.ResetTuning)
	root := injectSyntheticCorpus(t)
	t.Setenv("MALLCOP_REPO_ROOT", root)

	out, err := withStdio(t, "", func() error { return runExamDetect([]string{"--json"}) })
	if !isFindingsError(err) {
		t.Fatalf("expected findings sentinel error, got %v", err)
	}

	var report struct {
		Rows []struct {
			ScenarioID  string   `json:"scenario_id"`
			MustFire    []string `json:"must_fire"`
			MustNotFire []string `json:"must_not_fire"`
			Emitted     []string `json:"emitted"`
			Pass        bool     `json:"pass"`
		} `json:"rows"`
		Totals struct {
			Labeled   int `json:"labeled"`
			Unlabeled int `json:"unlabeled"`
			Passed    int `json:"passed"`
			Failed    int `json:"failed"`
		} `json:"totals"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\noutput:\n%s", err, out)
	}

	if report.Totals.Labeled != len(report.Rows) {
		t.Errorf("totals.labeled = %d, want %d (one row per labeled scenario)", report.Totals.Labeled, len(report.Rows))
	}
	if report.Totals.Passed+report.Totals.Failed != report.Totals.Labeled {
		t.Errorf("passed(%d) + failed(%d) != labeled(%d)", report.Totals.Passed, report.Totals.Failed, report.Totals.Labeled)
	}
	if report.Totals.Failed < 1 {
		t.Errorf("totals.failed = %d, want >= 1 while %s is labeled-and-unfixed", report.Totals.Failed, synthMustFireID)
	}

	var va03Found bool
	for _, row := range report.Rows {
		if row.ScenarioID != "VA-03-data-exfil" {
			continue
		}
		va03Found = true
		// The volume field/unit contract gap is closed (mallcoppro-3c9): VA-03's
		// metadata-carried spike now fires volume-anomaly, so the row is GREEN.
		if !row.Pass {
			t.Errorf("VA-03 row pass = false, want GREEN now that the volume contract is fixed (emitted: %v)", row.Emitted)
		}
		if len(row.MustFire) != 1 || row.MustFire[0] != "volume-anomaly" {
			t.Errorf("VA-03 must_fire = %v, want [volume-anomaly]", row.MustFire)
		}
	}
	if !va03Found {
		t.Error("no VA-03-data-exfil row in --json output")
	}
}
