package main

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
)

// repoRootForExamTest resolves the repo root from this test file's location
// (cmd/mallcop/ is two levels below the root). Inside `go test` os.Executable
// lands in a temp build dir, so the RepoRoot walk finds no marker; the test
// pins MALLCOP_REPO_ROOT (the documented production fallback) instead.
func repoRootForExamTest(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	return root
}

// TestRunExamDetect_SeededGapExitsRed proves the CLI surfaces the seeded VA-03
// detection gap as the errFindings sentinel (exit code 1): the corpus carries a
// labeled-and-unfixed must_fire that the real detect layer misses.
func TestRunExamDetect_SeededGapExitsRed(t *testing.T) {
	t.Setenv("MALLCOP_REPO_ROOT", repoRootForExamTest(t))

	out, err := withStdio(t, "", func() error { return runExamDetect(nil) })

	// Detection gaps present → errFindings sentinel (exit code 1), not a real error.
	if !isFindingsError(err) {
		t.Fatalf("expected findings sentinel error while VA-03 is labeled-and-unfixed, got %v\noutput:\n%s", err, out)
	}
	for _, want := range []string{"FAIL VA-03-data-exfil", "PASS AC-01-external-access-stolen-cred", "exam-detect:"} {
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
func TestRunExamDetect_JSONShape(t *testing.T) {
	t.Setenv("MALLCOP_REPO_ROOT", repoRootForExamTest(t))

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
		t.Errorf("totals.failed = %d, want >= 1 while VA-03 is labeled-and-unfixed", report.Totals.Failed)
	}

	var va03Found bool
	for _, row := range report.Rows {
		if row.ScenarioID != "VA-03-data-exfil" {
			continue
		}
		va03Found = true
		if row.Pass {
			t.Errorf("VA-03 row pass = true, want the seeded gap RED (emitted: %v)", row.Emitted)
		}
		if len(row.MustFire) != 1 || row.MustFire[0] != "volume-anomaly" {
			t.Errorf("VA-03 must_fire = %v, want [volume-anomaly]", row.MustFire)
		}
	}
	if !va03Found {
		t.Error("no VA-03-data-exfil row in --json output")
	}
}
