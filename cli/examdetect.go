package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mallcop-app/mallcop/core/eval"
)

// runExamDetect implements `mallcop exam-detect`: run the REAL offline detect
// pipeline (core/detect) over every LABELED exam scenario and grade the emitted
// findings against the scenario's expected_detection ground truth (must_fire /
// must_not_fire detector families). Offline, deterministic, LLM-free — no
// inference client is constructed; no network access or key is required.
//
// The corpus loads through the sha-pinned integrity interlock (corpus.pin) —
// a drifted corpus hard-fails before anything is graded. Unlabeled scenarios
// are skipped-but-counted.
//
// Exit codes mirror `scan` / `detect`:
//
//	0  All labeled scenarios pass
//	1  One or more labeled scenarios RED (a detection gap — the errFindings sentinel)
//	2  Failure (e.g. corpus integrity mismatch, repo root unresolvable)
func runExamDetect(args []string) error {
	fs := flag.NewFlagSet("exam-detect", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Output the report as JSON")
	tuningPath := fs.String("tuning", "", "Optional path to a detector tuning YAML (widen-only extra_* knobs)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Apply the optional widen-only tuning BEFORE grading, so exam-detect can
	// evaluate a tuning proposal against the labeled corpus — the K4
	// validate_proposal gate mechanism. Fatal on error (exit 2); flag-only, no
	// auto-discovery.
	if err := applyTuningFlag(*tuningPath); err != nil {
		return err
	}

	// Wire any configured WASM detector sidecars before grading runs core/detect
	// over the corpus (see loadSidecarDetectorsFromConfig / cli/sidecars.go).
	// `exam-detect` has no --config flag of its own, matching applyTuningFlag's
	// own config resolution above.
	if err := loadSidecarDetectorsFromConfig(""); err != nil {
		return err
	}

	root, err := eval.RepoRoot()
	if err != nil {
		return fmt.Errorf("resolving repo root: %w", err)
	}

	report, err := eval.RunExamDetect(root)
	if err != nil {
		return err
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encoding report: %w", err)
		}
	} else {
		printExamDetectReport(report)
	}

	if report.Totals.Failed > 0 {
		// Signal "detection gaps present" without printing it as an error.
		return errFindings
	}
	return nil
}

// printExamDetectReport renders the human-readable per-row + totals view.
func printExamDetectReport(report eval.ExamDetectReport) {
	for _, row := range report.Rows {
		status := "PASS"
		if !row.Pass {
			status = "FAIL"
		}
		fmt.Printf("%-4s %s\n", status, row.ScenarioID)
		if len(row.MustFire) > 0 {
			fmt.Printf("       must_fire:     %s\n", strings.Join(row.MustFire, ", "))
		}
		if len(row.MustNotFire) > 0 {
			fmt.Printf("       must_not_fire: %s\n", strings.Join(row.MustNotFire, ", "))
		}
		emitted := "(none)"
		if len(row.Emitted) > 0 {
			emitted = strings.Join(row.Emitted, ", ")
		}
		fmt.Printf("       emitted:       %s\n", emitted)
	}
	t := report.Totals
	fmt.Printf("exam-detect: %d labeled (%d passed, %d failed), %d unlabeled (skipped)\n",
		t.Labeled, t.Passed, t.Failed, t.Unlabeled)
}
