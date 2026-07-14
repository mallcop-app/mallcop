package cli

import (
	"context"
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
	recall := fs.Bool("recall", false, "Print the RECALL-FIRST breakdown instead of the per-scenario pass/fail: RECALL (attacks caught / must-fire, with missed attacks named) and PRECISION (benign kept silent / must-stay-silent, with false alarms named) reported separately — the honest denominator the self-heal loop needs")
	reportMode := fs.String("report", "", "Report mode. \"recall\" is equivalent to --recall; empty keeps the default per-scenario view")
	tuningPath := fs.String("tuning", "", "Optional path to a detector tuning YAML (widen-only extra_* knobs)")
	sidecarSrc := fs.String("sidecar-src", "", "Optional Go package directory to build to a wasip1 .wasm module and grade IN ADDITION to any configured sidecars — the CUSTOMER-TREE exam mode (mallcoppro-cc3e): the detector need not live in this repo's own tree at all, only be a valid Go package implementing core/detect.Detector via pkg/detectorhost")
	extraScenariosDir := fs.String("extra-scenarios-dir", "", "Optional directory of scenario YAML files to UNION into grading IN ADDITION to the pinned reference corpus (mallcoppro-f95) — e.g. a customer detector's OWN co-located detectors/<name>/scenarios/ efficacy scenarios. UNPINNED: never verified against corpus.pin, never counted in the reference corpus's own digest")
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

	// --sidecar-src: build and register an AD HOC wasm sidecar from source,
	// same host, same real wazero path — see buildAndRegisterSourceSidecar. The
	// scratch dir is removed when the command returns; the sidecar only needs
	// to survive this one grading pass.
	if *sidecarSrc != "" {
		scratch, err := os.MkdirTemp("", "mallcop-sidecar-src-")
		if err != nil {
			return fmt.Errorf("exam-detect: --sidecar-src scratch dir: %w", err)
		}
		defer os.RemoveAll(scratch)
		if err := buildAndRegisterSourceSidecar(context.Background(), *sidecarSrc, scratch); err != nil {
			return fmt.Errorf("exam-detect: --sidecar-src %s: %w", *sidecarSrc, err)
		}
	}

	root, err := eval.RepoRoot()
	if err != nil {
		return fmt.Errorf("resolving repo root: %w", err)
	}

	report, err := eval.RunExamDetectExtra(root, *extraScenariosDir)
	if err != nil {
		return err
	}

	// --recall / --report=recall selects the recall-first breakdown. It is a
	// second lens on the SAME graded rows — it re-runs no detector and does not
	// change grading, so the exit code below (and the whole flag-off path CI /
	// selfgate parse) is byte-identical whether or not this flag is set.
	recallMode := *recall || strings.EqualFold(strings.TrimSpace(*reportMode), "recall")

	switch {
	case recallMode && *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(eval.RecallFromReport(report)); err != nil {
			return fmt.Errorf("encoding recall report: %w", err)
		}
	case recallMode:
		printRecallReport(eval.RecallFromReport(report))
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encoding report: %w", err)
		}
	default:
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

// printRecallReport renders the recall-first breakdown: RECALL (attacks caught)
// and PRECISION (benign kept silent) separately, with the MISSED attacks — the
// fatal failures — named prominently and the false alarms named beneath
// precision.
func printRecallReport(rr eval.RecallReport) {
	rc := rr.Recall
	fmt.Printf("RECALL (attacks caught):        %d/%d = %.1f%%\n",
		rc.Detected, rc.MustFire, rc.Rate*100)
	if len(rc.Missed) > 0 {
		fmt.Printf("  MISSED ATTACKS (%d) — fatal false-negatives, these attacks were NOT detected:\n", len(rc.Missed))
		for _, m := range rc.Missed {
			note := ""
			if m.Reserved {
				note = " (reserved: detector not authored yet)"
			}
			fmt.Printf("    - %-40s missing: %s%s\n", m.ScenarioID, strings.Join(m.Missing, ", "), note)
		}
	}

	pr := rr.Precision
	fmt.Printf("PRECISION (benign kept silent): %d/%d = %.1f%%\n",
		pr.CorrectSilent, pr.MustStaySilent, pr.Rate*100)
	if len(pr.FalseAlarms) > 0 {
		fmt.Printf("  FALSE ALARMS (%d) — benign scenarios that fired:\n", len(pr.FalseAlarms))
		for _, fa := range pr.FalseAlarms {
			fmt.Printf("    - %-40s fired: %s\n", fa.ScenarioID, strings.Join(fa.Fired, ", "))
		}
	}
}
