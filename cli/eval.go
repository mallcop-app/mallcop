// eval.go — `mallcop eval`: the PER-OPERATOR local recall-first exam
// (mallcoppro-bc2, R2/R4). This is exam-detect's grading loop run the way a
// customer running mallcop out of their OWN deploy repo (scaffolded by
// `mallcop init --create-repo`, see cli/deployrepo.go) actually experiences
// it:
//
//   - The REFERENCE corpus comes from the BINARY, not the filesystem — a
//     shipped mallcop release has no exams/scenarios/ directory on disk in a
//     customer's deploy repo, so this always sources it via
//     eval.LoadEmbedded() rather than eval.Load(repoRoot) (which cli/examdetect.go
//     uses and which would simply fail with "corpus root not found" here).
//   - The OPERATOR'S OWN scenarios (scenarios/ at the deploy repo root, see
//     the scaffolded scenarios/README.md cli/init.go writes) are UNIONED in
//     via the identical LoadExtraScenarios primitive exam-detect's
//     --extra-scenarios-dir already uses — UNPINNED, never touching
//     corpus.pin or the reference corpus's own digest. An absent scenarios/
//     directory (the common case: a brand-new deploy repo before the
//     operator has authored anything) is NOT an error — it is an empty
//     union, exactly like exam-detect's extraScenariosDir=="" default.
//   - The fleet graded is the SAME fleet `mallcop scan`/`detect` runs: any
//     widen-only tuning overlay (applyTuningFlag) plus any configured WASM
//     sidecar detectors (loadSidecarDetectorsFromConfig) — the operator's
//     own detectors/<name> sidecars are exactly as gradeable here as a
//     built-in framework detector.
//   - The report prints/JSONs the SAME recall/precision split (core/eval's
//     RecallFromReport, mallcoppro's C1) TWICE: once over the reference
//     rows, once over the operator's own local rows (ExamDetectRow.Extra ==
//     true) — so "MY MISSED ATTACKS: n of m" (the operator's own coverage,
//     including their tracked reserved-but-unbuilt gaps) is never blended
//     with the shipped reference corpus's own recall number.
//
// No central harvest, no network call, no inference client anywhere on this
// path — everything here runs local to the operator's own deploy repo,
// exactly like exam-detect. Exit codes mirror exam-detect (0 = all labeled
// rows pass, 1 = errFindings sentinel on any hard failure, 2 = a real
// command failure).
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mallcop-app/mallcop/core/eval"
)

// runEval implements `mallcop eval`.
func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Output the reference+local recall/precision reports as JSON")
	scenariosDir := fs.String("scenarios-dir", "", "Path to the deploy repo's own scenarios/ directory to union into grading (default: <repo-root>/scenarios, repo-root resolved via eval.RepoRoot(); a missing default directory is NOT an error -- it is an empty union)")
	tuningPath := fs.String("tuning", "", "Optional path to a detector tuning YAML (widen-only extra_* knobs)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Apply the operator's widen-only tuning + configured WASM sidecars
	// BEFORE grading, exactly like exam-detect: `mallcop eval` grades the
	// SAME fleet `mallcop scan` runs, including the operator's own sidecar
	// detectors.
	if err := applyTuningFlag(*tuningPath); err != nil {
		return err
	}
	if err := loadSidecarDetectorsFromConfig(""); err != nil {
		return err
	}

	extra, err := loadEvalLocalScenarios(*scenariosDir)
	if err != nil {
		return err
	}

	corpus, err := eval.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("loading embedded reference corpus: %w", err)
	}

	report := eval.RunExamDetectOverCorpus(corpus, extra)
	referenceRows, localRows := splitEvalRowsByExtra(report.Rows)
	referenceRecall := eval.RecallFromReport(eval.ExamDetectReport{Rows: referenceRows})
	localRecall := eval.RecallFromReport(eval.ExamDetectReport{Rows: localRows})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(evalJSONReport{Reference: referenceRecall, Local: localRecall}); err != nil {
			return fmt.Errorf("encoding eval report: %w", err)
		}
	} else {
		printEvalReport(referenceRecall, localRecall, len(localRows))
	}

	if report.Totals.Failed > 0 {
		// Mirrors exam-detect: signal "detection gaps present" without
		// printing it as an error. Reserved-but-unregistered local gaps are
		// EXCLUDED from Totals.Failed (they land in Totals.Reserved instead)
		// so an operator's not-yet-built tracked gap never turns this red on
		// its own -- see core/eval/examdetect.go's package doc.
		return errFindings
	}
	return nil
}

// loadEvalLocalScenarios resolves the deploy repo's own scenarios/ directory
// and loads it via eval.LoadExtraScenarios. An EXPLICIT --scenarios-dir that
// does not exist is a loud error (the operator pointed somewhere on
// purpose); the DEFAULT (<repo-root>/scenarios) is allowed to be absent --
// a brand-new deploy repo before the operator has authored a local scenario
// yet is not a failure, it is an empty union.
func loadEvalLocalScenarios(explicitDir string) ([]eval.LoadedScenario, error) {
	if explicitDir != "" {
		scenarios, err := eval.LoadExtraScenarios(explicitDir)
		if err != nil {
			return nil, fmt.Errorf("--scenarios-dir %s: %w", explicitDir, err)
		}
		return scenarios, nil
	}

	root, err := eval.RepoRoot()
	if err != nil {
		return nil, fmt.Errorf("resolving deploy repo root (for the default scenarios/ directory): %w", err)
	}
	dir := filepath.Join(root, "scenarios")
	if fi, statErr := os.Stat(dir); statErr != nil || !fi.IsDir() {
		// No scenarios/ directory yet -- an empty local union, not an error.
		return nil, nil
	}
	scenarios, err := eval.LoadExtraScenarios(dir)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", dir, err)
	}
	return scenarios, nil
}

// splitEvalRowsByExtra partitions report rows into the reference-corpus set
// (Extra == false) and the operator's own local set (Extra == true), so each
// can be fed through eval.RecallFromReport independently -- RecallFromReport
// reads only Rows, never Totals, so this partition is a pure re-slice with no
// re-grading.
func splitEvalRowsByExtra(rows []eval.ExamDetectRow) (reference, local []eval.ExamDetectRow) {
	for _, r := range rows {
		if r.Extra {
			local = append(local, r)
		} else {
			reference = append(reference, r)
		}
	}
	return reference, local
}

// evalJSONReport is the --json wire shape: the SAME eval.RecallReport shape
// exam-detect's --recall --json already emits, reported twice under distinct
// keys so a caller (the self-heal loop, or an operator's own tooling) can
// tell shipped-corpus recall apart from the operator's own coverage.
type evalJSONReport struct {
	Reference eval.RecallReport `json:"reference"`
	Local     eval.RecallReport `json:"local"`
}

// printEvalReport renders the human-readable view: the reference corpus's
// recall/precision split (identical rendering to exam-detect's --recall
// view), then the operator's OWN local split with the "MY MISSED ATTACKS"/
// "MY FALSE ALARMS" framing that keeps it visually distinct from the
// reference numbers above it.
func printEvalReport(reference, local eval.RecallReport, localRowCount int) {
	fmt.Println("=== REFERENCE CORPUS (shipped with mallcop) ===")
	printRecallReport(reference)

	fmt.Println()
	fmt.Printf("=== YOUR SCENARIOS (scenarios/, %d local scenario(s)) ===\n", localRowCount)
	rc := local.Recall
	fmt.Printf("MY MISSED ATTACKS: %d of %d\n", len(rc.Missed), rc.MustFire)
	for _, m := range rc.Missed {
		note := ""
		if m.Reserved {
			note = " (reserved: not yet built -- tracked gap, not a regression)"
		}
		fmt.Printf("  - %-40s missing: %s%s\n", m.ScenarioID, strings.Join(m.Missing, ", "), note)
	}
	pr := local.Precision
	fmt.Printf("MY FALSE ALARMS: %d of %d\n", len(pr.FalseAlarms), pr.MustStaySilent)
	for _, fa := range pr.FalseAlarms {
		fmt.Printf("  - %-40s fired: %s\n", fa.ScenarioID, strings.Join(fa.Fired, ", "))
	}
}
