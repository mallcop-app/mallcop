package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mallcop-app/mallcop/core/selfgate"
)

// runValidateProposal implements `mallcop validate-proposal` — the FREE-TIER
// merge gate for self-extension proposals (K4). A proposal is a git diff
// (--base ref → --head ref, head defaulting to HEAD) authored by the
// self-extension loop; the gate runs the ordered $0 stages and SHORT-CIRCUITS
// on the first failing stage:
//
//  1. guard       — the K3 static invariant guard (widen-only diff rules)
//  2. structural  — head tree builds + authored-detector import allow-list
//  3. exam-detect — base vs head exam reports: no regression, coverage +1,
//     no undeclared new firings (monotonic-widen contract)
//
// --guard-only pins the run to stage 1. --json emits the full versioned
// selfgate.GateResult — the exact document the mallcop-pro metered tier
// consumes across the process boundary.
//
// Exit codes (mirror scan / detect / exam-detect):
//
//	0  proposal clean (every stage passed)
//	1  proposal REJECTED — one or more findings (the errFindings sentinel)
//	2  operational failure (unresolvable refs, not a git repo, ...)
func runValidateProposal(args []string) error {
	fs := flag.NewFlagSet("validate-proposal", flag.ContinueOnError)
	base := fs.String("base", "", "Base git ref the proposal diffs against (required)")
	head := fs.String("head", "HEAD", "Head git ref of the proposal")
	guardOnly := fs.Bool("guard-only", false, "Run only the static invariant guard stage")
	allowNoCoverageGain := fs.Bool("allow-no-coverage-gain", false,
		"Waive the coverage-+1 requirement (plumbing/no-op diffs); no-regression and no-new-firings are never waivable")
	jsonOut := fs.Bool("json", false, "Output the full GateResult as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *base == "" {
		return fmt.Errorf("--base is required (the ref the proposal diffs against)")
	}

	// The working directory anchors the repo — git resolves the tree, and
	// every gate path is repo-root-relative.
	result, err := selfgate.ValidateProposal(".", *base, *head, selfgate.Options{
		GuardOnly:           *guardOnly,
		AllowNoCoverageGain: *allowNoCoverageGain,
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("encoding gate result: %w", err)
		}
	} else {
		printGateResult(result)
	}

	if !result.Passed {
		return errFindings
	}
	return nil
}

func printGateResult(r selfgate.GateResult) {
	total := 0
	for _, stage := range r.Stages {
		status := "PASS"
		if !stage.Passed {
			status = "FAIL"
		}
		fmt.Printf("%-4s %-11s %s\n", status, stage.Name, stage.Evidence)
		for _, f := range stage.Findings {
			total++
			fmt.Printf("REJECT [%s/%s] %s: %s\n", stage.Name, f.Rule, f.Path, f.Detail)
		}
	}
	if r.Passed {
		fmt.Printf("validate-proposal: PASS (%.12s..%.12s, %d stage(s), coverage +%d)\n",
			r.BaseSHA, r.HeadSHA, len(r.Stages), r.CoveragePlus)
		return
	}
	last := r.Stages[len(r.Stages)-1]
	fmt.Printf("validate-proposal: REJECTED at stage %q — %d finding(s) (%.12s..%.12s)\n",
		last.Name, total, r.BaseSHA, r.HeadSHA)
}
