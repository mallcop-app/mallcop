package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mallcop-app/mallcop/core/selfgate"
)

// runValidateProposal implements `mallcop validate-proposal` — the merge gate
// for self-extension proposals. A proposal is a git diff (--base ref → --head
// ref, head defaulting to HEAD) authored by the self-extension loop; the gate
// runs it through ordered stages and rejects on the first stage's findings.
//
// K3 ships STAGE 1 only: the static invariant guard (core/selfgate) — the
// diff may only ever WIDEN what the detection committee sees. Later stages
// (exam-detect regression over the proposal's tuning, the eval interlock, ...)
// APPEND to the stages run below in the K4 step; --guard-only pins the run to
// stage 1 regardless of what ships later.
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
	jsonOut := fs.Bool("json", false, "Output the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *base == "" {
		return fmt.Errorf("--base is required (the ref the proposal diffs against)")
	}

	report := proposalReport{Base: *base, Head: *head, Pass: true}

	// Stage 1: the static invariant guard. The working directory anchors the
	// repo — git resolves the tree, and every guard path is repo-root-relative.
	findings, err := selfgate.Guard(".", *base, *head)
	if err != nil {
		return err
	}
	report.addStage("guard", findings)

	// FUTURE STAGES (K4+): exam-detect regression with the proposal's tuning
	// applied, the eval corpus interlock, ... Each appends here as
	//
	//	if !*guardOnly {
	//		report.addStage("<stage>", findings)
	//	}
	//
	// and the aggregate Pass / exit-code behavior below stays unchanged.
	_ = *guardOnly

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encoding report: %w", err)
		}
	} else {
		printProposalReport(report)
	}

	if !report.Pass {
		return errFindings
	}
	return nil
}

// proposalReport is the aggregate validate-proposal result across stages.
type proposalReport struct {
	Base   string        `json:"base"`
	Head   string        `json:"head"`
	Stages []stageReport `json:"stages"`
	Pass   bool          `json:"pass"`
}

// stageReport is one gate stage's outcome.
type stageReport struct {
	Name     string                  `json:"name"`
	Pass     bool                    `json:"pass"`
	Findings []selfgate.GuardFinding `json:"findings"`
}

func (r *proposalReport) addStage(name string, findings []selfgate.GuardFinding) {
	pass := len(findings) == 0
	if findings == nil {
		findings = []selfgate.GuardFinding{} // JSON: [] not null
	}
	r.Stages = append(r.Stages, stageReport{Name: name, Pass: pass, Findings: findings})
	r.Pass = r.Pass && pass
}

func printProposalReport(r proposalReport) {
	total := 0
	for _, stage := range r.Stages {
		for _, f := range stage.Findings {
			total++
			fmt.Printf("REJECT [%s/%s] %s: %s\n", stage.Name, f.Rule, f.Path, f.Detail)
		}
	}
	if r.Pass {
		fmt.Printf("validate-proposal: PASS (%s..%s, %d stage(s))\n", r.Base, r.Head, len(r.Stages))
		return
	}
	fmt.Printf("validate-proposal: REJECTED — %d finding(s) (%s..%s)\n", total, r.Base, r.Head)
}
