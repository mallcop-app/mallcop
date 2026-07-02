// Command mallcop is the customer-facing CLI for running mallcop scans.
//
// Usage:
//
//	mallcop scan        --store <dir> [--events <file> | --connector github --github-org <org>] [--tuning <yaml>] [--json]
//	mallcop detect      [--baseline <path>] [--tuning <yaml>]   < events.jsonl   > findings.jsonl
//	mallcop exam-detect [--json] [--tuning <yaml>]
//	mallcop validate-proposal --base <ref> [--head <ref>] [--guard-only] [--allow-no-coverage-gain] [--json]
//	mallcop init        [--dir <path>]
//	mallcop status      --store <dir>
//	mallcop config
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	args := flag.Args()[1:]

	var err error
	switch cmd {
	case "scan":
		err = runScan(args)
	case "detect":
		err = runDetect(args)
	case "exam-detect":
		err = runExamDetect(args)
	case "validate-proposal":
		err = runValidateProposal(args)
	case "init":
		err = runInit(args)
	case "status":
		err = runStatus(args)
	case "config":
		err = runConfig(args)
	case "feedback":
		err = runFeedback(args)
	default:
		fmt.Fprintf(os.Stderr, "mallcop: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		if isFindingsError(err) {
			// exit 1 = findings detected (not an error condition)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "mallcop %s: %v\n", cmd, err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `mallcop — security scan CLI

Commands:
  scan    Run a one-shot agentic security scan (connect -> detect -> cascade -> store)
    --store      Path to the git-repo store for findings/resolutions (required)
    --events     Events JSONL source (file path, or "-" for stdin; default: "-")
    --connector  "file" (default, reads --events) or "github"
    --github-org GitHub org to scan (required when --connector github)
    --baseline   Optional path to a baseline JSON file
    --base-url   Inference endpoint base URL (overrides $MALLCOP_INFERENCE_URL)
    --workers    Bounded resolve-pool size (0 = pipeline default)
    --tuning     Optional detector tuning YAML (widen-only extra_* knobs)
    --json       Output the summary as JSON
                 Inference auth: $MALLCOP_INFERENCE_URL + $MALLCOP_API_KEY
                 (BYOK: vendor URL+key; Forge: forge URL + mallcop-sk-* key).
                 With no URL, every finding force-escalates (fail-safe).

  detect  Run offline detection over events JSONL on stdin (no inference key)
    --baseline  Optional path to a baseline JSON file
    --tuning    Optional detector tuning YAML (widen-only extra_* knobs)
               Reads events JSONL from stdin, writes findings JSONL to stdout.

  exam-detect  Grade the offline detect layer against the labeled exam corpus
    --json     Output the report as JSON
    --tuning   Optional detector tuning YAML (widen-only extra_* knobs) —
               grades the corpus WITH the tuning applied, so a tuning
               proposal can be evaluated before it is committed.
               Runs core/detect over every exam scenario labeled with an
               expected_detection block (must_fire / must_not_fire detector
               families) and reports per-scenario pass/fail. Offline and
               deterministic — no inference key. Exit 1 = detection gap(s).

  validate-proposal  Run the FREE-TIER gate over a self-extension proposal diff
    --base       Base git ref the proposal diffs against (required)
    --head       Head git ref of the proposal (default: HEAD)
    --guard-only Run only the static invariant guard stage
    --allow-no-coverage-gain
                 Waive the coverage-+1 requirement (plumbing/no-op diffs)
    --json       Output the full versioned GateResult as JSON
                 Ordered $0 stages, short-circuiting on the first failure:
                 (1) guard — the static invariant guard: protected paths are
                 untouchable, existing detector code / exam scenarios are
                 frozen, and YAML data (detectors/tuning.yaml, operator-
                 decision routes) may only WIDEN what the detection committee
                 sees; (2) structural — the head tree builds and the authored
                 detector tree passes the import allow-list; (3) exam-detect —
                 base vs head exam reports must show no regression, at least
                 one closed detection gap, and no undeclared new firings.
                 Run from inside the repo being validated. Exit 1 = rejected.

  init    Scaffold a findings store + sample events and print runnable next steps
    --dir      Directory to initialize (default: current directory)

  status  Report findings/resolutions recorded in a store
    --store    Path to the git-repo store written by 'mallcop scan' (required)

  config  Print the effective scan config resolved from the environment

  feedback  Record an operator decision on a finding; the next scan honors it
    <finding_id> approve|dismiss   approve = activity known-good; dismiss = not actionable
    --store    Path to the git-repo store written by 'mallcop scan' (required)
    --reason   Operator rationale (free text, recorded for audit)
    --by       Operator identity (defaults to $USER)
               Both verbs persist a 'suppress' directive keyed on the finding's
               source/type/actor, so future findings of that class are dropped.

Exit codes (scan):
  0  No findings
  1  Findings present
  2  Scan failure`)
}
