// Package cli implements the full mallcop CLI as an importable package. An
// external module can embed the entire CLI with:
//
//	import "github.com/mallcop-app/mallcop/cli"
//	func main() { cli.Main() }
//
// The embedder controls its own detector linkage the same way cmd/mallcop
// does: blank-import whatever detect.Register-ing package(s) it wants before
// calling cli.Main() (core/detect/authored, or an external equivalent). This
// package intentionally does NOT import core/detect/authored itself — that
// blank import is the human-wired registration seam and belongs to the
// binary's main package, not to this reusable library.
//
// Usage:
//
//	mallcop scan        --store <dir> [--events <file> | --connector github --github-org <org>] [--tuning <yaml>] [--json]
//	mallcop detect      [--baseline <path>] [--tuning <yaml>]   < events.jsonl   > findings.jsonl
//	mallcop exam-detect [--json] [--tuning <yaml>]
//	mallcop validate-proposal --base <ref> [--head <ref>] [--guard-only] [--allow-no-coverage-gain] [--json]
//	mallcop collect     --store <dir> [--fidelity <json>] [--json]
//	mallcop init        [--dir <path>]
//	mallcop status      --store <dir>
//	mallcop config
package cli

import (
	"flag"
	"fmt"
	"os"
)

// Main is the CLI entrypoint. It parses os.Args (via the flag package's
// default CommandLine), dispatches to the requested subcommand, and calls
// os.Exit with the same exit codes cmd/mallcop has always used:
//
//	0  success
//	1  findings detected (scan / detect / exam-detect / validate-proposal)
//	2  any other command failure
//
// Callers (cmd/mallcop's main.go, or an external embedder) are expected to
// blank-import their detector registration package(s) before calling Main,
// then simply call cli.Main() as their entire main().
func Main() {
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
	case "collect":
		err = runCollect(args)
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
    --json        Output the report as JSON
    --tuning      Optional detector tuning YAML (widen-only extra_* knobs) —
                  grades the corpus WITH the tuning applied, so a tuning
                  proposal can be evaluated before it is committed.
    --sidecar-src Optional Go package directory built to a wasip1 .wasm module
                  and graded through the real detecthost host IN ADDITION to
                  any configured sidecars — the CUSTOMER-TREE exam mode: the
                  detector need not live in this repo's own tree, only be a
                  valid package implementing core/detect.Detector via
                  pkg/detectorhost.
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

  collect  Mine a scan's store for coverage gaps (the self-extension feedstock)
    --store     Path to the git-repo store written by 'mallcop scan' (required)
    --fidelity  Optional JSON array of eval.DetectFidelityRow (an exam-detect
                fidelity dump's 'rows') — enables the detect_miss gap kind the
                store cannot produce on its own. Absent, only the store-pure
                gap kinds (override_fp, dissent) are surfaced.
    --json      Emit the versioned envelope {schema_version, mapping_gaps,
                gap_candidates} — the stable process boundary the mallcop-pro
                proposer consumes. Offline, deterministic, no inference key.
                Human-readable summary otherwise. Exit 2 = failure.

  init    Scaffold a findings store + sample events and print runnable next steps
    --dir      Directory to initialize (default: current directory)

  status  Report findings/resolutions recorded in a store
    --store    Path to the git-repo store written by 'mallcop scan' (required)

  config  Print the effective scan config merged from a discovered mallcop.yaml + the environment

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
