// Command mallcop is the customer-facing CLI for running mallcop scans.
//
// Usage:
//
//	mallcop scan   --store <dir> [--events <file> | --connector github --github-org <org>] [--json]
//	mallcop detect [--baseline <path>]   < events.jsonl   > findings.jsonl
//	mallcop init   [--dir <path>]
//	mallcop status --store <dir>
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
	case "init":
		err = runInit(args)
	case "status":
		err = runStatus(args)
	case "config":
		err = runConfig(args)
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
    --json       Output the summary as JSON
                 Inference auth: $MALLCOP_INFERENCE_URL + $MALLCOP_API_KEY
                 (BYOK: vendor URL+key; Forge: forge URL + mallcop-sk-* key).
                 With no URL, every finding force-escalates (fail-safe).

  detect  Run offline detection over events JSONL on stdin (no inference key)
    --baseline  Optional path to a baseline JSON file
               Reads events JSONL from stdin, writes findings JSONL to stdout.

  init    Scaffold a findings store + sample events and print runnable next steps
    --dir      Directory to initialize (default: current directory)

  status  Report findings/resolutions recorded in a store
    --store    Path to the git-repo store written by 'mallcop scan' (required)

  config  Print the effective scan config resolved from the environment

Exit codes (scan):
  0  No findings
  1  Findings present
  2  Scan failure`)
}
