package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// runDetect implements `mallcop detect`: read events JSONL on stdin, run the
// offline core/detect pipeline (all 13 detectors), and write findings JSONL to
// stdout. No inference key, network access, or Forge account is required —
// detection is fully local and deterministic.
//
// An optional --baseline flag supplies historical context for the
// baseline-dependent detectors (new-actor, priv-escalation, unusual-login,
// unusual-timing, volume-anomaly, rate-anomaly, exfil-pattern). Without it,
// detection runs against an empty baseline; the content-only detectors
// (injection-probe, secrets-exposure, git-oops, config-drift,
// dependency-tamper, malicious-skill) still fire.
//
// Exit codes mirror `scan`:
//
//	0  No findings
//	1  Findings present
//	2  Failure (e.g. unreadable baseline)
func runDetect(args []string) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	baselinePath := fs.String("baseline", "", "Optional path to a baseline JSON file (no inference key required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var bl *baseline.Baseline
	if *baselinePath != "" {
		loaded, err := baseline.Load(*baselinePath)
		if err != nil {
			return fmt.Errorf("loading baseline %s: %w", *baselinePath, err)
		}
		bl = loaded
	} else {
		bl = &baseline.Baseline{}
	}

	events, err := readEventsJSONL(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading events: %w", err)
	}

	findings := detect.Detect(events, bl)

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	for i := range findings {
		if err := enc.Encode(&findings[i]); err != nil {
			return fmt.Errorf("encoding finding: %w", err)
		}
	}

	if len(findings) > 0 {
		// Signal "findings present" without printing it as an error.
		return errFindings
	}
	return nil
}

// readEventsJSONL parses newline-delimited JSON events from r. Blank lines are
// skipped; malformed lines are reported on stderr and skipped so a single bad
// record does not abort the whole scan.
func readEventsJSONL(r io.Reader) ([]event.Event, error) {
	var events []event.Event
	scanner := bufio.NewScanner(r)
	// Allow long lines (large payloads) — match detector-dependency-tamper.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			fmt.Fprintf(os.Stderr, "mallcop detect: skipping malformed event: %v\n", err)
			continue
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	return events, nil
}
