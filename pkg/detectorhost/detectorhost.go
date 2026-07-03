// Package detectorhost is the GUEST-side harness for a WASM detector sidecar.
// It is the human-written half of the wasip1 sidecar delivery model (the
// AI-authored half is the detect.Detector implementation itself, plus its
// tests): a sidecar main is exactly
//
//	func main() { os.Exit(detectorhost.Run(myDetector{})) }
//
// where myDetector implements core/detect.Detector. Run owns the whole stdio
// wire protocol so the authored detector never has to know it is running
// inside a wasip1 COMMAND module:
//
//   - stdin:  ONE JSON document {"events": [...pkg/event.Event...],
//     "baseline": {...pkg/baseline.Baseline...}}, read in full before Detect
//     is called.
//   - stdout: the resulting findings as a JSON array of pkg/finding.Finding
//     (an empty array, never null, when there are none).
//   - stderr: any error text. A nonzero process exit signals a detector/harness
//     error to the host (github.com/mallcop-app/mallcop/detecthost) — the host
//     surfaces it loudly (it never treats a failed sidecar as "zero findings").
//
// This package compiles cleanly under GOOS=wasip1 GOARCH=wasm (it is pure
// stdlib + the framework packages: core/detect, pkg/event, pkg/finding,
// pkg/baseline — the same surface the authored-detector import allowlist
// already recognizes as the detector framework, see core/lint/allowlist.go).
// It is also an ordinary Go package on any other GOOS/GOARCH, which is what
// lets tests exercise RunIO in-process without a wasm toolchain.
package detectorhost

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// Input is the single wire document a sidecar reads from stdin. Baseline may
// be nil (an omitted or "null" JSON field) — Run treats a nil Baseline as an
// empty one, mirroring core/detect.Detect's own nil-baseline contract.
type Input struct {
	Events   []event.Event      `json:"events"`
	Baseline *baseline.Baseline `json:"baseline"`
}

// Run reads the Input document from os.Stdin, calls d.Detect, and writes the
// resulting findings JSON to os.Stdout — the exact plumbing a sidecar main
// needs. It returns the process exit code to use: 0 on success, 1 on any
// harness or detector failure (with the failure text already written to
// os.Stderr). A sidecar main is:
//
//	func main() { os.Exit(detectorhost.Run(myDetector{})) }
func Run(d detect.Detector) int {
	return RunIO(d, os.Stdin, os.Stdout, os.Stderr)
}

// RunIO is the testable core of Run: it reads the Input document from in,
// writes findings JSON to out, and writes any error text to errOut. Split out
// from Run so tests can drive the exact stdio protocol without a wasm runtime
// or the real os.Stdin/Stdout/Stderr.
func RunIO(d detect.Detector, in io.Reader, out io.Writer, errOut io.Writer) int {
	data, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintf(errOut, "detectorhost: reading stdin: %v\n", err)
		return 1
	}

	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		fmt.Fprintf(errOut, "detectorhost: parsing input document: %v\n", err)
		return 1
	}
	bl := input.Baseline
	if bl == nil {
		bl = &baseline.Baseline{}
	}

	findings, err := detectSafely(d, input.Events, bl)
	if err != nil {
		fmt.Fprintf(errOut, "detectorhost: detector %q: %v\n", d.Name(), err)
		return 1
	}
	if findings == nil {
		// Never emit a JSON "null" — the host always unmarshals into a slice
		// and an explicit empty array is the unambiguous "no findings" wire
		// value.
		findings = []finding.Finding{}
	}

	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(findings); err != nil {
		fmt.Fprintf(errOut, "detectorhost: encoding findings: %v\n", err)
		return 1
	}
	return 0
}

// detectSafely calls d.Detect under a recover() so a panicking authored
// detector inside the sidecar produces a clean nonzero-exit + stderr message
// (surfaced loudly by the host) instead of a wasm trap with no diagnostic.
func detectSafely(d detect.Detector, events []event.Event, bl *baseline.Baseline) (findings []finding.Finding, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	findings = d.Detect(events, bl)
	return findings, nil
}
