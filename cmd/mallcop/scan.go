package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

const (
	defaultChart   = "charts/vertical-slice.toml"
	defaultTimeout = 10 * time.Minute
)

// ScanSummary holds the results of a completed scan cycle.
type ScanSummary struct {
	EventsScanned    int `json:"events_scanned"`
	FindingsDetected int `json:"findings_detected"`
	Escalated        int `json:"escalated"`
	Resolved         int `json:"resolved"`
}

// scanOutput collects structured Findings and Resolutions parsed from the
// agentic scan pipeline output (JSONL). Each line may be a Finding or a
// Resolution. Retained because the JSONL/output-dir parsing helpers below are
// exercised by tests and will be reused when the in-process scan pipeline is
// wired (pending core/pipeline).
type scanOutput struct {
	findings    []finding.Finding
	resolutions []resolution.Resolution
}

// errScanPipelineNotWired is returned by runScan while the agentic scan path is
// stubbed. The previous implementation exec'd the external legion binary
// (`we start --chart … --exit-on-idle`); that coupling has been removed. The
// in-process scan pipeline is a later item (pending core/pipeline).
var errScanPipelineNotWired = fmt.Errorf(
	"in-process scan pipeline not yet wired (pending core/pipeline); " +
		"the legion-backed agentic scan path has been removed")

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	chartPath := fs.String("chart", defaultChart, "Path to the scan chart TOML")
	_ = fs.String("timeout", "10m", "Max wait time for scan completion (reserved for the in-process pipeline)")
	_ = fs.Bool("json", false, "Output results as JSON (reserved for the in-process pipeline)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate the chart path exists so the command fails fast and clearly,
	// matching the deterministic-path UX, rather than only at pipeline wiring.
	if _, err := os.Stat(*chartPath); err != nil {
		return fmt.Errorf("scan chart %s: %w", *chartPath, err)
	}

	// The agentic scan path is intentionally a no-op until the in-process
	// pipeline lands. Deterministic detection remains available via the
	// standalone detector-* binaries. Return a clear, actionable error.
	return errScanPipelineNotWired
}

// errFindings is returned by runScan when findings are present (exit code 1).
var errFindings = &findingsError{}

type findingsError struct{}

func (e *findingsError) Error() string { return "findings detected" }

// isFindingsError reports whether err is the findings sentinel.
func isFindingsError(err error) bool {
	_, ok := err.(*findingsError)
	return ok
}

// scanOutputDir returns the directory where the scan pipeline writes
// findings/resolutions, derived from chart location. Returns "" if not
// determinable.
func scanOutputDir(chartPath string) string {
	chartDir := filepath.Dir(chartPath)
	candidate := filepath.Join(chartDir, "..", "output")
	return filepath.Clean(candidate)
}

// parseScanLine attempts to decode a JSONL line as Finding or Resolution.
func parseScanLine(line string, out *scanOutput) {
	// Heuristic: lines with "finding_id" are Resolutions; lines with "severity" and "source" are Findings.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &probe); err != nil {
		return
	}
	if _, hasFindingID := probe["finding_id"]; hasFindingID {
		var res resolution.Resolution
		if err := json.Unmarshal([]byte(line), &res); err == nil {
			out.resolutions = append(out.resolutions, res)
		}
		return
	}
	if _, hasSeverity := probe["severity"]; hasSeverity {
		var f finding.Finding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			out.findings = append(out.findings, f)
		}
	}
}

// readFindingsDir reads *.json finding files from dir.
func readFindingsDir(dir string) []finding.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var findings []finding.Finding
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if !strings.HasPrefix(e.Name(), "finding-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal(data, &f); err == nil {
			findings = append(findings, f)
		}
	}
	return findings
}

// readResolutionsDir reads *.json resolution files from dir.
func readResolutionsDir(dir string) []resolution.Resolution {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var resolutions []resolution.Resolution
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if !strings.HasPrefix(e.Name(), "resolution-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var res resolution.Resolution
		if err := json.Unmarshal(data, &res); err == nil {
			resolutions = append(resolutions, res)
		}
	}
	return resolutions
}

// buildSummary computes scan statistics from collected output.
func buildSummary(out scanOutput) ScanSummary {
	s := ScanSummary{
		FindingsDetected: len(out.findings),
	}
	for _, res := range out.resolutions {
		switch res.Action {
		case "escalate":
			s.Escalated++
		default:
			s.Resolved++
		}
	}
	return s
}

// printSummary writes a human-readable summary to stdout.
func printSummary(s ScanSummary) {
	fmt.Printf("Scan complete\n")
	fmt.Printf("  Events scanned:     %d\n", s.EventsScanned)
	fmt.Printf("  Findings detected:  %d\n", s.FindingsDetected)
	fmt.Printf("  Escalated:          %d\n", s.Escalated)
	fmt.Printf("  Resolved:           %d\n", s.Resolved)
}

// printJSON writes the summary as JSON to stdout.
func printJSON(s ScanSummary) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
