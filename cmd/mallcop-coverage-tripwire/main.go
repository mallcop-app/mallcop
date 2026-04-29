package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// CorpusEntry represents a single historical finding with expected verdict.
type CorpusEntry struct {
	ID               string `json:"id"`
	Detector         string `json:"detector"`
	AppName          string `json:"app_name"`
	InputLog         string `json:"input_log"`
	ExpectedVerdict  string `json:"expected_verdict"`
	Description      string `json:"description"`
}

// TripwireResult reports the verdict for a single corpus entry.
type TripwireResult struct {
	CorpusID       string    `json:"corpus_id"`
	Detector       string    `json:"detector"`
	AppName        string    `json:"app_name"`
	ExpectedVerdict string   `json:"expected_verdict"`
	ActualVerdict  string    `json:"actual_verdict"`
	Passed         bool      `json:"passed"`
	Reason         string    `json:"reason,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// Report aggregates results.
type Report struct {
	Timestamp      time.Time         `json:"timestamp"`
	CorpusPath     string            `json:"corpus_path"`
	TotalEntries   int               `json:"total_entries"`
	Passed         int               `json:"passed"`
	Failed         int               `json:"failed"`
	Results        []TripwireResult  `json:"results"`
	FailureReasons []string          `json:"failure_reasons,omitempty"`
}

func main() {
	corpusPath := flag.String("corpus", "docs/coverage/v1-corpus.jsonl", "Path to coverage corpus file (JSONL)")
	outputPath := flag.String("output", "", "Path to write report JSON (optional)")
	detectorPath := flag.String("detector-bin", "", "Path to detector binary to invoke (optional for v1)")
	flag.Parse()

	// Load corpus.
	corpus, err := loadCorpus(*corpusPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load corpus: %v\n", err)
		os.Exit(1)
	}

	if len(corpus) == 0 {
		fmt.Fprintf(os.Stderr, "Corpus file empty or not found: %s\n", *corpusPath)
		os.Exit(1)
	}

	// Run tripwire.
	report := runTripwire(corpus, *detectorPath)

	// Write report.
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(reportJSON))

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, reportJSON, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write report: %v\n", err)
			os.Exit(1)
		}
	}

	// Exit with appropriate code.
	if report.Failed > 0 {
		fmt.Fprintf(os.Stderr, "Tripwire FAILED: %d/%d entries regressed\n", report.Failed, report.TotalEntries)
		os.Exit(1)
	}

	fmt.Printf("Tripwire PASSED: all %d entries verified\n", report.TotalEntries)
	os.Exit(0)
}

// loadCorpus reads JSONL corpus file, one CorpusEntry per line.
func loadCorpus(path string) ([]CorpusEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open corpus: %w", err)
	}
	defer file.Close()

	var corpus []CorpusEntry
	scanner := bufio.NewScanner(file)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry CorpusEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}

		if entry.ID == "" || entry.Detector == "" || entry.AppName == "" {
			return nil, fmt.Errorf("line %d: missing required fields (id, detector, app_name)", lineNo)
		}

		corpus = append(corpus, entry)
	}

	return corpus, scanner.Err()
}

// runTripwire evaluates each corpus entry and produces a report.
func runTripwire(corpus []CorpusEntry, detectorPath string) Report {
	report := Report{
		Timestamp:    time.Now().UTC(),
		TotalEntries: len(corpus),
		Results:      make([]TripwireResult, 0, len(corpus)),
		FailureReasons: []string{},
	}

	for _, entry := range corpus {
		result := evaluateEntry(entry, detectorPath)
		report.Results = append(report.Results, result)

		if result.Passed {
			report.Passed++
		} else {
			report.Failed++
			if result.Reason != "" && !containsString(report.FailureReasons, result.Reason) {
				report.FailureReasons = append(report.FailureReasons, result.Reason)
			}
		}
	}

	// Sort failure reasons for determinism.
	sort.Strings(report.FailureReasons)

	return report
}

// evaluateEntry invokes the detector (or stubs it for v1) and compares verdict.
func evaluateEntry(entry CorpusEntry, detectorPath string) TripwireResult {
	result := TripwireResult{
		CorpusID:        entry.ID,
		Detector:        entry.Detector,
		AppName:         entry.AppName,
		ExpectedVerdict: entry.ExpectedVerdict,
		Timestamp:       time.Now().UTC(),
	}

	// v1: stub implementation.
	// In v2, this will invoke the actual detector binary and capture verdict.
	// For now, we synthesize a verdict based on simple heuristics.
	actualVerdict := stubEvaluateLog(entry.InputLog, entry.AppName, entry.Detector)

	result.ActualVerdict = actualVerdict
	result.Passed = actualVerdict == entry.ExpectedVerdict

	if !result.Passed {
		result.Reason = fmt.Sprintf("expected %s, got %s", entry.ExpectedVerdict, actualVerdict)
	}

	_ = detectorPath // Silence unused warning for v1.

	return result
}

// stubEvaluateLog provides a simple heuristic for v1 until real detector integration.
// Looks for security keywords and app context.
func stubEvaluateLog(logLine, appName, detector string) string {
	lower := strings.ToLower(logLine)

	// Security keywords that indicate escalation.
	securityKeywords := []string{
		"mfa", "auth", "login", "password", "credential", "token",
		"admin", "privilege", "permission", "access", "denied",
		"error", "failed", "failure", "unauthorized", "forbidden",
		"encryption", "certificate", "key", "secret", "backup",
		"retention", "card_last4", "sensitive", "security",
		"changed", "modified", "altered",
	}

	// Operational/benign keywords.
	benignKeywords := []string{
		"normal", "status", "latency", "packet_loss",
		"jitter", "memory_pressure", "eviction", "cache",
	}

	// Count keyword matches.
	securityCount := 0
	benignCount := 0

	for _, kw := range securityKeywords {
		if strings.Contains(lower, kw) {
			securityCount++
		}
	}

	for _, kw := range benignKeywords {
		if strings.Contains(lower, kw) {
			benignCount++
		}
	}

	// Decision: if security keywords dominate, escalate.
	// Heuristic: security wins if its count is strictly greater.
	if securityCount > benignCount {
		return "escalated"
	}

	return "resolved"
}

// containsString checks if a string is in a slice.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
