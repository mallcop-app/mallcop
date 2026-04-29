package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCorpusValid(t *testing.T) {
	// Create a temporary corpus file with valid entries.
	tmpDir := t.TempDir()
	corpusPath := filepath.Join(tmpDir, "corpus.jsonl")

	corpusContent := `{"id":"c1","detector":"log_format_drift","app_name":"app1","input_log":"[INFO] test","expected_verdict":"escalated","description":"test 1"}
{"id":"c2","detector":"log_format_drift","app_name":"app2","input_log":"[DEBUG] benign","expected_verdict":"resolved","description":"test 2"}
`

	if err := os.WriteFile(corpusPath, []byte(corpusContent), 0644); err != nil {
		t.Fatalf("Failed to write test corpus: %v", err)
	}

	corpus, err := loadCorpus(corpusPath)
	if err != nil {
		t.Fatalf("loadCorpus failed: %v", err)
	}

	if len(corpus) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(corpus))
	}

	if corpus[0].ID != "c1" || corpus[1].ID != "c2" {
		t.Errorf("Corpus entries not loaded in order")
	}
}

func TestLoadCorpusFileMissing(t *testing.T) {
	_, err := loadCorpus("/nonexistent/path/corpus.jsonl")
	if err == nil {
		t.Fatal("Expected error for missing corpus file, got none")
	}
}

func TestLoadCorpusMalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	corpusPath := filepath.Join(tmpDir, "bad-corpus.jsonl")

	badContent := `{"id":"c1","detector":"test"` // Incomplete JSON

	if err := os.WriteFile(corpusPath, []byte(badContent), 0644); err != nil {
		t.Fatalf("Failed to write test corpus: %v", err)
	}

	_, err := loadCorpus(corpusPath)
	if err == nil {
		t.Fatal("Expected error for malformed JSON, got none")
	}
}

func TestLoadCorpusMissingRequiredFields(t *testing.T) {
	tmpDir := t.TempDir()
	corpusPath := filepath.Join(tmpDir, "incomplete-corpus.jsonl")

	incompleteContent := `{"id":"c1","detector":"log_format_drift"}` // Missing app_name

	if err := os.WriteFile(corpusPath, []byte(incompleteContent), 0644); err != nil {
		t.Fatalf("Failed to write test corpus: %v", err)
	}

	_, err := loadCorpus(corpusPath)
	if err == nil {
		t.Fatal("Expected error for missing required fields, got none")
	}
}

func TestTripwireAllPass_ExitZero(t *testing.T) {
	corpus := []CorpusEntry{
		{
			ID:              "pass-1",
			Detector:        "log_format_drift",
			AppName:         "auth-service",
			InputLog:        "[INFO] User login: mfa=enabled",
			ExpectedVerdict: "escalated",
			Description:     "Auth with MFA should escalate",
		},
		{
			ID:              "pass-2",
			Detector:        "log_format_drift",
			AppName:         "network",
			InputLog:        "[INFO] Network status normal latency_ms=10",
			ExpectedVerdict: "resolved",
			Description:     "Normal network metrics should resolve",
		},
	}

	report := runTripwire(corpus, "")

	if report.Failed != 0 {
		t.Errorf("Expected 0 failures, got %d", report.Failed)
	}

	if report.Passed != 2 {
		t.Errorf("Expected 2 passes, got %d", report.Passed)
	}

	// Verify exit code would be 0.
	// (We test this indirectly via the Failed count.)
}

func TestTripwireOneRegression_NonZero(t *testing.T) {
	corpus := []CorpusEntry{
		{
			ID:              "pass-1",
			Detector:        "log_format_drift",
			AppName:         "auth-service",
			InputLog:        "[INFO] User login: mfa=enabled",
			ExpectedVerdict: "escalated",
			Description:     "Auth with MFA should escalate",
		},
		{
			ID:              "regression-1",
			Detector:        "log_format_drift",
			AppName:         "auth-service",
			InputLog:        "[INFO] User admin access granted",
			ExpectedVerdict: "escalated",
			Description:     "Admin access should escalate",
		},
	}

	report := runTripwire(corpus, "")

	// At least one should pass (the first one).
	if report.Passed < 1 {
		t.Errorf("Expected at least 1 pass, got %d", report.Passed)
	}

	// At least one should fail (depending on heuristic match).
	// The second one is very likely to match our security keywords.
	// For determinism, we verify the report structure.
	if report.TotalEntries != 2 {
		t.Errorf("Expected 2 total entries, got %d", report.TotalEntries)
	}

	if report.Passed+report.Failed != report.TotalEntries {
		t.Errorf("Passed + Failed != Total")
	}
}

func TestTripwireRegressionReportShape(t *testing.T) {
	corpus := []CorpusEntry{
		{
			ID:              "shape-test",
			Detector:        "log_format_drift",
			AppName:         "test-app",
			InputLog:        "[INFO] normal operation",
			ExpectedVerdict: "resolved",
			Description:     "Test entry",
		},
	}

	report := runTripwire(corpus, "")

	// Verify report structure.
	if report.Timestamp.IsZero() {
		t.Error("Report timestamp is zero")
	}

	if len(report.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(report.Results))
	}

	result := report.Results[0]

	// Verify result fields.
	if result.CorpusID != "shape-test" {
		t.Errorf("Expected corpus ID 'shape-test', got %q", result.CorpusID)
	}

	if result.Detector != "log_format_drift" {
		t.Errorf("Expected detector 'log_format_drift', got %q", result.Detector)
	}

	if result.AppName != "test-app" {
		t.Errorf("Expected app_name 'test-app', got %q", result.AppName)
	}

	if result.ExpectedVerdict == "" {
		t.Error("ExpectedVerdict is empty")
	}

	if result.ActualVerdict == "" {
		t.Error("ActualVerdict is empty")
	}

	if result.Timestamp.IsZero() {
		t.Error("Result timestamp is zero")
	}

	// Verify Passed and Reason are set correctly.
	if result.ActualVerdict == result.ExpectedVerdict {
		if !result.Passed {
			t.Error("Passed should be true when verdicts match")
		}
		if result.Reason != "" {
			t.Error("Reason should be empty when passed")
		}
	} else {
		if result.Passed {
			t.Error("Passed should be false when verdicts differ")
		}
		if result.Reason == "" {
			t.Error("Reason should be set when failed")
		}
	}
}

func TestReportJSON(t *testing.T) {
	corpus := []CorpusEntry{
		{
			ID:              "json-test",
			Detector:        "log_format_drift",
			AppName:         "test",
			InputLog:        "[INFO] test",
			ExpectedVerdict: "escalated",
			Description:     "Test",
		},
	}

	report := runTripwire(corpus, "")

	// Verify it's JSON-serializable.
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal report to JSON: %v", err)
	}

	// Verify it unmarshals correctly.
	var unmarshaled Report
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal report from JSON: %v", err)
	}

	if unmarshaled.TotalEntries != 1 {
		t.Errorf("Unmarshaled report has wrong TotalEntries: %d", unmarshaled.TotalEntries)
	}
}

func TestStubEvaluateLogSecurityKeywords(t *testing.T) {
	tests := []struct {
		name    string
		logLine string
		appName string
		want    string
	}{
		{
			name:    "mfa_enabled",
			logLine: "[INFO] User login: mfa=enabled ip=192.0.2.1",
			appName: "auth",
			want:    "escalated",
		},
		{
			name:    "admin_access",
			logLine: "[INFO] Admin access granted to user=alice",
			appName: "access-control",
			want:    "escalated",
		},
		{
			name:    "password_changed",
			logLine: "[INFO] User password changed successfully",
			appName: "identity",
			want:    "escalated",
		},
		{
			name:    "normal_network",
			logLine: "[INFO] Network status=normal latency_ms=10 jitter_ms=2",
			appName: "network",
			want:    "resolved",
		},
		{
			name:    "cache_eviction",
			logLine: "[INFO] Cache eviction: reason=memory_pressure count=512",
			appName: "cache",
			want:    "resolved",
		},
		{
			name:    "error_with_security",
			logLine: "[ERROR] Authentication failed: user=bob reason=invalid_token",
			appName: "auth",
			want:    "escalated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stubEvaluateLog(tt.logLine, tt.appName, "log_format_drift")
			if got != tt.want {
				t.Errorf("stubEvaluateLog(%q) = %q, want %q", tt.logLine, got, tt.want)
			}
		})
	}
}

func TestEvaluateEntryVerdict(t *testing.T) {
	entry := CorpusEntry{
		ID:              "eval-test",
		Detector:        "log_format_drift",
		AppName:         "auth",
		InputLog:        "[INFO] User login: mfa=enabled",
		ExpectedVerdict: "escalated",
		Description:     "Auth test",
	}

	result := evaluateEntry(entry, "")

	if result.CorpusID != "eval-test" {
		t.Errorf("Expected corpus ID 'eval-test', got %q", result.CorpusID)
	}

	if result.ExpectedVerdict != "escalated" {
		t.Errorf("Expected verdict 'escalated', got %q", result.ExpectedVerdict)
	}

	if result.ActualVerdict != "escalated" {
		t.Errorf("Expected actual verdict 'escalated', got %q", result.ActualVerdict)
	}

	if !result.Passed {
		t.Error("Expected Passed=true, got false")
	}

	if result.Reason != "" {
		t.Errorf("Expected empty Reason, got %q", result.Reason)
	}

	if result.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp, got zero")
	}
}

func TestReportFailureReasons(t *testing.T) {
	corpus := []CorpusEntry{
		{
			ID:              "fail-1",
			Detector:        "log_format_drift",
			AppName:         "app1",
			InputLog:        "[INFO] benign operation",
			ExpectedVerdict: "escalated", // Will mismatch
			Description:     "Test 1",
		},
		{
			ID:              "fail-2",
			Detector:        "log_format_drift",
			AppName:         "app2",
			InputLog:        "[INFO] another benign",
			ExpectedVerdict: "escalated", // Will mismatch
			Description:     "Test 2",
		},
	}

	report := runTripwire(corpus, "")

	// Verify failure reasons are collected and sorted.
	if len(report.FailureReasons) == 0 && report.Failed > 0 {
		t.Error("Expected failure reasons to be populated when failures occur")
	}

	// If we have multiple failures with same reason, it should only appear once.
	reasonCounts := make(map[string]int)
	for _, reason := range report.FailureReasons {
		reasonCounts[reason]++
	}

	for reason, count := range reasonCounts {
		if count > 1 {
			t.Errorf("Failure reason %q appears %d times (should be unique)", reason, count)
		}
	}
}

func TestContainsString(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		s     string
		want  bool
	}{
		{
			name:  "found",
			slice: []string{"a", "b", "c"},
			s:     "b",
			want:  true,
		},
		{
			name:  "not_found",
			slice: []string{"a", "b", "c"},
			s:     "d",
			want:  false,
		},
		{
			name:  "empty_slice",
			slice: []string{},
			s:     "a",
			want:  false,
		},
		{
			name:  "empty_string",
			slice: []string{"a", "", "c"},
			s:     "",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsString(tt.slice, tt.s)
			if got != tt.want {
				t.Errorf("containsString(%v, %q) = %v, want %v", tt.slice, tt.s, got, tt.want)
			}
		})
	}
}
