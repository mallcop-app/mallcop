//go:build e2e

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// TestScanE2E_StubReturnsNotWired builds the mallcop binary and runs
// `mallcop scan` against a valid chart. The agentic scan path was previously
// backed by the external legion binary (`we start --exit-on-idle`); that
// coupling has been removed and the path is stubbed pending the in-process
// pipeline. The command must now fail fast (exit 2) with the "not yet wired"
// message, regardless of whether a `we` binary is on PATH.
func TestScanE2E_StubReturnsNotWired(t *testing.T) {
	tmp := t.TempDir()
	mallcopBin := filepath.Join(tmp, "mallcop")
	build := exec.Command("go", "build", "-o", mallcopBin, ".")
	build.Dir = filepath.Join(repoRoot(t), "cmd", "mallcop")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build mallcop: %v", err)
	}

	scanDir := filepath.Join(tmp, "scan")
	chartsDir := filepath.Join(scanDir, "charts")
	binDir := filepath.Join(scanDir, "bin")
	outputDir := filepath.Join(scanDir, "output")
	for _, d := range []string{chartsDir, binDir, outputDir} {
		os.MkdirAll(d, 0o755)
	}

	chartFile := filepath.Join(chartsDir, "test.toml")
	os.WriteFile(chartFile, []byte("[identity]\nname=\"test\"\n"), 0o644)

	// Plant a fake `we` binary that would have emitted findings under the old
	// exec path; the stub must ignore it entirely.
	seedFindings(t, outputDir)
	fakeBin := filepath.Join(binDir, "we")
	os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755)

	cmd := exec.Command(mallcopBin, "scan", "--chart", chartFile, "--timeout", "30s")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PATH=%s:%s", binDir, os.Getenv("PATH")))
	cmd.Dir = scanDir

	out, err := cmd.CombinedOutput()
	t.Logf("mallcop scan output:\n%s", out)

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error running mallcop scan: %v", err)
		}
	}

	// Exit 2 = command error (the stub error is not the findings sentinel).
	if exitCode != 2 {
		t.Errorf("expected exit code 2 (scan path stubbed), got %d", exitCode)
	}

	if !strings.Contains(string(out), "in-process scan pipeline not yet wired") {
		t.Errorf("output missing stub message; got:\n%s", out)
	}
}

// TestScanE2E_MissingChart verifies `mallcop scan` fails clearly (exit 2) when
// the chart path does not exist.
func TestScanE2E_MissingChart(t *testing.T) {
	tmp := t.TempDir()
	mallcopBin := filepath.Join(tmp, "mallcop")
	build := exec.Command("go", "build", "-o", mallcopBin, ".")
	build.Dir = filepath.Join(repoRoot(t), "cmd", "mallcop")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build mallcop: %v", err)
	}

	cmd := exec.Command(mallcopBin, "scan", "--chart", filepath.Join(tmp, "nope.toml"))
	out, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		}
	}
	if exitCode != 2 {
		t.Errorf("expected exit code 2 (missing chart), got %d\noutput:\n%s", exitCode, out)
	}
}

// seedFindings writes fixture finding JSON files to dir.
func seedFindings(t *testing.T, dir string) {
	t.Helper()
	ts := time.Now().UTC()
	findings := []finding.Finding{
		{ID: "f-e2e-001", Source: "detector:unusual-login", Severity: "high", Type: "unusual-login", Timestamp: ts},
		{ID: "f-e2e-002", Source: "detector:secrets-exposure", Severity: "critical", Type: "secrets-exposure", Timestamp: ts},
	}
	for _, f := range findings {
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, fmt.Sprintf("finding-%s.json", f.ID))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// seedResolutions writes fixture resolution JSON files to dir. Retained as a
// helper for finding/resolution fixture construction in scan-path tests.
func seedResolutions(t *testing.T, dir string) {
	t.Helper()
	ts := time.Now().UTC()
	resolutions := []resolution.Resolution{
		{FindingID: "f-e2e-001", Action: "escalate", Severity: "high", Timestamp: ts},
		{FindingID: "f-e2e-002", Action: "block", Severity: "critical", Timestamp: ts},
	}
	for _, r := range resolutions {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, fmt.Sprintf("resolution-%s.json", r.FindingID))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// repoRoot walks up from the test file to find the go.mod root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}
