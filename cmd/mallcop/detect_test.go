package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestReadEventsJSONL_ParsesAndSkips verifies the stdin parser keeps valid
// events, skips blanks, and tolerates a malformed line without aborting.
func TestReadEventsJSONL_ParsesAndSkips(t *testing.T) {
	in := strings.Join([]string{
		`{"id":"e1","source":"github","type":"push","actor":"alice"}`,
		``,
		`not json`,
		`{"id":"e2","source":"chat","type":"message","actor":"bob"}`,
	}, "\n")

	events, err := readEventsJSONL(strings.NewReader(in))
	if err != nil {
		t.Fatalf("readEventsJSONL: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events (blank + malformed skipped), got %d: %+v", len(events), events)
	}
	if events[0].ID != "e1" || events[1].ID != "e2" {
		t.Errorf("unexpected event IDs: %q, %q", events[0].ID, events[1].ID)
	}
}

// withStdio runs fn with os.Stdin replaced by stdinContent and captures
// os.Stdout, returning the captured stdout. This exercises runDetect exactly as
// the CLI would invoke it.
func withStdio(t *testing.T, stdinContent string, fn func() error) (string, error) {
	t.Helper()

	// Replace stdin.
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdin: %v", err)
	}
	go func() {
		_, _ = io.WriteString(inW, stdinContent)
		inW.Close()
	}()

	// Capture stdout.
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	runErr := fn()

	outW.Close()
	var buf bytes.Buffer
	io.Copy(&buf, outR)
	return buf.String(), runErr
}

// TestRunDetect_FiresOnMaliciousStdin proves `mallcop detect` runs the real
// core/detect pipeline over stdin with NO baseline / NO inference key and emits
// findings JSONL. A force-push to main is a known-malicious git-oops event.
func TestRunDetect_FiresOnMaliciousStdin(t *testing.T) {
	stdin := `{"id":"g1","source":"github","type":"push","actor":"dev","payload":{"forced":true,"ref":"refs/heads/main"}}` + "\n"

	out, err := withStdio(t, stdin, func() error { return runDetect(nil) })

	// Findings present → errFindings sentinel (exit code 1), not a real error.
	if !isFindingsError(err) {
		t.Fatalf("expected findings sentinel error, got %v", err)
	}

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("output line is not a valid Finding: %v\nline: %s", err, line)
		}
		if f.Type == "git-oops" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a critical git-oops finding in detect output; got:\n%s", out)
	}
}

// TestRunDetect_CleanInputNoFindings verifies a benign event stream produces no
// findings and a nil error (exit code 0).
func TestRunDetect_CleanInputNoFindings(t *testing.T) {
	// A benign login by a known user from a known IP, with a matching baseline.
	tmp := t.TempDir()
	blPath := tmp + "/baseline.json"
	blJSON := `{"known_users":{"alice":{"known_ips":["1.2.3.4"],"known_geos":["US"]}},"known_actors":["alice"]}`
	if err := os.WriteFile(blPath, []byte(blJSON), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	stdin := `{"id":"l1","source":"app","type":"login","actor":"alice","payload":{"ip":"1.2.3.4","geo":"US"}}` + "\n"

	out, err := withStdio(t, stdin, func() error {
		return runDetect([]string{"--baseline", blPath})
	})
	if err != nil {
		t.Fatalf("expected nil error on clean input, got %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("expected no findings on clean input, got:\n%s", out)
	}
}

// TestRunDetect_BadBaselinePath surfaces a real error (exit code 2), not the
// findings sentinel.
func TestRunDetect_BadBaselinePath(t *testing.T) {
	_, err := withStdio(t, "", func() error {
		return runDetect([]string{"--baseline", "/nonexistent/baseline.json"})
	})
	if err == nil {
		t.Fatal("expected error for missing baseline file")
	}
	if isFindingsError(err) {
		t.Fatal("missing baseline should be a real error, not the findings sentinel")
	}
}
