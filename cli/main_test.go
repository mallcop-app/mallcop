package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// ---------------------------------------------------------------------------
// buildSummary
// ---------------------------------------------------------------------------

func TestBuildSummary_Empty(t *testing.T) {
	s := buildSummary(scanOutput{})
	if s.FindingsDetected != 0 {
		t.Errorf("expected 0 findings, got %d", s.FindingsDetected)
	}
	if s.Escalated != 0 {
		t.Errorf("expected 0 escalated, got %d", s.Escalated)
	}
	if s.Resolved != 0 {
		t.Errorf("expected 0 resolved, got %d", s.Resolved)
	}
}

func TestBuildSummary_Findings(t *testing.T) {
	out := scanOutput{
		findings: []finding.Finding{
			{ID: "f1", Severity: "high"},
			{ID: "f2", Severity: "low"},
		},
		resolutions: []resolution.Resolution{
			{FindingID: "f1", Action: "escalate"},
			{FindingID: "f2", Action: "alert"},
		},
	}
	s := buildSummary(out)
	if s.FindingsDetected != 2 {
		t.Errorf("expected 2 findings, got %d", s.FindingsDetected)
	}
	if s.Escalated != 1 {
		t.Errorf("expected 1 escalated, got %d", s.Escalated)
	}
	if s.Resolved != 1 {
		t.Errorf("expected 1 resolved, got %d", s.Resolved)
	}
}

func TestBuildSummary_AllEscalated(t *testing.T) {
	out := scanOutput{
		findings: []finding.Finding{
			{ID: "f1"}, {ID: "f2"}, {ID: "f3"},
		},
		resolutions: []resolution.Resolution{
			{FindingID: "f1", Action: "escalate"},
			{FindingID: "f2", Action: "escalate"},
			{FindingID: "f3", Action: "escalate"},
		},
	}
	s := buildSummary(out)
	if s.FindingsDetected != 3 {
		t.Errorf("expected 3 findings, got %d", s.FindingsDetected)
	}
	if s.Escalated != 3 {
		t.Errorf("expected 3 escalated, got %d", s.Escalated)
	}
	if s.Resolved != 0 {
		t.Errorf("expected 0 resolved, got %d", s.Resolved)
	}
}

// ---------------------------------------------------------------------------
// printSummary / printJSON
// ---------------------------------------------------------------------------

func TestPrintSummary_Format(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printSummary(ScanSummary{
		EventsScanned:    42,
		FindingsDetected: 3,
		Escalated:        1,
		Resolved:         2,
	})

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	for _, want := range []string{"42", "3", "1", "2", "Scan complete"} {
		if !strings.Contains(out, want) {
			t.Errorf("printSummary output missing %q; got:\n%s", want, out)
		}
	}
}

func TestPrintJSON_Valid(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printJSON(ScanSummary{EventsScanned: 10, FindingsDetected: 2, Escalated: 1, Resolved: 1})

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)

	var got ScanSummary
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("printJSON produced invalid JSON: %v\noutput: %s", err, buf.String())
	}
	if got.FindingsDetected != 2 {
		t.Errorf("expected 2 findings in JSON, got %d", got.FindingsDetected)
	}
}

// ---------------------------------------------------------------------------
// parseScanLine
// ---------------------------------------------------------------------------

func TestParseScanLine_Finding(t *testing.T) {
	ts := time.Now().UTC()
	f := finding.Finding{
		ID:        "f-001",
		Source:    "detector:unusual-login",
		Severity:  "high",
		Type:      "unusual-login",
		Timestamp: ts,
	}
	data, _ := json.Marshal(f)

	var out scanOutput
	parseScanLine(string(data), &out)

	if len(out.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.findings))
	}
	if out.findings[0].ID != "f-001" {
		t.Errorf("unexpected finding ID %q", out.findings[0].ID)
	}
}

func TestParseScanLine_Resolution(t *testing.T) {
	res := resolution.Resolution{
		FindingID: "f-001",
		Action:    "alert",
		Severity:  "high",
	}
	data, _ := json.Marshal(res)

	var out scanOutput
	parseScanLine(string(data), &out)

	if len(out.resolutions) != 1 {
		t.Fatalf("expected 1 resolution, got %d", len(out.resolutions))
	}
	if out.resolutions[0].FindingID != "f-001" {
		t.Errorf("unexpected finding_id %q", out.resolutions[0].FindingID)
	}
}

func TestParseScanLine_NonJSON(t *testing.T) {
	var out scanOutput
	parseScanLine("not json at all", &out)
	if len(out.findings) != 0 || len(out.resolutions) != 0 {
		t.Error("expected no findings/resolutions for non-JSON line")
	}
}

func TestParseScanLine_UnknownJSON(t *testing.T) {
	var out scanOutput
	parseScanLine(`{"some":"unrelated","fields":true}`, &out)
	if len(out.findings) != 0 || len(out.resolutions) != 0 {
		t.Error("expected no findings/resolutions for unrecognised JSON")
	}
}

// ---------------------------------------------------------------------------
// isFindingsError
// ---------------------------------------------------------------------------

func TestIsFindingsError(t *testing.T) {
	if !isFindingsError(errFindings) {
		t.Error("errFindings should be a findingsError")
	}
	if isFindingsError(fmt.Errorf("some other error")) {
		t.Error("generic error should not be a findingsError")
	}
	if isFindingsError(nil) {
		t.Error("nil should not be a findingsError")
	}
}

// ---------------------------------------------------------------------------
// readFindingsDir / readResolutionsDir
// ---------------------------------------------------------------------------

func TestReadFindingsDir_Empty(t *testing.T) {
	tmp := t.TempDir()
	got := readFindingsDir(tmp)
	if len(got) != 0 {
		t.Errorf("expected no findings in empty dir, got %d", len(got))
	}
}

func TestReadFindingsDir_Findings(t *testing.T) {
	tmp := t.TempDir()
	f := finding.Finding{ID: "f-xyz", Severity: "critical"}
	data, _ := json.Marshal(f)
	os.WriteFile(tmp+"/finding-f-xyz.json", data, 0o644)
	// Also write a non-finding file — should be skipped.
	os.WriteFile(tmp+"/something-else.json", []byte(`{}`), 0o644)

	got := readFindingsDir(tmp)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].ID != "f-xyz" {
		t.Errorf("unexpected ID %q", got[0].ID)
	}
}

func TestReadResolutionsDir_Resolutions(t *testing.T) {
	tmp := t.TempDir()
	res := resolution.Resolution{FindingID: "f-xyz", Action: "block"}
	data, _ := json.Marshal(res)
	os.WriteFile(tmp+"/resolution-f-xyz.json", data, 0o644)

	got := readResolutionsDir(tmp)
	if len(got) != 1 {
		t.Fatalf("expected 1 resolution, got %d", len(got))
	}
	if got[0].FindingID != "f-xyz" {
		t.Errorf("unexpected finding_id %q", got[0].FindingID)
	}
}

// ---------------------------------------------------------------------------
// usage()
// ---------------------------------------------------------------------------

// TestUsage_InitFlagsDocumented locks in the help-text fix: the top-level
// `mallcop`/`mallcop --help` usage() text must document every real `init`
// flag (--pro, --create-repo, --mallcop-version, --github-token-env), not
// just --dir. Before this fix, usage() silently omitted the deployment-repo
// flags a customer needs to find `mallcop init --create-repo`/`--pro`.
func TestUsage_InitFlagsDocumented(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	usage()
	w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	for _, want := range []string{"--dir", "--pro", "--create-repo", "--mallcop-version", "--github-token-env"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage() init section missing flag %q; got:\n%s", want, out)
		}
	}
}
