package detectorhost

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// fakeDetector is a minimal in-package detect.Detector stand-in — its
// behavior is parameterized per test so RunIO's stdio plumbing can be
// exercised without a real sidecar rule.
type fakeDetector struct {
	name    string
	out     []finding.Finding
	panicOn bool
	gotEv   []event.Event
	gotBl   *baseline.Baseline
}

func (f *fakeDetector) Name() string { return f.name }

func (f *fakeDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	f.gotEv = events
	f.gotBl = bl
	if f.panicOn {
		panic("boom")
	}
	return f.out
}

func TestRunIOHappyPath(t *testing.T) {
	in := `{"events":[{"id":"e1","source":"github","type":"push","actor":"alice"}],"baseline":{"known_actors":["alice"]}}`
	d := &fakeDetector{name: "example", out: []finding.Finding{{ID: "f1", Source: "detector:example", Severity: "low", Type: "example"}}}

	var out, errOut bytes.Buffer
	code := RunIO(d, strings.NewReader(in), &out, &errOut)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, errOut.String())
	}
	if len(d.gotEv) != 1 || d.gotEv[0].ID != "e1" {
		t.Fatalf("events not decoded correctly: %+v", d.gotEv)
	}
	if d.gotBl == nil || len(d.gotBl.KnownActors) != 1 || d.gotBl.KnownActors[0] != "alice" {
		t.Fatalf("baseline not decoded correctly: %+v", d.gotBl)
	}

	var findings []finding.Finding
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("stdout not valid findings JSON: %v (stdout=%s)", err, out.String())
	}
	if len(findings) != 1 || findings[0].ID != "f1" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

// TestRunIONilBaseline proves an omitted baseline decodes to an empty
// *baseline.Baseline, never nil — mirroring core/detect.Detect's contract.
func TestRunIONilBaseline(t *testing.T) {
	in := `{"events":[]}`
	d := &fakeDetector{name: "example"}

	var out, errOut bytes.Buffer
	code := RunIO(d, strings.NewReader(in), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, errOut.String())
	}
	if d.gotBl == nil {
		t.Fatal("baseline must never be nil inside Detect")
	}
}

// TestRunIONoFindingsEmitsEmptyArray proves "no findings" is encoded as `[]`,
// never `null` — the host always unmarshals stdout into a slice.
func TestRunIONoFindingsEmitsEmptyArray(t *testing.T) {
	in := `{"events":[]}`
	d := &fakeDetector{name: "example", out: nil}

	var out, errOut bytes.Buffer
	code := RunIO(d, strings.NewReader(in), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	got := strings.TrimSpace(out.String())
	if got != "[]" {
		t.Fatalf("stdout = %q, want %q", got, "[]")
	}
}

func TestRunIOMalformedInputIsLoudNonzeroExit(t *testing.T) {
	d := &fakeDetector{name: "example"}
	var out, errOut bytes.Buffer
	code := RunIO(d, strings.NewReader("{not json"), &out, &errOut)
	if code == 0 {
		t.Fatal("malformed input must be a nonzero exit, not a silent empty-findings success")
	}
	if errOut.Len() == 0 {
		t.Fatal("malformed input must write a diagnostic to stderr")
	}
}

// TestRunIOPanicIsRecoveredIntoLoudFailure proves a panicking detector impl
// does not crash the harness — it becomes a nonzero exit + stderr message,
// which the host (detecthost) surfaces as a loud detector error rather than
// silently reporting zero findings.
func TestRunIOPanicIsRecoveredIntoLoudFailure(t *testing.T) {
	d := &fakeDetector{name: "example", panicOn: true}
	var out, errOut bytes.Buffer
	code := RunIO(d, strings.NewReader(`{"events":[]}`), &out, &errOut)
	if code == 0 {
		t.Fatal("a panicking detector must produce a nonzero exit")
	}
	if !strings.Contains(errOut.String(), "boom") {
		t.Fatalf("stderr should surface the panic value, got %q", errOut.String())
	}
}
