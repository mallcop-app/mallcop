// customerexam_test.go — the GROUND-TRUTH INVARIANT proof for RunCustomerTreeExam
// (mallcoppro-cc3e): the customer-tree exam mode must grade the detector by
// running the compiled wasip1 .wasm THROUGH THE REAL detecthost/wazero host,
// never by linking the detector's Go source in-process.
//
// The proof detector (buildCustomerProbeModule) is deliberately observable:
// its finding Type embeds runtime.GOOS + "-" + runtime.GOARCH, read INSIDE
// Detect at whatever runtime actually executed the call. Compiled under
// GOOS=wasip1 GOARCH=wasm and run inside wazero, that pair is always
// "wasip1"/"wasm" — a value that DOES NOT EXIST on any host this test suite
// runs on (linux/amd64, darwin/arm64, ...). If RunCustomerTreeExam (or a
// future "optimization" of it) ever took a shortcut — e.g. compiling the
// probe natively and registering it as an in-process detect.Detector instead
// of building it to wasm and loading it through detecthost — the emitted
// family would read "wasm-host-proof-<native GOOS>-<native GOARCH>" instead,
// and TestRunCustomerTreeExam_GradesThroughRealWasmHost below would fail.
package selfgate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// customerProbeMainSrc is the customer-shaped detector's entire authored
// surface: a single package-main file implementing core/detect.Detector
// (structurally — it imports only pkg/event, pkg/finding, pkg/baseline,
// pkg/detectorhost, exactly the public framework surface a real external
// customer module would depend on) whose finding Type is
// "wasm-host-proof-<GOOS>-<GOARCH>" as observed AT RUNTIME. It never imports
// core/detect and is never referenced by any import in cmd/mallcop's own
// package graph — the whole point of the customer-tree shape.
const customerProbeMainSrc = `package main

import (
	"os"
	"runtime"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type probeDetector struct{}

func (probeDetector) Name() string { return "wasm-host-proof" }

func (probeDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	tag := "wasm-host-proof-" + runtime.GOOS + "-" + runtime.GOARCH
	out := make([]finding.Finding, 0, len(events))
	for _, ev := range events {
		out = append(out, finding.Finding{
			ID:     "finding-" + ev.ID + "-wasmhostproof",
			Source: "detector:wasm-host-proof",
			Type:   tag,
			Actor:  ev.Actor,
		})
	}
	return out
}

func main() {
	os.Exit(detectorhost.Run(probeDetector{}))
}
`

// buildCustomerProbeModule writes the probe detector as its OWN standalone Go
// module (own go.mod, `replace`d back to modulePath on the local filesystem —
// the offline-safe way to prove "an external module depending on this one
// builds" without a network fetch) under dir, and returns the module's root
// directory (dir itself). This is the CUSTOMER-SHAPED repo: a tree containing
// nothing but this one detector, never checked into modulePath, never
// imported by anything in it.
func buildCustomerProbeModule(t *testing.T, dir, modulePath string) string {
	t.Helper()
	goMod := fmt.Sprintf(`module example.com/customer-wasm-proof

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => %s
`, modulePath)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write customer probe go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(customerProbeMainSrc), 0o644); err != nil {
		t.Fatalf("write customer probe main.go: %v", err)
	}
	return dir
}

// TestRunCustomerTreeExam_GradesThroughRealWasmHost is the ground-truth
// invariant proof: RunCustomerTreeExam grades a detector living in a
// standalone module OUTSIDE the exam tree's own core/detect/authored/ tree by
// building it to a wasip1 .wasm module and running it through the REAL
// detecthost/wazero host — never in-process.
//
// The proof detector's finding Type carries runtime.GOOS + "-" + runtime.GOARCH
// AS OBSERVED AT THE MOMENT Detect RUNS. This test's own process (and any
// in-process shortcut RunCustomerTreeExam might take) reports the HOST's
// native pair (runtime.GOOS/runtime.GOARCH of the go test binary — asserted
// below to be something other than wasip1/wasm, closing the loophole where a
// wasip1 test runner would make this proof vacuous). Only a TRUE build-and-run
// through wazero reports "wasip1"/"wasm". If RunCustomerTreeExam ever linked
// the detector in-process instead of compiling+loading the .wasm, this test
// would observe the native pair and FAIL.
func TestRunCustomerTreeExam_GradesThroughRealWasmHost(t *testing.T) {
	if runtime.GOOS == "wasip1" || runtime.GOARCH == "wasm" {
		t.Fatalf("this test's own process reports GOOS=%s GOARCH=%s — the proof requires a NATIVE host process so the wasip1/wasm signature is only reachable through the real wasm host, never as a same-process shortcut", runtime.GOOS, runtime.GOARCH)
	}

	root := repoUnderTest(t)
	examTree := filepath.Join(t.TempDir(), "examtree")
	headSHA := headOf(t, root)
	if err := addWorktree(root, examTree, headSHA); err != nil {
		t.Fatalf("materialize exam tree worktree: %v", err)
	}
	defer removeWorktree(root, examTree)

	probeDir := buildCustomerProbeModule(t, t.TempDir(), examTree)

	report, err := RunCustomerTreeExam(examTree, probeDir)
	if err != nil {
		t.Fatalf("RunCustomerTreeExam: %v", err)
	}

	wantFamily := "wasm-host-proof-wasip1-wasm"
	nativeFamily := "wasm-host-proof-" + runtime.GOOS + "-" + runtime.GOARCH

	var sawWant, sawNative bool
	for _, row := range report.Rows {
		for _, fam := range row.Emitted {
			if fam == wantFamily {
				sawWant = true
			}
			if fam == nativeFamily {
				sawNative = true
			}
		}
	}

	if sawNative {
		t.Fatalf("saw family %q (this test process's NATIVE GOOS/GOARCH) in the exam report — the probe detector ran IN-PROCESS instead of through the real wasip1/wazero host; the ground-truth invariant is broken", nativeFamily)
	}
	if !sawWant {
		var all []string
		for _, row := range report.Rows {
			all = append(all, row.Emitted...)
		}
		t.Fatalf("never saw family %q (wasip1/wasm signature) in any exam row — the customer-tree exam did not run the compiled wasm module through the real host at all; emitted families seen: %s",
			wantFamily, strings.Join(all, ", "))
	}
	if report.Totals.Labeled == 0 {
		t.Fatalf("exam report graded zero labeled scenarios — the corpus did not load, this proof is vacuous")
	}
}

// TestRunCustomerTreeExam_OperationalErrorOnUnbuildableSource proves the error
// return is reserved for OPERATIONAL failures (a detector source that does not
// build), not folded into a "just fails every scenario" report.
func TestRunCustomerTreeExam_OperationalErrorOnUnbuildableSource(t *testing.T) {
	root := repoUnderTest(t)
	examTree := filepath.Join(t.TempDir(), "examtree")
	headSHA := headOf(t, root)
	if err := addWorktree(root, examTree, headSHA); err != nil {
		t.Fatalf("materialize exam tree worktree: %v", err)
	}
	defer removeWorktree(root, examTree)

	brokenDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(brokenDir, "go.mod"), []byte("module example.com/broken\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatalf("write broken go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "main.go"), []byte("package main\n\nfunc main() { this is not valid go }\n"), 0o644); err != nil {
		t.Fatalf("write broken main.go: %v", err)
	}

	if _, err := RunCustomerTreeExam(examTree, brokenDir); err == nil {
		t.Fatal("expected an operational error grading an unbuildable detector source, got nil")
	}
}
