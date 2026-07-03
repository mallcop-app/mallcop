package detecthost_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/detecthost"
	"github.com/mallcop-app/mallcop/examples/sidecar-detector/exampledetector"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// repoRoot walks up from the test binary's working directory (the package
// dir, under `go test`) to the go.mod marker. Mirrors core/lint's coreRoot
// helper.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// goBin resolves the Go toolchain binary: $PATH first, else the well-known
// install path this repo's environment uses.
func goBin(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	const fallback = "/usr/local/go/bin/go"
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	t.Fatal("go toolchain not found on $PATH or at /usr/local/go/bin/go")
	return ""
}

// buildWasm compiles the package at repo-relative pkgPath with
// GOOS=wasip1 GOARCH=wasm and returns the module bytes. Compilation happens
// IN THE TEST, per the mallcoppro-f70 done condition: a real .wasm, built from
// real source, run through the real host.
func buildWasm(t *testing.T, pkgPath string) []byte {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "module.wasm")

	cmd := exec.Command(goBin(t), "build", "-o", out, pkgPath)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s (GOOS=wasip1 GOARCH=wasm): %v\n%s", pkgPath, err, outBytes)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read built wasm: %v", err)
	}
	return data
}

// writeWasm writes wasmBytes to dir/name and returns the full path.
func writeWasm(t *testing.T, dir, name string, wasmBytes []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, wasmBytes, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestLoadAndDetect_RealWasmMatchesInProcess is the mallcoppro-f70 done
// condition: compile the example sidecar detector to a REAL .wasm module (in
// this test, via the real Go wasip1 toolchain), run it through the REAL
// wazero-based host, and assert its findings are byte-identical to calling
// the SAME detector logic in-process (exampledetector.Detector{}.Detect
// directly, no wasm involved at all). NOT SKIPPED, NOT MOCKED: both the
// compile and the run are real.
func TestLoadAndDetect_RealWasmMatchesInProcess(t *testing.T) {
	wasmBytes := buildWasm(t, "./examples/sidecar-detector")
	dir := t.TempDir()
	path := writeWasm(t, dir, "sidecar-example.wasm", wasmBytes)

	ctx := context.Background()
	rt, err := detecthost.NewRuntime(ctx, detecthost.CacheDir(dir))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	d, err := detecthost.Load(ctx, rt, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d.Name() != "sidecar-example" {
		t.Fatalf("Name() = %q, want %q (filename stem)", d.Name(), "sidecar-example")
	}

	events := []event.Event{
		{ID: "e1", Source: "github", Type: exampledetector.EventType, Actor: "alice"},
		{ID: "e2", Source: "github", Type: "push", Actor: "bob"}, // does not match the trigger
		{ID: "e3", Source: "github", Type: exampledetector.EventType, Actor: "carol"},
	}
	bl := &baseline.Baseline{KnownActors: []string{"alice", "bob", "carol"}}

	sidecarFindings := d.Detect(events, bl)
	inProcessFindings := exampledetector.Detector{}.Detect(events, bl)

	assertFindingsEqual(t, "sidecar vs in-process", sidecarFindings, inProcessFindings)
	if len(sidecarFindings) != 2 {
		t.Fatalf("expected 2 findings (e1, e3), got %d: %+v", len(sidecarFindings), sidecarFindings)
	}
}

// assertFindingsEqual compares two Finding slices via their JSON
// representation, which normalizes field order and gives a readable diff on
// failure — the sidecar and in-process runs are the SAME Go
// encoding/json-based marshaling code, compiled twice, so the wire bytes are
// expected to match exactly.
func assertFindingsEqual(t *testing.T, label string, got, want []finding.Finding) {
	t.Helper()
	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("%s: marshal got: %v", label, err)
	}
	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatalf("%s: marshal want: %v", label, err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("%s: findings differ\n--- got ---\n%s\n--- want ---\n%s", label, gotJSON, wantJSON)
	}
}

// TestDetectKillsHungGuest proves the ZERO-CAPS / TIMEOUT safety requirement:
// a guest stuck in a pure CPU infinite loop is FORCIBLY TERMINATED when its
// deadline fires (wazero RuntimeConfig.WithCloseOnContextDone), not merely
// abandoned. It asserts real wall-clock termination — the call returns well
// before it would if the deadline were not enforced — proving this is an
// actual kill, not a cooperative/best-effort one.
func TestDetectKillsHungGuest(t *testing.T) {
	wasmBytes := buildWasm(t, "./detecthost/testdata/hang")
	dir := t.TempDir()
	path := writeWasm(t, dir, "hang.wasm", wasmBytes)

	ctx := context.Background()
	rt, err := detecthost.NewRuntime(ctx, detecthost.CacheDir(dir))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	d, err := detecthost.Load(ctx, rt, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d.Timeout = 500 * time.Millisecond

	start := time.Now()
	var panicVal any
	func() {
		defer func() { panicVal = recover() }()
		d.Detect(nil, &baseline.Baseline{})
	}()
	elapsed := time.Since(start)

	if panicVal == nil {
		t.Fatal("Detect on a hung guest must panic (the only failure channel the frozen detect.Detector interface has) — got no panic, guest was not detected as failed")
	}
	// A generous ceiling: the guest must be killed close to the configured
	// timeout, never left to run indefinitely (the pre-existing detecthost.
	// DefaultTimeout is 8s; if the kill did not work we'd block for that long
	// or forever).
	if elapsed > 3*time.Second {
		t.Fatalf("Detect on a hung guest took %s to return — the context deadline did not actually terminate execution (configured timeout was %s)", elapsed, d.Timeout)
	}
	t.Logf("hung guest terminated after %s (timeout was %s): %v", elapsed, d.Timeout, panicVal)
}

// TestDetectZeroCapabilities runs a detector fixture that PROBES its own
// sandbox from the inside (attempts a filesystem open, reads well-known env
// vars) and asserts every probe failed/came back empty — proving zero WASI
// capabilities empirically, not merely by inspecting which ModuleConfig
// methods the host calls.
func TestDetectZeroCapabilities(t *testing.T) {
	wasmBytes := buildWasm(t, "./detecthost/testdata/zerocaps")
	dir := t.TempDir()
	path := writeWasm(t, dir, "zerocaps.wasm", wasmBytes)

	// Deliberately pollute the HOST process's own environment (AFTER the
	// build above, which itself needs a real $HOME for its build cache) with
	// a variable a leaky sandbox might forward, so a positive result would be
	// a real signal, not a false negative from the var never being set
	// anywhere.
	t.Setenv("HOME", "/should/not/leak/into/the/guest")

	ctx := context.Background()
	rt, err := detecthost.NewRuntime(ctx, detecthost.CacheDir(dir))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	d, err := detecthost.Load(ctx, rt, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	findings := d.Detect(nil, &baseline.Baseline{})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 probe finding, got %d: %+v", len(findings), findings)
	}

	var probe struct {
		OpenEtcPasswdErr string `json:"open_etc_passwd_err"`
		EnvHomeSet       bool   `json:"env_home_set"`
		EnvHomeValue     string `json:"env_home_value"`
		EnvPathSet       bool   `json:"env_path_set"`
		EnvPathValue     string `json:"env_path_value"`
	}
	if err := json.Unmarshal(findings[0].Evidence, &probe); err != nil {
		t.Fatalf("decode probe evidence: %v (evidence=%s)", err, findings[0].Evidence)
	}

	if probe.OpenEtcPasswdErr == "" || probe.OpenEtcPasswdErr == "<nil>" {
		t.Errorf("guest opened /etc/passwd successfully — no filesystem preopen should exist; err=%q", probe.OpenEtcPasswdErr)
	}
	if probe.EnvHomeSet {
		t.Errorf("guest observed HOME=%q — no environment variables should be forwarded into the sandbox", probe.EnvHomeValue)
	}
	if probe.EnvPathSet {
		t.Errorf("guest observed PATH=%q — no environment variables should be forwarded into the sandbox", probe.EnvPathValue)
	}
}

// TestNewRuntimeWiresOnDiskCompilationCache proves the wazero
// CompilationCache is actually wired to disk at construction: after loading a
// module through one Runtime pointed at cacheDir, the directory is populated
// with cache artifacts, and a SECOND, independent Runtime pointed at the same
// cacheDir can load + run the identical module correctly (proving the on-disk
// cache is not just present but functionally usable across process
// lifetimes — the scenario `mallcop scan`/`detect`/`exam-detect` runs in,
// since each invocation is a fresh process).
func TestNewRuntimeWiresOnDiskCompilationCache(t *testing.T) {
	wasmBytes := buildWasm(t, "./examples/sidecar-detector")
	moduleDir := t.TempDir()
	path := writeWasm(t, moduleDir, "sidecar-example.wasm", wasmBytes)
	cacheDir := detecthost.CacheDir(moduleDir)

	ctx := context.Background()

	rt1, err := detecthost.NewRuntime(ctx, cacheDir)
	if err != nil {
		t.Fatalf("NewRuntime (1st): %v", err)
	}
	d1, err := detecthost.Load(ctx, rt1, path)
	if err != nil {
		t.Fatalf("Load (1st runtime): %v", err)
	}
	_ = d1.Detect(nil, &baseline.Baseline{})
	rt1.Close(ctx)

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("read cache dir %s: %v", cacheDir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("compilation cache dir %s is empty after compiling a module — the on-disk cache was not wired", cacheDir)
	}

	// A second, independent Runtime + Detector pair pointed at the SAME
	// cacheDir must still compile/instantiate/run the module correctly.
	rt2, err := detecthost.NewRuntime(ctx, cacheDir)
	if err != nil {
		t.Fatalf("NewRuntime (2nd, reusing cache dir): %v", err)
	}
	defer rt2.Close(ctx)
	d2, err := detecthost.Load(ctx, rt2, path)
	if err != nil {
		t.Fatalf("Load (2nd runtime, from cache): %v", err)
	}

	events := []event.Event{{ID: "e1", Source: "github", Type: exampledetector.EventType, Actor: "alice"}}
	findings := d2.Detect(events, &baseline.Baseline{})
	if len(findings) != 1 {
		t.Fatalf("2nd runtime (cache-backed) produced wrong findings: %+v", findings)
	}
}

// TestLoadRejectsMissingModule proves a bad path is a LOUD load-time error
// (never a nil Detector silently registered).
func TestLoadRejectsMissingModule(t *testing.T) {
	ctx := context.Background()
	rt, err := detecthost.NewRuntime(ctx, "")
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	if _, err := detecthost.Load(ctx, rt, filepath.Join(t.TempDir(), "does-not-exist.wasm")); err == nil {
		t.Fatal("Load of a missing module must return an error")
	}
}

// TestLoadRejectsInvalidWasm proves a corrupt/non-wasm file fails to compile
// loudly at Load time.
func TestLoadRejectsInvalidWasm(t *testing.T) {
	dir := t.TempDir()
	path := writeWasm(t, dir, "not-really-wasm.wasm", []byte("this is not a wasm module"))

	ctx := context.Background()
	rt, err := detecthost.NewRuntime(ctx, "")
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	if _, err := detecthost.Load(ctx, rt, path); err == nil {
		t.Fatal("Load of an invalid wasm module must return a compile error")
	}
}

func TestCacheDir(t *testing.T) {
	got := detecthost.CacheDir(filepath.Join("store", "detectors", "bin"))
	want := filepath.Join("store", "detectors", ".mallcop", "wasmcache")
	if got != want {
		t.Fatalf("CacheDir = %q, want %q", got, want)
	}
}
