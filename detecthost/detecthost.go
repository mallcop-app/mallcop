// Package detecthost is the wazero-based HOST runtime for wasip1 WASM
// detector sidecars. It lives OUTSIDE core/ on purpose, mirroring
// connect/exec: core/detect (the detection seam) is pure stdlib +
// pkg/event/pkg/finding/pkg/baseline and forbids exec/runtime dependencies via
// core/lint — this package imports github.com/tetratelabs/wazero, which the
// core purity lint would reject if it lived under core/. The seam is honored
// by the process/runtime boundary itself: detecthost wraps one compiled wasm
// module and exposes it as an ordinary core/detect.Detector; core/detect never
// links wazero, it only ever sees the Detector interface.
//
// GUEST MODEL (ruled, see mallcoppro-2fd / mallcoppro-f70): the guest is a
// wasip1 COMMAND — a Go program compiled with GOOS=wasip1 GOARCH=wasm whose
// main is `os.Exit(detectorhost.Run(myDetector{}))` (package
// github.com/mallcop-app/mallcop/pkg/detectorhost). It reads ONE JSON document
// {"events":[...], "baseline":{...}} on stdin and writes a JSON array of
// findings to stdout; a nonzero exit is a detector/harness error, surfaced
// loudly by this package (see Detector.Detect below), never silently dropped.
//
// SAFETY: every sidecar instantiation is ZERO-CAPABILITY. NewRuntime wires
// ONLY wasi_snapshot_preview1 (stdio + the base WASI surface every wasip1 Go
// binary needs to start up) — no preopened directories (no ModuleConfig.WithFS
// / WithFSConfig call anywhere in this package), no environment variables (no
// WithEnv call), and no network (wasi_snapshot_preview1 predates BSD sockets;
// there is no network syscall for a guest to reach even if it tried). The
// guest's ONLY channel to the outside world is the stdin/stdout/stderr pipes
// Detect wires per call.
//
// TIMEOUT: NewRuntime enables wazero's RuntimeConfig.WithCloseOnContextDone,
// and Detect calls context.WithTimeout per invocation — wazero checks the
// context at every function call AND every loop back-edge when this option is
// set, so a guest spinning in a pure CPU infinite loop (not just one blocked on
// I/O) is forcibly terminated when the deadline fires. See
// detecthost_test.go's TestDetectKillsHungGuest for the proof (a deliberately
// hanging module, run through the real host).
package detecthost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// DefaultTimeout bounds a single sidecar invocation's wall-clock runtime. It
// is deliberately generous relative to core/detect's own 5s
// detectorTimeout — a sidecar wrapped by detecthost is itself a
// detect.Detector, so it is ALSO subject to that outer quarantine deadline;
// this inner timeout exists so a hung guest is torn down (wazero
// module.Close) rather than merely abandoned (which is all the outer
// goroutine-based timeout can do to a misbehaving Go detector).
const DefaultTimeout = 8 * time.Second

// NewRuntime constructs the shared wazero Runtime every sidecar Detector in a
// process is instantiated from. It is zero-capability by construction (see
// the package doc) and wires an on-disk CompilationCache at cacheDir so a
// module already compiled once is loaded from cache rather than recompiled —
// this matters because mallcop scan/detect/exam-detect are one-shot CLI
// invocations that would otherwise pay full wasm compilation cost on every
// run. cacheDir is created if missing; an empty cacheDir disables the on-disk
// cache (compilation is still cached IN-MEMORY for the lifetime of the
// returned Runtime, just not persisted across process invocations).
//
// Callers own the returned Runtime's lifecycle (Close it when done); every
// Detector Loaded from it shares the same compilation cache and WASI
// instance.
func NewRuntime(ctx context.Context, cacheDir string) (wazero.Runtime, error) {
	cfg := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("detecthost: create wasm compilation cache dir %q: %w", cacheDir, err)
		}
		cache, err := wazero.NewCompilationCacheWithDir(cacheDir)
		if err != nil {
			return nil, fmt.Errorf("detecthost: open wasm compilation cache %q: %w", cacheDir, err)
		}
		cfg = cfg.WithCompilationCache(cache)
	}

	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("detecthost: instantiate WASI preview1: %w", err)
	}
	return rt, nil
}

// CacheDir returns the on-disk wazero compilation cache directory for a
// sidecar dir at sidecarsDir: sidecarsDir's PARENT joined with
// ".mallcop/wasmcache". This mirrors the existing store-adjacent-state
// convention connect/exec.defaultCursorDir uses for kind:cloud connector
// cursors (<store>/.mallcop/cursors/<id>) — reusing the ".mallcop" reserved
// subdirectory name for another piece of mallcop-owned local state — but is
// rooted at the sidecar directory's parent rather than the git-backed findings
// store, because `mallcop detect` / `mallcop exam-detect` load sidecars with
// no store path available at all (only `mallcop scan` takes --store). Under
// the config default (detectors.sidecars.dir: ./detectors/bin), the parent IS
// learning.dir's default value ("detectors"), so the cache also lands
// naturally alongside the loop-owned learning overlay for the common case
// where sidecars ship inside the same learning tree.
func CacheDir(sidecarsDir string) string {
	return filepath.Join(filepath.Dir(sidecarsDir), ".mallcop", "wasmcache")
}

// Detector wraps one compiled wasip1 WASM module as a core/detect.Detector.
// Construct one via Load. The zero value is not usable.
type Detector struct {
	// Timeout bounds a single Detect invocation's wall-clock runtime (see the
	// package doc). Load sets it to DefaultTimeout; callers/tests may override
	// it afterward (e.g. to prove termination without waiting out the full
	// default).
	Timeout time.Duration

	name     string
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
}

var _ detect.Detector = (*Detector)(nil)

// Load reads and compiles the wasm module at path against the given shared
// Runtime (see NewRuntime) and returns a Detector wrapping it. Compilation
// happens HERE, at load time — a malformed/invalid wasm module is a loud error
// before any scan runs, never a failure silently discovered mid-scan. Name()
// is the file's basename with the .wasm extension trimmed (e.g.
// "my-rule.wasm" -> "my-rule") — the simplest of the two naming schemes the
// design allows (filename stem vs. a handshake), chosen because it needs no
// extra guest protocol and keeps discovery a pure filesystem operation.
func Load(ctx context.Context, rt wazero.Runtime, path string) (*Detector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("detecthost: read %s: %w", path, err)
	}
	compiled, err := rt.CompileModule(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("detecthost: compile %s: %w", path, err)
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	d := &Detector{Timeout: DefaultTimeout, name: name, runtime: rt, compiled: compiled}
	return d, nil
}

// Name implements detect.Detector.
func (d *Detector) Name() string { return d.name }

// Detect implements detect.Detector by running the wrapped wasm module as a
// fresh, zero-capability instance: it marshals {events, bl} to the
// detectorhost.Input wire document, feeds it on the guest's stdin, waits (under
// a d.Timeout deadline enforced by wazero's WithCloseOnContextDone — see the
// package doc) for the guest to run to completion, and unmarshals its stdout as
// the findings array.
//
// core/detect.Detector has no error return, so a sidecar failure (nonzero
// exit, a killed-on-timeout guest, or malformed stdout) is reported via
// PANIC — this is the only channel available under the frozen interface, and
// it is not a silent drop: core/detect's own per-detector runDetectSafely
// recovers the panic, QUARANTINES this detector (dropping only its output),
// and logs the reason via quarantineReporter, so the failure is loud
// (stderr/log) while every other detector's findings still come back. This
// composes with the existing framework machinery unchanged — detecthost adds
// no new isolation primitive of its own.
func (d *Detector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	if bl == nil {
		bl = &baseline.Baseline{}
	}
	input := detectorhost.Input{Events: events, Baseline: bl}
	inBytes, err := json.Marshal(input)
	if err != nil {
		panic(fmt.Errorf("detecthost: detector %q: marshal input: %w", d.name, err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	modCfg := wazero.NewModuleConfig().
		// WithName("") makes each instantiation anonymous so the same
		// CompiledModule can be re-instantiated across multiple Detect calls
		// (e.g. repeated scans in one long-lived process, or these tests)
		// without a "duplicate module name" collision.
		WithName("").
		WithStdin(bytes.NewReader(inBytes)).
		WithStdout(&stdout).
		WithStderr(&stderr)
		// Deliberately no WithFS/WithFSConfig, no WithEnv, no WithArgs beyond
		// the default: zero capabilities beyond the three stdio pipes above.

	mod, runErr := d.runtime.InstantiateModule(ctx, d.compiled, modCfg)
	if mod != nil {
		defer mod.Close(context.Background())
	}
	if runErr != nil {
		if exitErr, ok := runErr.(*sys.ExitError); !ok || exitErr.ExitCode() != 0 {
			panic(fmt.Errorf("detecthost: detector %q: sidecar failed: %w (stderr: %s)",
				d.name, runErr, stderrTail(&stderr)))
		}
	}

	var findings []finding.Finding
	if err := json.Unmarshal(stdout.Bytes(), &findings); err != nil {
		panic(fmt.Errorf("detecthost: detector %q: parse findings from stdout: %w (stdout: %q, stderr: %s)",
			d.name, err, stdout.String(), stderrTail(&stderr)))
	}
	return findings
}

// stderrTail returns up to the last 2000 bytes of buf as a string, so a
// failure message never balloons on a chatty/misbehaving guest.
func stderrTail(buf *bytes.Buffer) string {
	s := buf.String()
	const max = 2000
	if len(s) > max {
		return "..." + s[len(s)-max:]
	}
	return s
}
