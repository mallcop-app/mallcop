package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/detecthost"
)

// loadSidecarDetectorsFromConfig discovers the effective mallcop.yaml (the
// config.LoadEffective precedence: an explicit path override, else
// $MALLCOP_CONFIG, else a walk-up discovery, else config.Defaults()) and wires
// every *.wasm module found in detectors.sidecars.dir as a detect.Detector,
// exactly like loadSidecarDetectors below. Called from the commands that have
// no --config flag of their own (detect, exam-detect) with an empty override,
// mirroring resolveTuningPath/resolveBaselinePath's existing pattern of each
// concern independently resolving the effective config.
func loadSidecarDetectorsFromConfig(configPathFlag string) error {
	cfg, cfgPath, err := config.LoadEffective(configPathFlag)
	if err != nil {
		return fmt.Errorf("sidecars: loading config: %w", err)
	}
	return loadSidecarDetectors(cfg, cfgPath)
}

// loadSidecarDetectors is the sidecar discovery + registration seam shared by
// scan/detect/exam-detect command setup. It resolves detectors.sidecars.dir
// (default ./detectors/bin — see resolveSidecarsDir), globs *.wasm inside it,
// wraps each module via detecthost, and registers it through the SAME
// detect.Register a built-in detector uses — so a sidecar's findings appear in
// `mallcop scan` / `mallcop detect` output identically to a framework
// detector.
//
// An ABSENT or EMPTY sidecar dir is the OOTB default: filepath.Glob against a
// nonexistent directory returns (nil, nil) — zero sidecars, no error. A
// PRESENT dir with a module that fails to compile, or whose Name collides with
// an already-registered detector, IS a loud error: sidecar loading failures
// must halt the command, never silently drop a configured sidecar (mirroring
// connect/exec's "a configured source that cannot run halts the scan").
func loadSidecarDetectors(cfg config.Config, cfgPath string) error {
	dir := resolveSidecarsDir(cfg, cfgPath)

	paths, err := filepath.Glob(filepath.Join(dir, "*.wasm"))
	if err != nil {
		return fmt.Errorf("sidecars: glob %s: %w", dir, err)
	}
	if len(paths) == 0 {
		return nil
	}
	sort.Strings(paths) // deterministic registration order

	ctx := context.Background()
	rt, err := detecthost.NewRuntime(ctx, detecthost.CacheDir(dir))
	if err != nil {
		return fmt.Errorf("sidecars: %w", err)
	}

	for _, path := range paths {
		d, err := detecthost.Load(ctx, rt, path)
		if err != nil {
			return fmt.Errorf("sidecars: load %s: %w", path, err)
		}
		if err := registerSidecar(d); err != nil {
			return fmt.Errorf("sidecars: %w", err)
		}
	}
	return nil
}

// resolveSidecarsDir applies the same relative-path convention
// learningFile/resolveBaselinePath use: a relative detectors.sidecars.dir
// resolves against the directory the config was DISCOVERED in (the deployment
// root); an absolute one is used verbatim; with no config file discovered
// (cfgPath == "") it resolves against the current working directory, which is
// also where the config-default value (./detectors/bin) implicitly points
// with zero config present.
func resolveSidecarsDir(cfg config.Config, cfgPath string) string {
	dir := cfg.Detectors.Sidecars.Dir
	if dir == "" {
		dir = "./detectors/bin"
	}
	if cfgPath != "" && !filepath.IsAbs(dir) {
		dir = filepath.Join(filepath.Dir(cfgPath), dir)
	}
	return dir
}

// registerSidecar registers d with core/detect's package registry, converting
// a detect.Register panic (duplicate detector Name) into a returned error.
// detect.Register is designed to crash loudly at init()-time registration
// (see core/detect/detect.go) — appropriate for a build-time wiring mistake,
// but a runtime-discovered sidecar collision should surface as a clean command
// error (`mallcop <cmd>: sidecars: register sidecar detector "x": ...`, exit
// 2), not an unhandled panic and stack trace.
func registerSidecar(d *detecthost.Detector) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("register sidecar detector %q: %v", d.Name(), p)
		}
	}()
	detect.Register(d)
	return nil
}

// buildAndRegisterSourceSidecar is the AD HOC counterpart to
// loadSidecarDetectors: instead of discovering already-compiled *.wasm modules
// from a configured directory, it BUILDS one, from Go source at srcDir, right
// now. This is the seam `exam-detect --sidecar-src` (see runExamDetect) uses to
// grade a detector that never lives in this repo's own core/detect/authored/
// tree at all — a customer's own repo, or any standalone Go package directory
// implementing core/detect.Detector via
// github.com/mallcop-app/mallcop/pkg/detectorhost — against the SAME
// wasip1/wazero path a real deployment uses, never as an in-process Go import
// (the ground-truth invariant: the gate exercises the artifact that deploys).
// It compiles srcDir with `go build` under GOOS=wasip1 GOARCH=wasm (srcDir
// supplies its own module context — this repo's module, or a customer module
// with a `replace` back to a local mallcop checkout), writes the module into
// scratchDir, loads it through a FRESH detecthost.Runtime (in-memory
// compilation cache only — this is a one-shot build, not a long-lived
// deployment, so no on-disk cache directory is wired), and registers it
// exactly like a discovered sidecar.
//
// GOFLAGS=-mod=mod: a customer module's go.mod legitimately may not carry a
// complete go.sum yet (it depends on this repo's module via a local `replace`,
// which itself pulls in transitive deps like gopkg.in/yaml.v3 the customer
// never directly imports and has no reason to have already `go mod tidy`'d
// for) — -mod=mod lets `go build` compute the missing sum entries itself
// (from the local module cache when already populated, else the configured
// GOPROXY) instead of hard-failing with "missing go.sum entry". This mirrors
// what a customer running `go build` themselves would need anyway.
func buildAndRegisterSourceSidecar(ctx context.Context, srcDir, scratchDir string) error {
	info, err := os.Stat(srcDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("sidecar source %q is not a directory: %v", srcDir, err)
	}

	name := filepath.Base(strings.TrimRight(srcDir, string(filepath.Separator)))
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "sidecar-src"
	}
	out := filepath.Join(scratchDir, name+".wasm")

	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "GOFLAGS=-mod=mod")
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build (GOOS=wasip1 GOARCH=wasm) %s: %v\n%s", srcDir, err, outBytes)
	}

	rt, err := detecthost.NewRuntime(ctx, "")
	if err != nil {
		return fmt.Errorf("sidecar source %s: %w", srcDir, err)
	}
	d, err := detecthost.Load(ctx, rt, out)
	if err != nil {
		return fmt.Errorf("sidecar source %s: %w", srcDir, err)
	}
	return registerSidecar(d)
}
