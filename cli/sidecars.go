package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

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
