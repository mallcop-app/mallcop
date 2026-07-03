package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// runDetect implements `mallcop detect`: read events JSONL on stdin, run the
// offline core/detect pipeline (all 17 detectors), and write findings JSONL to
// stdout. No inference key, network access, or Forge account is required —
// detection is fully local and deterministic.
//
// An optional --baseline flag supplies historical context for the
// baseline-dependent detectors (new-actor, priv-escalation, unusual-login,
// unusual-timing, volume-anomaly, rate-anomaly, exfil-pattern). Without it,
// detection runs against an empty baseline; the content-only detectors
// (injection-probe, secrets-exposure, git-oops, config-drift,
// dependency-tamper, malicious-skill) still fire.
//
// Exit codes mirror `scan`:
//
//	0  No findings
//	1  Findings present
//	2  Failure (e.g. unreadable baseline)
func runDetect(args []string) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	baselinePath := fs.String("baseline", "", "Optional path to a baseline JSON file (flag wins; else config store.baseline)")
	tuningPath := fs.String("tuning", "", "Optional path to a detector tuning YAML (flag wins; else config learning.dir/tuning.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := applyTuningFlag(*tuningPath); err != nil {
		return err
	}

	// Wire any configured WASM detector sidecars before detection runs (see
	// loadSidecarDetectorsFromConfig / cli/sidecars.go). `detect` has no
	// --config flag of its own, so this resolves the effective config the
	// same way applyTuningFlag/resolveBaselinePath already do (walk-up
	// discovery / $MALLCOP_CONFIG, else built-in defaults).
	if err := loadSidecarDetectorsFromConfig(""); err != nil {
		return err
	}

	blPath, err := resolveBaselinePath(*baselinePath)
	if err != nil {
		return err
	}
	var bl *baseline.Baseline
	if blPath != "" {
		loaded, err := baseline.Load(blPath)
		if err != nil {
			return fmt.Errorf("loading baseline %s: %w", blPath, err)
		}
		bl = loaded
	} else {
		bl = &baseline.Baseline{}
	}

	events, err := readEventsJSONL(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading events: %w", err)
	}

	findings := detect.Detect(events, bl)

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	for i := range findings {
		if err := enc.Encode(&findings[i]); err != nil {
			return fmt.Errorf("encoding finding: %w", err)
		}
	}

	if len(findings) > 0 {
		// Signal "findings present" without printing it as an error.
		return errFindings
	}
	return nil
}

// applyTuningFlag loads and applies the widen-only detector tuning, resolving
// the file with the §C.1 precedence: the --tuning flag wins; else, when a
// mallcop.yaml is discovered, the config's learning.dir/tuning.yaml; else a
// no-op. The DEFERRED auto-discovery decision is now resolved by explicit
// config declaration (learning.dir) rather than a repo-root guess: with NO
// config present, tuning stays flag-only exactly as before, so existing
// flag-only usage and e2e are unaffected. A config-resolved tuning file that
// does not exist is a silent no-op (LoadTuningFile treats os.ErrNotExist as
// zero tuning); an explicit --tuning that fails to load is FATAL (exit 2), and
// so is a corrupt discovered mallcop.yaml — a typo must never silently degrade
// detection.
//
// The tuning schema is add-only by construction (core/detect/tuning.go):
// applying it can only WIDEN what the detectors see, never narrow it.
func applyTuningFlag(flagPath string) error {
	path, err := resolveTuningPath(flagPath)
	if err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	t, err := detect.LoadTuningFile(path)
	if err != nil {
		return fmt.Errorf("loading tuning %s: %w", path, err)
	}
	detect.ApplyTuning(t)
	return nil
}

// resolveTuningPath applies the tuning precedence flag > config > default(none):
// the --tuning flag wins; else the config learning.dir/tuning.yaml when a
// mallcop.yaml is discovered; else "" (flag-only, no auto-discovery). A corrupt
// discovered config is a loud error.
func resolveTuningPath(flagPath string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}
	cfg, cfgPath, err := config.LoadEffective("")
	if err != nil {
		return "", fmt.Errorf("loading config: %w", err)
	}
	if cfgPath == "" {
		return "", nil
	}
	return learningFile(cfg, cfgPath, "tuning.yaml"), nil
}

// learningFile joins the config-resolved learning.dir with a well-known
// loop-owned basename (tuning.yaml / rules.yaml). A relative learning.dir is
// resolved against the directory the config was discovered in (the deployment
// root); an absolute learning.dir is used verbatim. cfgPath must be non-empty.
func learningFile(cfg config.Config, cfgPath, name string) string {
	dir := cfg.Learning.Dir
	if dir == "" {
		dir = "detectors"
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(filepath.Dir(cfgPath), dir)
	}
	return filepath.Join(dir, name)
}

// resolveBaselinePath applies the baseline precedence flag > config > default:
// the --baseline flag wins; else the config store.baseline (resolved against the
// config's directory when relative) when a mallcop.yaml is discovered; else ""
// (an empty baseline — today's flag-only behavior when no config is present). A
// corrupt discovered config is a loud error.
func resolveBaselinePath(flagPath string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}
	cfg, cfgPath, err := config.LoadEffective("")
	if err != nil {
		return "", fmt.Errorf("loading config: %w", err)
	}
	if cfgPath == "" || cfg.Store.Baseline == "" {
		return "", nil
	}
	b := cfg.Store.Baseline
	if !filepath.IsAbs(b) {
		b = filepath.Join(filepath.Dir(cfgPath), b)
	}
	return b, nil
}

// readEventsJSONL parses newline-delimited JSON events from r. Blank lines are
// skipped; malformed lines are reported on stderr and skipped so a single bad
// record does not abort the whole scan.
func readEventsJSONL(r io.Reader) ([]event.Event, error) {
	var events []event.Event
	scanner := bufio.NewScanner(r)
	// Allow long lines (large payloads) — match detector-dependency-tamper.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			fmt.Fprintf(os.Stderr, "mallcop detect: skipping malformed event: %v\n", err)
			continue
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	return events, nil
}
