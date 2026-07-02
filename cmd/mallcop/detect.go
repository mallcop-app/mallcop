package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// envDeclRules optionally names a declarative rules YAML (detectors/rules.yaml
// shape). The --rules flag wins over it; both absent => auto-discovery from the
// resolved repo root, mirroring the tuning/operator-decisions loaders.
const envDeclRules = "MALLCOP_DECL_RULES"

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
	baselinePath := fs.String("baseline", "", "Optional path to a baseline JSON file (no inference key required)")
	tuningPath := fs.String("tuning", "", "Optional path to a detector tuning YAML (widen-only extra_* knobs)")
	rulesPath := fs.String("rules", "", "Optional declarative detector rules YAML (overrides $"+envDeclRules+"; else auto-discovered at <repo>/detectors/rules.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := applyTuningFlag(*tuningPath); err != nil {
		return err
	}
	if err := loadDeclRulesAutodiscover(*rulesPath); err != nil {
		return err
	}

	var bl *baseline.Baseline
	if *baselinePath != "" {
		loaded, err := baseline.Load(*baselinePath)
		if err != nil {
			return fmt.Errorf("loading baseline %s: %w", *baselinePath, err)
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

// applyTuningFlag loads and applies the widen-only detector tuning named by the
// --tuning flag. FLAG-ONLY: an empty path is a no-op — there is deliberately NO
// auto-discovery of a default tuning file (auto-discovery is a deferred Baron
// decision). A load error is returned as a fatal error (exit 2 in main): a
// corrupt or typo'd tuning file must never silently degrade detection.
//
// The tuning schema is add-only by construction (core/detect/tuning.go):
// applying it can only WIDEN what the detectors see, never narrow it.
func applyTuningFlag(path string) error {
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

// resolveDeclRulesPath resolves the declarative rules file: the explicit path
// (--rules flag) wins, then $MALLCOP_DECL_RULES, then auto-discovery at
// <root>/detectors/rules.yaml when a repo root is known. An empty root with no
// explicit path/env yields "" (no rules) — auto-discovery is best-effort, never
// fatal, exactly like the tuning flag is a no-op when unset.
func resolveDeclRulesPath(explicit, root string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv(envDeclRules); env != "" {
		return env
	}
	if root == "" {
		return ""
	}
	return filepath.Join(root, "detectors", "rules.yaml")
}

// loadDeclRulesAt loads and REGISTERS the declarative detector rules at path,
// one detector per rule (Name "decl:<name>"). An empty path is a no-op. An
// absent file is a no-op (LoadRules treats os.ErrNotExist as "no rules"); a
// present-but-invalid corpus (unknown field, bad enum, unknown event type,
// uncompilable regex, framework-name collision, sha256 mismatch under
// enforcement) is FATAL — a corrupt rules file must never silently degrade
// detection. Registration is at explicit startup, never init().
func loadDeclRulesAt(path string) error {
	if path == "" {
		return nil
	}
	if _, err := detect.LoadRules(path); err != nil {
		return fmt.Errorf("loading decl rules %s: %w", path, err)
	}
	return nil
}

// loadDeclRulesAutodiscover resolves the repo root (best-effort — an
// unresolvable root just means no auto-discovered rules) and loads the rules
// file for the commands (scan, detect) that do not otherwise resolve a root.
func loadDeclRulesAutodiscover(explicit string) error {
	root, _ := eval.RepoRoot() // "" on failure => no auto-discovery
	return loadDeclRulesAt(resolveDeclRulesPath(explicit, root))
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
