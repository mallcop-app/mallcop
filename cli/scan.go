package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	connexec "github.com/mallcop-app/mallcop/connect/exec"
	"github.com/mallcop-app/mallcop/connect/github"
	"github.com/mallcop-app/mallcop/connect/overlay"
	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/toolrun"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/notify"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

const (
	// envInferenceURL / envInferenceKey are the {BaseURL, Key} pivot: point the URL
	// at the vendor for BYOK or at Forge for the metered managed path; the key is
	// the vendor key (BYOK) or a mallcop-sk-* tenant key (Forge). Empty URL means
	// "no inference client" — the scan still runs and force-escalates everything
	// (the cascade's documented nil-client fail-safe), it just resolves nothing.
	envInferenceURL = "MALLCOP_INFERENCE_URL"
	envInferenceKey = "MALLCOP_API_KEY"
	// envInferenceModel optionally overrides the model id sent on the wire.
	envInferenceModel = "MALLCOP_MODEL"
	// envDiscordWebhook GATES the scan→Discord emit. Unset → no emit, scan
	// behaves exactly as today (no network). Set → escalated findings are posted
	// to the Discord incoming webhook. No bot token is involved.
	envDiscordWebhook = "DISCORD_WEBHOOK_URL"
	// envLearnedMappings optionally names a learned-mappings YAML (the overlay
	// data). The --learned-mappings flag wins over it; both absent => no overlay
	// (classification is byte-identical to the pre-overlay behavior).
	envLearnedMappings = "MALLCOP_LEARNED_MAPPINGS"
)

// ScanSummary holds the results of a completed scan cycle.
type ScanSummary struct {
	EventsScanned    int `json:"events_scanned"`
	FindingsDetected int `json:"findings_detected"`
	Escalated        int `json:"escalated"`
	Resolved         int `json:"resolved"`
}

// scanOutput collects structured Findings and Resolutions parsed from a JSONL
// stream. Each line may be a Finding or a Resolution. The live scan path is now
// the in-process pipeline (runScan → core/pipeline), which writes findings +
// resolutions straight to the git store; these JSONL/output-dir parsing helpers
// remain as utilities for reading a store-written stream back (and are covered by
// main_test.go).
type scanOutput struct {
	findings    []finding.Finding
	resolutions []resolution.Resolution
}

// runScan implements `mallcop scan`: the full in-process agentic scan pipeline,
// connect → detect → cascade → store, assembled from the core packages.
//
// It reads events from the --events source (a file path, or "-"/stdin), runs the
// deterministic detector floor, resolves EACH finding through the tiered
// triage→investigate→escalate cascade against the inference endpoint named by
// MALLCOP_INFERENCE_URL (+ MALLCOP_API_KEY — the BYOK ⇄ Forge pivot), and durably
// appends the findings + resolutions to the git store at --store. It prints a
// summary and returns the findings sentinel (exit 1) when any finding was flagged.
//
// Exit codes (mapped in main.go):
//
//	0  No findings
//	1  Findings present (errFindings sentinel)
//	2  Scan failure (any other error)
func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	eventsPath := fs.String("events", "-", `Events JSONL source (file path, or "-" for stdin)`)
	storePath := fs.String("store", "", "Path to the git-repo store for findings/resolutions (created if missing)")
	baselinePath := fs.String("baseline", "", "Optional path to a baseline JSON file")
	baseURL := fs.String("base-url", "", "Inference endpoint base URL (overrides $"+envInferenceURL+")")
	workers := fs.Int("workers", 0, "Bounded resolve-pool size (0 = pipeline default)")
	asJSON := fs.Bool("json", false, "Output the summary as JSON")
	connector := fs.String("connector", "file", `Connector: "file" (default, reads --events) or "github"`)
	githubOrg := fs.String("github-org", "", "GitHub org to scan (required when --connector github)")
	learnedMappings := fs.String("learned-mappings", "", "Optional learned-mappings YAML overlay (overrides $"+envLearnedMappings+")")
	tuningPath := fs.String("tuning", "", "Optional path to a detector tuning YAML (widen-only extra_* knobs)")
	maxFindings := fs.Int("max-findings", 0, "Volume circuit-breaker ceiling: a scan producing MORE findings than this force-escalates a critical meta-finding to a human (0 = default 25)")
	configPath := fs.String("config", "", "Path to mallcop.yaml (overrides discovery/$"+config.EnvConfigPath+"); absent config => today's flag-only behavior")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Record which flags were EXPLICITLY set so config-vs-legacy precedence can
	// tell an explicit `--connector file` from the flag's default value.
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	// (cfg) Load the effective config. An ABSENT config (no --config, no
	// $MALLCOP_CONFIG, no discovered mallcop.yaml) resolves cfgPath == "" and
	// haveConfig == false — in which case EVERY resolution below falls back to
	// today's EXACT flag/env behavior, so existing scripts and e2e are unaffected.
	// A present config supplies defaults with the design §C.1 precedence
	// flag > env > config > built-in default.
	cfg, cfgPath, err := config.LoadEffective(*configPath)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	haveConfig := cfgPath != ""

	// (-1) Wire any configured WASM detector sidecars BEFORE anything runs
	// detect.Detect: detectors.sidecars.dir (default ./detectors/bin) is
	// globbed for *.wasm modules, each wrapped via detecthost and registered
	// through detect.Register, so a sidecar's findings appear identically to
	// a built-in detector for the rest of this scan. An absent dir is the
	// OOTB default (zero sidecars, no error); a present-but-broken sidecar is
	// a loud failure.
	if err := loadSidecarDetectors(cfg, cfgPath); err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// Store path: flag --store wins, else config store.path. When config is
	// absent, --store stays REQUIRED exactly as before.
	resolvedStore := *storePath
	if resolvedStore == "" && haveConfig {
		resolvedStore = cfg.Store.Path
	}
	if resolvedStore == "" {
		return fmt.Errorf("scan: --store is required (the git-repo path where findings/resolutions are written)")
	}

	// learnDir is the store-repo-relative loop-owned overlay dir (learning.dir,
	// default detectors/). It supplies the default tuning/rules/learned-mappings
	// paths when config is present, replacing the flag-only / repo-root
	// auto-discovery of those files. Empty when config is absent (legacy path).
	learnDir := ""
	if haveConfig {
		ld := cfg.Learning.Dir
		if ld == "" {
			ld = "detectors"
		}
		learnDir = filepath.Join(resolvedStore, ld)
	}

	// (0) Apply the optional widen-only detector tuning BEFORE any detection
	// runs. Fatal on error (exit 2). Precedence: flag > learning.dir/tuning.yaml
	// (config present) > today's default (none).
	tuning := *tuningPath
	if tuning == "" && learnDir != "" {
		tuning = filepath.Join(learnDir, "tuning.yaml") // LoadTuningFile tolerates absent
	}
	if err := applyTuningFlag(tuning); err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// (1) Resolve the inference client: the {BaseURL, Key} pivot. Precedence
	// flag > env > config > default. An empty URL yields a nil client — the scan
	// still runs and force-escalates everything (cascade fail-safe). offline mode
	// carries an empty endpoint, so a donut/byoi config supplies one while an
	// offline config leaves the client nil.
	url := config.Resolve(*baseURL, os.Getenv(envInferenceURL), cfgStr(haveConfig, cfg.Inference.Endpoint))
	var client agent.Client
	if url != "" {
		// Key: env $MALLCOP_API_KEY wins; else the env var NAMED by
		// inference.key_env (config). model: env $MALLCOP_MODEL > config > default.
		key := os.Getenv(envInferenceKey)
		if key == "" && haveConfig && cfg.Inference.KeyEnv != "" {
			key = os.Getenv(cfg.Inference.KeyEnv)
		}
		model := config.Resolve(os.Getenv(envInferenceModel), cfgStr(haveConfig, cfg.Inference.Model), "mallcop-default")
		client = &inference.DirectClient{
			BaseURL: url,
			Key:     key,
			Model:   model,
		}
	}

	// (2) Open (initializing if necessary) the git store.
	st, err := openOrInitStore(resolvedStore)
	if err != nil {
		return err
	}

	// (3) Load the optional baseline: flag --baseline wins, else config store.baseline.
	resolvedBaseline := *baselinePath
	if resolvedBaseline == "" && haveConfig {
		resolvedBaseline = cfg.Store.Baseline
	}
	var bl *baseline.Baseline
	if resolvedBaseline != "" {
		bl, err = baseline.Load(resolvedBaseline)
		if err != nil {
			return fmt.Errorf("scan: load baseline %s: %w", resolvedBaseline, err)
		}
	}

	// (3.4) Resolve the optional learned-mapping overlay: the --learned-mappings
	// flag wins, then $MALLCOP_LEARNED_MAPPINGS, then (config present)
	// learning.dir/learned_mappings.yaml IF it exists — LoadLearnedMappings is
	// fail-loud on a NAMED-but-missing file, so the config-derived default is only
	// used when present. Both/all absent => nil (no overlay). A named-but-invalid
	// file is fatal (exit 2); every mapped target is validated inside
	// LoadLearnedMappings against detect.KnownEventTypes().
	ovPath := *learnedMappings
	if ovPath == "" {
		ovPath = os.Getenv(envLearnedMappings)
	}
	if ovPath == "" && learnDir != "" {
		if p := filepath.Join(learnDir, "learned_mappings.yaml"); fileExists(p) {
			ovPath = p
		}
	}
	ov, err := overlay.LoadLearnedMappings(ovPath)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// (3.5) Build the connector(s). When config declares connectors and no legacy
	// connector-selection flag is present, fan every configured source in via
	// buildConnectors → connect.Multi (file+github+cloud in ONE pass). The
	// legacy single-connector flags (--connector/--github-org) still select a
	// single connector — as an OVERRIDE when set, and as the ONLY path when
	// config is absent, preserving today's exact behavior.
	legacyConnFlag := setFlags["connector"] || setFlags["github-org"]
	var conn connect.Connector
	if haveConfig && len(cfg.Connectors) > 0 && !legacyConnFlag {
		conn, err = buildConnectors(cfg, resolvedStore, ov)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
	} else {
		switch *connector {
		case "file":
			conn = connect.FromPath(*eventsPath)
		case "github":
			if *githubOrg == "" {
				return fmt.Errorf("scan: --github-org is required with --connector github")
			}
			gc, gerr := github.NewFromEnv(*githubOrg)
			if gerr != nil {
				return fmt.Errorf("scan: github connector: %w", gerr)
			}
			gc.SetOverlay(ov)
			conn = gc
		default:
			return fmt.Errorf("scan: unknown --connector %q", *connector)
		}
	}

	// (3.9) Volume circuit-breaker ceiling: flag --max-findings wins, else config
	// budgets.max_findings; 0 lets the pipeline apply its default (25).
	resolvedMax := *maxFindings
	if resolvedMax == 0 && haveConfig {
		resolvedMax = cfg.Budgets.MaxFindings
	}

	// (4) Run the pipeline.
	ctx := context.Background()
	sum, err := pipeline.Run(ctx, pipeline.Config{
		Connector: conn,
		Client:    client,
		Store:     st,
		Baseline:  bl,
		Workers:   *workers,
		// Volume circuit-breaker ceiling. 0 lets the pipeline apply its default
		// (25, from src/mallcop/budget.py); a positive value overrides it.
		Budget: agent.BudgetConfig{MaxFindingsForActors: resolvedMax},
		// Consensus ON by default (safety-first): on every RESOLVE, the gate
		// re-runs the cascade DefaultConsensusRuns more times and any-escalate-wins.
		// Validated to cut missed attacks 9→2 on the eval corpus under the
		// asymmetric error policy (false-negatives catastrophic).
		//
		// Tools: the PRODUCTION ToolRunner (core/toolrun). It gives the live cascade
		// the SAME tool surface the eval scenarioToolRunner gives the bakeoff —
		// search-events (folding operator rules §3.8), check-baseline, search-findings
		// over the live store + baseline — and computes the observable force-escalate
		// predicates via the SHARED core/observe package, so the validated 83.9% /
		// 2-missed-attacks transfers (proven byte-identical in core/eval/parity_test.go).
		// RepoRoot="" lets SearchEventsWrapped resolve the operator-decisions corpus via
		// the production os.Executable binary-walk. Nil-safe: omitting Tools runs
		// tools-off (finding-context-only with fail-safe escalation).
		Cascade: agent.CascadeOptions{
			ConsensusRuns: agent.DefaultConsensusRuns,
			Tools:         &toolrun.Runner{Store: st, Baseline: bl, RepoRoot: ""},
		},
	})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// (4.5) GATED Discord emit: when DISCORD_WEBHOOK_URL is set, post the
	// ESCALATED findings to Discord. With the var unset this whole block is
	// skipped and scan behaves exactly as before — no network, no token. We read
	// the resolutions this scan just wrote back from the store and emit the
	// escalated ones through the shared pkg/notify send path.
	if webhook := os.Getenv(envDiscordWebhook); webhook != "" {
		escalated, derr := loadEscalatedResolutions(st, sum.FindingsDetected)
		if derr != nil {
			return fmt.Errorf("scan: read resolutions for Discord emit: %w", derr)
		}
		if err := notify.EmitEscalations(ctx, webhook, escalated); err != nil {
			// A notification failure must not fail the scan (the findings are
			// already durably stored); surface it on stderr and continue.
			fmt.Fprintf(os.Stderr, "scan: discord emit: %v\n", err)
		}
	}

	out := ScanSummary{
		EventsScanned:    sum.EventsScanned,
		FindingsDetected: sum.FindingsDetected,
		Escalated:        sum.Escalated,
		Resolved:         sum.Resolved,
	}
	if *asJSON {
		if err := printJSON(out); err != nil {
			return fmt.Errorf("scan: encode summary: %w", err)
		}
	} else {
		printSummary(out)
	}

	// Exit 1 when anything was flagged; the sentinel is mapped to exit 1 in main.
	if sum.FindingsDetected > 0 {
		return errFindings
	}
	return nil
}

// buildConnectors is the config → connector composition root (design §C.4). It
// turns each cfg.Connectors entry into a live connect.Connector and wraps them
// in a MultiConnector so `mallcop scan` pulls EVERY configured source in one
// pass. Kind dispatch mirrors the legacy single-connector switch:
//
//   - file:   connect.FromPath(path) — the credential-free default.
//   - github: github.NewFromEnv(org) + the learned-mapping overlay (github-first).
//   - cloud:  connexec.New — forks the sibling binary mallcop-connector-<source>
//     at the process boundary, persisting an incremental cursor under
//     <store>/.mallcop/cursors/<id> and honoring budgets.scan_timeout.
//
// Any unknown kind, or a github/cloud construction failure, is a LOUD error
// (never a silently dropped source): the scan halts, never under-reports.
func buildConnectors(cfg config.Config, storePath string, ov *overlay.Overlay) (connect.Connector, error) {
	timeout := scanTimeout(cfg)
	var subs []connect.Connector
	for _, c := range cfg.Connectors {
		switch c.Kind {
		case "file":
			subs = append(subs, connect.FromPath(c.Path))
		case "github":
			gc, err := github.NewFromEnv(c.Org)
			if err != nil {
				return nil, fmt.Errorf("connector %q (github): %w", c.ID, err)
			}
			gc.SetOverlay(ov)
			subs = append(subs, gc)
		case "cloud":
			subs = append(subs, connexec.New(connexec.Spec{
				ID:         c.ID,
				Binary:     c.Binary,
				Source:     c.Source,
				Args:       c.Args,
				Since:      c.Since,
				CursorFile: cursorPath(storePath, c.ID),
				Env:        c.Env,
				Timeout:    timeout,
			}))
		default:
			return nil, fmt.Errorf("unknown connector kind %q (connector %q)", c.Kind, c.ID)
		}
	}
	return connect.Multi(subs...), nil
}

// scanTimeout parses budgets.scan_timeout into a duration bounding each cloud
// sibling process. An empty/unparseable value yields 0 (no per-connector
// deadline beyond the caller's context) — a best-effort budget, never fatal.
func scanTimeout(cfg config.Config) time.Duration {
	d, err := time.ParseDuration(cfg.Budgets.ScanTimeout)
	if err != nil {
		return 0
	}
	return d
}

// cursorPath is where a kind:cloud connector persists its incremental cursor:
// <store>/.mallcop/cursors/<id>, so the cursor travels with the git-backed store
// and the next scan pulls only new events.
func cursorPath(storePath, id string) string {
	return filepath.Join(storePath, ".mallcop", "cursors", id)
}

// cfgStr returns s only when a config was actually loaded; otherwise "". It gates
// config-supplied string values so the ABSENT-config path contributes nothing
// (Config.Defaults() is non-empty, so an absent config must not leak defaults
// into the flag>env>config>default resolution).
func cfgStr(haveConfig bool, s string) string {
	if haveConfig {
		return s
	}
	return ""
}

// fileExists reports whether path names an existing regular (non-dir) file.
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// openOrInitStore opens the git-backed store at path, running `git init` (and a
// minimal author config + an empty initial commit) first if path is not yet a
// git work tree. The store itself does NOT create repos (that is the CLI's job);
// this is where the CLI owns that lifecycle.
func openOrInitStore(path string) (*store.Store, error) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("scan: create store dir %q: %w", path, err)
	}
	if _, err := os.Stat(filepath.Join(path, ".git")); err != nil {
		for _, args := range [][]string{
			{"init", "-q"},
			{"config", "user.email", "store@mallcop.app"},
			{"config", "user.name", "mallcop-store"},
			{"commit", "--allow-empty", "-q", "-m", "mallcop scan: init store"},
		} {
			cmd := exec.Command("git", args...)
			cmd.Dir = path
			if outBytes, err := cmd.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("scan: git %v in %q: %w\n%s", args, path, err, outBytes)
			}
		}
	}
	st, err := store.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scan: open store %q: %w", path, err)
	}
	return st, nil
}

// loadEscalatedResolutions reads the resolutions stream and returns the
// escalated resolutions written by THIS scan. The pipeline appends exactly one
// resolution per kept finding (FindingsDetected of them, after suppression), in
// append order, so the LAST `thisRun` resolutions are this scan's. Of those, the
// ones with Action=="escalate" are returned for the gated Discord emit.
//
// This keeps the pipeline's return signature unchanged: the durable store is the
// one brain, and the scan reads its own just-written output back from it.
func loadEscalatedResolutions(st *store.Store, thisRun int) ([]resolution.Resolution, error) {
	if thisRun <= 0 {
		return nil, nil
	}
	raws, err := st.Load(store.KindResolutions)
	if err != nil {
		return nil, err
	}
	start := len(raws) - thisRun
	if start < 0 {
		start = 0
	}
	var out []resolution.Resolution
	for _, raw := range raws[start:] {
		var r resolution.Resolution
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode resolution: %w", err)
		}
		if r.Action == "escalate" {
			out = append(out, r)
		}
	}
	return out, nil
}

// errFindings is returned by runScan when findings are present (exit code 1).
var errFindings = &findingsError{}

type findingsError struct{}

func (e *findingsError) Error() string { return "findings detected" }

// isFindingsError reports whether err is the findings sentinel.
func isFindingsError(err error) bool {
	_, ok := err.(*findingsError)
	return ok
}

// parseScanLine attempts to decode a JSONL line as Finding or Resolution.
func parseScanLine(line string, out *scanOutput) {
	// Heuristic: lines with "finding_id" are Resolutions; lines with "severity" and "source" are Findings.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &probe); err != nil {
		return
	}
	if _, hasFindingID := probe["finding_id"]; hasFindingID {
		var res resolution.Resolution
		if err := json.Unmarshal([]byte(line), &res); err == nil {
			out.resolutions = append(out.resolutions, res)
		}
		return
	}
	if _, hasSeverity := probe["severity"]; hasSeverity {
		var f finding.Finding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			out.findings = append(out.findings, f)
		}
	}
}

// readFindingsDir reads *.json finding files from dir.
func readFindingsDir(dir string) []finding.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var findings []finding.Finding
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if !strings.HasPrefix(e.Name(), "finding-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal(data, &f); err == nil {
			findings = append(findings, f)
		}
	}
	return findings
}

// readResolutionsDir reads *.json resolution files from dir.
func readResolutionsDir(dir string) []resolution.Resolution {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var resolutions []resolution.Resolution
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if !strings.HasPrefix(e.Name(), "resolution-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var res resolution.Resolution
		if err := json.Unmarshal(data, &res); err == nil {
			resolutions = append(resolutions, res)
		}
	}
	return resolutions
}

// buildSummary computes scan statistics from collected output.
func buildSummary(out scanOutput) ScanSummary {
	s := ScanSummary{
		FindingsDetected: len(out.findings),
	}
	for _, res := range out.resolutions {
		switch res.Action {
		case "escalate":
			s.Escalated++
		default:
			s.Resolved++
		}
	}
	return s
}

// printSummary writes a human-readable summary to stdout.
func printSummary(s ScanSummary) {
	fmt.Printf("Scan complete\n")
	fmt.Printf("  Events scanned:     %d\n", s.EventsScanned)
	fmt.Printf("  Findings detected:  %d\n", s.FindingsDetected)
	fmt.Printf("  Escalated:          %d\n", s.Escalated)
	fmt.Printf("  Resolved:           %d\n", s.Resolved)
}

// printJSON writes the summary as JSON to stdout.
func printJSON(s ScanSummary) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
