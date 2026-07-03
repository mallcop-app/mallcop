package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
)

// gitOopsEvent is a deterministic, content-only firing event: a force-push to
// main is a known-malicious git-oops (no baseline / no inference required). It
// fires the same finding every run, so two scans over the same input write
// byte-identical findings to the store — the substrate for the byte-identical
// proof below.
const gitOopsEvent = `{"id":"g1","source":"github","type":"push","actor":"dev","payload":{"forced":true,"ref":"refs/heads/main"}}` + "\n"

// cfgFindings runs an offline scan (nil inference client → force-escalate) and
// returns the raw findings JSONL the pipeline durably wrote to the store, so two
// runs can be compared byte-for-byte.
func loadStoreFindings(t *testing.T, storePath string) [][]byte {
	t.Helper()
	st, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("open store %s: %v", storePath, err)
	}
	raws, err := st.Load(store.KindFindings)
	if err != nil {
		t.Fatalf("load findings: %v", err)
	}
	out := make([][]byte, len(raws))
	for i, r := range raws {
		out[i] = []byte(r)
	}
	return out
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestScanConfigOnly_ByteIdenticalToFlags is deliverable (1): a config-only scan
// (zero scan flags — everything comes from mallcop.yaml, discovered via --config)
// over a file connector produces the SAME findings, byte-for-byte, as the
// equivalent `--store --connector file --events` flagged run. Both run offline so
// detection is fully deterministic.
func TestScanConfigOnly_ByteIdenticalToFlags(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEvent)

	// (A) The flagged baseline run.
	flagStore := filepath.Join(dir, "store-flags")
	err := runScan([]string{"--store", flagStore, "--connector", "file", "--events", eventsPath})
	if !isFindingsError(err) {
		t.Fatalf("flagged run: want findings sentinel, got %v", err)
	}
	flagFindings := loadStoreFindings(t, flagStore)
	if len(flagFindings) == 0 {
		t.Fatalf("flagged run wrote no findings")
	}

	// (B) The config-only run: a mallcop.yaml naming the same file connector and
	// store, offline inference, discovered via --config. ZERO scan flags.
	cfgStore := filepath.Join(dir, "store-config")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeFile(t, cfgPath, `version: 1
inference:
  mode: offline
  endpoint: ""
  key_env: MALLCOP_API_KEY
  model: mallcop-default
store:
  path: `+cfgStore+`
  baseline: ""
connectors:
  - kind: file
    id: local-events
    path: `+eventsPath+`
detectors:
  builtin:
    enabled: true
    disable: []
learning:
  dir: detectors
  autonomy: non
  enforce_pin: false
sovereignty:
  tier: open
  contribute_back: false
budgets:
  max_findings: 25
  scan_timeout: 10m
  selfext_spend_cap_usd: 25
`)
	err = runScan([]string{"--config", cfgPath})
	if !isFindingsError(err) {
		t.Fatalf("config-only run: want findings sentinel, got %v", err)
	}
	cfgFindings := loadStoreFindings(t, cfgStore)

	// Byte-identical proof: same count, same bytes per finding.
	if len(cfgFindings) != len(flagFindings) {
		t.Fatalf("finding count differs: flags=%d config=%d", len(flagFindings), len(cfgFindings))
	}
	for i := range flagFindings {
		if !bytes.Equal(flagFindings[i], cfgFindings[i]) {
			t.Fatalf("finding %d differs:\n flags:  %s\n config: %s", i, flagFindings[i], cfgFindings[i])
		}
	}
}

// TestScanConfigTwoConnectors_OnePass is deliverable (2): a config with TWO
// connectors — a file source and a fake cloud sibling on PATH — pulls BOTH in a
// single scan pass. The file source contributes one git-oops event and the fake
// sibling contributes another; a whole-corpus scan therefore reports 2 events and
// yields findings from both sources.
func TestScanConfigTwoConnectors_OnePass(t *testing.T) {
	dir := t.TempDir()

	// File source: one force-push (git-oops).
	filePath := filepath.Join(dir, "file-events.jsonl")
	writeFile(t, filePath, gitOopsEvent)

	// Fake cloud sibling on PATH: mallcop-connector-fake emits one DISTINCT
	// git-oops event to stdout and a cursor line to stderr (the sibling contract).
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	sibling := filepath.Join(binDir, "mallcop-connector-fake")
	writeFile(t, sibling, `#!/bin/sh
printf '%s\n' '{"id":"c1","source":"github","type":"push","actor":"ops","payload":{"forced":true,"ref":"refs/heads/main"}}'
printf 'cursor: tok-1\n' 1>&2
`)
	if err := os.Chmod(sibling, 0o755); err != nil {
		t.Fatalf("chmod sibling: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfgStore := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeFile(t, cfgPath, `version: 1
inference:
  mode: offline
store:
  path: `+cfgStore+`
connectors:
  - kind: file
    id: local-events
    path: `+filePath+`
  - kind: cloud
    id: fake-cloud
    source: fake
detectors:
  builtin:
    enabled: true
learning:
  dir: detectors
budgets:
  max_findings: 25
  scan_timeout: 10m
`)

	err := runScan([]string{"--config", cfgPath, "--json"})
	if !isFindingsError(err) {
		t.Fatalf("two-connector run: want findings sentinel, got %v", err)
	}

	// Both sources were pulled: two events entered the corpus, and both distinct
	// git-oops findings (finding-g1 from file, finding-c1 from the sibling) landed.
	findings := loadStoreFindings(t, cfgStore)
	var haveFile, haveCloud bool
	for _, f := range findings {
		if bytes.Contains(f, []byte(`"finding-g1"`)) {
			haveFile = true
		}
		if bytes.Contains(f, []byte(`"finding-c1"`)) {
			haveCloud = true
		}
	}
	if !haveFile || !haveCloud {
		t.Fatalf("expected findings from BOTH sources in one pass (file=%v cloud=%v); findings=%d", haveFile, haveCloud, len(findings))
	}

	// The sibling's cursor was persisted under <store>/.mallcop/cursors/<id>.
	curFile := cursorPath(cfgStore, "fake-cloud")
	got, err := os.ReadFile(curFile)
	if err != nil {
		t.Fatalf("read persisted cursor %s: %v", curFile, err)
	}
	if string(bytes.TrimSpace(got)) != "tok-1" {
		t.Fatalf("cursor not persisted: want tok-1, got %q", got)
	}
}

// TestScanLegacyFlagsOverrideConfig is deliverable (3): with a config present, a
// legacy connector-selection flag still overrides it. The config names a file
// connector that would fire, but `--connector github --github-org acme` with a
// broken (invalid learned-mappings) setup exercises the LEGACY branch — proving
// the flag, not the config connectors, selected the connector.
func TestScanLegacyFlagsOverrideConfig(t *testing.T) {
	dir := t.TempDir()

	// A config whose file connector, if used, would produce a git-oops finding.
	firingEvents := filepath.Join(dir, "events.jsonl")
	writeFile(t, firingEvents, gitOopsEvent)
	cfgStore := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeFile(t, cfgPath, `version: 1
inference:
  mode: offline
store:
  path: `+cfgStore+`
connectors:
  - kind: file
    id: local-events
    path: `+firingEvents+`
learning:
  dir: detectors
`)

	// A bad --learned-mappings file rejected fail-loud BEFORE any connector runs.
	// This error can only surface on the LEGACY --connector github path (the
	// config file-connector path would instead succeed and produce findings), so
	// seeing it proves the legacy flags overrode the config connectors.
	badLM := filepath.Join(dir, "lm.yaml")
	writeFile(t, badLM, "github:\n  repo.rename: not_a_real_event_type\n")

	err := runScan([]string{
		"--config", cfgPath,
		"--connector", "github", "--github-org", "acme",
		"--learned-mappings", badLM,
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("unknown event_type")) {
		t.Fatalf("want legacy-path overlay validation error 'unknown event_type', got: %v", err)
	}
}

// TestScanAbsentConfigStoreRequired is deliverable (4) part one: with NO config
// (no --config, no discoverable mallcop.yaml), --store stays REQUIRED — today's
// exact behavior is unchanged. The scan runs from a temp cwd that has no
// mallcop.yaml on any ancestor, proving discovery finds nothing.
func TestScanAbsentConfigStoreRequired(t *testing.T) {
	t.Chdir(t.TempDir()) // an isolated cwd with no mallcop.yaml above it
	err := runScan([]string{"--connector", "file", "--events", "-"})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("--store is required")) {
		t.Fatalf("absent config: want '--store is required', got: %v", err)
	}
}
