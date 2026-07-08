package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
)

// customer0LegacyConfig is the EXACT pre-v0.10 (v0.9.3) mallcop.yaml shape the
// customer0 deploy fixture (~/projects/mallcop-deploy) carries — the config the
// strict v0.10 loader rejects with "field secrets not found" /
// "connectors: cannot unmarshal map into []Connector" / "field routing not
// found". This is the ground-truth input `mallcop migrate` must fix.
const customer0LegacyConfig = `secrets:
  backend: env
connectors:
  github:
    org: 3dl-dev
    installation_id: 116376961
routing: {}
actor_chain: {}
budget:
  max_findings_for_actors: 25
  max_tokens_per_run: 50000
  max_tokens_per_finding: 5000
pro:
  account_url: https://api.mallcop.app/api/account
  inference_url: https://api.mallcop.app
`

// TestLegacyConfigIsRejectedByStrictLoader documents the actual breakage this
// item exists to fix: the old shape does NOT load under the current schema.
// If this ever stops failing, the migration is moot and this test should be
// revisited.
func TestLegacyConfigIsRejectedByStrictLoader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.ConfigFileName)
	if err := os.WriteFile(path, []byte(customer0LegacyConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected the legacy config to be REJECTED by the strict loader, but Load succeeded")
	}
}

// TestMigrateLegacyConfigProducesValidSchema is the core proof: the customer0
// legacy config migrates to a Config the strict loader accepts, carrying the
// github org, the donut rail, and the findings budget forward.
func TestMigrateLegacyConfigProducesValidSchema(t *testing.T) {
	cfg, warnings, err := migrateLegacyConfig([]byte(customer0LegacyConfig))
	if err != nil {
		t.Fatalf("migrateLegacyConfig: %v", err)
	}

	// The migrated struct must round-trip through the STRICT loader.
	if err := roundTripValidate(cfg); err != nil {
		t.Fatalf("migrated config failed strict round-trip: %v", err)
	}

	// Donut rail carried over from the old pro block.
	if cfg.Inference.Mode != "donut" {
		t.Errorf("inference.mode = %q, want donut", cfg.Inference.Mode)
	}
	if cfg.Inference.Endpoint != "https://api.mallcop.app" {
		t.Errorf("inference.endpoint = %q, want https://api.mallcop.app", cfg.Inference.Endpoint)
	}
	if cfg.Inference.KeyEnv != "MALLCOP_API_KEY" {
		t.Errorf("inference.key_env = %q, want MALLCOP_API_KEY", cfg.Inference.KeyEnv)
	}

	// github connector: map -> single list entry, installation_id dropped.
	if len(cfg.Connectors) != 1 {
		t.Fatalf("connectors = %+v, want exactly 1", cfg.Connectors)
	}
	c := cfg.Connectors[0]
	if c.Kind != "github" || c.ID != "github" || c.Org != "3dl-dev" {
		t.Errorf("connector = %+v, want kind=github id=github org=3dl-dev", c)
	}

	// findings budget carried over.
	if cfg.Budgets.MaxFindings != 25 {
		t.Errorf("budgets.max_findings = %d, want 25", cfg.Budgets.MaxFindings)
	}

	// every block that actually DROPPED data must be reported loudly. The
	// customer0 fixture's routing:{}/actor_chain:{} are empty, so they carry
	// nothing and correctly produce no warning.
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"secrets", "installation_id", "account_url", "max_tokens"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected a warning mentioning %q, got:\n%s", want, joined)
		}
	}
}

// TestMigrateNoProBlockKeepsOffline proves a legacy config with no pro block
// migrates to the offline fail-safe rail (not accidentally donut).
func TestMigrateNoProBlockKeepsOffline(t *testing.T) {
	legacy := `secrets:
  backend: env
connectors:
  github:
    org: acme
budget:
  max_findings_for_actors: 10
`
	cfg, _, err := migrateLegacyConfig([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Inference.Mode != "offline" {
		t.Errorf("inference.mode = %q, want offline (no pro block)", cfg.Inference.Mode)
	}
	if err := roundTripValidate(cfg); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
}

// TestRunMigrateInPlace exercises the whole command against a fixture deploy
// repo laid out exactly like customer0: legacy mallcop.yaml, a stale scan.yml,
// NO mallcop-investigate.yml, and a go.mod pinned to the old release. After
// migrate the config loads, both workflows exist pinned to the new release,
// and the go.mod pin is bumped.
func TestRunMigrateInPlace(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "mallcop.yaml"), customer0LegacyConfig)
	mustWrite(t, filepath.Join(dir, "go.mod"), "module github.com/3dl-dev/mallcop-deploy\n\ngo 1.24\n\nrequire github.com/mallcop-app/mallcop v0.9.3\n")
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "scan.yml"), "name: stale\n")

	if err := runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.10.1"}); err != nil {
		t.Fatalf("runMigrate: %v", err)
	}

	// config now loads under the strict schema.
	if _, err := config.Load(filepath.Join(dir, "mallcop.yaml")); err != nil {
		t.Fatalf("migrated mallcop.yaml still fails to Load: %v", err)
	}

	// both workflows exist, pinned to the new version.
	scan := mustRead(t, filepath.Join(dir, ".github", "workflows", "scan.yml"))
	if strings.Contains(scan, "name: stale") {
		t.Error("scan.yml was not refreshed (still the stale content)")
	}
	if !strings.Contains(scan, "v0.10.1") {
		t.Error("scan.yml is not pinned to v0.10.1")
	}
	inv := mustRead(t, filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml"))
	if !strings.Contains(inv, "v0.10.1") {
		t.Error("mallcop-investigate.yml missing or not pinned to v0.10.1")
	}

	// go.mod pin bumped.
	gomod := mustRead(t, filepath.Join(dir, "go.mod"))
	if !strings.Contains(gomod, "require github.com/mallcop-app/mallcop v0.10.1") {
		t.Errorf("go.mod pin not bumped:\n%s", gomod)
	}
	if !strings.Contains(gomod, "module github.com/3dl-dev/mallcop-deploy") {
		t.Error("go.mod module line was clobbered")
	}
}

// TestRunMigrateIsIdempotent proves a second migrate on an already-migrated
// repo is a no-op that does not corrupt the config.
func TestRunMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "mallcop.yaml"), customer0LegacyConfig)
	mustWrite(t, filepath.Join(dir, "go.mod"), "module x\n\ngo 1.24\n\nrequire github.com/mallcop-app/mallcop v0.9.3\n")

	if err := runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.10.1"}); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	first := mustRead(t, filepath.Join(dir, "mallcop.yaml"))
	if err := runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.10.1"}); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	second := mustRead(t, filepath.Join(dir, "mallcop.yaml"))
	if first != second {
		t.Errorf("migrate is not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
