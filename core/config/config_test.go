package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes content to <dir>/mallcop.yaml and returns the path.
func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// TestResolvePrecedence proves the flag > env > config > default precedence for
// a representative string key. Resolve is the primitive scan/detect will call
// per §C.1; the exhaustive per-setting wiring is a later item.
func TestResolvePrecedence(t *testing.T) {
	const (
		flagV = "flag-endpoint"
		envV  = "env-endpoint"
		cfgV  = "cfg-endpoint"
		defV  = "default-endpoint"
	)
	cases := []struct {
		name             string
		flag, env, cfg   string
		want             string
	}{
		{"flag wins over all", flagV, envV, cfgV, flagV},
		{"env wins when no flag", "", envV, cfgV, envV},
		{"config wins when no flag/env", "", "", cfgV, cfgV},
		{"default when nothing set", "", "", "", defV},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve(tc.flag, tc.env, tc.cfg, defV)
			if got != tc.want {
				t.Fatalf("Resolve(%q,%q,%q,%q)=%q, want %q", tc.flag, tc.env, tc.cfg, defV, got, tc.want)
			}
		})
	}
}

// TestResolveIntPrecedence proves the same precedence for an int setting where
// a non-positive value means "unset" (the --max-findings 0 → 25 convention).
func TestResolveIntPrecedence(t *testing.T) {
	if got := ResolveInt(10, 50, 25); got != 10 {
		t.Fatalf("flag should win: got %d want 10", got)
	}
	if got := ResolveInt(0, 50, 25); got != 50 {
		t.Fatalf("config should win when no flag: got %d want 50", got)
	}
	if got := ResolveInt(0, 0, 25); got != 25 {
		t.Fatalf("default should win: got %d want 25", got)
	}
}

// TestLoadAbsentReturnsDefaults proves an absent file resolves to the built-in
// defaults Config (today's flag-only path unaffected).
func TestLoadAbsentReturnsDefaults(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	cfg, err := Load(missing)
	if err != nil {
		t.Fatalf("absent file must not error: %v", err)
	}
	if got, want := cfg, Defaults(); got.Version != want.Version ||
		got.Inference.Mode != "offline" ||
		got.Store.Path != "./store" ||
		got.Learning.Dir != "detectors" ||
		got.Budgets.MaxFindings != 25 ||
		len(got.Connectors) != 1 {
		t.Fatalf("absent file did not return Defaults(): %+v", got)
	}

	// Empty override path is also the absent case.
	if cfg, err := Load(""); err != nil || cfg.Inference.Mode != "offline" {
		t.Fatalf("empty path should return Defaults(): cfg=%+v err=%v", cfg, err)
	}
}

// TestLoadValidFullConfig proves a full, valid config decodes and overlays onto
// the defaults, and that a partial config keeps defaults for omitted keys.
func TestLoadValidFullConfig(t *testing.T) {
	dir := t.TempDir()
	p := writeConfig(t, dir, `
version: 1
inference:
  mode: donut
  endpoint: https://api.mallcop.app
  key_env: MALLCOP_API_KEY
  model: mallcop-default
store:
  path: ./store
connectors:
  - kind: file
    id: local-events
    path: ./events.jsonl
  - kind: cloud
    id: aws-prod
    source: aws
    args: [--region, us-east-1]
    since: 24h
    env: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]
detectors:
  builtin:
    enabled: true
    disable: []
learning:
  dir: detectors
  autonomy: off
  enforce_pin: false
sovereignty:
  tier: open
  contribute_back: false
budgets:
  max_findings: 25
  scan_timeout: 10m
  selfext_spend_cap_usd: 25
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("valid config should load: %v", err)
	}
	if cfg.Inference.Mode != "donut" || cfg.Inference.Endpoint != "https://api.mallcop.app" {
		t.Fatalf("inference decode wrong: %+v", cfg.Inference)
	}
	if len(cfg.Connectors) != 2 || cfg.Connectors[1].Kind != "cloud" || cfg.Connectors[1].Source != "aws" {
		t.Fatalf("connectors decode wrong: %+v", cfg.Connectors)
	}
	if len(cfg.Connectors[1].Args) != 2 || cfg.Connectors[1].Env[0] != "AWS_ACCESS_KEY_ID" {
		t.Fatalf("cloud connector args/env decode wrong: %+v", cfg.Connectors[1])
	}

	// Partial config keeps defaults for omitted sections.
	pp := writeConfig(t, t.TempDir(), "inference:\n  endpoint: https://example.test\n")
	partial, err := Load(pp)
	if err != nil {
		t.Fatalf("partial config should load: %v", err)
	}
	if partial.Inference.Endpoint != "https://example.test" {
		t.Fatalf("partial override lost: %+v", partial.Inference)
	}
	if partial.Store.Path != "./store" || partial.Learning.Dir != "detectors" || partial.Budgets.MaxFindings != 25 {
		t.Fatalf("partial config did not keep defaults: %+v", partial)
	}
}

// TestLoadRejectsUnknownKey proves the strict KnownFields(true) decode makes an
// unknown key a loud load error, never a silent default.
func TestLoadRejectsUnknownKey(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "version: 1\ninference:\n  mode: offline\n  bogus_field: value\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("unknown key must be a loud error")
	}
	if !strings.Contains(err.Error(), "bogus_field") {
		t.Fatalf("error should name the offending key: %v", err)
	}
}

// TestLoadRejectsInlineSecretKeyEnv proves an inline secret in key_env is a loud
// load error — key_env is an env-var NAME, never a literal key.
func TestLoadRejectsInlineSecretKeyEnv(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "inference:\n  mode: donut\n  key_env: mallcop-sk-abc123DEADBEEF\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("inline secret in key_env must be a loud error")
	}
	if !strings.Contains(err.Error(), "key_env") {
		t.Fatalf("error should name key_env: %v", err)
	}
}

// TestLoadRejectsInlineSecretConnectorEnv proves an inline secret in a
// connector's env list is rejected too (env lists NAMES, not values).
func TestLoadRejectsInlineSecretConnectorEnv(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "connectors:\n  - kind: cloud\n    id: aws-prod\n    source: aws\n    env: [sk-live-abc123]\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("inline secret in connector env must be a loud error")
	}
	if !strings.Contains(err.Error(), "aws-prod") {
		t.Fatalf("error should name the connector: %v", err)
	}
}

// TestDiscoverWalkUp proves discovery finds a mallcop.yaml in a PARENT dir when
// invoked from a nested cwd, and honors the explicit override + $MALLCOP_CONFIG.
func TestDiscoverWalkUp(t *testing.T) {
	root := t.TempDir()
	parent := writeConfig(t, root, "version: 1\n")
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	t.Chdir(nested)

	got, err := Discover("")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// Resolve symlinks (macOS /tmp) so the comparison is stable.
	gotR, _ := filepath.EvalSymlinks(got)
	wantR, _ := filepath.EvalSymlinks(parent)
	if gotR != wantR {
		t.Fatalf("walk-up found %q, want parent config %q", gotR, wantR)
	}

	// Explicit override beats discovery.
	if got, _ := Discover("/explicit/path.yaml"); got != "/explicit/path.yaml" {
		t.Fatalf("override ignored: %q", got)
	}

	// $MALLCOP_CONFIG beats the walk-up.
	t.Setenv(EnvConfigPath, "/env/path.yaml")
	if got, _ := Discover(""); got != "/env/path.yaml" {
		t.Fatalf("$%s ignored: %q", EnvConfigPath, got)
	}
}

// TestDiscoverAbsent proves discovery returns "" (the absent case) when no
// mallcop.yaml exists anywhere on the walk-up.
func TestDiscoverAbsent(t *testing.T) {
	// A temp dir with no config anywhere below it. The walk-up may still find a
	// mallcop.yaml in a real ancestor of the process, so only assert LoadEffective
	// falls back to Defaults() when Discover yields "".
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv(EnvConfigPath, "")
	// If an ancestor of the temp dir happens to carry a mallcop.yaml, skip — the
	// filesystem, not the code, would decide the result.
	if p, _ := Discover(""); p != "" {
		t.Skipf("an ancestor of %s carries a %s; walk-up correctly found it at %s", dir, ConfigFileName, p)
	}
	cfg, path, err := LoadEffective("")
	if err != nil {
		t.Fatalf("LoadEffective absent: %v", err)
	}
	if path != "" {
		t.Fatalf("expected empty path for absent config, got %q", path)
	}
	if cfg.Inference.Mode != "offline" {
		t.Fatalf("absent config should be Defaults(): %+v", cfg)
	}
}

// TestLoadEffectiveDiscoversAndLoads proves the convenience entry discovers a
// parent config and loads it with strict decode.
func TestLoadEffectiveDiscoversAndLoads(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, "inference:\n  mode: donut\n  endpoint: https://api.mallcop.app\n")
	nested := filepath.Join(root, "sub")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(nested)
	t.Setenv(EnvConfigPath, "")

	cfg, path, err := LoadEffective("")
	if err != nil {
		t.Fatalf("LoadEffective: %v", err)
	}
	if path == "" {
		t.Fatalf("expected a discovered path")
	}
	if cfg.Inference.Mode != "donut" || cfg.Inference.Endpoint != "https://api.mallcop.app" {
		t.Fatalf("effective config wrong: %+v", cfg.Inference)
	}
}
