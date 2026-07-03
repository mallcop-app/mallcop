package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
)

// TestInitGeneratesRunnableConfig proves `mallcop init` in a fresh dir writes a
// mallcop.yaml that config.Load accepts, plus store/ and events.jsonl — the
// zero-flag scan seed (design §B). Default inference is the offline fail-safe.
func TestInitGeneratesRunnableConfig(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{"--dir", dir}); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	cfgPath := filepath.Join(dir, config.ConfigFileName)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("generated config failed to Load: %v", err)
	}
	if cfg.Inference.Mode != "offline" {
		t.Fatalf("default inference mode = %q, want offline", cfg.Inference.Mode)
	}
	if len(cfg.Connectors) != 1 || cfg.Connectors[0].Kind != "file" || cfg.Connectors[0].Path != "./events.jsonl" {
		t.Fatalf("default connector wrong: %+v", cfg.Connectors)
	}
	if cfg.Learning.Dir != "detectors" || cfg.Learning.Autonomy != "off" {
		t.Fatalf("learning defaults wrong: %+v", cfg.Learning)
	}
	if cfg.Budgets.SelfextSpendCapUSD != 25 {
		t.Fatalf("spend cap = %v, want 25", cfg.Budgets.SelfextSpendCapUSD)
	}

	for _, p := range []string{"store", "events.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}
}

// TestInitPro proves `mallcop init --pro` flips ONLY the inference block to the
// donut rail; every other default is unchanged.
func TestInitPro(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{"--dir", dir, "--pro"}); err != nil {
		t.Fatalf("runInit --pro: %v", err)
	}
	cfg, err := config.Load(filepath.Join(dir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Inference.Mode != "donut" {
		t.Fatalf("--pro inference mode = %q, want donut", cfg.Inference.Mode)
	}
	if cfg.Inference.Endpoint != "https://api.mallcop.app" {
		t.Fatalf("--pro endpoint = %q, want https://api.mallcop.app", cfg.Inference.Endpoint)
	}
	if cfg.Inference.KeyEnv != "MALLCOP_API_KEY" {
		t.Fatalf("--pro key_env = %q, want MALLCOP_API_KEY", cfg.Inference.KeyEnv)
	}
	// Non-inference blocks stay at OSS defaults.
	if cfg.Learning.Autonomy != "off" || cfg.Sovereignty.Tier != "open" {
		t.Fatalf("--pro changed a non-inference block: learning=%+v sovereignty=%+v", cfg.Learning, cfg.Sovereignty)
	}
}

// TestInitIdempotent proves a re-run skips every existing file and never
// clobbers user edits to the generated config.
func TestInitIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{"--dir", dir}); err != nil {
		t.Fatalf("first runInit: %v", err)
	}

	// User edits the config after init.
	cfgPath := filepath.Join(dir, config.ConfigFileName)
	edited := "version: 1\ninference:\n  mode: byoi\n"
	if err := os.WriteFile(cfgPath, []byte(edited), 0o644); err != nil {
		t.Fatalf("edit config: %v", err)
	}
	// And edits the sample events.
	eventsPath := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(eventsPath, []byte("custom\n"), 0o644); err != nil {
		t.Fatalf("edit events: %v", err)
	}

	if err := runInit([]string{"--dir", dir}); err != nil {
		t.Fatalf("second runInit: %v", err)
	}

	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(got) != edited {
		t.Fatalf("re-run clobbered edited config:\n%s", got)
	}
	gotEvents, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if string(gotEvents) != "custom\n" {
		t.Fatalf("re-run clobbered edited events: %q", gotEvents)
	}
}
