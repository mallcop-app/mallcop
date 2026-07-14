package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- AddConnector ----

func TestAddConnector_ValidAppendsAndPreservesExisting(t *testing.T) {
	cfg := Defaults() // has the one default "local-events" file connector
	before := len(cfg.Connectors)

	next, err := AddConnector(cfg, Connector{Kind: "github", ID: "acme-gh", Org: "acme"})
	if err != nil {
		t.Fatalf("AddConnector: unexpected error: %v", err)
	}
	if len(next.Connectors) != before+1 {
		t.Fatalf("expected %d connectors, got %d", before+1, len(next.Connectors))
	}
	if next.Connectors[0].ID != cfg.Connectors[0].ID {
		t.Fatalf("existing connector was not preserved: got %+v", next.Connectors[0])
	}
	last := next.Connectors[len(next.Connectors)-1]
	if last.ID != "acme-gh" || last.Kind != "github" || last.Org != "acme" {
		t.Fatalf("new connector not appended correctly: %+v", last)
	}

	// cfg itself must be untouched (no in-place mutation / no shared backing array).
	if len(cfg.Connectors) != before {
		t.Fatalf("AddConnector mutated its input cfg in place: len=%d want %d", len(cfg.Connectors), before)
	}
}

func TestAddConnector_DuplicateIDRejected(t *testing.T) {
	cfg := Defaults()
	dupID := cfg.Connectors[0].ID
	_, err := AddConnector(cfg, Connector{Kind: "file", ID: dupID, Path: "./other.jsonl"})
	if err == nil {
		t.Fatal("expected error for duplicate connector id, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error should mention duplicate id, got: %v", err)
	}
}

func TestAddConnector_InvalidKindRejected(t *testing.T) {
	cfg := Defaults()
	_, err := AddConnector(cfg, Connector{Kind: "ftp", ID: "bad-kind"})
	if err == nil {
		t.Fatal("expected error for invalid connector kind, got nil")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Fatalf("error should mention kind, got: %v", err)
	}
}

func TestAddConnector_EmptyIDRejected(t *testing.T) {
	cfg := Defaults()
	_, err := AddConnector(cfg, Connector{Kind: "file", Path: "./x.jsonl"})
	if err == nil {
		t.Fatal("expected error for empty connector id, got nil")
	}
}

func TestAddConnector_InlineSecretInEnvRejected(t *testing.T) {
	cfg := Defaults()
	_, err := AddConnector(cfg, Connector{
		Kind: "cloud", ID: "leaky", Source: "acme",
		Env: []string{"sk-live-abc123"},
	})
	if err == nil {
		t.Fatal("expected error for inline secret in connector env, got nil")
	}
	if !strings.Contains(err.Error(), "env-var NAME") {
		t.Fatalf("error should explain the env-var-name rule, got: %v", err)
	}
}

// ---- SetAutonomy ----

func TestSetAutonomy_AllValidValues(t *testing.T) {
	for _, v := range []string{AutonomyNon, AutonomySemi, AutonomyFully} {
		cfg := Defaults()
		next, err := SetAutonomy(cfg, v)
		if err != nil {
			t.Fatalf("SetAutonomy(%q): unexpected error: %v", v, err)
		}
		if next.Learning.Autonomy != v {
			t.Fatalf("SetAutonomy(%q): got %q", v, next.Learning.Autonomy)
		}
		// input untouched
		if cfg.Learning.Autonomy != AutonomyNon {
			t.Fatalf("SetAutonomy mutated its input cfg in place: got %q", cfg.Learning.Autonomy)
		}
	}
}

func TestSetAutonomy_InvalidValueRejected(t *testing.T) {
	cfg := Defaults()
	_, err := SetAutonomy(cfg, "yolo")
	if err == nil {
		t.Fatal("expected error for invalid autonomy value, got nil")
	}
	if !strings.Contains(err.Error(), "non") || !strings.Contains(err.Error(), "yolo") {
		t.Fatalf("error should name the enum and the bad value, got: %v", err)
	}
}

func TestSetAutonomy_TypoDoesNotSilentlyFallBackToDefault(t *testing.T) {
	cfg := Defaults()
	cfg.Learning.Autonomy = AutonomyFully // start somewhere non-default
	next, err := SetAutonomy(cfg, "Semi") // wrong case — must NOT be accepted as "semi"
	if err == nil {
		t.Fatalf("expected error for case-mismatched autonomy value, got success: %+v", next)
	}
}

// ---- SetContributeBack ----

func TestSetContributeBack_TogglesAndPreservesOtherFields(t *testing.T) {
	cfg := Defaults()
	if cfg.Learning.ContributeBack != false {
		t.Fatalf("Defaults(): Learning.ContributeBack = %v, want false (zero value)", cfg.Learning.ContributeBack)
	}

	on, err := SetContributeBack(cfg, true)
	if err != nil {
		t.Fatalf("SetContributeBack(true): unexpected error: %v", err)
	}
	if !on.Learning.ContributeBack {
		t.Fatalf("SetContributeBack(true): Learning.ContributeBack = false, want true")
	}
	if on.Learning.Autonomy != cfg.Learning.Autonomy || on.Learning.Dir != cfg.Learning.Dir {
		t.Fatalf("SetContributeBack changed unrelated Learning fields: got %+v", on.Learning)
	}
	// input untouched
	if cfg.Learning.ContributeBack {
		t.Fatal("SetContributeBack mutated its input cfg in place")
	}

	off, err := SetContributeBack(on, false)
	if err != nil {
		t.Fatalf("SetContributeBack(false): unexpected error: %v", err)
	}
	if off.Learning.ContributeBack {
		t.Fatalf("SetContributeBack(false): Learning.ContributeBack = true, want false")
	}
}

// ---- Round trip: AddConnector + SetAutonomy -> WriteConfigAtomic -> Load ----

func TestMutate_RoundTripThroughWriteAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)

	cfg := Defaults()
	if err := WriteConfig(path, cfg); err != nil {
		t.Fatalf("seed WriteConfig: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load seed: %v", err)
	}

	mutated, err := AddConnector(loaded, Connector{Kind: "github", ID: "acme-gh", Org: "acme"})
	if err != nil {
		t.Fatalf("AddConnector: %v", err)
	}
	mutated, err = SetAutonomy(mutated, AutonomySemi)
	if err != nil {
		t.Fatalf("SetAutonomy: %v", err)
	}
	mutated, err = SetContributeBack(mutated, true)
	if err != nil {
		t.Fatalf("SetContributeBack: %v", err)
	}

	if err := WriteConfigAtomic(path, mutated); err != nil {
		t.Fatalf("WriteConfigAtomic: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload after mutation: %v", err)
	}
	found := false
	for _, c := range reloaded.Connectors {
		if c.ID == "acme-gh" && c.Kind == "github" && c.Org == "acme" {
			found = true
		}
	}
	if !found {
		t.Fatalf("added connector not present after reload: %+v", reloaded.Connectors)
	}
	if reloaded.Learning.Autonomy != AutonomySemi {
		t.Fatalf("autonomy not persisted: got %q", reloaded.Learning.Autonomy)
	}
	if !reloaded.Learning.ContributeBack {
		t.Fatal("contribute_back not persisted: got false")
	}

	// No leftover temp files from the atomic write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".mallcop-config-") {
			t.Fatalf("leftover temp file from WriteConfigAtomic: %s", e.Name())
		}
	}
}

func TestWriteConfigAtomic_RejectsInvalidCfgViaMarshalRoundTrip(t *testing.T) {
	// WriteConfigAtomic itself does not re-validate (mutation entry points
	// already validated via AddConnector/SetAutonomy); this test documents
	// that a directly-constructed invalid Config still marshals (Marshal has
	// no validation step) so callers MUST go through AddConnector/SetAutonomy
	// — a reviewer reading this test sees why those functions call Validate
	// before ever reaching WriteConfigAtomic.
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	bad := Defaults()
	bad.Learning.Autonomy = "not-a-real-value"

	if err := WriteConfigAtomic(path, bad); err != nil {
		t.Fatalf("WriteConfigAtomic (no validation by design): %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load should reject the invalid autonomy value written above")
	}
}

func TestValidate_ExportedWrapperMatchesLoadBehavior(t *testing.T) {
	cfg := Defaults()
	cfg.Inference.KeyEnv = "sk-inline-secret"
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate should reject an inline-secret-shaped key_env, matching Load's validate() call")
	}
}
