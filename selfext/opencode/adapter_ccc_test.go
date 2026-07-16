package opencode

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCodeAuthoringModelIsOpaqueAlias pins the leak-prevention contract: the
// CODE-authoring model string the PUBLIC binary sends must
// be the OPAQUE lane alias "coding" — never a raw catalog id (the model the
// product exists to obscure) and never a reseller name. Forge resolves the alias
// server-side to the real coder. It must also never be a bare weak/Fable token.
func TestCodeAuthoringModelIsOpaqueAlias(t *testing.T) {
	if CodeAuthoringModel == "" {
		t.Fatal("CodeAuthoringModel must not be empty")
	}
	if CodeAuthoringModel != "coding" {
		t.Errorf("CodeAuthoringModel = %q, want the opaque alias %q (the raw model id is resolved server-side and must never ship in the public binary —)", CodeAuthoringModel, "coding")
	}
	if strings.Contains(strings.ToLower(CodeAuthoringModel), "fable") {
		t.Fatalf("CodeAuthoringModel must never be a Fable model (got %q) — Fable 5 refuses security-adjacent authoring tasks", CodeAuthoringModel)
	}
	// The alias must not leak the model or reseller the product hides.
	for _, forbidden := range []string{"deepinfra", "glm-5.2", "@"} {
		if strings.Contains(strings.ToLower(CodeAuthoringModel), forbidden) {
			t.Errorf("CodeAuthoringModel %q must not contain the raw model/reseller token %q — it must be an opaque alias", CodeAuthoringModel, forbidden)
		}
	}
}

// TestAdapterModelOverridesLaneInRequestAndProviderConfig proves the
// CODE-authoring lane resolves to the stronger coder end to end: when Model
// is set, it is what opencode is told to request (the ProviderConfig models
// map key) — NOT the bare Lane string ("heal", which round-6 evidence showed
// resolving to qwen3-32b on the self-ext build account).
func TestAdapterModelOverridesLaneInRequestAndProviderConfig(t *testing.T) {
	a := &Adapter{Lane: "heal", Model: CodeAuthoringModel, Provider: "forge"}

	if got := a.model(); got != CodeAuthoringModel {
		t.Fatalf("a.model() = %q, want %q", got, CodeAuthoringModel)
	}
	if got := a.model(); got == a.Lane {
		t.Fatalf("a.model() must resolve to Model (%q), not fall back to Lane (%q)", CodeAuthoringModel, a.Lane)
	}

	cfgStr, err := a.ProviderConfig("test-key", "https://forge.example.com")
	if err != nil {
		t.Fatalf("ProviderConfig: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgStr), &cfg); err != nil {
		t.Fatalf("unmarshal provider config: %v", err)
	}
	provider := cfg["provider"].(map[string]any)["forge"].(map[string]any)
	models := provider["models"].(map[string]any)
	if _, ok := models[CodeAuthoringModel]; !ok {
		t.Errorf("provider config models map = %v, want key %q (the stronger coder)", models, CodeAuthoringModel)
	}
	if _, ok := models["heal"]; ok {
		t.Errorf("provider config models map must NOT register the bare lane %q once Model overrides it — got %v", "heal", models)
	}
	if _, ok := models["qwen3-32b"]; ok {
		t.Error("provider config models map must never register qwen3-32b for the code-authoring lane")
	}
}

// TestAdapterModelEmptyFallsBackToLane proves the pre-behavior
// is preserved when Model is unset (e.g. the BYOI rail, which must never have
// an Anthropic catalog id forced onto a user's own arbitrary endpoint — see
// cmd/mallcop-ops's codeAuthoringModel doc).
func TestAdapterModelEmptyFallsBackToLane(t *testing.T) {
	a := &Adapter{Lane: "heal"}
	if got := a.model(); got != "heal" {
		t.Errorf("a.model() with Model unset = %q, want Lane (%q)", got, "heal")
	}
}
