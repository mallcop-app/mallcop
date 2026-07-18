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
		name           string
		flag, env, cfg string
		want           string
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
  autonomy: semi
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

// TestDefaultsAutonomyIsNon proves the safe-by-default dial position is "non"
// (propose-only, human approves ALL changes) — the fail-safe an absent
// mallcop.yaml (or an absent learning: section) resolves to. rd mallcoppro-315.
// TestDefaultsModelIsRealLane locks the default inference model to a real
// tenant lane. "mallcop-default" was a placeholder that 404s on the donut rail
// (the proxy only resolves the lane names triage/investigate/heal) —
// mallcoppro-2b9.
func TestDefaultsModelIsRealLane(t *testing.T) {
	if got := Defaults().Inference.Model; got != "triage" {
		t.Fatalf("Defaults().Inference.Model = %q, want triage (a real lane)", got)
	}
}

// TestDefaultsInvestigateOnByDefault proves detection-time investigation
// (mallcoppro-e3c) is ON with the documented budget/window defaults even with
// NO config file present — the "ships in the binary, no template change"
// requirement — and that Load("") (the absent-config path) resolves to the
// identical defaults, not a zero-value struct.
func TestDefaultsInvestigateOnByDefault(t *testing.T) {
	want := Investigate{
		Enabled: true, Model: "", MaxPerScan: 10, Retries: 0,
		NeighborWindow: "1h", MaxNeighbors: 50, CorrelationWindow: "10m", MaxTokens: 1024,
	}
	if got := Defaults().Investigate; got != want {
		t.Fatalf("Defaults().Investigate = %+v, want %+v", got, want)
	}
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Investigate != want {
		t.Fatalf("Load(\"\").Investigate = %+v, want %+v", cfg.Investigate, want)
	}
}

// TestLoadInvestigateBlockOverridesOnlySetFields proves a PARTIAL
// investigate: block overlays onto Defaults() — an explicit max_per_scan
// override keeps every other Investigate default (enabled stays true, etc.),
// matching the rest of this package's partial-overlay contract.
func TestLoadInvestigateBlockOverridesOnlySetFields(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "investigate:\n  max_per_scan: 3\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Investigate.MaxPerScan != 3 {
		t.Errorf("Investigate.MaxPerScan = %d, want 3", cfg.Investigate.MaxPerScan)
	}
	if !cfg.Investigate.Enabled {
		t.Error("Investigate.Enabled should keep its default (true) when only max_per_scan is set")
	}
	if cfg.Investigate.NeighborWindow != "1h" {
		t.Errorf("Investigate.NeighborWindow = %q, want default 1h preserved", cfg.Investigate.NeighborWindow)
	}
}

// TestLoadInvestigateExplicitlyDisabled proves an explicit `enabled: false`
// overrides the ON default — the same "explicit false still wins" contract
// every other bool in this package documents.
func TestLoadInvestigateExplicitlyDisabled(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "investigate:\n  enabled: false\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Investigate.Enabled {
		t.Error("explicit investigate.enabled: false should override the ON default")
	}
}

// TestLoadRejectsUnknownInvestigateKey proves the strict decode extends to
// the investigate: block — a typo'd/unknown key is a loud load error, exactly
// like every other section (design: "strict decode only rejects PRESENT
// unknown keys").
func TestLoadRejectsUnknownInvestigateKey(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "investigate:\n  enabled: true\n  bogus_field: value\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected a load error for an unknown investigate: key")
	}
}

// TestDefaultsOrgEmpty proves org: absent-section-is-safe-default — Defaults()
// carries a nil Owned list, same pattern as every other optional block, and
// Load("") (no config file present) resolves to the identical empty Org.
func TestDefaultsOrgEmpty(t *testing.T) {
	if got := Defaults().Org; !(got.Owned == nil) {
		t.Fatalf("Defaults().Org.Owned = %+v, want nil", got.Owned)
	}
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Org.Owned != nil {
		t.Fatalf("Load(\"\").Org.Owned = %+v, want nil", cfg.Org.Owned)
	}
}

// TestLoadOrgBlockOverlay proves a partial org: yaml block round-trips
// through Load — each configured owned entity's match/name/relationship
// decode verbatim.
func TestLoadOrgBlockOverlay(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "org:\n  owned:\n    - match: \"225635015146\"\n      name: forge-proxy\n      relationship: operator's own hourly inference relay\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Org.Owned) != 1 {
		t.Fatalf("Org.Owned len = %d, want 1", len(cfg.Org.Owned))
	}
	got := cfg.Org.Owned[0]
	want := OwnedEntity{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own hourly inference relay"}
	if got != want {
		t.Fatalf("Org.Owned[0] = %+v, want %+v", got, want)
	}
}

// TestValidateRejectsEmptyOrgMatch proves an empty org.owned[].match is a
// loud load error, mirroring TestValidate's existing secret/autonomy checks —
// an empty Match would substring-match every identity field, silently
// marking every finding as owned.
func TestValidateRejectsEmptyOrgMatch(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "org:\n  owned:\n    - match: \"\"\n      name: x\n      relationship: y\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected a load error for an empty org.owned[].match")
	}
}

// TestValidateRejectsShortOrgMatch proves a too-short match string (below
// minOrgMatchLen) is a loud load error — a short generic fragment like "aws"
// would substring-match broadly across unrelated findings.
func TestValidateRejectsShortOrgMatch(t *testing.T) {
	p := writeConfig(t, t.TempDir(), "org:\n  owned:\n    - match: aws\n      name: x\n      relationship: y\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected a load error for an org.owned[].match shorter than minOrgMatchLen")
	}
}

func TestDefaultsAutonomyIsNon(t *testing.T) {
	if got := Defaults().Learning.Autonomy; got != AutonomyNon {
		t.Fatalf("Defaults().Learning.Autonomy = %q, want %q", got, AutonomyNon)
	}
	// An absent file resolves to Defaults() via Load, so the dial default is
	// exercised on the real load path too, not just the struct literal.
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Learning.Autonomy != AutonomyNon {
		t.Fatalf("Load(\"\").Learning.Autonomy = %q, want %q", cfg.Learning.Autonomy, AutonomyNon)
	}
}

// TestLoadAcceptsEachAutonomyValue proves all three dial positions decode
// cleanly (STRICT enum, not free text).
func TestLoadAcceptsEachAutonomyValue(t *testing.T) {
	for _, v := range []string{AutonomyNon, AutonomySemi, AutonomyFully} {
		v := v
		t.Run(v, func(t *testing.T) {
			p := writeConfig(t, t.TempDir(), "learning:\n  autonomy: "+v+"\n")
			cfg, err := Load(p)
			if err != nil {
				t.Fatalf("autonomy %q should load: %v", v, err)
			}
			if cfg.Learning.Autonomy != v {
				t.Fatalf("Learning.Autonomy = %q, want %q", cfg.Learning.Autonomy, v)
			}
		})
	}
}

// TestLoadRejectsInvalidAutonomy proves an unrecognized dial value (including
// the RETIRED "off"/"on" spelling) is a loud config error, never a silent
// fallback to the fail-safe default — a typo must not be mistaken for an
// explicit, reviewed choice of "non".
func TestLoadRejectsInvalidAutonomy(t *testing.T) {
	for _, v := range []string{"off", "on", "auto", "NON", ""} {
		v := v
		t.Run("bad_"+v, func(t *testing.T) {
			p := writeConfig(t, t.TempDir(), "learning:\n  autonomy: \""+v+"\"\n")
			_, err := Load(p)
			if err == nil {
				t.Fatalf("autonomy %q must be a loud load error", v)
			}
			if !strings.Contains(err.Error(), "learning.autonomy") {
				t.Fatalf("error should name learning.autonomy: %v", err)
			}
		})
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

// TestMarshalRoundTrip proves the config `mallcop init` generates is a valid
// config: Marshal(Defaults()) written to disk and re-Load'd equals Defaults()
// with no strict-decode error. This is the doc-test seed for §14 — the marketing
// mallcop.yaml is made byte-identical to init's generated default.
func TestMarshalRoundTrip(t *testing.T) {
	want := Defaults()
	data, err := Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), "# mallcop.yaml") {
		t.Fatalf("Marshal output missing header comment:\n%s", data)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("Load of marshaled default failed (should round-trip): %v", err)
	}
	// Compare the load-bearing scalars. A full reflect.DeepEqual would trip on
	// yaml.v3's nil-vs-empty-slice quirk (a nil []string marshals to `[]` and
	// decodes back to an empty non-nil slice) — a distinction with no runtime
	// meaning here. Assert the values instead.
	if got.Version != want.Version ||
		got.Inference != want.Inference ||
		got.Store != want.Store ||
		got.Learning != want.Learning ||
		got.Sovereignty != want.Sovereignty ||
		got.Budgets != want.Budgets ||
		got.Detectors.Builtin.Enabled != want.Detectors.Builtin.Enabled {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
	if len(got.Connectors) != 1 || got.Connectors[0].Kind != "file" ||
		got.Connectors[0].ID != "local-events" || got.Connectors[0].Path != "./events.jsonl" {
		t.Fatalf("round-trip connector mismatch: %+v", got.Connectors)
	}
}

// TestMarshalOmitsEmptyConnectorFields is the regression for rd mallcoppro-8f5:
// the default file connector sets only Kind/ID/Path — the github/cloud-only
// fields (Org, Source, Args, Since, Env, Binary) are all zero-valued and MUST
// NOT appear in the generated mallcop.yaml as noise (`org: ""`, `source: ""`,
// `args: []`).
func TestMarshalOmitsEmptyConnectorFields(t *testing.T) {
	data, err := Marshal(Defaults())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	// Match the connector list item's own 4-space-indented field lines
	// (`    org:`), not lookalike substrings elsewhere in the document (e.g.
	// inference's `key_env:` also contains "env:").
	for _, noise := range []string{"\n    org:", "\n    source:", "\n    args:", "\n    since:", "\n    env:", "\n    binary:"} {
		if strings.Contains(s, noise) {
			t.Fatalf("Marshal output still contains empty-field noise %q:\n%s", noise, s)
		}
	}
	if !strings.Contains(s, "path: ./events.jsonl") {
		t.Fatalf("Marshal output missing the connector's actual field (path):\n%s", s)
	}
}

// TestWriteConfigRoundTrip proves the WriteConfig helper writes a file Load
// accepts, and that a --pro-style donut inference flip survives the round-trip.
func TestWriteConfigRoundTrip(t *testing.T) {
	cfg := Defaults()
	cfg.Inference = Inference{
		Mode:     "donut",
		Endpoint: "https://api.mallcop.app",
		KeyEnv:   "MALLCOP_API_KEY",
		Model:    "mallcop-default",
	}
	dir := t.TempDir()
	p := filepath.Join(dir, ConfigFileName)
	if err := WriteConfig(p, cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Inference != cfg.Inference {
		t.Fatalf("donut inference not preserved: got=%+v want=%+v", got.Inference, cfg.Inference)
	}
}

// TestAutonomyVocabularyPinnedAcrossRepoBoundary is a CONTRACT test (rd
// mallcoppro-315): mallcop-pro cannot import this package (module boundary —
// see internal/selfext/autonomy.go's package doc in mallcop-pro), so it keeps
// its OWN pinned copy of this exact three-value set as
// internal/selfext/autonomy.Dial's three untyped-constant literals ("non",
// "semi", "fully") — see mallcop-pro's
// internal/selfext/autonomy/autonomy_test.go:
// TestAutonomyVocabularyPinnedAcrossRepoBoundary (same name, other repo). The
// two vocabularies are two independent spellings with NO shared code; this
// test is the tripwire on THIS side — if a value is ever added, renamed, or
// removed here without a matching edit on the mallcop-pro side, this test
// still passes (it only checks internal consistency), but the mallcop-pro
// contract test's literal set will now disagree with what a human reading
// both files expects, and code review across the two failing/passing pairs is
// how the drift is caught. Keep the accepted set literal (not a loop over
// package internals) so an addition/removal is a visible one-line diff here.
func TestAutonomyVocabularyPinnedAcrossRepoBoundary(t *testing.T) {
	want := map[string]bool{"non": true, "semi": true, "fully": true}

	got := map[string]bool{AutonomyNon: true, AutonomySemi: true, AutonomyFully: true}
	if len(got) != len(want) {
		t.Fatalf("AutonomyNon/AutonomySemi/AutonomyFully constants collapsed to %d distinct values, want 3", len(got))
	}
	for v := range want {
		if !got[v] {
			t.Fatalf("expected constant %q missing from {AutonomyNon=%q, AutonomySemi=%q, AutonomyFully=%q}", v, AutonomyNon, AutonomySemi, AutonomyFully)
		}
	}

	// The full space of one-character-off / retired spellings a config author
	// might type must all be rejected by IsValidAutonomy — pinning the set to
	// EXACTLY these three, not "these three plus whatever else validates".
	for _, bad := range []string{"off", "on", "auto", "NON", "Non", "semi ", " semi", "fully!", "", "non,semi,fully"} {
		if IsValidAutonomy(bad) {
			t.Fatalf("IsValidAutonomy(%q) = true, want false (accepted set is EXACTLY {non, semi, fully})", bad)
		}
	}
	for v := range want {
		if !IsValidAutonomy(v) {
			t.Fatalf("IsValidAutonomy(%q) = false, want true (it is one of the pinned three)", v)
		}
	}
}
