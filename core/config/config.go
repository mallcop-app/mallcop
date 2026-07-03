// Package config is the loader for mallcop.yaml — the one file mallcop reads.
//
// It is the FOUNDATION of the config-driven mallcop (rd mallcoppro-901): the
// user names their sources, inference rail, store, and loop-owned learning dir
// once in a file instead of juggling flags on every invocation. scan/detect
// resolve each setting with the §C.1 precedence flag > env > config > default
// via the Resolve helpers here (those callers are later work items — this
// package delivers the struct, the strict loader, and the precedence primitive).
//
// Purity: this package depends only on gopkg.in/yaml.v3 + stdlib. It lives in
// core/ (YAML in core/ is already precedented — core/detect/tuning.go) and does
// NOT trip the core/connect purity lint, which only forbids
// inference/transport/vendor-SDK deps under core/connect.
//
// Trust posture: the loader is human-written product code — the same "agent
// authors DATA, a frozen human-written loader interprets it" division of labor
// as core/detect/tuning.go, generalized to the whole config. Two rules are baked
// in and enforced by Load:
//
//   - STRICT decode (yaml KnownFields(true)): any unknown/smuggled key is a LOUD
//     load error, never a silent default — identical discipline to
//     core/detect/tuning.go.
//   - key_env / connector env are env-var NAMES, never inline secrets. A value
//     that looks like a literal key (contains "sk-", e.g. a mallcop-sk-* token)
//     is a loud load error.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfigFileName is the well-known basename discovered by a walk-up from cwd.
const ConfigFileName = "mallcop.yaml"

// EnvConfigPath names the env var that overrides discovery with an explicit path.
const EnvConfigPath = "MALLCOP_CONFIG"

// Config is the whole mallcop.yaml schema (design §A). Every top-level key is a
// struct so the strict decode reports the exact offending path on an unknown
// key. Zero values are meaningful: a present-but-partial file overlays only the
// keys it sets onto Defaults() (see Load), so an absent section keeps its
// default and an explicit `enabled: false` still overrides.
type Config struct {
	Version     int         `yaml:"version"`
	Inference   Inference   `yaml:"inference"`
	Store       Store       `yaml:"store"`
	Connectors  []Connector `yaml:"connectors"`
	Detectors   Detectors   `yaml:"detectors"`
	Learning    Learning    `yaml:"learning"`
	Sovereignty Sovereignty `yaml:"sovereignty"`
	Budgets     Budgets     `yaml:"budgets"`
}

// Inference is the LLM rail. mode is donut (Forge managed) | byoi | offline.
// key_env is the NAME of the env var holding the key (mallcop-sk-* on the donut
// rail) — NEVER an inline secret.
type Inference struct {
	Mode     string `yaml:"mode"`
	Endpoint string `yaml:"endpoint"`
	KeyEnv   string `yaml:"key_env"`
	Model    string `yaml:"model"`
}

// Store points at the git-backed findings/resolutions store and an optional
// baseline JSON.
type Store struct {
	Path     string `yaml:"path"`
	Baseline string `yaml:"baseline"`
}

// Connector is one configured source. `mallcop scan` pulls from ALL of them in
// one pass (the MultiConnector fan-in is a later item). Kind selects the loader
// branch: file | github | cloud.
//
//   - file:   Path is the events JSONL.
//   - github: Org is the GitHub org (creds via env, github.NewFromEnv).
//   - cloud:  Source maps to the sibling binary mallcop-connector-<source>;
//     Args/Since/Env/Binary parameterize the exec (later item). Env lists
//     env-var NAMES, never values.
type Connector struct {
	Kind   string   `yaml:"kind"`
	ID     string   `yaml:"id"`
	Path   string   `yaml:"path"`
	Org    string   `yaml:"org"`
	Source string   `yaml:"source"`
	Args   []string `yaml:"args"`
	Since  string   `yaml:"since"`
	Env    []string `yaml:"env"`
	// Binary is an optional explicit override for the kind:cloud sibling path
	// (design §A / Ruling #3); empty means the mallcop-connector-<source>
	// convention on $PATH.
	Binary string `yaml:"binary"`
}

// Detectors gates the built-in framework detectors and configures WASM
// sidecar detector discovery.
type Detectors struct {
	Builtin  Builtin  `yaml:"builtin"`
	Sidecars Sidecars `yaml:"sidecars"`
}

// Sidecars configures discovery of wasip1 WASM detector sidecar modules (see
// package detecthost). Dir is scanned for *.wasm files at command setup for
// scan/detect/exam-detect; each is wrapped via detecthost and registered
// through the same detect.Register seam a built-in detector uses. A relative
// Dir is resolved against the directory the config was discovered in (the
// deployment root), matching Learning.Dir/Store.Baseline's convention; when no
// config file is present it resolves against the current working directory. A
// dir that does not exist on disk yields zero sidecars and no error — the
// OOTB default (no config, no ./detectors/bin present) is unaffected.
type Sidecars struct {
	Dir string `yaml:"dir"`
}

// Builtin turns the 17 framework detectors on and optionally narrows the result
// set. disable is OWNER discretion ONLY — the self-extension loop is
// structurally forbidden from writing it (it only ever widens learning.dir).
type Builtin struct {
	Enabled bool     `yaml:"enabled"`
	Disable []string `yaml:"disable"`
}

// Learning points at the LOOP-OWNED overlay dir (store-repo-relative). It stays
// the default `detectors/` so the guard's widen dispatch (gated on the
// detectors/ prefix) fires byte-for-byte unchanged.
type Learning struct {
	Dir        string `yaml:"dir"`
	Autonomy   string `yaml:"autonomy"`
	EnforcePin bool   `yaml:"enforce_pin"`
}

// Sovereignty carries the deployment tier and the opt-in OSS contribute-back flag.
type Sovereignty struct {
	Tier           string `yaml:"tier"`
	ContributeBack bool   `yaml:"contribute_back"`
}

// Budgets holds the volume circuit-breaker, the scan timeout, and the
// self-extension spend cap.
type Budgets struct {
	MaxFindings        int     `yaml:"max_findings"`
	ScanTimeout        string  `yaml:"scan_timeout"`
	SelfextSpendCapUSD float64 `yaml:"selfext_spend_cap_usd"`
}

// Defaults returns the built-in default Config — the safe OSS defaults `mallcop
// init` generates (design §B): offline fail-safe inference, auto-mutation OFF,
// the single sample file connector, learning.dir=detectors, the $25 cap. An
// absent config resolves to exactly this, so today's flag-only path is
// unaffected.
func Defaults() Config {
	return Config{
		Version: 1,
		Inference: Inference{
			Mode:     "offline",
			Endpoint: "",
			KeyEnv:   "MALLCOP_API_KEY",
			Model:    "mallcop-default",
		},
		Store: Store{Path: "./store", Baseline: ""},
		Connectors: []Connector{
			{Kind: "file", ID: "local-events", Path: "./events.jsonl"},
		},
		Detectors: Detectors{
			Builtin:  Builtin{Enabled: true, Disable: []string{}},
			Sidecars: Sidecars{Dir: "./detectors/bin"},
		},
		Learning:    Learning{Dir: "detectors", Autonomy: "off", EnforcePin: false},
		Sovereignty: Sovereignty{Tier: "open", ContributeBack: false},
		Budgets:     Budgets{MaxFindings: 25, ScanTimeout: "10m", SelfextSpendCapUSD: 25},
	}
}

// Load reads and STRICTLY decodes the config file at path onto a Defaults()
// base, so a present-but-partial file keeps defaults for the keys it omits while
// still letting an explicit value (including a false bool) override.
//
// Behavior (mirroring core/detect/tuning.go's loud/fail-safe contract):
//   - path == "" or the file does not exist -> Defaults(), nil. This is the
//     ABSENT case: today's flag-only path is unaffected.
//   - present-but-empty file                -> Defaults(), nil (EOF).
//   - any UNKNOWN yaml key                   -> loud error (KnownFields(true)).
//   - any inline secret in key_env / env     -> loud error (validate).
//   - any other parse error                  -> loud error.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return Defaults(), fmt.Errorf("config: read %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Defaults(), fmt.Errorf("config: parse %s (strict): %w", path, err)
	}

	if err := validate(cfg); err != nil {
		return Defaults(), fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Discover resolves which config file to load, honoring in order:
//  1. an explicit override (the --config flag) — returned verbatim;
//  2. $MALLCOP_CONFIG;
//  3. a walk-up from cwd for mallcop.yaml (mirrors eval.RepoRoot's marker walk).
//
// It returns "" (no error) when nothing is found — the ABSENT case, which the
// caller resolves to Defaults().
func Discover(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if v := os.Getenv(EnvConfigPath); v != "" {
		return v, nil
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("config: getwd: %w", err)
	}
	for {
		candidate := filepath.Join(dir, ConfigFileName)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", nil
}

// LoadEffective is the convenience entry: Discover(override) then Load. It
// returns the resolved Config, the path it loaded from ("" when absent → the
// Config is Defaults()), and any load error.
func LoadEffective(override string) (Config, string, error) {
	path, err := Discover(override)
	if err != nil {
		return Defaults(), "", err
	}
	if path == "" {
		return Defaults(), "", nil
	}
	cfg, err := Load(path)
	if err != nil {
		return Defaults(), path, err
	}
	return cfg, path, nil
}

// secretMarker is the substring that flags a value as a literal secret rather
// than an env-var NAME. It catches mallcop-sk-* and any vendor sk-* token.
const secretMarker = "sk-"

// looksLikeSecret reports whether s looks like an inline credential value rather
// than an env-var NAME. Env-var names are uppercase/underscore (MALLCOP_API_KEY)
// and never contain "sk-"; a value that does is almost certainly a smuggled key.
func looksLikeSecret(s string) bool {
	return strings.Contains(strings.ToLower(s), secretMarker)
}

// validate enforces the "NAMES, never secrets" rule across every credential
// surface after a successful strict decode. A smuggled inline key is a LOUD
// load error, never silently accepted.
func validate(cfg Config) error {
	if looksLikeSecret(cfg.Inference.KeyEnv) {
		return fmt.Errorf("inference.key_env must be an env-var NAME (e.g. MALLCOP_API_KEY), not an inline secret value — got %q, which looks like a literal key", cfg.Inference.KeyEnv)
	}
	for _, c := range cfg.Connectors {
		for _, e := range c.Env {
			if looksLikeSecret(e) {
				return fmt.Errorf("connectors[%s].env must list env-var NAMES, not inline secret values — got %q", c.ID, e)
			}
		}
	}
	return nil
}

// marshalHeader is prepended to every generated mallcop.yaml so the file
// announces itself and points at the one-path workflow. It is a plain YAML
// comment — Load ignores it, so a Marshal→Load round-trip is unaffected.
const marshalHeader = `# mallcop.yaml — the one file mallcop reads. Generated by ` + "`mallcop init`" + `.
# Run the scan with no flags:  mallcop scan
# Add a source by editing connectors: below.
`

// Marshal serializes cfg to the YAML bytes `mallcop init` writes. The output is
// a header comment plus the strict, fully-keyed encoding of every struct field,
// so it round-trips through Load with no error (the doc-test seed for §14): the
// generated default IS a valid config. Two-space indent matches the schema in
// the design doc.
func Marshal(cfg Config) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(marshalHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("config: marshal: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("config: marshal close: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteConfig marshals cfg and writes it to path with 0644 perms. Idempotency
// (skip-if-exists) is the caller's concern — `mallcop init` stats first and only
// calls WriteConfig when the file is absent, mirroring its store/events guard.
func WriteConfig(path string, cfg Config) error {
	data, err := Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}

// Resolve returns the first non-empty value in argument order. Passing the
// arguments as (flag, env, configValue, default) expresses the design §C.1
// precedence flag > env > config > default. scan/detect call this per setting
// (later items); this package ships the primitive + its tests.
func Resolve(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ResolveInt expresses the same precedence for an int setting where a
// non-positive value means "unset" (the scan.go convention, e.g. --max-findings
// 0 → default 25). flag wins when > 0, else the config value when > 0, else def.
func ResolveInt(flag, configValue, def int) int {
	if flag > 0 {
		return flag
	}
	if configValue > 0 {
		return configValue
	}
	return def
}
