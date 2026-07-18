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
	Investigate Investigate `yaml:"investigate"`
	Org         Org         `yaml:"org"`
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
//
// Kind and ID are always emitted (they identify the connector even at their
// zero value). Every other field is kind-specific — file uses Path only,
// github uses Org only, cloud uses Source/Args/Since/Env/Binary — so they
// marshal with `omitempty`: without it, the generated mallcop.yaml pads every
// connector entry with the OTHER kinds' unused fields as empty noise
// (`org: ""`, `source: ""`, `args: []`).
type Connector struct {
	Kind   string   `yaml:"kind"`
	ID     string   `yaml:"id"`
	Path   string   `yaml:"path,omitempty"`
	Org    string   `yaml:"org,omitempty"`
	Source string   `yaml:"source,omitempty"`
	Args   []string `yaml:"args,omitempty"`
	Since  string   `yaml:"since,omitempty"`
	Env    []string `yaml:"env,omitempty"`
	// Binary is an optional explicit override for the kind:cloud sibling path
	// (design §A / Ruling #3); empty means the mallcop-connector-<source>
	// convention on $PATH.
	Binary string `yaml:"binary,omitempty"`
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
//
// Autonomy is the self-extension AUTONOMY DIAL (rd mallcoppro-315): the
// operator-owned blast-radius setting mallcop-pro's selfext router + engine
// read to decide whether a gate-GREEN change auto-applies or waits for a
// human. Exactly one of AutonomyNon / AutonomySemi / AutonomyFully — see
// IsValidAutonomy. Any other value is a loud config load error (STRICT, same
// discipline as the rest of this package): a typo must never silently fall
// back to the fail-safe default and be mistaken for an explicit choice.
//
//	non   - propose-only. EVERY change (data overlay write AND authored code)
//	        waits for a human to approve. The default — mallcop ships fail-safe.
//	semi  - DATA changes (learned mappings / tuning overlays) auto-apply on a
//	        gate-GREEN clean widen; CODE changes (authored detectors/
//	        connectors) still always wait for a human.
//	fully - DATA and CODE both auto-apply on a gate-GREEN clean widen.
//
// Contribute-back to the shared OSS pool is NEVER auto-merged regardless of
// this dial (a hard line, not operator-overridable — rd mallcoppro-13c/49f):
// the router's OSS-PR artifact is always a human/maintainer-reviewed
// deliverable, at every autonomy setting.
//
// ContributeBack is the STANDING operator opt-in gate for the shared OSS
// contribute-back path (rd mallcoppro-9af, ruling: standing knob + per-
// improvement confirm — two layers of consent, both required):
//
//  1. STANDING (this field, default FALSE): the operator opts their
//     deployment in to contribute-back being offered AT ALL. false means the
//     router never proposes opening a shared-OSS PR for this deployment's
//     learned improvements, full stop — the second gate below never comes
//     into play.
//  2. PER-IMPROVEMENT (a later slice — chat/CLI confirmation at promote
//     time): even with the standing knob on, each individual improvement
//     still requires an explicit confirm before a PR is opened.
//
// Contribute-back NEVER auto-merges at any autonomy dial setting — the
// router's OSS-PR artifact has no merge path; it always lands as a human/
// maintainer-reviewed PR. This field only controls whether the flow is
// offered at all, never whether it merges unattended.
type Learning struct {
	Dir            string `yaml:"dir"`
	Autonomy       string `yaml:"autonomy"`
	EnforcePin     bool   `yaml:"enforce_pin"`
	ContributeBack bool   `yaml:"contribute_back"`
}

// The three self-extension autonomy dial positions (Learning.Autonomy).
const (
	AutonomyNon   = "non"
	AutonomySemi  = "semi"
	AutonomyFully = "fully"
)

// IsValidAutonomy reports whether s is one of the three dial positions.
func IsValidAutonomy(s string) bool {
	switch s {
	case AutonomyNon, AutonomySemi, AutonomyFully:
		return true
	default:
		return false
	}
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

// Investigate configures detection-time investigation (mallcoppro-e3c): after
// a scan escalates a finding, ONE metered narrate call assembles a
// deterministic evidence chain (identity, neighbors, recurrence, baseline,
// scan-schedule correlation) and a model narrative, committed beside the
// finding as investigations/<finding-id>.json (core/inquest). DEFAULT ON —
// this feature ships IN THE BINARY, not gated behind a mallcop.yaml template
// change: an absent investigate: block resolves to exactly these defaults, so
// a zero-config deploy still gets detection-time investigation, bounded by
// MaxPerScan.
type Investigate struct {
	Enabled bool `yaml:"enabled"`
	// Model is "" (inherit inference.model) or an explicit lane name (e.g.
	// "investigate") to pin a stronger Forge lane for the narrate call.
	Model      string `yaml:"model"`
	MaxPerScan int    `yaml:"max_per_scan"`
	// Retries is carried for schema completeness only — core/inquest always
	// makes exactly ONE call per finding regardless of this value (the hard
	// one-call contract; see core/inquest.Config's doc comment).
	Retries           int    `yaml:"retries"`
	NeighborWindow    string `yaml:"neighbor_window"`
	MaxNeighbors      int    `yaml:"max_neighbors"`
	CorrelationWindow string `yaml:"correlation_window"`
	MaxTokens         int    `yaml:"max_tokens"`

	// LowConfidenceThreshold (mallcoppro-09a) is the investigator-confidence
	// floor below which an "ok" but shaky escalated investigation is re-run with
	// a DEEPER pass and put to a committee RE-VOTE (any-escalate-wins) before any
	// customer-facing action-required copy is generated from it. 0 or negative
	// DISABLES the retrigger entirely (the pre-09a behavior). The default (0.5)
	// is a starting value, not a proven optimum — it directly trades cost (how
	// often the expensive deep-pass+revote fires) against trust (too high wastes
	// budget re-voting confident-enough findings; too low ships shaky verdicts
	// unchallenged) and is an open tuning question (rd mallcoppro-09a).
	LowConfidenceThreshold float64 `yaml:"low_confidence_threshold"`
	// MaxDeepPerScan bounds the metered deeper-investigation narrate calls the
	// low-confidence retrigger may make this scan — a SEPARATE budget from
	// MaxPerScan (each deep pass also drives a full committee re-vote). <= 0 uses
	// core/inquest's defaultMaxDeepPerScan (5).
	MaxDeepPerScan int `yaml:"max_deep_per_scan"`
	// DeepModel is the model lane the deeper investigation pass pins — typically
	// a stronger lane than the first pass. "" inherits Model.
	DeepModel string `yaml:"deep_model"`
}

// Org names the operator's OWN accounts/roles/relays (mallcoppro-995) so
// core/inquest's detection-time investigation can resolve a recurring,
// baseline-known actor as an OWNED entity by name and relationship, instead
// of narrating it as a stranger. Absent org: is a safe default — Owned is nil
// and no evidence is ever marked owned; this is a naming augmentation only,
// never a verdict override (see core/inquest/narrate.go's systemPrompt
// clause).
type Org struct {
	Owned []OwnedEntity `yaml:"owned"`
}

// OwnedEntity is one operator-configured owned account/role/relay. Match is
// substring-matched against the finding's caller/target/actor identity
// fields (core/inquest's assembleOrgContext) — first configured entry wins
// per field. Name/Relationship are the plain-language labels the narrate
// prompt is instructed to use instead of "unknown external actor".
type OwnedEntity struct {
	// Match identifies the entity: an account id, ARN, or role-name segment.
	// MUST be non-empty (validate rejects "" — an empty Match would
	// substring-match every identity field via strings.Contains(x, ""),
	// silently marking every finding as owned).
	Match string `yaml:"match"`
	// Name is a short label, e.g. "mallcop-bedrock-relay".
	Name string `yaml:"name"`
	// Relationship is the plain-language phrase narrate must use, e.g.
	// "operator's own hourly inference relay".
	Relationship string `yaml:"relationship"`
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
			// A real tenant lane, NOT a placeholder: the donut rail only resolves
			// the lane names (triage/investigate/heal) to a Bedrock model and 404s
			// on anything else. triage (glm-4.7-flash, open sovereignty) is the
			// cheapest lane and the safe default (mallcoppro-2b9).
			Model: "triage",
		},
		Store: Store{Path: "./store", Baseline: ""},
		Connectors: []Connector{
			{Kind: "file", ID: "local-events", Path: "./events.jsonl"},
		},
		Detectors: Detectors{
			Builtin:  Builtin{Enabled: true, Disable: []string{}},
			Sidecars: Sidecars{Dir: "./detectors/bin"},
		},
		Learning:    Learning{Dir: "detectors", Autonomy: AutonomyNon, EnforcePin: false, ContributeBack: false},
		Sovereignty: Sovereignty{Tier: "open", ContributeBack: false},
		Budgets:     Budgets{MaxFindings: 25, ScanTimeout: "10m", SelfextSpendCapUSD: 25},
		Investigate: Investigate{
			Enabled: true, Model: "", MaxPerScan: 10, Retries: 0,
			NeighborWindow: "1h", MaxNeighbors: 50, CorrelationWindow: "10m", MaxTokens: 1024,
			// Low-confidence re-vote ON by default (mallcoppro-09a): a shaky
			// escalated investigation goes deeper + to a committee re-vote before
			// customer-facing copy ships. 0.5 threshold, deep budget 5, deep lane
			// "investigate" (a stronger lane than the triage default).
			LowConfidenceThreshold: 0.5, MaxDeepPerScan: 5, DeepModel: "investigate",
		},
		Org: Org{Owned: nil},
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
	if !IsValidAutonomy(cfg.Learning.Autonomy) {
		return fmt.Errorf("learning.autonomy must be one of %q, %q, %q — got %q", AutonomyNon, AutonomySemi, AutonomyFully, cfg.Learning.Autonomy)
	}
	for _, c := range cfg.Connectors {
		for _, e := range c.Env {
			if looksLikeSecret(e) {
				return fmt.Errorf("connectors[%s].env must list env-var NAMES, not inline secret values — got %q", c.ID, e)
			}
		}
	}
	if cfg.Investigate.LowConfidenceThreshold > 1 {
		return fmt.Errorf("investigate.low_confidence_threshold must be <= 1.0 (investigator confidence is a [0,1] score) — got %v; a value above 1 would send EVERY escalated investigation to the expensive deep-pass+revote path", cfg.Investigate.LowConfidenceThreshold)
	}
	for i, o := range cfg.Org.Owned {
		if strings.TrimSpace(o.Match) == "" {
			return fmt.Errorf("org.owned[%d].match must be non-empty — an empty match string substring-matches EVERY identity field, silently marking every finding as owned", i)
		}
		if len(o.Match) < minOrgMatchLen {
			return fmt.Errorf("org.owned[%d].match %q is only %d characters — must be at least %d (a full account id or ARN/role-name segment) to avoid false-positive substring matches across unrelated findings", i, o.Match, len(o.Match), minOrgMatchLen)
		}
	}
	return nil
}

// minOrgMatchLen is the minimum length org.owned[].match must be — short
// generic fragments (e.g. "aws", "role") would substring-match broadly
// across unrelated identity fields. AWS account ids are 12 digits; ARNs and
// role-name segments run well past this floor.
const minOrgMatchLen = 8

// marshalHeader is prepended to every generated mallcop.yaml so the file
// announces itself and points at the one-path workflow. It is a plain YAML
// comment — Load ignores it, so a Marshal→Load round-trip is unaffected.
const marshalHeader = `# mallcop.yaml — the one file mallcop reads. Generated by ` + "`mallcop init`" + `.
# Run the scan with no flags:  mallcop scan
# Add a source by editing connectors: below.
`

// Marshal serializes cfg to the YAML bytes `mallcop init` writes. The output is
// a header comment plus the strict, fully-keyed encoding of every struct field
// — EXCEPT Connector's kind-specific fields (Path/Org/Source/Args/Since/Env/
// Binary), which omit when empty so a connector entry only shows the fields its
// own kind uses (see Connector's doc comment) — so it round-trips through Load
// with no error (the doc-test seed for §14): the generated default IS a valid
// config. Two-space indent matches the schema in the design doc.
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
