// lookup_rules.go — the lookup-rules pure read tool + operator-decisions.yaml
// loader, ported from cmd/mallcop-investigate-tools/tools_lookup_rules.go.
//
// LookupRules is a PURE function: given a repo root, a finding family, and a
// flat metadata predicate, it returns the operator rules that match. It reads
// only the flat-file rule corpus at agents/rules/operator-decisions.yaml. It
// performs no inference, opens no channel, and produces no side effects beyond
// reading the corpus from disk.
//
// # YAML schema
//
//	rules:
//	  - id: "R-001"
//	    applies_to:
//	      family: "unusual-timing"            # detector family / finding.detector
//	      metadata_match:
//	        <key>: <value>                    # conjunctive flat-map predicate
//	    operator_directive: |
//	      <evidence-grounded resolution rationale>
//
// # File location
//
// The rules file lives at agents/rules/operator-decisions.yaml (repo-relative).
// The caller resolves the repo root and passes it in — this package does not
// guess at process environment.
//
// # Security note
//
// rule_id forgery is prevented downstream by requiring a cited rule_id to
// actually load from the YAML file. A consumer that invents "R-999" gets zero
// rules from LookupRules because no such rule exists in the corpus.
package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// expectedOperatorRulesSHA256 pins the sha256 of agents/rules/operator-decisions.yaml.
//
// Belt+suspenders defence against tampering of the rule corpus after deploy.
// The primary defence is hermetic copy + atomic rename at deploy time; this is
// a runtime check that any tampering surfaces as a load error rather than a
// silent gate bypass via fabricated rules.
//
// MAINTENANCE: this constant MUST be regenerated whenever
// agents/rules/operator-decisions.yaml changes. Recompute with:
//
//	sha256sum agents/rules/operator-decisions.yaml
//
// The verification is OPTIONAL at runtime — it is enforced only when
// MALLCOP_RULES_SHA256_ENFORCE is truthy or MALLCOP_RULES_SHA256 is set to a
// non-empty value. Default is permissive so dev/test workflows that edit the
// corpus on the fly are not broken; production deploys set the enforce flag.
//
// When MALLCOP_RULES_SHA256 is set it overrides this constant (lets the build/
// release process pin a corpus that wasn't yet hardcoded). Mismatch in either
// path returns an error from LoadOperatorRules.
const expectedOperatorRulesSHA256 = "7818b0e01d2d4f5c2ce3e4b0474a1aef4c477dedbf22c636fd0d46c432f96a2b"

// OperatorRule is a single rule loaded from operator-decisions.yaml.
type OperatorRule struct {
	ID                string        `yaml:"id" json:"id"`
	AppliesTo         RuleAppliesTo `yaml:"applies_to" json:"applies_to"`
	OperatorDirective string        `yaml:"operator_directive" json:"operator_directive"`
}

// RuleAppliesTo is the matching predicate for a rule.
//
// Family matches finding.detector (string equality, case-insensitive).
// MetadataMatch is a conjunctive flat map: every (key, value) pair must appear
// in the supplied finding metadata for the rule to match. Values are compared
// case-insensitively as strings.
type RuleAppliesTo struct {
	Family        string            `yaml:"family" json:"family"`
	MetadataMatch map[string]string `yaml:"metadata_match,omitempty" json:"metadata_match,omitempty"`
}

// operatorRulesFile is the on-disk top-level shape of operator-decisions.yaml.
type operatorRulesFile struct {
	Rules []OperatorRule `yaml:"rules"`
}

// LookupRulesInput is the input for LookupRules.
//
// FindingID identifies the finding being investigated (echoed back in output).
// FindingFamily filters rules by AppliesTo.Family (case-insensitive equality).
//
// The metadata predicate is supplied as a flat set of named string fields, not
// a nested object. This works around a reliability problem with the prior
// nested object schema: flat named string properties are the schema shape every
// reliably-called tool uses. Each known flag corresponds 1:1 with a
// metadata_match key currently used by operator-decisions.yaml.
//
// FindingMetadata is retained as a back-compatibility shim — when callers
// supply the legacy nested object, it is merged into the assembled flat map.
// Direct flat fields take precedence over FindingMetadata entries with the same
// key.
type LookupRulesInput struct {
	FindingID     string `json:"finding_id"`
	FindingFamily string `json:"finding_family"`

	// Flat named predicate fields (the canonical shape).
	MaintenanceWindow    string `json:"maintenance_window,omitempty"`
	Scheduled            string `json:"scheduled,omitempty"`
	ResolutionEvent      string `json:"resolution_event,omitempty"`
	LocationChange       string `json:"location_change,omitempty"`
	AutomationProvenance string `json:"automation_provenance,omitempty"`
	DeployRelease        string `json:"deploy_release,omitempty"`
	SensitiveBulkRead    string `json:"sensitive_bulk_read,omitempty"`
	HrProvisioning       string `json:"hr_provisioning,omitempty"`
	ScenarioPattern      string `json:"scenario_pattern,omitempty"`
	ActorRole            string `json:"actor_role,omitempty"`

	// FindingMetadata is the legacy nested-object input. Retained as a
	// back-compatibility shim. New callers should use the flat fields above.
	FindingMetadata map[string]string `json:"finding_metadata,omitempty"`
}

// assembleMetadata builds the flat metadata map the rule matcher expects from
// the input's named flat fields plus the legacy FindingMetadata map. Only
// non-empty values are included so a caller that omits a flag does not match
// rules that require that flag.
//
// Flat named fields take precedence over FindingMetadata entries with the same
// key — the named field is the canonical surface and the legacy map is a shim.
func (in LookupRulesInput) assembleMetadata() map[string]string {
	out := map[string]string{}
	// Seed from legacy nested map first; flat fields will overwrite below.
	for k, v := range in.FindingMetadata {
		if v == "" {
			continue
		}
		out[k] = v
	}
	flat := map[string]string{
		"maintenance_window":    in.MaintenanceWindow,
		"scheduled":             in.Scheduled,
		"resolution_event":      in.ResolutionEvent,
		"location_change":       in.LocationChange,
		"automation_provenance": in.AutomationProvenance,
		"deploy_release":        in.DeployRelease,
		"sensitive_bulk_read":   in.SensitiveBulkRead,
		"hr_provisioning":       in.HrProvisioning,
		"scenario_pattern":      in.ScenarioPattern,
		"actor_role":            in.ActorRole,
	}
	for k, v := range flat {
		if v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// LookupRulesOutput is the result of LookupRules: the finding id echoed back
// and the matching rules (empty slice, never nil, on no matches).
type LookupRulesOutput struct {
	FindingID string         `json:"finding_id"`
	Rules     []OperatorRule `json:"rules"`
}

// rulesCachePath returns the absolute path to operator-decisions.yaml under the
// repo root. The caller is responsible for resolving the repo root.
func rulesCachePath(repoRoot string) string {
	return filepath.Join(repoRoot, "agents", "rules", "operator-decisions.yaml")
}

// rulesCache memoizes the parsed rules file per source path. Within one process
// (e.g. repeated LookupRules calls against the same corpus) we avoid re-parsing.
var (
	rulesCacheMu   sync.Mutex
	rulesCacheOnce sync.Once
	rulesCacheData []OperatorRule
	rulesCacheErr  error
	rulesCacheKey  string // path used for last load, to invalidate on path change
)

// LoadOperatorRules reads operator-decisions.yaml from repoRoot and returns the
// parsed rules. Returns an empty slice (not an error) when the file does not
// exist — a missing file means "no pre-seeded rules" rather than an error.
func LoadOperatorRules(repoRoot string) ([]OperatorRule, error) {
	path := rulesCachePath(repoRoot)

	rulesCacheMu.Lock()
	defer rulesCacheMu.Unlock()

	// Invalidate cache when the path changes (test isolation: each test points
	// at a different temp repo root).
	if rulesCacheKey != path {
		rulesCacheData = nil
		rulesCacheErr = nil
		rulesCacheOnce = sync.Once{}
		rulesCacheKey = path
	}

	rulesCacheOnce.Do(func() {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				rulesCacheData = []OperatorRule{}
				rulesCacheErr = nil
				return
			}
			rulesCacheErr = fmt.Errorf("read operator-decisions.yaml: %w", err)
			return
		}
		// Belt+suspenders sha256 check. Enforced only when
		// MALLCOP_RULES_SHA256_ENFORCE is truthy or MALLCOP_RULES_SHA256 is set.
		// Mismatch surfaces as a load error so a tampered corpus cannot silently
		// grant rule_id citations downstream.
		if err := verifyOperatorRulesChecksum(data); err != nil {
			rulesCacheErr = err
			return
		}
		var file operatorRulesFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			rulesCacheErr = fmt.Errorf("parse operator-decisions.yaml: %w", err)
			return
		}
		rulesCacheData = file.Rules
		rulesCacheErr = nil
	})

	return rulesCacheData, rulesCacheErr
}

// verifyOperatorRulesChecksum enforces the sha256 pin on the operator-decisions
// corpus when configured to do so. Returns nil when no enforcement is active or
// the checksum matches; returns a non-nil error on mismatch.
//
// Enforcement modes:
//
//   - MALLCOP_RULES_SHA256 set to a non-empty value → that hex digest is the
//     expected hash (overrides expectedOperatorRulesSHA256). Enforcement is
//     implicitly on.
//   - MALLCOP_RULES_SHA256_ENFORCE in {"1","true","yes","on"} (case-insensitive)
//     → expectedOperatorRulesSHA256 is the expected hash. Enforcement is on.
//   - Otherwise → enforcement is off (returns nil regardless of file content).
//
// The permissive default mirrors other env-toggled defences and keeps test
// fixtures (which write a corpus with a different hash than the shipped one)
// working without ceremony.
func verifyOperatorRulesChecksum(data []byte) error {
	override := strings.TrimSpace(os.Getenv("MALLCOP_RULES_SHA256"))
	enforce := false
	expected := ""
	switch {
	case override != "":
		expected = strings.ToLower(override)
		enforce = true
	case isTruthyEnv(os.Getenv("MALLCOP_RULES_SHA256_ENFORCE")):
		expected = strings.ToLower(expectedOperatorRulesSHA256)
		enforce = true
	}
	if !enforce {
		return nil
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != expected {
		return fmt.Errorf("operator-decisions.yaml sha256 mismatch: expected %s, got %s (corpus may be tampered; regenerate expectedOperatorRulesSHA256 or check MALLCOP_RULES_SHA256)", expected, got)
	}
	return nil
}

// isTruthyEnv returns true for common truthy env values, case-insensitive.
func isTruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// matchesRule returns true when the given finding family + metadata satisfy the
// rule's applies_to predicate. Family is case-insensitive equality;
// metadata_match is a conjunctive case-insensitive flat-map predicate.
//
// An empty rule.Family matches any family (defensive — a real rule should
// always set family). An empty rule.MetadataMatch matches any metadata (rule
// applies whenever family matches).
func matchesRule(rule OperatorRule, family string, metadata map[string]string) bool {
	if rule.AppliesTo.Family != "" && !strings.EqualFold(rule.AppliesTo.Family, family) {
		return false
	}
	for k, want := range rule.AppliesTo.MetadataMatch {
		got, ok := lookupMetadataCaseInsensitive(metadata, k)
		if !ok {
			return false
		}
		if !strings.EqualFold(got, want) {
			return false
		}
	}
	return true
}

// lookupMetadataCaseInsensitive does a case-insensitive key lookup against the
// supplied metadata map. Returns (value, true) on hit, ("", false) on miss.
func lookupMetadataCaseInsensitive(metadata map[string]string, key string) (string, bool) {
	if v, ok := metadata[key]; ok {
		return v, true
	}
	keyLower := strings.ToLower(key)
	for k, v := range metadata {
		if strings.ToLower(k) == keyLower {
			return v, true
		}
	}
	return "", false
}

// FindRuleByID looks up a rule by its ID (case-insensitive). Returns the rule
// and true on hit, or zero value and false on miss.
func FindRuleByID(rules []OperatorRule, ruleID string) (OperatorRule, bool) {
	for _, r := range rules {
		if strings.EqualFold(r.ID, ruleID) {
			return r, true
		}
	}
	return OperatorRule{}, false
}

// LookupRules is the pure lookup-rules read tool.
//
// Given a repo root and an input (finding id + family + metadata predicate), it
// loads the operator-decisions corpus and returns the rules whose applies_to
// predicate matches. An empty Rules slice (never nil) means "no rules matched"
// — that is a valid result, never an error. LookupRules returns an error only
// for a malformed input (missing finding_id / finding_family) or a corpus that
// cannot be loaded (read error or sha256 mismatch when enforcement is on).
func LookupRules(repoRoot string, input LookupRulesInput) (LookupRulesOutput, error) {
	if input.FindingID == "" {
		return LookupRulesOutput{}, errors.New("lookup-rules: finding_id is required")
	}
	if input.FindingFamily == "" {
		return LookupRulesOutput{}, errors.New("lookup-rules: finding_family is required")
	}

	rules, err := LoadOperatorRules(repoRoot)
	if err != nil {
		return LookupRulesOutput{}, fmt.Errorf("lookup-rules: %w", err)
	}

	metadata := input.assembleMetadata()
	matches := []OperatorRule{}
	for _, r := range rules {
		if matchesRule(r, input.FindingFamily, metadata) {
			matches = append(matches, r)
		}
	}

	return LookupRulesOutput{
		FindingID: input.FindingID,
		Rules:     matches,
	}, nil
}
