// tools_lookup_rules.go — lookup-rules action tool + operator-decisions.yaml loader.
//
// Implements mallcoppro-00c (Wave 3 / Phase 2): a flat-file operator decisions
// rule store that investigate/triage workers can query to find a matching
// operator directive for a finding. When a worker cites a matched rule_id in
// the resolve-finding `reason` field (or the new `rule_id` parameter), the
// confidence gate treats the citation as a SATISFIED CITATION:
//
//   - rule_id counts as 1 citation toward the gate's citation_count.
//   - rule_id bypasses the zero-citation hard floor at tools_f1g_gate.go:513.
//
// # YAML schema (matches mallcoppro-2fc's seed file)
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
// The investigate sandbox already mounts agents/ read-only via the chart's
// `extra_ro` list, so the worker subprocess can read the file natively.
//
// # Security note
//
// rule_id forgery is prevented at the gate by requiring the cited rule_id to
// actually load from the YAML file. A worker that invents "R-999" gets zero
// citation credit from the rule_id path — it still has to find evidence the
// regular way.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// Belt+suspenders defence (mallcoppro-b92) against tampering of the rule corpus
// after deploy. The primary defence is hermetic copy + atomic rename in
// scripts/bootstrap-deploy.sh; this is a runtime check that any tampering
// surfaces as a load error rather than a silent gate bypass via fabricated rules.
//
// MAINTENANCE: this constant MUST be regenerated whenever
// agents/rules/operator-decisions.yaml changes. Recompute with:
//
//	sha256sum agents/rules/operator-decisions.yaml
//
// TestExpectedOperatorRulesSHA256_MatchesShippedCorpus enforces the regen as a
// regression guard — CI fails if the constant and the shipped corpus diverge.
//
// The verification is OPTIONAL at runtime — it is enforced only when
// MALLCOP_RULES_SHA256_ENFORCE is truthy or MALLCOP_RULES_SHA256 is set to a
// non-empty value. Default is permissive so dev/test workflows that edit the
// corpus on the fly are not broken; production deploys set the enforce flag in
// the activate envelope. This matches the existing security posture in
// tools_f1g_gate.go where bypass gates default off and are enabled per-deploy.
//
// When MALLCOP_RULES_SHA256 is set it overrides this constant (lets the build/
// release process pin a corpus that wasn't yet hardcoded). Mismatch in either
// path returns an error from loadOperatorRules, which surfaces as a
// resolve-finding gate fire (lookup-rules emits an error result).
const expectedOperatorRulesSHA256 = "b5b9d30505a4c5e7a59ecb74388999cfbe196beb384271abaf1e4b5e19ac9656"

// operatorRule is a single rule loaded from operator-decisions.yaml.
type operatorRule struct {
	ID         string         `yaml:"id" json:"id"`
	AppliesTo  ruleAppliesTo  `yaml:"applies_to" json:"applies_to"`
	OperatorDirective string `yaml:"operator_directive" json:"operator_directive"`
}

// ruleAppliesTo is the matching predicate for a rule.
//
// Family matches finding.detector (string equality, case-insensitive).
// MetadataMatch is a conjunctive flat map: every (key, value) pair must appear
// in the supplied finding_metadata for the rule to match. Values are compared
// case-insensitively as strings.
type ruleAppliesTo struct {
	Family        string            `yaml:"family" json:"family"`
	MetadataMatch map[string]string `yaml:"metadata_match,omitempty" json:"metadata_match,omitempty"`
}

// operatorRulesFile is the on-disk top-level shape of operator-decisions.yaml.
type operatorRulesFile struct {
	Rules []operatorRule `yaml:"rules"`
}

// lookupRulesInput is the input_schema for the lookup-rules action tool.
//
// FindingFamily filters rules by AppliesTo.Family (case-insensitive equality).
// FindingMetadata supplies the metadata predicate values — a rule's
// metadata_match keys must all be present in FindingMetadata with matching
// values (case-insensitive) for the rule to be returned.
type lookupRulesInput struct {
	FindingID       string            `json:"finding_id"`
	FindingFamily   string            `json:"finding_family"`
	FindingMetadata map[string]string `json:"finding_metadata,omitempty"`
}

// lookupRulesOutput is the JSON output for lookup-rules.
type lookupRulesOutput struct {
	FindingID string         `json:"finding_id"`
	Rules     []operatorRule `json:"rules"`
}

// rulesCachePath returns the absolute path to operator-decisions.yaml under
// the repo root. The caller is responsible for resolving the repo root.
func rulesCachePath(repoRoot string) string {
	return filepath.Join(repoRoot, "agents", "rules", "operator-decisions.yaml")
}

// rulesCache memoizes the parsed rules file for the lifetime of the process.
// Each binary invocation is a fresh process, but within one process (e.g. the
// gate-check + lookup-rules call paths in tests), we avoid re-parsing.
var (
	rulesCacheMu   sync.Mutex
	rulesCacheOnce sync.Once
	rulesCacheData []operatorRule
	rulesCacheErr  error
	rulesCacheKey  string // path used for last load, to invalidate on path change
)

// loadOperatorRules reads operator-decisions.yaml from repoRoot and returns
// the parsed rules. Returns an empty slice (not an error) when the file does
// not exist — a missing file means "no pre-seeded rules" rather than an error.
func loadOperatorRules(repoRoot string) ([]operatorRule, error) {
	path := rulesCachePath(repoRoot)

	rulesCacheMu.Lock()
	defer rulesCacheMu.Unlock()

	// Invalidate cache when the path changes (test isolation: each test sets
	// MALLCOP_REPO_ROOT to a different t.TempDir).
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
				rulesCacheData = []operatorRule{}
				rulesCacheErr = nil
				return
			}
			rulesCacheErr = fmt.Errorf("read operator-decisions.yaml: %w", err)
			return
		}
		// Belt+suspenders sha256 check (mallcoppro-b92). Enforced only when
		// MALLCOP_RULES_SHA256_ENFORCE is truthy or MALLCOP_RULES_SHA256 is
		// set. Mismatch surfaces as a load error so a tampered corpus cannot
		// silently grant rule_id citations at the gate.
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
// The permissive default mirrors the gate's other env-toggled defences and
// keeps test fixtures (writeRulesFixture writes a 3-rule fixture with a
// different hash than the shipped corpus) working without ceremony.
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

// matchesRule returns true when the given finding family + metadata satisfy
// the rule's applies_to predicate. Family is case-insensitive equality;
// metadata_match is a conjunctive case-insensitive flat-map predicate.
//
// An empty rule.Family matches any family (defensive — a real rule should
// always set family).
// An empty rule.MetadataMatch matches any metadata (rule applies whenever
// family matches).
func matchesRule(rule operatorRule, family string, metadata map[string]string) bool {
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

// lookupMetadataCaseInsensitive does a case-insensitive key lookup against
// the supplied metadata map. Returns (value, true) on hit, ("", false) on miss.
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

// findRuleByID looks up a rule by its ID (case-insensitive). Returns the rule
// and true on hit, or zero value and false on miss.
func findRuleByID(rules []operatorRule, ruleID string) (operatorRule, bool) {
	for _, r := range rules {
		if strings.EqualFold(r.ID, ruleID) {
			return r, true
		}
	}
	return operatorRule{}, false
}

// runLookupRules is the lookup-rules action tool handler.
//
// It reads finding_id + finding_family + finding_metadata from the input JSON
// and emits a JSON object with the matching rules array. Empty array on no
// matches; never an error for "no rules found."
func runLookupRules(inputJSON string) error {
	var input lookupRulesInput
	inputJSON = stripMarkdownFences(inputJSON)
	if inputJSON == "" {
		return errors.New("lookup-rules: input JSON required (missing positional argument)")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("lookup-rules: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("lookup-rules: finding_id is required")
	}
	if input.FindingFamily == "" {
		return errors.New("lookup-rules: finding_family is required")
	}

	repoRoot, err := resolveRepoRoot()
	if err != nil {
		return fmt.Errorf("lookup-rules: resolve repo root: %w", err)
	}

	rules, err := loadOperatorRules(repoRoot)
	if err != nil {
		return fmt.Errorf("lookup-rules: %w", err)
	}

	matches := []operatorRule{}
	for _, r := range rules {
		if matchesRule(r, input.FindingFamily, input.FindingMetadata) {
			matches = append(matches, r)
		}
	}

	return emitJSON(lookupRulesOutput{
		FindingID: input.FindingID,
		Rules:     matches,
	})
}
