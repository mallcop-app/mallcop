// Package exam provides types and loader logic for mallcop exam scenarios.
// Scenarios are YAML files that describe a security finding, supporting events,
// baseline state, and expected resolution outcomes.
package exam

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Sentinel errors returned by Load for distinct validation failures.
var (
	ErrMissingID         = errors.New("scenario missing required field: id")
	ErrMissingFinding    = errors.New("scenario missing required field: finding")
	ErrMalformedEvents   = errors.New("scenario has malformed events: each event must have an id")
	ErrMalformedBaseline = errors.New("scenario has malformed baseline: known_entities must be present")
)

// FindingMetadata holds arbitrary key/value pairs from a finding's metadata block.
// Values may be strings, lists, or numbers — we capture as any to stay flexible.
type FindingMetadata map[string]any

// ScenarioFinding mirrors the finding: block in the scenario YAML.
type ScenarioFinding struct {
	ID       string          `yaml:"id"`
	Detector string          `yaml:"detector"`
	Title    string          `yaml:"title"`
	Severity string          `yaml:"severity"`
	EventIDs []string        `yaml:"event_ids"`
	Metadata FindingMetadata `yaml:"metadata"`
}

// EventMetadata holds arbitrary key/value pairs from an event's metadata block.
type EventMetadata map[string]any

// Event mirrors a single entry in the events: sequence in the scenario YAML.
type Event struct {
	ID         string        `yaml:"id"`
	Timestamp  string        `yaml:"timestamp"`
	IngestedAt string        `yaml:"ingested_at"`
	Source     string        `yaml:"source"`
	EventType  string        `yaml:"event_type"`
	Actor      string        `yaml:"actor"`
	Action     string        `yaml:"action"`
	Target     string        `yaml:"target"`
	Severity   string        `yaml:"severity"`
	Metadata   EventMetadata `yaml:"metadata"`
	Raw        any           `yaml:"raw"`
}

// KnownEntities holds the known actors and sources from the baseline.
//
// ActorRoles / ActorHours mirror the corpus's per-actor role and active-hour
// baseline blocks. They are parsed here so the YAML is no longer silently dropped
// during unmarshal; the eval projection decides which (if any) it feeds into the
// typed baseline (priv-escalation deliberately does NOT consume ActorRoles, so a
// known-Contributor actor still escalates — the Known-Actor-Trust trap). Additive
// fields with yaml tags are safe: scenarios without these blocks unmarshal to nil.
type KnownEntities struct {
	Actors     []string            `yaml:"actors"`
	Sources    []string            `yaml:"sources"`
	ActorRoles map[string][]string `yaml:"actor_roles"`
	ActorHours map[string][]int    `yaml:"actor_hours"`
}

// RelationshipEntry describes a historical relationship between actor and target.
type RelationshipEntry struct {
	Count     int    `yaml:"count"`
	FirstSeen string `yaml:"first_seen"`
	LastSeen  string `yaml:"last_seen"`
}

// Baseline mirrors the baseline: block in the scenario YAML.
type Baseline struct {
	KnownEntities   KnownEntities                `yaml:"known_entities"`
	FrequencyTables map[string]int               `yaml:"frequency_tables"`
	Relationships   map[string]RelationshipEntry `yaml:"relationships"`
}

// ActorChainEntry mirrors a single entry in the actor_chain: sequence (optional field).
type ActorChainEntry struct {
	Actor  string `yaml:"actor"`
	Action string `yaml:"action"`
	Target string `yaml:"target"`
}

// ConnectorToolReturns holds the canned return value for a connector tool.
type ConnectorToolReturns map[string]any

// ConnectorTool mirrors a single entry in the connector_tools: sequence.
type ConnectorTool struct {
	Name        string               `yaml:"name"`
	Description string               `yaml:"description"`
	Returns     ConnectorToolReturns `yaml:"returns"`
}

// ExpectedResolution mirrors the expected: block — the ground truth for grading.
//
// ExpectedResolution, TrapDescription, and TrapResolvedMeans are ground-truth
// fields. They MUST NOT be rendered to worker input. The blind-render layer
// (exam-seed) is responsible for stripping them before posting scenarios to
// worker campfires.
type ExpectedResolution struct {
	ChainAction              string   `yaml:"chain_action"`
	TriageAction             string   `yaml:"triage_action"`
	ReasoningMustMention     []string `yaml:"reasoning_must_mention"`
	ReasoningMustNotMention  []string `yaml:"reasoning_must_not_mention"`
	InvestigateMustUseTools  bool     `yaml:"investigate_must_use_tools"`
	MinInvestigateIterations int      `yaml:"min_investigate_iterations"`
	MinInvestigationQuality  int      `yaml:"min_investigation_quality"`
}

// ExpectedDetection mirrors the expected_detection: block — the ground truth
// for grading the OFFLINE detect layer (core/detect) against a scenario's
// events, independent of any agent resolution.
//
// ExpectedDetection is a ground-truth field. It MUST NOT be rendered to worker
// input. The blind-render layer (exam-seed) is responsible for stripping it
// before posting scenarios to worker campfires.
//
// MustFire lists detector family tokens (e.g. "volume-anomaly") that must
// appear among the findings core/detect emits for the scenario's events +
// baseline. MustNotFire lists family tokens that must be absent. Grading is on
// family PRESENCE over the whole emitted set — not counts or actors. Scenarios
// without the block unmarshal to a nil pointer (additive yaml-tagged fields are
// safe — see the KnownEntities doc above) and are skipped by the grader.
type ExpectedDetection struct {
	MustFire    []string `yaml:"must_fire"`
	MustNotFire []string `yaml:"must_not_fire"`
}

// Scenario is the Go representation of a mallcop exam scenario YAML file.
//
// Ground-truth fields (ExpectedResolution, TrapDescription, TrapResolvedMeans)
// are exported for grader use but MUST NOT be rendered to worker input. The
// blind-render layer strips them before handing a scenario to a worker campfire.
type Scenario struct {
	// Core identity fields
	ID          string `yaml:"id"`
	FailureMode string `yaml:"failure_mode"`
	Detector    string `yaml:"detector"`
	Category    string `yaml:"category"`
	Difficulty  string `yaml:"difficulty"`

	// Finding that enters the pipeline
	Finding *ScenarioFinding `yaml:"finding"`

	// Events the worker's connector tools will return
	Events []Event `yaml:"events"`

	// Baseline state at the time of the finding
	Baseline *Baseline `yaml:"baseline"`

	// Optional actor chain (some scenarios model multi-hop activity)
	ActorChain []ActorChainEntry `yaml:"actor_chain"`

	// Optional canned connector tool definitions
	ConnectorTools []ConnectorTool `yaml:"connector_tools"`

	// Optional tags for filtering
	Tags []string `yaml:"tags"`

	// Ground truth — NEVER rendered to worker input.
	// ExpectedResolution holds the expected chain_action, triage_action,
	// and reasoning constraints used to grade worker responses.
	ExpectedResolution *ExpectedResolution `yaml:"expected"`

	// TrapDescription is a human-readable description of the reasoning trap
	// this scenario probes. NEVER rendered to worker input.
	TrapDescription string `yaml:"trap_description"`

	// TrapResolvedMeans describes what an incorrect resolution indicates about
	// the worker's reasoning failure. NEVER rendered to worker input.
	TrapResolvedMeans string `yaml:"trap_resolved_means"`

	// ExpectedDetection is the ground truth for grading the offline detect
	// layer (must_fire / must_not_fire detector families). NEVER rendered to
	// worker input. nil when the scenario carries no expected_detection block —
	// such scenarios are skipped (but counted) by the exam-detect grader.
	ExpectedDetection *ExpectedDetection `yaml:"expected_detection"`
}

// Load reads the YAML file at path, unmarshals it into a Scenario, and
// validates required fields. Validation errors wrap the exported sentinel
// errors so callers can use errors.Is to distinguish failure modes.
//
//   - ErrMissingID            — id field is empty
//   - ErrMissingFinding       — finding block is absent
//   - ErrMalformedEvents      — an event entry is missing its id
//   - ErrMalformedBaseline    — baseline block is present but known_entities is empty
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("exam.Load: read %s: %w", path, err)
	}

	var s Scenario
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("exam.Load: unmarshal %s: %w", path, err)
	}

	// Validate required fields.
	if s.ID == "" {
		return nil, fmt.Errorf("exam.Load: %w", ErrMissingID)
	}
	if s.Finding == nil {
		return nil, fmt.Errorf("exam.Load: %w", ErrMissingFinding)
	}
	for i, ev := range s.Events {
		if ev.ID == "" {
			return nil, fmt.Errorf("exam.Load: event[%d] has no id: %w", i, ErrMalformedEvents)
		}
	}
	if s.Baseline != nil {
		if len(s.Baseline.KnownEntities.Actors) == 0 && len(s.Baseline.KnownEntities.Sources) == 0 {
			return nil, fmt.Errorf("exam.Load: %w", ErrMalformedBaseline)
		}
	}

	return &s, nil
}
