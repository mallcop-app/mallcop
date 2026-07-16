package proposer

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// collectSchemaVersion is the collect-envelope wire-format version this proposer
// was written against. It MIRRORS mallcop's cmd/mallcop.CollectSchemaVersion
// (and selfgate.GateSchemaVersion) over the PROCESS BOUNDARY: mallcop-pro must
// NOT import the mallcop module, so it duplicates the envelope shape and refuses
// a report whose schema_version is newer than it understands.
const collectSchemaVersion = 1

// MappingGap is the mallcop-pro-side DUPLICATE of mallcop core/collect.MappingGap
// (mapping.go:49). Plain data with matching json tags — it crosses the module
// boundary unchanged via `mallcop collect --json`. The proposer maps RawAction
// onto one member of SuggestedVocabulary (the CLOSED enum the mallcop side
// populated from detect.KnownEventTypes); the proposer NEVER calls
// detect.KnownEventTypes directly — the vocabulary arrives as DATA.
type MappingGap struct {
	Source              string   `json:"source"`
	RawAction           string   `json:"raw_action"`
	Count               int      `json:"count"`
	SampleEventIDs      []string `json:"sample_event_ids"`
	SuggestedVocabulary []string `json:"suggested_vocabulary"`
}

// GapEvidence is the mallcop-pro-side DUPLICATE of mallcop core/collect.GapEvidence
// (gaps.go:49). It carries only STRUCTURED, classifier-controlled fields — never
// raw untrusted free text — so a proposal built from it cannot smuggle
// attacker-influenced content into the prompt.
type GapEvidence struct {
	ScenarioID       string   `json:"scenario_id,omitempty"`
	ExpectedAction   string   `json:"expected_action,omitempty"`
	ExpectedActor    string   `json:"expected_actor,omitempty"`
	EmittedDetectors []string `json:"emitted_detectors,omitempty"`
	HumanVerb        string   `json:"human_verb,omitempty"`
	AgentAction      string   `json:"agent_action,omitempty"`
	DissentMarker    string   `json:"dissent_marker,omitempty"`
}

// GapCandidate is the mallcop-pro-side DUPLICATE of mallcop core/collect.GapCandidate
// (gaps.go:66). Plain data with matching json tags. Consumed by the tuning lane
// (a detector's additive extra_* keyword list); it carries no raw untrusted free
// text — all evidence is structured.
type GapCandidate struct {
	Kind           string      `json:"kind"`
	Source         string      `json:"source,omitempty"`
	EventType      string      `json:"event_type,omitempty"`
	DetectorFamily string      `json:"detector_family,omitempty"`
	Severity       string      `json:"severity,omitempty"`
	FindingIDs     []string    `json:"finding_ids,omitempty"`
	SampleEventIDs []string    `json:"sample_event_ids,omitempty"`
	Evidence       GapEvidence `json:"evidence"`
}

// CollectEnvelope is the mallcop-pro-side DUPLICATE of mallcop's collectReport —
// the single versioned JSON envelope `mallcop collect --json` emits. Arrays are
// always non-null on the wire, so the consumer never special-cases JSON null.
type CollectEnvelope struct {
	SchemaVersion int            `json:"schema_version"`
	MappingGaps   []MappingGap   `json:"mapping_gaps"`
	GapCandidates []GapCandidate `json:"gap_candidates"`
}

// DecodeCollectEnvelope decodes a `mallcop collect --json` envelope, failing loud
// on an unknown field (schema drift) or a schema_version newer than supported.
// It is the proposer's process-boundary decoder — the ONLY place the collect
// wire shape is trusted, and it is trusted only structurally.
func DecodeCollectEnvelope(data []byte) (CollectEnvelope, error) {
	var env CollectEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return CollectEnvelope{}, fmt.Errorf("proposer: decode collect envelope: %w", err)
	}
	if env.SchemaVersion > collectSchemaVersion {
		return CollectEnvelope{}, fmt.Errorf("proposer: collect envelope schema_version %d newer than supported %d",
			env.SchemaVersion, collectSchemaVersion)
	}
	return env, nil
}
