// tuning.go — the HUMAN-WRITTEN loader for the data-externalized detector
// tuning knobs (detectors/tuning.yaml). K2b of the self-extension loop.
//
// THE CONTRACT (consensus-not-rules invariant): tuning may only WIDEN what the
// committee sees. That is not a code-review promise — it is ADD-ONLY BY
// CONSTRUCTION: the schema below has ONLY extra_* list fields. There is no
// field that removes, replaces, disables, or overrides a built-in keyword,
// action keyword, or event type — narrowing is INEXPRESSIBLE in the data. A
// proposal that wants to narrow the detector has no syntax to say it with; the
// strict decoder (KnownFields) rejects any unknown field loudly, so a
// smuggled "remove_*"/"override_*" key is a load error, not a silent no-op.
//
// Division of labor: the self-extension loop authors tuning.yaml as DATA; this
// loader (human-written, reviewed product code) is the only interpreter. The
// detector itself (priv_escalation.go) stays I/O-free — Detect() never reads a
// file; the CLI applies tuning once at startup via ApplyTuning.
package detect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// PrivEscalationTuning is the priv-escalation section of detectors/tuning.yaml.
// Every field is an ADDITIVE list — values are lowercased and ADDED to the
// detector's built-in sets by ApplyTuning. No field can express removal.
type PrivEscalationTuning struct {
	// ExtraElevatedKeywords are ADDITIONAL role/permission substrings that
	// indicate elevated access (joins elevatedKeywords).
	ExtraElevatedKeywords []string `yaml:"extra_elevated_keywords"`
	// ExtraElevatedActionKeywords are ADDITIONAL action substrings that indicate
	// elevation regardless of role fields (joins elevatedActionKeywords).
	ExtraElevatedActionKeywords []string `yaml:"extra_elevated_action_keywords"`
	// ExtraElevationEventTypes are ADDITIONAL event types that may carry
	// privilege escalation (joins elevationEventTypes).
	ExtraElevationEventTypes []string `yaml:"extra_elevation_event_types"`
}

// Tuning is the full detectors/tuning.yaml document. The zero value applies
// zero mutations: ApplyTuning(Tuning{}) leaves detection byte-identical.
type Tuning struct {
	PrivEscalation PrivEscalationTuning `yaml:"priv_escalation"`
}

// LoadTuningFile reads and strictly parses a tuning YAML file.
//
//   - Path does not exist       -> (Tuning{}, nil): silent fall-through — an
//     absent tuning file is the documented "no tuning" state, not an error.
//   - Present but empty         -> (Tuning{}, nil): zero mutations.
//   - Any parse error           -> loud error (a corrupt tuning file must never
//     silently degrade to "some knobs applied, some not").
//   - Any UNKNOWN yaml key      -> loud error (yaml.v3 strict KnownFields
//     decode) — catches both typos (extra_elevated_keyword) and any attempt to
//     introduce a non-additive field the schema does not carry.
func LoadTuningFile(path string) (Tuning, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Tuning{}, nil
		}
		return Tuning{}, fmt.Errorf("detect: read tuning file %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var t Tuning
	if err := dec.Decode(&t); err != nil {
		if errors.Is(err, io.EOF) {
			// Present-but-empty file: zero-value tuning, zero mutations.
			return Tuning{}, nil
		}
		return Tuning{}, fmt.Errorf("detect: parse tuning file %s: %w", path, err)
	}
	return t, nil
}

// ApplyTuning WIDENS the priv-escalation knob sets with the tuning's extra_*
// values: each value is trimmed, lowercased, and ADDED to the corresponding
// built-in set (elevatedKeywords / elevatedActionKeywords /
// elevationEventTypes). Nothing is ever removed — the only reachable mutation
// is set-insertion, so the committee's view can only grow.
//
// A zero-value Tuning applies zero mutations (detection stays byte-identical).
// Empty/whitespace-only entries are ignored. ApplyTuning mutates package-level
// state; the CLI calls it once at startup, before any Detect run.
func ApplyTuning(t Tuning) {
	for _, kw := range t.PrivEscalation.ExtraElevatedKeywords {
		if v := strings.ToLower(strings.TrimSpace(kw)); v != "" {
			elevatedKeywords[v] = true
		}
	}
	for _, kw := range t.PrivEscalation.ExtraElevatedActionKeywords {
		if v := strings.ToLower(strings.TrimSpace(kw)); v != "" {
			elevatedActionKeywords = append(elevatedActionKeywords, v)
		}
	}
	for _, et := range t.PrivEscalation.ExtraElevationEventTypes {
		if v := strings.ToLower(strings.TrimSpace(et)); v != "" {
			elevationEventTypes[v] = true
		}
	}
}
