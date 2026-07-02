// Package overlay is the shared LEARNED-MAPPING overlay: a widen-only data layer
// that maps a connector's raw action string to a known event_type, consulted
// ONLY when the connector's own classification fell through to its default
// bucket ("<sourceID>_other"). It is the self-extension loop's "learn to map a
// new source" data lane — DATA a human-written loader interprets, never
// connector code the agent authors.
//
// PLACEMENT: this package sits at top-level connect/ (OUTSIDE core/), like
// connect/github and connect/decl, so it may import gopkg.in/yaml.v3 without
// tripping core/lint's core/connect purity rule. It imports core/detect solely
// for KnownEventTypes()/IsKnownEventType — the single validation authority every
// mapped target is checked against.
//
// BASE-WINS, STRUCTURALLY: Apply returns an overlay target ONLY when the base
// classification is the default bucket AND an overlay entry exists. A conflicting
// overlay key for an action the connector already classifies is unreachable — the
// connector's own decision always wins, so the overlay can only ever WIDEN
// coverage of the long tail, never override a real classification.
package overlay

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/detect"
	"gopkg.in/yaml.v3"
)

// Overlay is an immutable learned-mapping lookup keyed source -> rawAction ->
// eventType. A nil *Overlay is a valid empty overlay (Apply is a no-op), so an
// absent learned-mappings file needs no special-casing at the call site.
type Overlay struct {
	bySource map[string]map[string]string
}

// LoadLearnedMappings reads a learned-mappings YAML from path into an Overlay.
// An empty path returns (nil, nil) — no overlay. A path that cannot be read is
// an error (fail-loud: the operator named a file). Every mapped target is
// validated against detect.KnownEventTypes(); an unknown target is a hard error
// naming the offending (source, action, target). The file shape is a top-level
// mapping source -> {rawAction -> event_type}, matching the guard's
// checkMappingWidenOnly parse.
func LoadLearnedMappings(path string) (*Overlay, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("overlay: read learned mappings %q: %w", path, err)
	}
	ov, err := ParseLearnedMappings(data)
	if err != nil {
		return nil, fmt.Errorf("overlay: %q: %w", path, err)
	}
	return ov, nil
}

// ParseLearnedMappings decodes and validates learned-mapping YAML bytes. It is
// the seam LoadLearnedMappings and tests share. An empty document yields a
// non-nil empty overlay (Apply is a no-op). Any non-string value or non-mapping
// shape is a decode error (fail-loud). Every target must be a KnownEventTypes
// member.
func ParseLearnedMappings(data []byte) (*Overlay, error) {
	var raw map[string]map[string]string
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && err != io.EOF {
		return nil, fmt.Errorf("not a source->action->event_type mapping: %w", err)
	}

	ov := &Overlay{bySource: map[string]map[string]string{}}
	for _, source := range sortedKeys(raw) {
		if strings.TrimSpace(source) == "" {
			return nil, fmt.Errorf("empty source key")
		}
		actions := raw[source]
		for _, action := range sortedKeys(actions) {
			target := actions[action]
			if strings.TrimSpace(action) == "" {
				return nil, fmt.Errorf("source %q has an empty action key", source)
			}
			if !detect.IsKnownEventType(target) {
				return nil, fmt.Errorf(
					"source %q action %q maps to unknown event_type %q (not in detect.KnownEventTypes — a learned mapping may only target a type some detector gates on)",
					source, action, target)
			}
			if ov.bySource[source] == nil {
				ov.bySource[source] = map[string]string{}
			}
			ov.bySource[source][action] = target
		}
	}
	return ov, nil
}

// Apply returns the event type for (sourceID, rawAction) given the connector's
// own base classification. BASE WINS STRUCTURALLY: the overlay is consulted ONLY
// when baseType is the default bucket "<sourceID>_other" AND an entry exists;
// otherwise baseType is returned unchanged. A nil overlay is a no-op.
func (o *Overlay) Apply(sourceID, rawAction, baseType string) string {
	if o == nil {
		return baseType
	}
	// The connector's own classification always wins: only a fall-through to the
	// default bucket is eligible for an overlay fill.
	if baseType != sourceID+"_other" {
		return baseType
	}
	if actions := o.bySource[sourceID]; actions != nil {
		if t, ok := actions[rawAction]; ok {
			return t
		}
	}
	return baseType
}

// sortedKeys returns the keys of a string-keyed map in sorted order (stable
// validation-error ordering).
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
