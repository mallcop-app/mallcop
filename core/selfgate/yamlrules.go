// yamlrules.go — the SEMANTIC widen-only rules the guard applies to YAML data
// the self-extension loop is allowed to modify in place. Two checkers:
//
//   - checkOperatorDecisions: agents/rules/operator-decisions.yaml. Pure
//     widens only — new escalate_routes entries or alias additions to an
//     existing route with every other field identical. The rules: section
//     (global resolution rules) is entirely frozen.
//   - checkWidenOnlyYAML: detectors/tuning.yaml (and future widen-only data
//     overlays, e.g. connect learned_mappings). For every list under every
//     section, old must be a subset of new after the same lowercase/trim
//     normalization core/detect's ApplyTuning applies.
//
// Both checkers FAIL CLOSED: an unparseable document, an unrecognized shape,
// or an unknown top-level section change is a rejection, never a pass.
package selfgate

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---- operator-decisions.yaml ------------------------------------------------

// checkOperatorDecisions enforces the pure-widen semantic rule on
// agents/rules/operator-decisions.yaml.
//
// PASS (pure widens only):
//   - a NEW escalate_routes entry (new unique id) — purely additive: findings
//     matching the new route now escalate; nothing else changes. A new route
//     MAY carry a metadata_match: it narrows only its own (new) firing
//     condition, so the floor still only grows.
//   - alias ADDITIONS to an existing route with all other fields identical —
//     more spellings collapse onto the same escalation, a strict widen.
//
// HARD-FAIL:
//   - removal of any existing route, or removal of any existing alias;
//   - mutation of any non-alias field on an existing route;
//   - ADDING or expanding metadata_match on an existing route — the predicate
//     is conjunctive, so attaching/extending it NARROWS when the route fires;
//   - ANY change under the rules: section — the global resolution rules are
//     frozen (consensus-not-rules, invariant 1);
//   - any unrecognized top-level section or unparseable document (fail closed).
//
// NOTE (design decision, no mechanical-pair exception): a PASSING widen here is
// ADDITIVE (new routes / alias additions only). As DEFENCE-IN-DEPTH, the sha256
// pin on this file (core/tools/lookup_rules.go expectedOperatorRulesSHA256)
// lives on a protected path the proposal cannot touch, so — WHEN sha256
// enforcement is enabled in the deployment env (MALLCOP_RULES_SHA256_ENFORCE
// set truthy, or an explicit MALLCOP_RULES_SHA256 digest; the check is OPT-IN
// and OFF by default, see verifyOperatorRulesChecksum) — the runtime corpus SHA
// check fires until a human re-pins. The pin coupling is a deployment-
// conditional defence, not an unconditional guarantee; the widen-only rules
// enforced here are the always-on floor.
func checkOperatorDecisions(p string, baseData, headData []byte) []GuardFinding {
	reject := func(format string, args ...any) []GuardFinding {
		return []GuardFinding{{Path: p, Rule: RuleOperatorDecisionsWidenOnly, Detail: fmt.Sprintf(format, args...)}}
	}

	baseDoc, err := decodeYAMLMap(baseData)
	if err != nil {
		return reject("base version unparseable (%v) — cannot prove a widen, fail closed", err)
	}
	headDoc, err := decodeYAMLMap(headData)
	if err != nil {
		return reject("head version unparseable (%v) — fail closed", err)
	}

	var findings []GuardFinding

	// Only the two known sections may exist, in either version. Anything else
	// is an unrecognized shape — fail closed.
	for _, doc := range []map[string]any{baseDoc, headDoc} {
		for key := range doc {
			if key != "escalate_routes" && key != "rules" {
				findings = append(findings, GuardFinding{Path: p, Rule: RuleOperatorDecisionsWidenOnly,
					Detail: fmt.Sprintf("unrecognized top-level section %q — fail closed", key)})
			}
		}
	}
	if len(findings) > 0 {
		return findings
	}

	// rules: — the global resolution rules are FROZEN. Any difference (added,
	// removed, reordered, or mutated entry) is a rejection.
	if !reflect.DeepEqual(baseDoc["rules"], headDoc["rules"]) {
		findings = append(findings, GuardFinding{Path: p, Rule: RuleOperatorDecisionsWidenOnly,
			Detail: "the rules: section (global resolution rules) is frozen — no additions, removals, or mutations (invariant 1)"})
	}

	// escalate_routes: — widen-only.
	baseRoutes, errs := routesByID(p, baseDoc["escalate_routes"], "base")
	findings = append(findings, errs...)
	headRoutes, errs := routesByID(p, headDoc["escalate_routes"], "head")
	findings = append(findings, errs...)
	if len(findings) > 0 {
		return findings
	}

	for _, id := range sortedKeys(baseRoutes) {
		baseRoute := baseRoutes[id]
		headRoute, ok := headRoutes[id]
		if !ok {
			findings = append(findings, GuardFinding{Path: p, Rule: RuleOperatorDecisionsWidenOnly,
				Detail: fmt.Sprintf("escalate route %q removed — removing a route lowers the pre-LLM floor", id)})
			continue
		}
		findings = append(findings, compareRoute(p, id, baseRoute, headRoute)...)
	}
	// Head-only ids are new routes: allowed (already shape-checked by
	// routesByID — a map with a unique non-empty string id).

	return findings
}

// compareRoute checks one existing escalate route base→head: aliases may only
// GROW; every other field must be identical.
func compareRoute(p, id string, base, head map[string]any) []GuardFinding {
	var findings []GuardFinding
	reject := func(format string, args ...any) {
		findings = append(findings, GuardFinding{Path: p, Rule: RuleOperatorDecisionsWidenOnly, Detail: fmt.Sprintf(format, args...)})
	}

	keys := map[string]bool{}
	for k := range base {
		keys[k] = true
	}
	for k := range head {
		keys[k] = true
	}
	for _, k := range sortedKeys(keys) {
		baseVal, inBase := base[k]
		headVal, inHead := head[k]
		switch {
		case k == "aliases":
			baseAliases, err := stringList(baseVal)
			if err != nil {
				reject("route %q: base aliases %v — fail closed", id, err)
				continue
			}
			headAliases, err := stringList(headVal)
			if err != nil {
				reject("route %q: head aliases %v — fail closed", id, err)
				continue
			}
			headSet := map[string]bool{}
			for _, a := range headAliases {
				headSet[a] = true
			}
			for _, a := range baseAliases {
				if !headSet[a] {
					reject("route %q: alias %q removed — alias sets may only grow", id, a)
				}
			}
		case !inBase && k == "metadata_match":
			reject("route %q: metadata_match added to an existing route — the conjunctive predicate NARROWS when the route fires", id)
		case !inBase:
			reject("route %q: field %q added — existing routes admit only alias additions", id, k)
		case !inHead:
			reject("route %q: field %q removed — existing routes admit only alias additions", id, k)
		case !reflect.DeepEqual(baseVal, headVal):
			if k == "metadata_match" {
				reject("route %q: metadata_match changed on an existing route — expanding the conjunctive predicate NARROWS when the route fires", id)
			} else {
				reject("route %q: field %q mutated — existing routes admit only alias additions", id, k)
			}
		}
	}
	return findings
}

// routesByID validates the escalate_routes section shape (a sequence of maps,
// each with a unique non-empty string id) and indexes it by id. Shape
// violations fail closed.
func routesByID(p string, v any, which string) (map[string]map[string]any, []GuardFinding) {
	reject := func(format string, args ...any) (map[string]map[string]any, []GuardFinding) {
		return nil, []GuardFinding{{Path: p, Rule: RuleOperatorDecisionsWidenOnly, Detail: fmt.Sprintf(format, args...)}}
	}
	routes := map[string]map[string]any{}
	if v == nil {
		return routes, nil
	}
	list, ok := v.([]any)
	if !ok {
		return reject("%s escalate_routes is not a sequence — fail closed", which)
	}
	for i, item := range list {
		route, ok := item.(map[string]any)
		if !ok {
			return reject("%s escalate_routes[%d] is not a mapping — fail closed", which, i)
		}
		id, ok := route["id"].(string)
		if !ok || strings.TrimSpace(id) == "" {
			return reject("%s escalate_routes[%d] has no non-empty string id — fail closed", which, i)
		}
		if _, dup := routes[id]; dup {
			return reject("%s escalate_routes has duplicate id %q — fail closed", which, id)
		}
		routes[id] = route
	}
	return routes, nil
}

// ---- widen-only list data (detectors/tuning.yaml + future overlays) ---------

// tuningKnownSchema mirrors core/detect/tuning.go's Tuning struct: the ONLY
// top-level sections, and the ONLY fields within each, that the human-written
// loader recognizes for detectors/tuning.yaml. checkWidenOnlyYAML fails closed
// on anything else, so an unknown top-level section or an unknown field is
// rejected at the GUARD layer — not left to be caught downstream by the loader's
// strict KnownFields decode or by exam-detect (a head-only unknown section would
// otherwise sail past the widen subset check, since head-only IS the widen).
// If the loader gains a new additive field, extend this in the SAME change: the
// guard schema and the loader schema move together.
var tuningKnownSchema = map[string]map[string]bool{
	"priv_escalation": {
		"extra_elevated_keywords":        true,
		"extra_elevated_action_keywords": true,
		"extra_elevation_event_types":    true,
	},
}

// checkWidenOnlyYAML enforces the widen-direction rule on section→field→list
// YAML data (detectors/tuning.yaml today; future connect learned_mappings
// overlays use the same checker). For every list under every section, the base
// elements must be a SUBSET of the head elements — set semantics, after the
// same lowercase/trim normalization core/detect's ApplyTuning applies.
// Absent-in-base → present-in-head is fine (that IS the widen); any removed or
// changed element is a rejection. Any document that is not
// mapping→mapping→list-of-strings is an unrecognized shape — fail closed.
func checkWidenOnlyYAML(p string, baseData, headData []byte) []GuardFinding {
	reject := func(format string, args ...any) []GuardFinding {
		return []GuardFinding{{Path: p, Rule: RuleDetectorDataWidenOnly, Detail: fmt.Sprintf(format, args...)}}
	}

	base, err := decodeWidenDoc(baseData)
	if err != nil {
		return reject("base version: %v — cannot prove a widen, fail closed", err)
	}
	head, err := decodeWidenDoc(headData)
	if err != nil {
		return reject("head version: %v — fail closed", err)
	}

	var findings []GuardFinding

	// SECTION / FIELD ALLOWLIST (fail closed, mirroring checkOperatorDecisions).
	// Only sections and fields the loader (tuningKnownSchema) recognizes may
	// appear, in EITHER version. A head-only unknown top-level section or field
	// is the widen direction and would pass the subset check below — so reject
	// it HERE instead of relying on exam-detect / the loader to catch it later.
	for _, doc := range []map[string]map[string][]string{base, head} {
		for _, section := range sortedKeys(doc) {
			allowedFields, ok := tuningKnownSchema[section]
			if !ok {
				findings = append(findings, GuardFinding{Path: p, Rule: RuleDetectorDataWidenOnly,
					Detail: fmt.Sprintf("unrecognized top-level section %q — the tuning loader (core/detect) declares no such section; fail closed", section)})
				continue
			}
			for _, field := range sortedKeys(doc[section]) {
				if !allowedFields[field] {
					findings = append(findings, GuardFinding{Path: p, Rule: RuleDetectorDataWidenOnly,
						Detail: fmt.Sprintf("section %q: unrecognized field %q — the tuning loader declares no such field; fail closed", section, field)})
				}
			}
		}
	}
	if len(findings) > 0 {
		return findings
	}

	for _, section := range sortedKeys(base) {
		headSection, ok := head[section]
		if !ok {
			findings = append(findings, GuardFinding{Path: p, Rule: RuleDetectorDataWidenOnly,
				Detail: fmt.Sprintf("section %q removed — narrowing", section)})
			continue
		}
		for _, field := range sortedKeys(base[section]) {
			headList, ok := headSection[field]
			if !ok {
				findings = append(findings, GuardFinding{Path: p, Rule: RuleDetectorDataWidenOnly,
					Detail: fmt.Sprintf("%s.%s removed — narrowing", section, field)})
				continue
			}
			headSet := map[string]bool{}
			for _, v := range headList {
				headSet[v] = true
			}
			for _, v := range base[section][field] {
				if !headSet[v] {
					findings = append(findings, GuardFinding{Path: p, Rule: RuleDetectorDataWidenOnly,
						Detail: fmt.Sprintf("%s.%s: element %q removed — every base element must survive into head (widen-only)", section, field, v)})
				}
			}
		}
	}
	// Head-only sections/fields/elements are the widen — allowed.
	return findings
}

// decodeWidenDoc decodes and shape-validates a widen-only data document:
// mapping of section → mapping of field → list of strings. Elements are
// normalized with the SAME lowercase/trim rule core/detect's ApplyTuning uses,
// so the guard's subset check matches what the loader actually applies. A nil
// (empty) document is an empty map. Anything else is an error (fail closed).
func decodeWidenDoc(data []byte) (map[string]map[string][]string, error) {
	raw, err := decodeYAMLMap(data)
	if err != nil {
		return nil, fmt.Errorf("unparseable (%v)", err)
	}
	doc := map[string]map[string][]string{}
	for section, sv := range raw {
		fields, ok := sv.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unrecognized structure: section %q is not a mapping", section)
		}
		doc[section] = map[string][]string{}
		for field, fv := range fields {
			list, err := stringList(fv)
			if err != nil {
				return nil, fmt.Errorf("unrecognized structure: %s.%s %v", section, field, err)
			}
			normalized := make([]string, 0, len(list))
			for _, v := range list {
				if n := strings.ToLower(strings.TrimSpace(v)); n != "" {
					normalized = append(normalized, n)
				}
			}
			doc[section][field] = normalized
		}
	}
	return doc, nil
}

// ---- shared decode helpers ---------------------------------------------------

// decodeYAMLMap decodes a YAML document into a string-keyed map. A nil/empty
// document decodes to an empty map. A non-mapping document is an error.
func decodeYAMLMap(data []byte) (map[string]any, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		doc = map[string]any{}
	}
	return doc, nil
}

// stringList coerces a decoded YAML value into a []string. nil is an empty
// list. Any non-list value or non-string element is an error (fail closed).
func stringList(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("is not a list")
	}
	out := make([]string, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("element %d is not a string", i)
		}
		out = append(out, s)
	}
	return out, nil
}

// sortedKeys returns the keys of a string-keyed map in sorted order, for
// deterministic finding ordering.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
