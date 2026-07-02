// declarative.go — the K6 DECLARATIVE DETECTOR ENGINE. The primary moat-killer's
// detection half: "detect anything" expressed as DATA (detectors/rules.yaml) that
// this human-written loader interprets, NEVER as agent-authored detector code.
//
// THE DIVISION OF LABOR (mirrors tuning.go / connect/decl): the self-extension
// loop authors RULES as data; this file is the only interpreter. A Rule names an
// event-type gate, a match spec (regex / keyword / event-type-presence), a
// severity, a fixed-placeholder reason template, and a dedup key. LoadRules
// validates a rule corpus fail-loud and registers ONE declRule Detector per rule
// into the same package registry the 17 framework detectors use, so
// detect.Detect (hence `mallcop exam-detect`) picks them up with no further
// wiring. Registration happens ONLY at explicit LoadRules time, called from
// cmd/mallcop {scan,detect,exam-detect} startup — never from init(); hot-reload
// is deliberately out of scope (mallcop is a one-shot CLI).
//
// SAFETY BOUNDARIES (consensus-not-rules, invariants 1/9/10):
//   - A rule can only WIDEN detection: it adds a new finding family
//     ("decl:<name>"), never removes or narrows a built-in. The K3 guard treats
//     detectors/rules.yaml as append-only widen data (checkDeclRulesAppendOnly).
//   - Every rule.EventTypes entry must be a KnownEventTypes() member (empty =
//     gate on all events) — a rule can only act on a type some detector already
//     recognizes.
//   - The reason template substitutes ONLY the fixed tokens {actor} {event_type}
//     {match} {rule} in a SINGLE pass (strings.Replacer): replacement text is not
//     re-scanned, so a payload-derived value that itself contains "{rule}" cannot
//     inject a SECOND expansion into what the committee reads. Scope precisely:
//     the payload-derived values ({actor}, {event_type}, and the regex {match}
//     substring) are ATTACKER-CONTROLLED. This engine does NOT sanitize their
//     content; it BOUNDS the blast radius before they reach the committee-facing
//     free-text Reason — each is stripped of control chars/newlines, length-capped,
//     and wrapped in an untrusted-evidence delimiter (boxUntrusted) the committee
//     prompt treats as quoted evidence, never as instructions. The full raw matched
//     value is emitted losslessly ONLY in the structured Evidence JSON, mirroring
//     the framework detectors (injection_probe.go, which never echoes the attacker
//     payload into its Reason). Single-pass render prevents second-order token
//     re-expansion; the attacker-controlled match is bounded+quoted, not
//     interpolated verbatim.
//   - Detect is pure: no I/O, no network, no shared mutable state. It reads the
//     event's Payload (decoded per call) and emits findings; the leaked-goroutine
//     isolation contract in detect.go holds because a declRule owns only its own
//     immutable compiled spec.
package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// DeclNamePrefix is the family namespace every declarative rule detector lives
// under: a rule named "audit-tamper" registers as detector "decl:audit-tamper"
// and emits finding.Type "decl:audit-tamper". Namespacing keeps a loop-authored
// rule from ever colliding with (or impersonating) one of the 17 built-in
// families.
const DeclNamePrefix = "decl:"

// expectedDeclRulesSHA256 pins the sha256 of the committed detectors/rules.yaml
// seed. Belt-and-suspenders against tampering of the rules corpus AFTER deploy,
// exactly like core/tools/lookup_rules.go's operator-decisions pin: the primary
// defence is the K3 append-only guard, this is a runtime check that surfaces any
// out-of-band edit as a load error instead of a silent new detection family.
//
// The check is OPT-IN and OFF by default (dev/test edit the corpus freely):
//   - MALLCOP_DECL_RULES_SHA256 set non-empty -> that digest is expected
//     (overrides this constant); enforcement implicitly on.
//   - MALLCOP_DECL_RULES_SHA256_ENFORCE truthy -> this constant is expected.
//   - otherwise -> no enforcement.
//
// MAINTENANCE: regenerate with `sha256sum detectors/rules.yaml` whenever the
// committed seed changes. A widened corpus therefore needs a human re-pin under
// enforcement — the same no-mechanical-pair-exception posture the guard doc
// (core/selfgate/guard.go) describes for operator-decisions.
const expectedDeclRulesSHA256 = "3f97704dd74d138256fa828d924562da01862cdd3da30d4c1f5da3b51e58a66c"

// MatchKind enumerates how a rule inspects an event.
type MatchKind string

const (
	// MatchRegex — any Patterns[] regexp matches a scanned target string.
	MatchRegex MatchKind = "regex"
	// MatchKeyword — any Patterns[] keyword is a case-insensitive substring of a
	// scanned target string.
	MatchKeyword MatchKind = "keyword"
	// MatchEventTypePresent — the event's type satisfied the gate (EventTypes);
	// no payload inspection. Patterns/Fields are ignored.
	MatchEventTypePresent MatchKind = "event_type_present"
)

// DedupKey enumerates how a rule composes finding IDs so a match cannot flood:
// findings sharing an ID collapse downstream (the deduped findings snapshot).
type DedupKey string

const (
	// DedupActor — one finding per actor (ID keyed on actor).
	DedupActor DedupKey = "actor"
	// DedupActorType — one finding per (actor, event type).
	DedupActorType DedupKey = "actor_type"
	// DedupEvent — one finding per event (ID keyed on event id).
	DedupEvent DedupKey = "event"
)

// MatchSpec is a rule's match configuration.
type MatchSpec struct {
	// Kind selects the match strategy (regex | keyword | event_type_present).
	Kind MatchKind `yaml:"kind"`
	// Patterns are the regexps (Kind=regex) or keywords (Kind=keyword) to test.
	// Ignored for event_type_present.
	Patterns []string `yaml:"patterns"`
	// Fields are dotted payload paths (e.g. "metadata.user_agent") to scan. Empty
	// => recursively scan every string value in the decoded payload. Ignored for
	// event_type_present.
	Fields []string `yaml:"fields"`
}

// Rule is one declarative detector, authored as data.
type Rule struct {
	// Name is the rule identifier; the detector registers as "decl:"+Name and
	// emits finding.Type "decl:"+Name. Must be non-empty and unique in the file.
	Name string `yaml:"name"`
	// EventTypes gates which events the rule inspects. Empty => all events. Every
	// non-empty entry must be a KnownEventTypes() member (validated at load).
	EventTypes []string `yaml:"event_types"`
	// Match is the match spec.
	Match MatchSpec `yaml:"match"`
	// Severity is the emitted finding severity (critical|high|medium|low).
	Severity string `yaml:"severity"`
	// ReasonTemplate is the emitted finding reason. ONLY the fixed placeholders
	// {actor} {event_type} {match} {rule} are substituted, at render time, in a
	// single pass. The payload-derived values ({actor}/{event_type}/{match}) are
	// attacker-controlled, so renderReason bounds+delimits them (boxUntrusted)
	// before they enter the committee-facing free-text; the raw value lives only in
	// the structured Evidence (invariant 9/10).
	ReasonTemplate string `yaml:"reason_template"`
	// DedupKey composes the finding ID (actor|actor_type|event).
	DedupKey DedupKey `yaml:"dedup_key"`
}

// declRulesFile is the on-disk shape of detectors/rules.yaml.
type declRulesFile struct {
	Rules []Rule `yaml:"rules"`
}

// validSeverities / validDedupKeys / validMatchKinds are the closed enum sets
// the loader checks membership against (fail-loud on anything else).
var (
	validSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	validDedupKeys  = map[DedupKey]bool{DedupActor: true, DedupActorType: true, DedupEvent: true}
	validMatchKinds = map[MatchKind]bool{MatchRegex: true, MatchKeyword: true, MatchEventTypePresent: true}
)

// LoadRules reads, validates, and REGISTERS a declarative rule corpus, returning
// the number of rules registered. It is the human-written interpreter for the
// loop-authored detectors/rules.yaml data lane.
//
// Behaviour (mirrors LoadTuningFile / LoadOperatorRules):
//   - path absent (os.ErrNotExist) => (0, nil): the documented "no rules" state.
//   - present-but-empty => (0, nil).
//   - malformed YAML, an UNKNOWN field (strict KnownFields), a duplicate/empty
//     rule Name, an unknown enum, an EventTypes entry outside KnownEventTypes,
//     an uncompilable regex, or a Name that collides with an already-registered
//     detector (built-in or a prior decl rule) => a LOUD error and ZERO rules
//     registered (validation is fully two-phase: nothing registers unless every
//     rule validates, so a bad corpus never partially mutates the registry).
//   - sha256 pin mismatch when enforcement is engaged => a loud error.
//
// Registration goes through detect.Register (panics on a true duplicate), but
// the pre-check against the live registry guarantees Register never sees one —
// a colliding Name is a returned error, never a panic (a panic would be a DoS
// vector for a loop-authored corpus).
func LoadRules(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil // absent corpus => no rules, not an error.
		}
		return 0, fmt.Errorf("detect: read rules file %s: %w", path, err)
	}

	if err := verifyDeclRulesChecksum(data); err != nil {
		return 0, err
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var file declRulesFile
	if err := dec.Decode(&file); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil // present-but-empty => zero rules.
		}
		return 0, fmt.Errorf("detect: parse rules file %s: %w", path, err)
	}

	// PHASE 1 — validate every rule and build the detectors. Nothing is
	// registered until all rules pass, so a rejected corpus never leaves a
	// partially-mutated registry.
	existing := existingDetectorNames()
	existingFold := lowerKeySet(existing)
	seen := map[string]bool{}     // derived names claimed by THIS file
	seenFold := map[string]bool{} // case-folded derived names claimed by THIS file
	built := make([]*declRule, 0, len(file.Rules))
	known := KnownEventTypes()
	for i, r := range file.Rules {
		dr, err := compileRule(r, existing, existingFold, seen, seenFold, known)
		if err != nil {
			return 0, fmt.Errorf("detect: rules file %s: rule[%d]: %w", path, i, err)
		}
		seen[dr.Name()] = true
		seenFold[strings.ToLower(dr.Name())] = true
		built = append(built, dr)
	}

	// PHASE 2 — register. The pre-check above guarantees no duplicate reaches
	// Register (which would panic).
	for _, dr := range built {
		Register(dr)
	}
	return len(built), nil
}

// existingDetectorNames is the set of detector Names LoadRules must not collide
// with: every currently-registered detector (built-in framework detectors, any
// authored detectors the binary links, AND any decl rules a prior LoadRules
// already registered) PLUS the checked-in framework name list. The framework
// list is unioned in so the collision check is identical whether or not the
// running binary happens to link the framework detectors (the K7 shape gate
// relies on the same list for exactly this reason).
func existingDetectorNames() map[string]bool {
	out := map[string]bool{}
	for _, d := range Detectors() {
		out[d.Name()] = true
	}
	for _, n := range FrameworkDetectorNames() {
		out[n] = true
	}
	return out
}

// lowerKeySet returns a copy of m keyed by the lowercased key, for the
// case-insensitive rule-name collision check (fix: decl:foo vs decl:Foo).
func lowerKeySet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[strings.ToLower(k)] = true
	}
	return out
}

// compileRule validates one Rule and returns its ready-to-register declRule.
// existing is the pre-existing detector-name set; seen is the set of derived
// names already claimed by earlier rules in the same file; known is the event
// vocabulary. Every failure is a returned error (fail-loud) — compileRule never
// registers or mutates shared state.
func compileRule(r Rule, existing, existingFold, seen, seenFold map[string]bool, known map[string]bool) (*declRule, error) {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		return nil, errors.New("rule has an empty name")
	}
	// A rule may not impersonate an existing detector by its RAW name, nor may its
	// derived "decl:<name>" collide with an existing/earlier detector.
	if existing[name] {
		return nil, fmt.Errorf("rule name %q shadows an existing detector — decl rules register under the %q namespace and must not reuse a built-in name", name, DeclNamePrefix)
	}
	derived := DeclNamePrefix + name
	if existing[derived] || seen[derived] {
		return nil, fmt.Errorf("rule name %q collides with an already-registered detector %q (a duplicate would panic Register)", name, derived)
	}
	// Case-fold collision: eval aliases a finding family to a single lowercased
	// token, so "decl:foo" and "decl:Foo" would register as two DISTINCT detectors
	// yet collapse to ONE family token downstream — an ambiguous alias. Reject a
	// case-variant collision (with an existing detector OR an earlier rule in this
	// file) fail-loud rather than silently aliasing. (The exact-case checks above
	// catch true duplicates first with a Register-panic-specific message.)
	foldDerived := strings.ToLower(derived)
	if existingFold[foldDerived] || seenFold[foldDerived] {
		return nil, fmt.Errorf("rule name %q collides case-insensitively with an already-registered detector family (%q folds to %q) — decl rule names must be unique ignoring case so eval cannot alias two rules onto one family token", name, derived, foldDerived)
	}

	if !validMatchKinds[r.Match.Kind] {
		return nil, fmt.Errorf("rule %q: unknown match.kind %q (want regex|keyword|event_type_present)", name, r.Match.Kind)
	}
	if !validSeverities[strings.ToLower(strings.TrimSpace(r.Severity))] {
		return nil, fmt.Errorf("rule %q: unknown severity %q (want critical|high|medium|low)", name, r.Severity)
	}
	if !validDedupKeys[r.DedupKey] {
		return nil, fmt.Errorf("rule %q: unknown dedup_key %q (want actor|actor_type|event)", name, r.DedupKey)
	}
	if strings.TrimSpace(r.ReasonTemplate) == "" {
		return nil, fmt.Errorf("rule %q: reason_template is required", name)
	}

	// EventTypes gate: every entry must be a known vocabulary member. Empty is
	// allowed (gate on all events).
	gate := map[string]bool{}
	for _, et := range r.EventTypes {
		norm := strings.ToLower(strings.TrimSpace(et))
		if norm == "" {
			return nil, fmt.Errorf("rule %q: empty event_types entry", name)
		}
		if !known[norm] {
			return nil, fmt.Errorf("rule %q: event_type %q is not a known event type — a rule may only gate on a type some detector recognizes (detect.KnownEventTypes)", name, et)
		}
		gate[norm] = true
	}

	dr := &declRule{
		name:           name,
		severity:       strings.ToLower(strings.TrimSpace(r.Severity)),
		reasonTemplate: r.ReasonTemplate,
		dedupKey:       r.DedupKey,
		kind:           r.Match.Kind,
		fields:         append([]string(nil), r.Match.Fields...),
		eventTypes:     gate,
	}

	switch r.Match.Kind {
	case MatchEventTypePresent:
		// No patterns needed; payload is not inspected.
	case MatchKeyword:
		if len(r.Match.Patterns) == 0 {
			return nil, fmt.Errorf("rule %q: match.kind keyword requires at least one pattern", name)
		}
		for _, p := range r.Match.Patterns {
			kw := strings.ToLower(strings.TrimSpace(p))
			if kw == "" {
				return nil, fmt.Errorf("rule %q: empty keyword pattern", name)
			}
			dr.keywords = append(dr.keywords, keyword{lower: kw, display: p})
		}
	case MatchRegex:
		if len(r.Match.Patterns) == 0 {
			return nil, fmt.Errorf("rule %q: match.kind regex requires at least one pattern", name)
		}
		for _, p := range r.Match.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("rule %q: pattern %q does not compile: %w", name, p, err)
			}
			dr.regexps = append(dr.regexps, re)
		}
	}
	return dr, nil
}

// keyword pairs a lowercased keyword (for the case-insensitive test) with its
// original spelling (rendered into {match}).
type keyword struct {
	lower   string
	display string
}

// declRule is one compiled declarative rule as a Detector. It is IMMUTABLE after
// LoadRules builds it, so Detect stays pure and the leaked-goroutine isolation
// contract (detect.go) holds.
type declRule struct {
	name           string
	severity       string
	reasonTemplate string
	dedupKey       DedupKey
	kind           MatchKind
	fields         []string
	keywords       []keyword
	regexps        []*regexp.Regexp
	eventTypes     map[string]bool // gate; empty => all events
}

// Name returns the namespaced detector name ("decl:<rule-name>").
func (d *declRule) Name() string { return DeclNamePrefix + d.name }

// Detect applies the rule to every event, emitting one finding per matching
// event (deduped to a single ID per DedupKey). Pure: it decodes each event's
// payload locally and never touches shared state.
func (d *declRule) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if len(d.eventTypes) > 0 && !d.eventTypes[strings.ToLower(strings.TrimSpace(ev.Type))] {
			continue
		}
		matched, matchStr := d.matchEvent(ev)
		if !matched {
			continue
		}
		out = append(out, finding.Finding{
			ID:        d.dedupID(ev),
			Source:    "detector:" + d.Name(),
			Severity:  d.severity,
			Type:      d.Name(),
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    d.renderReason(ev, matchStr),
			Evidence:  d.evidence(ev, matchStr),
		})
	}
	return out
}

// matchEvent reports whether the event matches and, if so, the string rendered
// into {match}. event_type_present matches on the gate alone (matchStr = the
// event type); regex/keyword scan the selected fields (or the whole payload).
func (d *declRule) matchEvent(ev event.Event) (bool, string) {
	if d.kind == MatchEventTypePresent {
		return true, ev.Type
	}
	targets := d.scanTargets(ev.Payload)
	switch d.kind {
	case MatchKeyword:
		for _, t := range targets {
			lower := strings.ToLower(t)
			for _, kw := range d.keywords {
				if strings.Contains(lower, kw.lower) {
					return true, kw.display
				}
			}
		}
	case MatchRegex:
		for _, t := range targets {
			for _, re := range d.regexps {
				if m := re.FindString(t); m != "" {
					return true, m
				}
			}
		}
	}
	return false, ""
}

// scanTargets returns the string values the match tests against: every string
// under each configured Field path, or (Fields empty) every string in the whole
// decoded payload. A payload that does not decode yields no targets (no match).
func (d *declRule) scanTargets(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	var root any
	if err := json.Unmarshal(payload, &root); err != nil {
		return nil
	}
	var strs []string
	if len(d.fields) == 0 {
		collectStrings(root, &strs)
		return strs
	}
	for _, f := range d.fields {
		if v, ok := walkDeclPath(root, f); ok {
			collectStrings(v, &strs)
		}
	}
	return strs
}

// renderReason substitutes ONLY the fixed placeholders in the template, in a
// SINGLE left-to-right pass (strings.Replacer). Replacement text is NOT
// re-scanned, so a payload-derived {match}/{actor} value that itself contains
// "{rule}" (or any other token) cannot inject a second substitution into what
// the committee reads (invariant 9).
//
// The payload-derived values ({actor}, {event_type}, and the regex {match}
// substring) are ATTACKER-CONTROLLED and could otherwise carry unbounded prose or
// fake prompt structure into the committee-facing free-text, so each is passed
// through boxUntrusted (control-char strip + length cap + untrusted delimiter)
// before interpolation. {rule} is the rule-authored name (loop DATA gated by K3),
// not payload-derived, so it is interpolated as-is. The full raw matched value is
// still surfaced losslessly in the structured Evidence (see evidence()).
func (d *declRule) renderReason(ev event.Event, matchStr string) string {
	return strings.NewReplacer(
		"{actor}", boxUntrusted(ev.Actor),
		"{event_type}", boxUntrusted(ev.Type),
		"{match}", boxUntrusted(matchStr),
		"{rule}", d.name,
	).Replace(d.reasonTemplate)
}

const (
	// maxReasonValueRunes caps each payload-derived value interpolated into the
	// committee-facing free-text Reason, so a broad regex over an attacker field
	// cannot carry unbounded attacker prose into the prompt the committee reads.
	maxReasonValueRunes = 120
	// untrustedOpen / untrustedClose delimit a payload-derived value in the Reason
	// so the committee prompt treats the span as QUOTED EVIDENCE, never as
	// instructions. Distinctive markers unlikely to occur in a legitimate template.
	untrustedOpen  = "«untrusted:"
	untrustedClose = "»"
)

// boxUntrusted bounds, sanitizes, and delimits an attacker-controlled value before
// it is interpolated into the committee-facing free-text Reason. It (1) strips
// control characters and collapses whitespace so the value cannot inject newlines
// or fake prompt scaffolding, (2) caps it on a rune boundary, and (3) wraps it in
// an untrusted-evidence delimiter. The RAW, unbounded value is preserved losslessly
// in the structured Evidence JSON (evidence()) — nothing is lost for machine
// consumers; it is only kept out of the free-text prose. Mirrors injection_probe.go,
// which never echoes the attacker payload into its Reason.
func boxUntrusted(s string) string {
	s = sanitizeReasonValue(s)
	if r := []rune(s); len(r) > maxReasonValueRunes {
		s = string(r[:maxReasonValueRunes]) + "…"
	}
	return untrustedOpen + s + untrustedClose
}

// sanitizeReasonValue replaces every control character (incl. newlines/tabs) and
// whitespace run with a single space and trims the edges, so a payload-derived
// value cannot inject line structure into the committee prompt. It also DROPS the
// untrusted-box delimiter runes (« U+00AB / » U+00BB): otherwise an attacker-controlled
// value could close the «untrusted:…» span early and smuggle an instruction OUTSIDE
// the box, where the committee reads it as un-boxed (trusted) text — a forged box
// defeats the entire quoting guarantee (invariant 9).
func sanitizeReasonValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	pendingSpace := false
	for _, r := range s {
		if r == '«' || r == '»' {
			// Delimiter rune in attacker text — drop it so the box is unforgeable.
			continue
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			pendingSpace = true
			continue
		}
		if pendingSpace && b.Len() > 0 {
			b.WriteByte(' ')
		}
		pendingSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

// evidence emits structured (JSON) supporting data. It is machine-structured,
// not committee free-text, so echoing the matched value here is safe.
func (d *declRule) evidence(ev event.Event, matchStr string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{
		"rule":       d.name,
		"event_type": ev.Type,
		"match":      matchStr,
	})
	return b
}

// dedupID composes the finding ID per DedupKey so repeated matches collapse:
// per-actor, per-(actor,type), or per-event.
func (d *declRule) dedupID(ev event.Event) string {
	switch d.dedupKey {
	case DedupActorType:
		return "decl-" + d.name + "-actortype-" + ev.Actor + "-" + ev.Type
	case DedupEvent:
		return "decl-" + d.name + "-event-" + ev.ID
	default: // DedupActor
		return "decl-" + d.name + "-actor-" + ev.Actor
	}
}

// verifyDeclRulesChecksum enforces the sha256 pin on the rules corpus when
// configured (OPT-IN, OFF by default) — the same discipline as
// core/tools/lookup_rules.go's verifyOperatorRulesChecksum.
func verifyDeclRulesChecksum(data []byte) error {
	override := strings.TrimSpace(os.Getenv("MALLCOP_DECL_RULES_SHA256"))
	enforce := false
	expected := ""
	switch {
	case override != "":
		expected = strings.ToLower(override)
		enforce = true
	case isTruthyDeclEnv(os.Getenv("MALLCOP_DECL_RULES_SHA256_ENFORCE")):
		expected = strings.ToLower(expectedDeclRulesSHA256)
		enforce = true
	}
	if !enforce {
		return nil
	}
	got := sha256Hex(data)
	if got != expected {
		return fmt.Errorf("detect: rules.yaml sha256 mismatch: expected %s, got %s (corpus may be tampered; regenerate expectedDeclRulesSHA256 or check MALLCOP_DECL_RULES_SHA256)", expected, got)
	}
	return nil
}

// sha256Hex returns the lowercase-hex sha256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// isTruthyDeclEnv mirrors the truthy-env parsing used elsewhere.
func isTruthyDeclEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ---- minimal helpers (no external deps) -------------------------------------

// collectStrings appends every JSON string value reachable in v (a value decoded
// from JSON into map[string]any / []any / scalars) to out, recursively. Non-string
// scalars are ignored — keyword/regex matching is over text.
func collectStrings(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case map[string]any:
		for _, mv := range t {
			collectStrings(mv, out)
		}
	case []any:
		for _, iv := range t {
			collectStrings(iv, out)
		}
	}
}

// walkDeclPath resolves a dotted path against a JSON-decoded value. Segments
// split on '.'; a segment may carry trailing "[n]" array indices. An empty path
// selects the root. A missing key / out-of-range index / type mismatch yields
// (nil, false). This is the same minimal grammar connect/decl uses, reimplemented
// here so core/detect stays free of any connect import.
func walkDeclPath(root any, path string) (any, bool) {
	cur := root
	if strings.TrimSpace(path) == "" {
		return cur, true
	}
	for _, seg := range strings.Split(path, ".") {
		key, indices, ok := parseDeclSegment(seg)
		if !ok {
			return nil, false
		}
		if key != "" {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			cur, ok = m[key]
			if !ok {
				return nil, false
			}
		}
		for _, idx := range indices {
			arr, ok := cur.([]any)
			if !ok || idx < 0 || idx >= len(arr) {
				return nil, false
			}
			cur = arr[idx]
		}
	}
	return cur, true
}

// parseDeclSegment splits one dotted segment into its key and trailing array
// indices: "items[0]" -> ("items",[0]); "[2]" -> ("",[2]). A malformed bracket
// expression fails (ok=false).
func parseDeclSegment(seg string) (key string, indices []int, ok bool) {
	i := strings.IndexByte(seg, '[')
	if i < 0 {
		return seg, nil, true
	}
	key = seg[:i]
	rest := seg[i:]
	for len(rest) > 0 {
		if rest[0] != '[' {
			return "", nil, false
		}
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", nil, false
		}
		n, err := strconv.Atoi(rest[1:end])
		if err != nil {
			return "", nil, false
		}
		indices = append(indices, n)
		rest = rest[end+1:]
	}
	return key, indices, true
}
