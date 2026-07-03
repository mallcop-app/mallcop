package detect

import "strings"

// vocab.go — the DERIVED event-type VOCABULARY.
//
// There is no authoritative event_type enum in the product; the ONLY authority
// for "what event types can a detector act on" is the set of literals the
// detectors actually GATE on. KnownEventTypes reconstructs that set BY REFERENCE
// to the live per-detector gate maps (so it can never fall out of sync with a
// detector that widens its own gate) PLUS a co-located list of the literals the
// inline-comparison detectors compare ev.Type against directly.
//
// It is the single validation authority consumed by the self-extension DATA
// lane: the learned-mapping overlay validates every mapped target against it. A
// target outside this set is rejected fail-loud — a learned mapping can only
// ever name a type some detector can already act on.
//
// COUPLING (vocab_test.go, invariant 11): a mechanical go/ast scan re-derives
// this set from the detector source — every gate-map key and every `ev.Type ==`
// / `switch ev.Type` literal — and asserts it EQUALS KnownEventTypes() in BOTH
// directions. So no member is dead (every member is a real gate) and no gate is
// missing (every gate literal is a member); the set cannot silently drift when a
// detector adds or removes a gate.

// literalGateEventTypes are the event types the INLINE-COMPARISON detectors gate
// on — detectors that compare ev.Type against string literals directly rather
// than indexing a map[string]bool gate set. Every entry is a real gate literal
// in a core/detect/*.go detector (proven exhaustive by vocab_test.go's AST scan):
//
//	git-oops            push / branch_delete / tag_delete       (git_oops.go)
//	unusual-login       login                                   (unusual_login.go)
//	rate-anomaly        api_request / api_burst / rate_event    (rate_anomaly.go)
//	malicious-skill     skill_install/_update/_register/_invoke (malicious_skill.go)
//	log-format-drift    log_format_drift                        (log_format_drift.go)
//	auth-failure-burst  login_failure / login_success           (auth_failure_burst.go)
//
// admin_action (priv_escalation.go:195) and dependency_add (dependency_tamper.go:174)
// are ALSO inline ev.Type comparisons, but they already belong to a gate map
// (builtinElevationEventTypes / depTamperEventTypes), so they are NOT duplicated
// here — the union with the map keys already covers them.
//
// The scan-all detectors (injection-probe, secrets-exposure, volume-anomaly,
// unusual-timing) gate on NO specific Type and contribute no vocabulary members.
var literalGateEventTypes = []string{
	"push", "branch_delete", "tag_delete",
	"login",
	"api_request", "api_burst", "rate_event",
	"skill_install", "skill_update", "skill_register", "skill_invoke",
	"log_format_drift",
	"login_failure", "login_success",
}

// KnownEventTypes returns a FRESH set of every event type any built-in detector
// gates on. The returned map is a new allocation each call: callers own it and
// MUST NOT mutate the gate maps it is built from (it aggregates their keys by
// reference-read, never by exposing the backing maps).
func KnownEventTypes() map[string]bool {
	out := make(map[string]bool)

	// (a) map-based gate sets, read by reference off the live detector vars.
	for _, gate := range []map[string]bool{
		builtinElevationEventTypes, // priv-escalation
		entityCreationEventTypes,   // new-actor (created entity)
		externalAccessEventTypes,   // new-external-access
		exfilEventTypes,            // exfil-pattern
		depTamperEventTypes,        // dependency-tamper
		resourceAccessEventTypes,   // unusual-resource-access
	} {
		for k := range gate {
			out[k] = true
		}
	}

	// (b) config-drift's per-event-type rule table (built in config_drift.go's
	// init from configRules; fully populated by the time any caller runs).
	for k := range configRuleByEventType {
		out[k] = true
	}

	// (c) the inline-comparison detectors.
	for _, t := range literalGateEventTypes {
		out[t] = true
	}

	return out
}

// CanonicalEventType is the SINGLE normalization applied to an event type before
// membership/gate comparison: lowercase + trim (mirrors config_drift.go's ev.Type
// handling). It is the canonical spelling every KnownEventTypes member is already
// in (the gate literals are lowercase, untrimmed), so it is BOTH the form
// IsKnownEventType matches against AND the form the self-extension DATA lanes must
// EMIT a mapped target in.
//
// SOUNDNESS (invariant 10): the case-sensitive typed detectors gate on the bare
// lowercase literal (e.g. unusual_login.go `ev.Type != "login"`, git_oops.go
// `ev.Type != "push"`), so a validated-but-non-canonical target like "PUSH" or
// " login " would pass IsKnownEventType (which normalizes the QUERY) yet be
// EMITTED verbatim and silently never fire. The learned-mapping overlay
// therefore canonicalizes the target through THIS function before
// emitting/storing it, so a target that validates as known is emitted in the
// exact spelling the typed detectors gate on.
func CanonicalEventType(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// IsKnownEventType reports whether s names an event type some built-in detector
// gates on. It normalizes the query through CanonicalEventType; every
// KnownEventTypes member is itself already canonical, so normalizing the query is
// sufficient. This is the fail-loud membership check the learned-mapping overlay
// uses to reject an unknown target.
func IsKnownEventType(s string) bool {
	return KnownEventTypes()[CanonicalEventType(s)]
}
