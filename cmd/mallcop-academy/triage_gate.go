// Rung-2 deterministic triage gate (Wk2 — mallcoppro-379, v2 amend).
//
// Trigger: when all of the following hold for a non-rung-0 scenario, emit a
// synthetic terminal-resolved event at zero LLM cost and skip the normal
// work:create dispatch:
//
//  1. DetectorNotBlocked: detector ∉ NEVER_AUTO_RESOLVE
//  2. NonCriticalSeverity: finding.severity != "critical"
//  3. IsKnownActor: finding.metadata.actor ∈ baseline.known_entities.actors
//  4. TypedHistory: countTypedEvents(actor, event_type) ≥ 3
//     Count only freq-table entries where BOTH event_type AND actor match the
//     finding's metadata.event_type and metadata.actor (key format:
//     source:event_type:actor — 3-part exact match on parts[1] and parts[2]).
//  5. SpecializationRatio: typed_count / total_actor_events ≥ 0.05
//     The event_type must constitute ≥5% of the actor's total observed history.
//     total_actor_events is the sum over all freq-table entries ending in
//     ":<actor>" (i.e. parts[len-1] == actor — matches legacy countPriorEvents
//     semantics, inclusive of 5-part time-bucketed keys).
//
// Critical-severity findings NEVER auto-resolve regardless of baseline.
// Rung-0 detectors take precedence: the rung-0 check runs before this gate
// (see cmd/mallcop-academy/main.go wiring), so rung-0 detectors never reach
// rung-2 evaluation.
//
// # Legacy Python source
//
// Port of the rung-2 logic from mallcop/src/mallcop/resolution_rules.py.
// The Python predicate uses a 4-tuple detector:actor:event_type:target_prefix
// with human-feedback confirmation. This Go gate is the deterministic subset —
// no target-prefix match and no human-feedback path. Type-tuple + ratio is the
// closest Go equivalent that is fully deterministic against the 57-scenario corpus.
//
// # Known unfixable by any frequency predicate
//
// Two scenarios cannot be correctly classified by any predicate over
// FrequencyTables alone and remain on the LLM path:
//
//   - UT-05 (AiTM proxy): admin-user performing routine logins — high typed_count
//     and high ratio — but the session originates from a VPS IP (AiTM attack).
//     Discrimination requires IP-geo/ISP reasoning not in FrequencyTables.
//
//   - BG-01 (borderline timing): admin-user with moderate baseline — concurrent
//     anomaly cluster (IP shift + user-agent change + late timing) that each have
//     plausible benign explanations individually. Frequency alone cannot distinguish
//     this from a benign marginal-variation case.
//
// Both are documented here. Do NOT add their detectors to NEVER_AUTO_RESOLVE —
// they do not have a single discriminating detector class. They are handled by the
// LLM chain and are outside the scope of any frequency-based gate.
//
// # Resonance loop (RPT §3.5)
//
// Auto-resolve is a side-channel that emits zero detector telemetry — a §3.5
// violation. The shadow-LLM sampler (mallcoppro-W2A-shadow, P1) addresses this:
// 5–10% of auto-resolved scenarios are also dispatched to the slow LLM chain;
// disagreement rate is tracked; the predicate is auto-disabled if disagreement
// exceeds 2% over a rolling window. The sampler is a SEPARATE item and does not
// block this PR. Do NOT implement sampler hooks here.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/thirdiv/mallcop-legion/internal/exam"
)

// neverAutoResolveDetectors is the set of detector classes that must NEVER be
// auto-resolved by the rung-2 gate, even when all other predicate conditions
// hold. These detectors are hard security constraints (same set as rung-0's
// alwaysEscalateDetectors) and require human review or LLM-driven triage.
//
// DO NOT remove detectors from this set. The safety invariant is one-way:
// new detectors may be added to block auto-resolve; existing ones may not be
// removed without a design-deliberation ruling.
var neverAutoResolveDetectors = map[string]bool{
	"priv-escalation":    true, // privilege changes always need audit
	"log-format-drift":   true, // structural drift = security blind spot
	"injection-probe":    true, // prompt-injection attempts
	"boundary-violation": true, // access-boundary violations
}

// minPriorTypedEvents is the minimum number of typed (actor + event_type matching)
// prior events for an actor to qualify for auto-resolve. Condition 4.
// NOTE: The ≥3 → ≥1 relaxation pathway from the original spec is REMOVED.
// The qualitative bug (KA shortcut attacks) is fixed by the specialization ratio
// (condition 5), not by adjusting this count. Do not lower this constant.
const minPriorTypedEvents = 3

// minTypeRatio is the minimum specialization ratio:
// typed_count / total_actor_events must be ≥ this threshold. Condition 5.
// Empirically anchored against the full 57-scenario corpus: yields 7 correct SCs
// with zero false resolves on the KA-negative set (excluding known-unfixable
// UT-05 and BG-01 which require qualitative reasoning). Do NOT change this
// without re-running the corpus analysis.
const minTypeRatio = 0.05

// triageGatePredicate evaluates the rung-2 gate conditions for a scenario.
// Returns (reason, true) if all conditions pass and the scenario should be
// auto-resolved. Returns ("", false) if any condition fails and the scenario
// must fall through to the normal LLM triage path.
//
// Conditions (all must hold, evaluated in order):
//  1. detector ∉ neverAutoResolveDetectors
//  2. finding.severity != "critical"
//  3. actor is in baseline.known_entities.actors
//  4. countTypedEvents(actor, event_type) ≥ minPriorTypedEvents
//  5. typed_count / total_actor_events ≥ minTypeRatio
func triageGatePredicate(s *exam.Scenario) (string, bool) {
	if s == nil || s.Finding == nil {
		return "", false
	}

	// Condition 1: detector must not be in the never-auto-resolve set.
	// Rung-0 runs before this gate for these detectors, but this guard
	// provides defense-in-depth if called out of order.
	if neverAutoResolveDetectors[s.Finding.Detector] {
		return "", false
	}

	// Condition 2: critical-severity findings never auto-resolve.
	if strings.EqualFold(s.Finding.Severity, "critical") {
		return "", false
	}

	// Extract actor from finding.metadata.actor (canonical field).
	// Fall back to empty string if absent — empty actor fails condition 3.
	actor := extractActor(s.Finding.Metadata)

	// Condition 3: actor must be in baseline.known_entities.actors.
	if !isKnownActor(s.Baseline, actor) {
		return "", false
	}

	// Extract event_type from finding.metadata.event_type.
	// Empty event_type produces typed_count=0, failing condition 4.
	eventType := extractEventType(s.Finding.Metadata)

	// Condition 4: actor must have ≥ minPriorTypedEvents typed events.
	typedCount := countTypedEvents(s.Baseline, actor, eventType)
	if typedCount < minPriorTypedEvents {
		return "", false
	}

	// Condition 5: specialization ratio must be ≥ minTypeRatio.
	total := countActorTotalEvents(s.Baseline, actor)
	if total == 0 {
		return "", false
	}
	ratio := float64(typedCount) / float64(total)
	if ratio < minTypeRatio {
		return "", false
	}

	reason := fmt.Sprintf(
		"Rung-2 deterministic resolve: actor=%q is known, severity=%q (non-critical), "+
			"detector=%q is not in never-auto-resolve set, "+
			"typed_count(%s,%s)=%d (≥%d threshold), "+
			"total_actor_events=%d, specialization_ratio=%.3f (≥%.2f threshold). "+
			"Short-circuited at zero LLM cost (reason=known-pattern-deterministic).",
		actor, s.Finding.Severity, s.Finding.Detector,
		eventType, actor, typedCount, minPriorTypedEvents,
		total, ratio, minTypeRatio,
	)
	return reason, true
}

// extractActor reads the "actor" key from a finding's metadata map.
// Returns "" if the key is absent or not a string.
func extractActor(metadata exam.FindingMetadata) string {
	if metadata == nil {
		return ""
	}
	v, ok := metadata["actor"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// extractEventType reads the "event_type" key from a finding's metadata map.
// Returns "" if the key is absent or not a string.
func extractEventType(metadata exam.FindingMetadata) string {
	if metadata == nil {
		return ""
	}
	v, ok := metadata["event_type"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// isKnownActor reports whether actor appears in baseline.known_entities.actors.
// Returns false if baseline is nil or known_entities.actors is empty.
func isKnownActor(baseline *exam.Baseline, actor string) bool {
	if baseline == nil || actor == "" {
		return false
	}
	for _, a := range baseline.KnownEntities.Actors {
		if a == actor {
			return true
		}
	}
	return false
}

// countTypedEvents counts prior events where BOTH the actor AND event_type match
// the finding's metadata. Only 3-part keys "source:event_type:actor" are matched
// (parts[1] == eventType AND parts[2] == actor). Keys with more than 3 parts
// (e.g. time-bucketed keys "source:event_type:actor:dow:period") are excluded —
// they represent sub-typed signals, not the canonical event_type count.
//
// This replaces the old countPriorEvents which matched on actor alone (last segment),
// making it vulnerable to KA-failure-mode shortcut attacks where actors with
// high total history could auto-resolve on unrelated event types.
func countTypedEvents(baseline *exam.Baseline, actor, eventType string) int {
	if baseline == nil || actor == "" || eventType == "" {
		return 0
	}
	total := 0
	for k, v := range baseline.FrequencyTables {
		// Key format: "source:event_type:actor" — exactly 3 parts.
		// Do not match 5-part time-bucketed keys like "source:event_type:actor:dow:period".
		parts := strings.Split(k, ":")
		if len(parts) == 3 && parts[1] == eventType && parts[2] == actor {
			total += v
		}
	}
	return total
}

// countActorTotalEvents counts all prior events for an actor across ALL event types.
// Keys are matched by the last colon-delimited segment equaling actor — this is
// inclusive of 3-part and 5-part time-bucketed keys, which is intentional: we want
// the full historical footprint to compute a meaningful specialization ratio.
//
// This preserves the semantics of the old countPriorEvents function, used here
// only as the denominator in the specialization ratio (condition 5).
func countActorTotalEvents(baseline *exam.Baseline, actor string) int {
	if baseline == nil || actor == "" {
		return 0
	}
	total := 0
	for k, v := range baseline.FrequencyTables {
		parts := strings.Split(k, ":")
		if len(parts) >= 1 && parts[len(parts)-1] == actor {
			total += v
		}
	}
	return total
}

// triageGateResolvedPayload is the synthetic work:close payload posted to the
// work campfire when rung-2 short-circuits a scenario.
type triageGateResolvedPayload struct {
	ItemID    string `json:"item_id"`
	Action    string `json:"action"`
	Skill     string `json:"skill"`
	Reason    string `json:"reason"`
	FindingID string `json:"finding_id"`
}

// seedTriageGateResolve handles a scenario that passes the rung-2 predicate.
// It posts a synthetic terminal-resolved event to the work campfire and
// populates the trackedScenario as terminal (action="resolved", chain length 1).
// No work:create is posted — LLM worker spawn count is exactly zero.
//
// Returns the synthetic close message ID so the caller can register it in
// workItemToScenario for watch-loop bookkeeping symmetry with the LLM path.
func seedTriageGateResolve(
	sender Sender,
	s *exam.Scenario,
	runID, campfireID, reason string,
	ts *trackedScenario,
) (string, error) {
	syntheticItemID := "rung2-" + findingTrackingID(runID, s.ID)

	payload := triageGateResolvedPayload{
		ItemID:    syntheticItemID,
		Action:    "resolved",
		Skill:     "task:triage-gate",
		Reason:    reason,
		FindingID: s.Finding.ID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal triage-gate payload: %w", err)
	}

	tags := []string{
		"work:close",
		"action:resolved",
		"academy:triage-gate",
		"detector:" + s.Finding.Detector,
		"scenario:" + s.ID,
		"run:" + runID,
		"finding:" + s.Finding.ID,
	}
	msgID, err := sender.send(campfireID, string(body), tags)
	if err != nil {
		return "", fmt.Errorf("post synthetic terminal-resolved: %w", err)
	}

	now := time.Now()

	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.workItemID = syntheticItemID
	ts.postedAt = now
	ts.chain = []ChainEntry{{
		ItemID: syntheticItemID,
		Skill:  "task:triage-gate",
		Action: "resolved",
	}}
	ts.terminal = true
	ts.terminalAt = now
	ts.terminalAction = "resolved"
	ts.terminalItemID = syntheticItemID
	ts.terminalReason = reason
	// Triage close action mirrors the terminal action so grading code that
	// inspects triageCloseAction sees the deterministic resolve, not "".
	ts.triageCloseAction = "resolved"

	return msgID, nil
}
