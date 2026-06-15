// tools_f1g_gate.go — F2A confidence-score pre-close gate for resolve-finding.
//
// When MALLCOP_SKILL=task:investigate OR task:triage, runResolveFinding calls
// checkConfidenceGate before emitting work:output. If the structural confidence
// score for the session is below the configured floor, the gate fires.
//
// The fan-out semantic depends on the skill that fired the gate:
//
//   - task:investigate (existing): emits 4 work:create messages
//     1. write-partial-transcript
//     2. escalate-to-deep (benign)
//     3. escalate-to-deep (malicious)
//     4. escalate-to-deep (incomplete)
//     5. create-investigate-merge wired to the 3 deep ids
//
//   - task:triage (mallcoppro-499): emits 1 work:create — a force escalate-to-
//     investigator handoff. Triage is a 2-tool flow; spending fan-out donuts on
//     a 3-way deep-investigate panel for a triage short-circuit is overkill.
//     The correct structural response to "triage resolved with insufficient
//     evidence" is "make the investigator do the work," not "spawn a panel."
//
// The gate decision lives in binary code — the agent CANNOT skip it from prompt.
//
// # Configuration
//
// Weights and thresholds are read from environment variables. Prefix:
// MALLCOP_CONFIDENCE_GATED_CLOSE_
//
// NOTE (mallcoppro-276): legion's apiToolEnv (worker.go:94-144) does NOT pass
// MALLCOP_CONFIDENCE_GATED_CLOSE_* env vars to tool subprocesses — the
// passthrough list is hard-coded to ANTHROPIC_*, FORGE_*, GRAPH_*, MALLCOP_RUN_ID.
// As a result, env-var overrides only take effect for direct CLI / unit-test
// invocations of the binary. For worker-spawned invocations, the binary defaults
// below are what runs. We therefore default Enabled=true + ScoreFloor=0.40 so the
// gate fires in the bakeoff (Phase 1 of the chain-redesign — Decision B,
// asymmetric gate). When legion grows env-var passthrough or a per-skill env
// block, these defaults can flip back to off and the chart can carry the policy.
//
//	MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED              bool   (default: true,  was false pre-mallcoppro-276)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR          float  (default: 0.40, was 0.55 pre-mallcoppro-276)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR   float  (default: 0.18, added in mallcoppro-499)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_WEIGHT     float  (default: 0.04)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_CAP        int    (default: 8)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_WEIGHT      float  (default: 0.08)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_CAP         int    (default: 4)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_WEIGHT      float  (default: 0.04)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_CAP         int    (default: 5)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_PENALTY         float  (default: -0.02)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_THRESHOLD       int    (default: 3)
//
// # TriageScoreFloor calibration (mallcoppro-499)
//
// Triage uses a 2-tool flow (check-baseline + search-events). Typical legitimate
// triage resolve scores ~0.24 (2 tools, 0-2 citations). The investigate-tuned
// floor of 0.40 would false-fire on ~90% of legitimate triage resolves.
//
// TriageScoreFloor defaults to 0.18 to discriminate between:
//   - "I executed the rubric" (2 tools + at least 1 citation, score ≥ ~0.20) → pass
//   - "I short-circuited" (1 tool + 0 citations, score ~0.04, or 0 citations
//     hitting the universal hard floor) → fire
//
// The zero-citation hard floor (at gate.go:444) applies to BOTH skills — "no
// evidence = no resolve" is a universal invariant, not a skill-specific check.
//
// # Transcript source
//
// The gate reads the engagement campfire (MALLCOP_CAMPFIRE_ID) via cf read --json
// --all and counts tool_use tagged messages. This is equivalent to calling
// get_session_transcript, which reads the same campfire.
//
// # Security note
//
// os/exec is used here (not in main.go) so that TestInvestigateTools_NoNetworkImports
// (which scans main.go only) remains green.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// lookupRulesSkipPenalty is the soft penalty subtracted from the structural
// confidence score when MALLCOP_SKILL=task:investigate AND the worker resolved
// without ever invoking the lookup-rules tool AND did not cite a valid rule_id.
//
// mallcoppro-8b0: Wave 4 evidence showed investigate workers writing prose like
// "events carry maintenance_window=true ... which match a benign-pattern flag
// suitable for lookup-rules" and then escalating WITHOUT actually invoking the
// tool. Across all B1 scenarios, 0/3 had rule_id citations — the operator-
// decisions infrastructure shipped in Waves 2-3 was dead code because nothing
// enforced tool usage.
//
// The penalty is a *soft* signal, not a hard verdict:
//
//   - Scores well above the floor (pre-penalty ≥ floor+0.10) remain above the
//     floor after the penalty — the resolve still passes (some legitimate
//     resolves genuinely have no matching rule and the worker has strong
//     direct evidence; we do not want to false-fire those).
//   - Scores below the floor (pre-penalty < floor) already fire — the penalty
//     is redundant but doesn't change the outcome.
//   - Borderline scores (pre-penalty ∈ [floor, floor+0.10)) flip from pass to
//     fire — the worker's confidence claim is weaker when they had a tool that
//     could have produced a citation and chose not to use it.
//
// 0.10 is a conservative default: it equals the citation weight (0.04) times
// 2.5, i.e. "two and a half missing citations' worth of evidence weight." A
// stronger penalty (0.20 or hard fire) would over-fire on legitimate resolves
// where no rule applied; a weaker penalty would barely move the gate decision.
const lookupRulesSkipPenalty = 0.10

// lookupRulesSkippedResolves counts resolves where the gate observed a
// lookup-rules skip (worker did not invoke lookup-rules AND did not supply a
// valid rule_id). Used for bakeoff-level adoption tracking — incremented
// whenever the soft penalty path is taken regardless of whether the gate
// ultimately fired. Read via test helpers; not exposed on stdout.
var lookupRulesSkippedResolves int64

// lookupRulesInvoked reports whether the worker's chain contains at least one
// invocation of the lookup-rules tool. Detection is tag-based: legion emits a
// tool:lookup-rules tag on the tool_use record for each call (see
// tools_f1g_gate.go::allowedRetrievalTags — lookup-rules is already in the
// retrieval allowlist for citation cross-checking).
//
// The function only checks message tags; payload content is not consulted
// because a model-controlled payload could mention the string "lookup-rules"
// without ever invoking the tool. Tag presence requires legion's tool
// infrastructure to have actually fired the tool — the model cannot forge it.
func lookupRulesInvoked(msgs []cfMessage) bool {
	for _, msg := range msgs {
		for _, tag := range msg.Tags {
			if tag == "tool:lookup-rules" {
				return true
			}
		}
	}
	return false
}

// confidenceGateConfig holds the parsed configuration for the gate.
type confidenceGateConfig struct {
	Enabled           bool
	ScoreFloor        float64
	// TriageScoreFloor is the floor used when MALLCOP_SKILL=task:triage.
	// Triage's 2-tool flow produces lower typical scores than investigate's
	// 4+ tool flow, so it needs its own calibration. See file header for the
	// rationale behind the 0.18 default.
	TriageScoreFloor  float64
	ToolCallWeight    float64
	ToolCallCap       int
	DistinctWeight    float64
	DistinctCap       int
	CitationWeight    float64
	CitationCap       int
	IterPenalty       float64
	IterThreshold     int
}

// Fan-out mode identifiers. These are the values runConfidenceGateFanOut
// dispatches on. New skill registry entries reference one of these values
// (or add a new one paired with a dispatch branch in runConfidenceGateFanOut).
const (
	// fanoutModeDeepX3Merge is the task:investigate fan-out: write-partial-
	// transcript + escalate-to-deep ×3 + create-investigate-merge wiring the 3
	// deep ids. Spent fan-out donuts on a 3-way deep-investigate panel.
	fanoutModeDeepX3Merge = "deep_x3_merge"
	// fanoutModeEscalateToInvestigator is the task:triage fan-out: a single
	// work:create handoff to a fresh task:investigate worker. The triage
	// rubric's 2-tool flow is too thin to warrant a deep panel; the structural
	// fix for "triage short-circuited" is "make the investigator do the work."
	fanoutModeEscalateToInvestigator = "escalate_to_investigator"
)

// skillGateConfig holds per-skill gate parameters. Add new entries to
// confidenceGateConfig.skillRegistry to gate additional skills without
// touching the dispatch logic.
//
// mallcoppro-801d (chain-redesign Wave 5 follow-up): replaces the hardcoded
// `switch skill { ... }` block in checkConfidenceGate so a 3rd gated skill
// (e.g., task:deep_investigate) can be added by appending one map entry.
type skillGateConfig struct {
	// floor is the effective score floor below which the gate fires.
	floor float64
	// fanoutMode names the fan-out dispatch branch in runConfidenceGateFanOut.
	// One of: fanoutModeDeepX3Merge, fanoutModeEscalateToInvestigator.
	fanoutMode string
	// applyLookupPenalty controls whether the lookupRulesSkipPenalty
	// (mallcoppro-8b0) applies when the worker resolved without invoking
	// lookup-rules AND without citing a valid rule_id.
	//
	// Currently true only for task:investigate. Triage is exempt because the
	// triage rubric's Step 2b uses lookup-rules only when the worker has
	// already observed a benign-pattern flag — a triage resolve without
	// lookup-rules is not by itself a process violation. Investigate, by
	// contrast, is the stage where unresolved triage findings land, and
	// skipping the corpus query there means the Wave 2-3 operator-decisions
	// infrastructure isn't being used.
	applyLookupPenalty bool
}

// skillRegistry returns the per-skill gate configuration table. Lookup keys
// are MALLCOP_SKILL values (e.g., "task:investigate", "task:triage"). A
// missing key means the gate is a no-op for that skill (returns Fired=false
// in checkConfidenceGate before any campfire I/O).
//
// The registry is computed from the parsed confidenceGateConfig each call so
// env-var overrides of ScoreFloor / TriageScoreFloor flow through to the
// effective floor on the next invocation.
func (cfg confidenceGateConfig) skillRegistry() map[string]skillGateConfig {
	return map[string]skillGateConfig{
		"task:investigate": {
			floor:              cfg.ScoreFloor,
			fanoutMode:         fanoutModeDeepX3Merge,
			applyLookupPenalty: true,
		},
		"task:triage": {
			floor:              cfg.TriageScoreFloor,
			fanoutMode:         fanoutModeEscalateToInvestigator,
			applyLookupPenalty: false,
		},
	}
}

// defaultGateConfig returns the default gate configuration.
//
// mallcoppro-276 (Phase 1, asymmetric gate): Enabled defaults true and
// ScoreFloor defaults 0.40 so the gate fires by default in the bakeoff
// without requiring env-var passthrough (which legion's apiToolEnv does
// not currently support — see file header). The zero-citation hard floor
// at gate.go:444 remains an unconditional fire regardless of score.
//
// mallcoppro-499 (RPT-structural follow-up): TriageScoreFloor defaults to
// 0.18 so the gate also fires on task:triage short-circuit resolves without
// false-firing on legitimate 2-tool triage flows. See file header for the
// calibration rationale.
func defaultGateConfig() confidenceGateConfig {
	return confidenceGateConfig{
		Enabled:          true,
		ScoreFloor:       0.40,
		TriageScoreFloor: 0.18,
		ToolCallWeight:   0.04,
		ToolCallCap:      8,
		DistinctWeight:   0.08,
		DistinctCap:      4,
		CitationWeight:   0.04,
		CitationCap:      5,
		IterPenalty:      -0.02,
		IterThreshold:    3,
	}
}

// loadGateConfig reads gate configuration from environment variables.
// Variables use prefix MALLCOP_CONFIDENCE_GATED_CLOSE_.
func loadGateConfig() confidenceGateConfig {
	cfg := defaultGateConfig()

	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED"); v != "" {
		cfg.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.ScoreFloor = f
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_TRIAGE_SCORE_FLOOR"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.TriageScoreFloor = f
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_WEIGHT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.ToolCallWeight = f
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ToolCallCap = n
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_WEIGHT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.DistinctWeight = f
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.DistinctCap = n
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_WEIGHT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.CitationWeight = f
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CitationCap = n
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_PENALTY"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.IterPenalty = f
		}
	}
	if v := os.Getenv("MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.IterThreshold = n
		}
	}
	return cfg
}

// transcriptStats holds the parsed statistics from the engagement campfire.
type transcriptStats struct {
	ToolCallCount    int
	DistinctToolCount int
	Iterations       int
}

// cfMessage is the JSON shape of a message from cf read --json --all.
type cfMessage struct {
	ID      string   `json:"id"`
	Payload string   `json:"payload"`
	Tags    []string `json:"tags"`
}

// readEngagementTranscript reads all messages from the engagement campfire
// (MALLCOP_CAMPFIRE_ID) and returns transcript statistics plus the raw messages.
// The raw messages are used by extractRetrievedIDs to cross-check cited IDs.
// The engagement campfire contains all tool_use records posted by the worker.
//
// Returns an error if cf is not on PATH or the campfire read fails. The caller
// is responsible for fail-closed handling (see checkConfidenceGate).
// Set MALLCOP_GATE_ALLOW_NO_CF=1 to bypass the cf-missing check in test environments.
func readEngagementTranscript(campfireID string) (transcriptStats, []cfMessage, error) {
	cfBin, err := cfBinPath()
	if err != nil {
		return transcriptStats{}, nil, fmt.Errorf("readEngagementTranscript: %w", err)
	}

	cmd := exec.Command(cfBin, "read", campfireID, "--json", "--all") // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		// Propagate the error so the caller can fail closed.
		return transcriptStats{}, nil, fmt.Errorf("readEngagementTranscript: cf read: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return transcriptStats{}, nil, nil
	}

	var msgs []cfMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		// Parse failure — propagate so the caller can fail closed.
		return transcriptStats{}, nil, fmt.Errorf("readEngagementTranscript: parse JSON: %w", err)
	}

	return parseTranscriptStats(msgs), msgs, nil
}

// allowedRetrievalTags is the set of campfire tags whose payloads can contribute
// IDs to the retrieved-evidence set. Restricting to this allowlist closes the
// citation-fabrication bypass (mallcoppro-a5d, originally surfaced as
// mallcoppro-db3 HIGH-severity finding "Bypass 6"):
//
// Before the allowlist, extractRetrievedIDs scanned every payload — including
// model-controlled tool output (annotate-finding, write-partial-transcript,
// the worker's own free-form notes). A malicious worker could pre-write
// citation-shape tokens via annotate-finding ("see fnd_shk_999 for evidence"),
// then cite them in resolve-finding. The retrieved-ID cross-check from
// mallcoppro-467 (Bypass 5 defense) trusted the campfire as a witness of
// tool-retrieved data, but a model-driven write made the worker its own
// witness.
//
// The fix is provenance-based: only payloads tagged with a TRUSTED retrieval
// tool can contribute retrieved IDs. The retrieval-tool tags are:
//
//	tool:check-baseline      — baseline-stats lookup
//	tool:search-events       — event-store retrieval
//	tool:search-findings     — finding-store retrieval
//	tool:lookup-rules        — operator-decisions rule retrieval
//	tool:read-finding        — single-finding read
//	tool:baseline-stats      — alias for check-baseline (compat)
//	tool:result              — generic retrieval-result wrapper (emitted by
//	                            legion's tool-result side-channel alongside a
//	                            specific tool:<name> tag; presence alone is
//	                            sufficient because legion only emits tool:result
//	                            for retrieval-tool outputs, never for
//	                            model-controlled tools like annotate-finding)
//
// Conservative interpretation for multi-tag messages: a message contributes
// retrieved IDs IFF at least one of its tags is in the allowlist AND it carries
// NO tags from the model-controlled denylist (finding:annotation,
// transcript:partial, transcript:annotate, etc). Untagged messages contribute
// nothing (no provenance = no trust). See isAllowedRetrievalMessage for the
// exact rule.
var allowedRetrievalTags = map[string]struct{}{
	"tool:check-baseline":  {},
	"tool:search-events":   {},
	"tool:search-findings": {},
	"tool:lookup-rules":    {},
	"tool:read-finding":    {},
	"tool:baseline-stats":  {},
	"tool:result":          {},
}

// modelControlledTags identifies tags applied by tools whose payload content is
// fully model-controlled (the agent writes the body). These tags must NEVER
// contribute retrieved-evidence IDs, even when a retrieval-tag also appears.
// This is the denylist half of the mallcoppro-a5d defense.
var modelControlledTags = map[string]struct{}{
	"finding:annotation":   {}, // annotate-finding payload (note field is model-controlled)
	"transcript:partial":   {}, // write-partial-transcript payload
	"transcript:annotate":  {}, // legacy annotate transcript tag
}

// isAllowedRetrievalMessage reports whether a campfire message's tags qualify
// its payload as retrieved-evidence. The rule is:
//
//   - At least one tag must be in allowedRetrievalTags (positive provenance), AND
//   - No tag may be in modelControlledTags (negative provenance).
//
// Untagged messages contribute nothing (no provenance = no trust). Companion
// tags posted alongside retrieval-tool outputs (tool_use, the specific
// tool:<name> tag) are tolerated as long as they are not in the denylist.
//
// This is the conservative interpretation called out in mallcoppro-a5d. A
// payload that simultaneously carries a retrieval-tool tag AND a model-
// controlled tag (e.g., a misbehaving tool wrapper) is treated as untrusted
// — defense-in-depth against future tool refactors that might collide tags.
func isAllowedRetrievalMessage(tags []string) bool {
	hasAllowed := false
	for _, tag := range tags {
		if _, denied := modelControlledTags[tag]; denied {
			return false
		}
		if _, ok := allowedRetrievalTags[tag]; ok {
			hasAllowed = true
		}
	}
	return hasAllowed
}

// extractRetrievedIDs scans campfire message payloads for citation-pattern IDs
// (same regex as countCitations) and returns the set of IDs that appear in
// payloads from TRUSTED retrieval tools (see allowedRetrievalTags). Payloads
// from model-controlled tools (annotate-finding, write-partial-transcript) or
// untagged payloads are skipped — they cannot contribute "retrieved" evidence
// because the worker can write to them at will.
//
// mallcoppro-a5d (security defense): before this restriction, a worker could
// write citation-shape tokens via annotate-finding and then cite them in
// resolve-finding; the cross-check from mallcoppro-467 would falsely match.
// The allowlist closes that hole: only payloads with positive retrieval
// provenance count.
func extractRetrievedIDs(msgs []cfMessage) map[string]struct{} {
	retrieved := make(map[string]struct{})
	for _, msg := range msgs {
		if msg.Payload == "" {
			continue
		}
		if !isAllowedRetrievalMessage(msg.Tags) {
			continue
		}
		for _, id := range citationPattern.FindAllString(msg.Payload, -1) {
			retrieved[id] = struct{}{}
		}
	}
	return retrieved
}

// parseTranscriptStats counts tool_use and assistant turns from campfire messages.
// Tool_use messages are identified by the "tool_use" tag or by a payload that
// starts with a JSON object containing a "tool_use" key.
// Iterations are the number of messages tagged "assistant:turn" or the total
// number of distinct payload round-trips (each tool-call counts as one iteration).
func parseTranscriptStats(msgs []cfMessage) transcriptStats {
	var stats transcriptStats
	toolNames := make(map[string]struct{})

	// Count tool_use tagged messages as tool calls.
	// Also count distinct assistant turns as iterations.
	assistantTurns := make(map[string]struct{})

	for _, msg := range msgs {
		isToolUse := false
		for _, tag := range msg.Tags {
			if tag == "tool_use" || strings.HasPrefix(tag, "tool:") {
				isToolUse = true
				break
			}
		}

		if !isToolUse && msg.Payload != "" {
			// Try to parse payload as a JSON object with tool_use key.
			var p map[string]interface{}
			if json.Unmarshal([]byte(msg.Payload), &p) == nil {
				if _, ok := p["tool_use"]; ok {
					isToolUse = true
				}
				if toolName, ok := p["tool_name"].(string); ok && toolName != "" {
					isToolUse = true
					toolNames[toolName] = struct{}{}
				}
			}
		}

		if isToolUse {
			stats.ToolCallCount++
			// Extract tool name from tags or payload.
			for _, tag := range msg.Tags {
				if strings.HasPrefix(tag, "tool:") {
					toolName := strings.TrimPrefix(tag, "tool:")
					if toolName != "" {
						toolNames[toolName] = struct{}{}
					}
				}
			}
			if msg.Payload != "" {
				var p map[string]interface{}
				if json.Unmarshal([]byte(msg.Payload), &p) == nil {
					if toolName, ok := p["name"].(string); ok && toolName != "" {
						toolNames[toolName] = struct{}{}
					}
					if tu, ok := p["tool_use"].(map[string]interface{}); ok {
						if toolName, ok := tu["name"].(string); ok && toolName != "" {
							toolNames[toolName] = struct{}{}
						}
					}
				}
			}
			// Each tool call counts as one assistant turn / iteration.
			assistantTurns[msg.ID] = struct{}{}
		}
	}

	stats.DistinctToolCount = len(toolNames)
	stats.Iterations = len(assistantTurns)

	// Fallback: if no tool_use tagged messages, count all messages as iterations.
	// This gives a non-zero iteration count even in bare campfire scenarios.
	if stats.Iterations == 0 {
		stats.Iterations = len(msgs)
	}

	return stats
}

// citationPattern matches event-ID-like patterns in the resolve-finding reason field.
// Matches patterns like: evt_001, fnd_shk_005, evt-abc123, finding-1a2b3c
// These are the event/finding ID shapes found in mallcop fixture scenarios.
var citationPattern = regexp.MustCompile(`\b[a-z]+[-_][a-z0-9]{3,}\b`)

// countCitations counts event-ID-like citation patterns in the reason field.
// When retrievedIDs is non-nil, only IDs that appear in the retrieved set are
// counted — IDs that were never seen in any campfire message payload are not
// counted as valid citations. Pass nil to count all matching tokens (used in
// unit tests and sanity checks that bypass the cross-check).
func countCitations(reason string, retrievedIDs map[string]struct{}) int {
	matches := citationPattern.FindAllString(reason, -1)
	seen := make(map[string]struct{}, len(matches))
	count := 0
	for _, m := range matches {
		if _, dup := seen[m]; !dup {
			seen[m] = struct{}{}
			if retrievedIDs != nil {
				if _, ok := retrievedIDs[m]; !ok {
					continue
				}
			}
			count++
		}
	}
	return count
}

// computeConfidenceScore computes the structural confidence score from
// transcript stats and citation count, using the provided config weights.
func computeConfidenceScore(cfg confidenceGateConfig, stats transcriptStats, citationCount int) float64 {
	// tool_call_weight * min(tool_call_count, tool_call_cap)
	score := cfg.ToolCallWeight * float64(min(stats.ToolCallCount, cfg.ToolCallCap))

	// distinct_tool_weight * min(distinct_tool_count, distinct_tool_cap)
	score += cfg.DistinctWeight * float64(min(stats.DistinctToolCount, cfg.DistinctCap))

	// citation_weight * min(citation_count, citation_cap)
	score += cfg.CitationWeight * float64(min(citationCount, cfg.CitationCap))

	// iteration_penalty * max(iterations - threshold, 0)  [penalty is negative]
	overIterations := math.Max(float64(stats.Iterations-cfg.IterThreshold), 0)
	score += cfg.IterPenalty * overIterations

	return score
}

// min returns the smaller of a and b (integers).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// gateResult is the outcome of checkConfidenceGate.
type gateResult struct {
	// Fired is true when the gate fired (score < floor and enabled).
	Fired bool
	// Score is the computed confidence score.
	Score float64
	// Stats is the parsed transcript statistics.
	Stats transcriptStats
	// CitationCount is the number of citations found in the reason field.
	CitationCount int
	// EffectiveFloor is the floor that was applied (ScoreFloor for investigate,
	// TriageScoreFloor for triage). Recorded so the fan-out payload reports the
	// floor that actually fired the gate, not whichever skill's floor we look
	// up later.
	EffectiveFloor float64
	// FanoutMode names the fan-out dispatch branch the gate selected for this
	// skill (one of fanoutMode* constants). runConfidenceGateFanOut dispatches
	// on this value instead of skill identity, so adding a 3rd gated skill is
	// a registry entry change rather than a switch-statement change.
	//
	// mallcoppro-801d: replaces the previous TriageMode bool field. The triage
	// case now sets FanoutMode == fanoutModeEscalateToInvestigator.
	FanoutMode string
	// SkippedLookup is true when the worker resolved on task:investigate
	// without invoking the lookup-rules tool AND without citing a valid
	// rule_id. Recorded for logging and metrics — the soft penalty has
	// already been applied to Score by the time this flag is set.
	// mallcoppro-8b0: the structural signal that the operator-decisions
	// corpus is dead code in production because the worker is not querying
	// it. Drives the lookupRulesSkippedResolves counter.
	SkippedLookup bool
}

// checkConfidenceGate evaluates the confidence gate for a resolve-finding call.
// Returns (gateResult, error). When gateResult.Fired is true, the caller should
// emit fan-out work:create messages instead of the normal work:output.
//
// The gate is a no-op (Fired=false) when:
//   - action != "resolved" (escalations and remediations skip the gate — see below)
//   - MALLCOP_SKILL is not in {task:investigate, task:triage}
//   - config.Enabled == false
//   - citations >= 1 AND score >= effective_floor
//
// The gate fires (Fired=true) when:
//   - action == "resolved" AND citations == 0 AND ruleID is empty/invalid
//     (hard requirement — tool volume alone is not evidence)
//   - action == "resolved" AND score < effective_floor (after rule_id citation bonus)
//
// mallcoppro-00c: ruleID is the optional rule_id from resolve-finding input.
// When ruleID is non-empty AND loads successfully from
// agents/rules/operator-decisions.yaml, the gate:
//
//   - Adds 1 to citation_count for score computation.
//   - Bypasses the zero-citation hard floor.
//
// An invalid rule_id (one that does not load from the YAML) is silently
// ignored — the agent does not get to forge a citation by inventing IDs.
//
// effective_floor:
//   - cfg.ScoreFloor       when skill = task:investigate
//   - cfg.TriageScoreFloor when skill = task:triage
//
// When the gate fires on task:triage, gateResult.TriageMode=true and the caller
// dispatches forceEscalateToInvestigator instead of the deep×3 + merge panel.
//
// Action gating (rung 3 — restored from March pipeline.py:221-243):
// The consensus check exists to second-guess the LLM when it claims a finding is
// benign (resolved). Escalation is already a system PASS — there is no payoff in
// spending fan-out donuts to challenge an escalate decision, and doing so was
// punishing the safe choice on ~78% of scenarios. We early-return for any non-
// "resolved" action to restore the original semantic.
//
// Fail-closed semantics: if the transcript cannot be read (cf missing, campfire
// unreachable, parse failure), the gate fires with score=0. The risk of an
// accidental fan-out is much lower than the risk of a gate bypass.
//
// Exception: MALLCOP_GATE_ALLOW_NO_CF=1 disables the fail-closed behaviour for
// test environments that do not have cf on PATH. This env var must never be set
// in production worker jails.
func checkConfidenceGate(campfireID, action, reason, ruleID string) (gateResult, error) {
	// Action check: only gate on "resolved" — escalations need no double-check
	// (escalate is already a system PASS). Restores March rung-3 semantic.
	if action != "resolved" {
		return gateResult{Fired: false}, nil
	}

	// Skill check: dispatch via the per-skill registry (mallcoppro-801d).
	// Adding a new gated skill is a registry entry — this block is invariant.
	skill := os.Getenv("MALLCOP_SKILL")
	cfg := loadGateConfig()
	skillCfg, ok := cfg.skillRegistry()[skill]
	if !ok {
		return gateResult{Fired: false}, nil
	}
	effectiveFloor := skillCfg.floor
	fanoutMode := skillCfg.fanoutMode

	// Config check: gate must be enabled.
	if !cfg.Enabled {
		return gateResult{Fired: false}, nil
	}

	// Read the engagement campfire transcript.
	stats, msgs, err := readEngagementTranscript(campfireID)
	if err != nil {
		// Fail CLOSED: if we cannot read the transcript, we cannot verify the
		// worker's evidence. Treat as score=0 and fire the gate.
		// MALLCOP_GATE_ALLOW_NO_CF=1 bypasses this for unit-test environments
		// that do not have cf on PATH.
		if os.Getenv("MALLCOP_GATE_ALLOW_NO_CF") == "1" {
			return gateResult{Fired: false}, nil
		}
		readErr := fmt.Errorf("confidence gate: read transcript: %w", err)
		return gateResult{
			Fired:          true,
			Score:          0,
			EffectiveFloor: effectiveFloor,
			FanoutMode:     fanoutMode,
		}, readErr
	}

	// Cross-check cited IDs against IDs actually retrieved from the campfire.
	// This prevents citation inflation via pseudo-IDs stuffed in the reason field.
	retrievedIDs := extractRetrievedIDs(msgs)

	// Count citations in the reason field (only retrieved IDs count).
	citationCount := countCitations(reason, retrievedIDs)

	// mallcoppro-00c: rule_id citation path. When the resolve-finding caller
	// supplied a rule_id AND that rule_id loads from
	// agents/rules/operator-decisions.yaml, count it as +1 toward the score
	// AND treat it as evidence for the zero-citation hard floor below.
	//
	// Forgery defence: only IDs that successfully load from the YAML count.
	// An invented "R-999" silently contributes nothing — the agent still has
	// to retrieve real evidence or call lookup-rules and cite the result.
	//
	// mallcoppro-8b0: track validRuleIDCited so the lookup-rules-skip penalty
	// can distinguish "worker did the work and cited a rule" from "worker
	// invented an ID that happens to not load." Only valid rule_id citations
	// exempt the worker from the soft penalty below.
	validRuleIDCited := false
	if ruleID != "" {
		repoRoot, rrErr := resolveRepoRoot()
		if rrErr == nil {
			if rules, lrErr := loadOperatorRules(repoRoot); lrErr == nil {
				if _, ok := findRuleByID(rules, ruleID); ok {
					citationCount++
					validRuleIDCited = true
				}
			}
		}
	}

	// Hard citation requirement: zero citations → gate fires unconditionally.
	// Tool volume and breadth alone (tool_call_weight + distinct_weight) are not
	// sufficient to satisfy the "evidence-grounded reasoning" spec intent.
	// An agent making 8 calls across 4 distinct tools scores 0.64 on those
	// components alone, clearing the 0.55 floor with zero evidence anchoring.
	// Requiring at least one citation closes this score-cap bypass.
	//
	// mallcoppro-499: this hard floor applies to BOTH task:investigate and
	// task:triage. "No evidence = no resolve" is a universal invariant.
	//
	// mallcoppro-00c: a valid rule_id contributes to citationCount above and
	// thus also satisfies this hard floor — citing an operator-decision rule
	// is evidence-grounded reasoning, just with a different evidence source
	// (the pre-seeded operator corpus) than retrieved event IDs.
	if citationCount == 0 {
		score := computeConfidenceScore(cfg, stats, 0)
		return gateResult{
			Fired:          true,
			Score:          score,
			Stats:          stats,
			CitationCount:  0,
			EffectiveFloor: effectiveFloor,
			FanoutMode:     fanoutMode,
		}, nil
	}

	// Compute score.
	score := computeConfidenceScore(cfg, stats, citationCount)

	// mallcoppro-8b0: lookup-rules-skip soft penalty (task:investigate only).
	//
	// When the investigate worker resolved WITHOUT invoking lookup-rules AND
	// did NOT cite a valid rule_id, subtract lookupRulesSkipPenalty from the
	// score. This tips borderline scores (pre-penalty ∈ [floor, floor+0.10))
	// from pass to fire, without affecting:
	//
	//   - high scores ≥ floor+0.10 (which absorb the penalty and still pass)
	//   - already-firing scores < floor (penalty redundant, same outcome)
	//   - the zero-citation hard floor above (already fired)
	//
	// Triage is exempt because triage's Step 2b is correctly advisory — the
	// triage rubric uses lookup-rules only when the worker has already
	// observed a benign-pattern flag, so a triage resolve without lookup-rules
	// is not by itself a process violation. Investigate, by contrast, is the
	// stage where unresolved triage findings land, and skipping the corpus
	// query there means the Wave 2-3 infrastructure isn't being used.
	//
	// A valid rule_id citation exempts the worker because citing a rule from
	// the corpus proves they queried it (the rule_id had to come from
	// somewhere). Forged rule_ids are silently filtered above (validRuleIDCited
	// stays false), so they do not provide the exemption.
	// mallcoppro-801d: penalty applicability is now a registry field, not a
	// literal skill check. Only skills whose skillGateConfig.applyLookupPenalty
	// is true take the penalty path. Currently that is task:investigate only;
	// triage stays exempt by registry. The rest of the condition (valid rule_id
	// citation + lookup-rules invocation) is unchanged from mallcoppro-8b0.
	skippedLookup := false
	if skillCfg.applyLookupPenalty && !validRuleIDCited && !lookupRulesInvoked(msgs) {
		skippedLookup = true
		score -= lookupRulesSkipPenalty
		atomic.AddInt64(&lookupRulesSkippedResolves, 1)
		// Structured log — surfaces in worker stderr and bakeoff logs so the
		// operator can see when the borderline tip fires. The "fired" decision
		// is made by the floor comparison below; this log records the signal.
		fmt.Fprintf(os.Stderr,
			"gate: skipped-lookup-rules penalty applied "+
				"(skill=%s score_after=%.4f floor=%.4f citation_count=%d)\n",
			skill, score, effectiveFloor, citationCount)
	}

	if score >= effectiveFloor {
		return gateResult{
			Fired:          false,
			Score:          score,
			Stats:          stats,
			CitationCount:  citationCount,
			EffectiveFloor: effectiveFloor,
			FanoutMode:     fanoutMode,
			SkippedLookup:  skippedLookup,
		}, nil
	}

	// Gate fires.
	if skippedLookup {
		fmt.Fprintf(os.Stderr,
			"gate: skipped-lookup-rules borderline tip → FIRED "+
				"(skill=%s score=%.4f floor=%.4f)\n",
			skill, score, effectiveFloor)
	}
	return gateResult{
		Fired:          true,
		Score:          score,
		Stats:          stats,
		CitationCount:  citationCount,
		EffectiveFloor: effectiveFloor,
		FanoutMode:     fanoutMode,
		SkippedLookup:  skippedLookup,
	}, nil
}

// runConfidenceGateFanOut dispatches the fan-out emission when the gate fires.
//
// Dispatch is by gr.FanoutMode (mallcoppro-801d, replacing the previous
// gr.TriageMode bool):
//
//   - fanoutModeEscalateToInvestigator (task:triage): delegates to
//     forceEscalateToInvestigator — a single work:create handoff to a fresh
//     task:investigate worker. Triage's 2-tool flow does not warrant the
//     investigate-tuned deep×3 + merge panel; the structural response to
//     "triage short-circuited" is "make the investigator do the work."
//
//   - fanoutModeDeepX3Merge (task:investigate): emits the 4-message
//     investigate fan-out:
//      1. write-partial-transcript — saves the partial reasoning chain.
//      2. escalate-to-deep × 3 — creates deep-investigate items per hypothesis.
//      3. create-investigate-merge — creates the merge item wired to the 3 deep ids.
//
// Unknown FanoutMode values fall through to the deep×3 + merge default to
// preserve the historical behavior for any caller that constructs a gateResult
// without populating FanoutMode (e.g., existing tests that build the struct
// directly).
//
// Returns an error only if a critical step fails (transcript write or all 3 deep
// escalations fail). The merge item creation is best-effort.
func runConfidenceGateFanOut(findingID, reason string, gr gateResult) error {
	if gr.FanoutMode == fanoutModeEscalateToInvestigator {
		return forceEscalateToInvestigator(findingID, reason, gr)
	}

	workCampfireID, err := requireEnv("MALLCOP_WORK_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("confidence gate fan-out: %w", err)
	}

	// Step 1: write-partial-transcript.
	partialContent := fmt.Sprintf("# Partial transcript — confidence gate fired\n\n"+
		"finding_id: %s\n"+
		"score: %.4f (floor: %.4f)\n"+
		"tool_calls: %d, distinct_tools: %d, citations: %d, iterations: %d\n\n"+
		"## Reason from investigate worker\n\n%s\n",
		findingID, gr.Score, gr.EffectiveFloor,
		gr.Stats.ToolCallCount, gr.Stats.DistinctToolCount, gr.CitationCount, gr.Stats.Iterations,
		reason)

	transcriptInputJSON, _ := json.Marshal(map[string]interface{}{
		"finding_id": findingID,
		"content":    partialContent,
	})
	var transcriptPath string
	transcriptOut := captureStdoutSilent(func() error {
		return runWritePartialTranscript(string(transcriptInputJSON))
	})
	if transcriptOut != "" {
		var tResult map[string]interface{}
		if json.Unmarshal([]byte(transcriptOut), &tResult) == nil {
			if p, ok := tResult["path"].(string); ok {
				transcriptPath = p
			}
		}
	}
	if transcriptPath == "" {
		// Fallback path if write failed. Uses resolveRunID so the path still
		// resolves correctly under the bakeoff harness even if the upstream
		// write-partial-transcript call failed silently.
		transcriptPath = fmt.Sprintf(".run/transcripts/%s/%s-partial.md", resolveRunID(findingID), findingID)
	}

	// Step 2: escalate-to-deep × 3 (benign, malicious, incomplete).
	hypotheses := []string{"benign", "malicious", "incomplete"}
	deepItemIDs := make([]string, 0, 3)
	for _, hyp := range hypotheses {
		deepInputJSON, _ := json.Marshal(map[string]interface{}{
			"finding_id":             findingID,
			"hypothesis":             hyp,
			"partial_transcript_path": transcriptPath,
		})
		deepOut := captureStdoutSilent(func() error {
			// Temporarily override MALLCOP_WORK_CAMPFIRE_ID to ensure the work
			// campfire is set (it should already be set from requireEnv above).
			_ = workCampfireID
			return runEscalateToDeep(string(deepInputJSON))
		})
		var itemID string
		if deepOut != "" {
			var dResult map[string]interface{}
			if json.Unmarshal([]byte(deepOut), &dResult) == nil {
				if id, ok := dResult["item_id"].(string); ok && id != "" {
					itemID = id
				}
			}
		}
		if itemID != "" {
			deepItemIDs = append(deepItemIDs, itemID)
		}
	}

	if len(deepItemIDs) != 3 {
		return fmt.Errorf("confidence gate fan-out: expected 3 deep item IDs, got %d", len(deepItemIDs))
	}

	// Step 3: create-investigate-merge wired to the 3 deep ids.
	mergeInputJSON, _ := json.Marshal(map[string]interface{}{
		"finding_id":   findingID,
		"deep_item_ids": deepItemIDs,
	})
	mergeOut := captureStdoutSilent(func() error {
		return runCreateInvestigateMerge(string(mergeInputJSON))
	})
	var mergeItemID string
	if mergeOut != "" {
		var mResult map[string]interface{}
		if json.Unmarshal([]byte(mergeOut), &mResult) == nil {
			if id, ok := mResult["item_id"].(string); ok {
				mergeItemID = id
			}
		}
	}

	// Emit the gate-fired summary as our output (replaces work:output).
	// gr.EffectiveFloor is the floor that actually fired the gate (investigate's
	// ScoreFloor here — kept in the result so the report matches the decision
	// even if config is reloaded between check and report).
	return emitJSON(map[string]interface{}{
		"gate_fired":          true,
		"finding_id":          findingID,
		"score":               gr.Score,
		"score_floor":         gr.EffectiveFloor,
		"tool_calls":          gr.Stats.ToolCallCount,
		"distinct_tools":      gr.Stats.DistinctToolCount,
		"citations":           gr.CitationCount,
		"iterations":          gr.Stats.Iterations,
		"partial_transcript":  transcriptPath,
		"deep_item_ids":       deepItemIDs,
		"merge_item_id":       mergeItemID,
		"fanout_action":       "deep-investigate-panel",
		"reason":              "confidence gate fired — score below floor; fan-out to deep-investigate",
	})
}

// forceEscalateToInvestigator is the task:triage fan-out (mallcoppro-499).
//
// When the gate fires on a triage worker, the structural problem is "triage
// claimed resolution without doing the work." The cheapest correct fix is to
// hand the finding off to a fresh investigator with the full investigate tool
// set — not to spawn a 3-way deep-investigate panel.
//
// This emits ONE work:create message via cfWorkCreate: a fresh task:investigate
// item whose context records that it was force-escalated by the gate. It does
// NOT emit a synthetic terminal work:output for the original triage scenario —
// the investigator that picks up this item will emit its own resolve-finding
// terminal carrying the same finding:<id> tag (same pattern as the
// runEscalateToInvestigator handoff). Academy attributes the chain via the
// finding-tag path (mallcoppro-60e).
//
// Returns the gate-fired summary as the worker's stdout (replaces work:output).
func forceEscalateToInvestigator(findingID, reason string, gr gateResult) error {
	workCampfireID, err := requireEnv("MALLCOP_WORK_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("confidence gate fan-out (triage): %w", err)
	}
	parentItemID := os.Getenv("MALLCOP_ITEM_ID")

	title := fmt.Sprintf("investigate: %s (gate:triage)", findingID)
	gateContext := fmt.Sprintf(
		"confidence-gate fired on triage: score=%.4f floor=%.4f tool_calls=%d distinct_tools=%d citations=%d iterations=%d",
		gr.Score, gr.EffectiveFloor,
		gr.Stats.ToolCallCount, gr.Stats.DistinctToolCount, gr.CitationCount, gr.Stats.Iterations,
	)
	ctx := fmt.Sprintf("skill=task:investigate finding_id=%s reason=%s parent_item_id=%s gate=%s",
		findingID, reason, parentItemID, gateContext)

	itemID, err := cfWorkCreate(workCampfireID, "task:investigate", title, ctx, findingID)
	if err != nil {
		return fmt.Errorf("confidence gate fan-out (triage): %w", err)
	}

	// Emit tool-usage so academy counts this dispatch as a forge_call.
	// Do NOT emit a synthetic scenario terminal — the downstream investigate
	// worker will produce its own resolve-finding terminal that academy
	// attributes back to this finding (see runEscalateToInvestigator for the
	// same handoff pattern, and mallcoppro-2d4 for the bug a synthetic
	// terminal here would reintroduce).
	emitToolUsage(workCampfireID, findingID, parentItemID)

	return emitJSON(map[string]interface{}{
		"gate_fired":     true,
		"finding_id":     findingID,
		"score":          gr.Score,
		"score_floor":    gr.EffectiveFloor,
		"tool_calls":     gr.Stats.ToolCallCount,
		"distinct_tools": gr.Stats.DistinctToolCount,
		"citations":      gr.CitationCount,
		"iterations":     gr.Stats.Iterations,
		"item_id":        itemID,
		"fanout_action":  "escalate-to-investigator",
		"reason":         "confidence gate fired on triage — force escalate-to-investigator",
	})
}

// captureStdoutSilent runs fn while capturing stdout output.
// Returns the captured output string. Used internally by the fan-out to collect
// sub-tool outputs without emitting them to the parent process's stdout.
func captureStdoutSilent(fn func() error) string {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		_ = fn()
		return ""
	}
	os.Stdout = w

	_ = fn()

	w.Close()
	os.Stdout = origStdout

	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	r.Close()
	return string(buf[:n])
}
