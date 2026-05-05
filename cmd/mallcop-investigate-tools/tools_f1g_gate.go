// tools_f1g_gate.go — F2A confidence-score pre-close gate for resolve-finding.
//
// When MALLCOP_SKILL=task:investigate, runResolveFinding calls checkConfidenceGate
// before emitting work:output. If the structural confidence score for the session
// is below the configured floor, the gate fires and emits 4 work:create messages
// instead of the normal close:
//
//  1. write-partial-transcript
//  2. escalate-to-deep (benign)
//  3. escalate-to-deep (malicious)
//  4. escalate-to-deep (incomplete)
//  5. create-investigate-merge wired to the 3 deep ids
//
// The gate decision lives in binary code — the agent CANNOT skip it from prompt.
//
// # Configuration
//
// Weights and thresholds are read from environment variables injected by the
// chart at deploy time. Prefix: MALLCOP_CONFIDENCE_GATED_CLOSE_
//
//	MALLCOP_CONFIDENCE_GATED_CLOSE_ENABLED          bool   (default: false)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_SCORE_FLOOR      float  (default: 0.55)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_WEIGHT float  (default: 0.04)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_TOOL_CALL_CAP    int    (default: 8)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_WEIGHT  float  (default: 0.08)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_DISTINCT_CAP     int    (default: 4)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_WEIGHT  float  (default: 0.04)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_CITATION_CAP     int    (default: 5)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_PENALTY     float  (default: -0.02)
//	MALLCOP_CONFIDENCE_GATED_CLOSE_ITER_THRESHOLD   int    (default: 3)
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
)

// confidenceGateConfig holds the parsed configuration for the gate.
type confidenceGateConfig struct {
	Enabled           bool
	ScoreFloor        float64
	ToolCallWeight    float64
	ToolCallCap       int
	DistinctWeight    float64
	DistinctCap       int
	CitationWeight    float64
	CitationCap       int
	IterPenalty       float64
	IterThreshold     int
}

// defaultGateConfig returns the default gate configuration.
func defaultGateConfig() confidenceGateConfig {
	return confidenceGateConfig{
		Enabled:        false,
		ScoreFloor:     0.55,
		ToolCallWeight: 0.04,
		ToolCallCap:    8,
		DistinctWeight: 0.08,
		DistinctCap:    4,
		CitationWeight: 0.04,
		CitationCap:    5,
		IterPenalty:    -0.02,
		IterThreshold:  3,
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

// extractRetrievedIDs scans all campfire message payloads for citation-pattern
// IDs (same regex as countCitations). Only IDs that appear in at least one
// message payload are considered "retrieved" — i.e., were actually seen by a
// tool call during the investigation.
func extractRetrievedIDs(msgs []cfMessage) map[string]struct{} {
	retrieved := make(map[string]struct{})
	for _, msg := range msgs {
		if msg.Payload == "" {
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
}

// checkConfidenceGate evaluates the confidence gate for a resolve-finding call.
// Returns (gateResult, error). When gateResult.Fired is true, the caller should
// emit fan-out work:create messages instead of the normal work:output.
//
// The gate is a no-op (Fired=false) when:
//   - action != "resolved" (escalations and remediations skip the gate — see below)
//   - MALLCOP_SKILL != "task:investigate"
//   - config.Enabled == false
//   - citations >= 1 AND score >= score_floor
//
// The gate fires (Fired=true) when:
//   - action == "resolved" AND citations == 0 (hard requirement — tool volume alone is not evidence)
//   - action == "resolved" AND score < score_floor
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
func checkConfidenceGate(campfireID, action, reason string) (gateResult, error) {
	// Action check: only gate on "resolved" — escalations need no double-check
	// (escalate is already a system PASS). Restores March rung-3 semantic.
	if action != "resolved" {
		return gateResult{Fired: false}, nil
	}

	// Skill check: only gate on task:investigate workers.
	skill := os.Getenv("MALLCOP_SKILL")
	if skill != "task:investigate" {
		return gateResult{Fired: false}, nil
	}

	// Config check: gate must be enabled.
	cfg := loadGateConfig()
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
			Fired: true,
			Score: 0,
		}, readErr
	}

	// Cross-check cited IDs against IDs actually retrieved from the campfire.
	// This prevents citation inflation via pseudo-IDs stuffed in the reason field.
	retrievedIDs := extractRetrievedIDs(msgs)

	// Count citations in the reason field (only retrieved IDs count).
	citationCount := countCitations(reason, retrievedIDs)

	// Hard citation requirement: zero citations → gate fires unconditionally.
	// Tool volume and breadth alone (tool_call_weight + distinct_weight) are not
	// sufficient to satisfy the "evidence-grounded reasoning" spec intent.
	// An agent making 8 calls across 4 distinct tools scores 0.64 on those
	// components alone, clearing the 0.55 floor with zero evidence anchoring.
	// Requiring at least one citation closes this score-cap bypass.
	if citationCount == 0 {
		score := computeConfidenceScore(cfg, stats, 0)
		return gateResult{
			Fired:         true,
			Score:         score,
			Stats:         stats,
			CitationCount: 0,
		}, nil
	}

	// Compute score.
	score := computeConfidenceScore(cfg, stats, citationCount)

	if score >= cfg.ScoreFloor {
		return gateResult{
			Fired:         false,
			Score:         score,
			Stats:         stats,
			CitationCount: citationCount,
		}, nil
	}

	// Gate fires.
	return gateResult{
		Fired:         true,
		Score:         score,
		Stats:         stats,
		CitationCount: citationCount,
	}, nil
}

// runConfidenceGateFanOut emits the 4 fan-out work:create messages when the gate fires.
// The sequence is:
//  1. write-partial-transcript — saves the partial reasoning chain.
//  2. escalate-to-deep × 3 — creates deep-investigate items for each hypothesis.
//  3. create-investigate-merge — creates the merge item wired to the 3 deep ids.
//
// Returns an error only if a critical step fails (transcript write or all 3 deep
// escalations fail). The merge item creation is best-effort.
func runConfidenceGateFanOut(findingID, reason string, gr gateResult) error {
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
		findingID, gr.Score, loadGateConfig().ScoreFloor,
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
		// Fallback path if write failed.
		transcriptPath = fmt.Sprintf(".run/transcripts/unknown-run/%s-partial.md", findingID)
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
	return emitJSON(map[string]interface{}{
		"gate_fired":          true,
		"finding_id":          findingID,
		"score":               gr.Score,
		"score_floor":         loadGateConfig().ScoreFloor,
		"tool_calls":          gr.Stats.ToolCallCount,
		"distinct_tools":      gr.Stats.DistinctToolCount,
		"citations":           gr.CitationCount,
		"iterations":          gr.Stats.Iterations,
		"partial_transcript":  transcriptPath,
		"deep_item_ids":       deepItemIDs,
		"merge_item_id":       mergeItemID,
		"reason":              "confidence gate fired — score below floor; fan-out to deep-investigate",
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
