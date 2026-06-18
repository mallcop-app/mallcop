// runner.go — the IN-PROCESS scenario runner (portable-agent-architecture.md §4).
//
// Each scenario runs through the PORTABLE core (core/agent.ResolveFindingWith) IN
// THE SAME PROCESS — no subprocess, no campfire, no legion. The runner:
//
//  1. Builds a core finding.Finding from the scenario's finding: block, with
//     finding.Type = scenario.Detector so the data-driven PRE-LLM floor's
//     hard-constraint routes (priv-escalation, injection-probe, log-format-drift,
//     ...) fire BEFORE any model call — exactly as in production (§4.3: not every
//     finding deserves agent inference).
//  2. Projects the scenario's events + baseline into a deterministic ToolEvidence
//     the cascade boxes and the structural gate scores (the eval's per-scenario
//     baseline is what makes runs reproducible, §4.1).
//  3. Drives the cascade through a CONTROLLABLE inference Client — a cannedbackend
//     for the creds-free merge-gate, a real DirectClient for the parity run (the
//     {base_url,key} pivot). The runner is parameterized over the Client; it never
//     dials the network itself.
//  4. CAPTURES A PER-SCENARIO TRANSCRIPT — every model request (system + boxed
//     user prompt + advertised tools) and every model reply — via a recording
//     Client wrapper. Transcript capture is NON-NEGOTIABLE (§4.7): it is how a
//     silent-empty tool return or a bypassed channel becomes diagnosable.
//
// The runner imports core/agent (the portable core) and pkg/finding ONLY. It does
// NOT import core/inference — the caller injects whatever Client it wants. That
// keeps the {cannedbackend ⇄ real} pivot in the caller's hands and keeps this file
// substrate-free.
package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TranscriptEntry is one model exchange the harness observed: the full request
// the cascade sent (model, system prompt, boxed user prompt, advertised tools)
// and the model's reply. §4.7 demands every tool call, input, output, and model
// message be captured — this is the unit.
type TranscriptEntry struct {
	// Seq is the 0-based call index within this scenario (triage=0,
	// investigate=1, escalate-formatter / deep-panel = 2+).
	Seq int `json:"seq"`
	// Model is the model id the cascade requested for this call (the tier).
	Model string `json:"model"`
	// System is the tier's system prompt (the ported POST.md).
	System string `json:"system"`
	// UserPrompt is the boxed user message text (USER_DATA-wrapped finding +
	// tool transcript) the model saw. This is where a planted injection is
	// visible — the audit value of §4.7.
	UserPrompt string `json:"user_prompt"`
	// Tools are the names of tools advertised on this call (the model's actual
	// API surface, §3.8).
	Tools []string `json:"tools,omitempty"`
	// Reply is the model's first text block — the verdict-carrying reply the
	// cascade parsed (or the escalate formatter's free-text alert).
	Reply string `json:"reply"`
	// Err is non-empty when the model call returned an error (the cascade
	// fail-safes such a call to escalate).
	Err string `json:"err,omitempty"`
}

// recordingClient wraps an agent.Client and appends a TranscriptEntry for every
// Messages call. It is the §4.7 transcript-capture seam: the cascade reaches the
// model only through agent.Client, so wrapping the Client captures EVERY exchange
// with no change to the cascade. Concurrency-safe — the fan-out panel issues
// parallel deep-investigate calls.
type recordingClient struct {
	inner agent.Client

	mu      sync.Mutex
	entries []TranscriptEntry
}

func (rc *recordingClient) Messages(ctx context.Context, req agent.MessagesRequest) (agent.MessagesResponse, error) {
	resp, err := rc.inner.Messages(ctx, req)

	entry := TranscriptEntry{
		Model:      req.Model,
		System:     req.System,
		UserPrompt: firstUserText(req),
		Tools:      toolNames(req.Tools),
		Reply:      firstReplyText(resp),
	}
	if err != nil {
		entry.Err = err.Error()
	}

	rc.mu.Lock()
	entry.Seq = len(rc.entries)
	rc.entries = append(rc.entries, entry)
	rc.mu.Unlock()

	return resp, err
}

func (rc *recordingClient) transcript() []TranscriptEntry {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := make([]TranscriptEntry, len(rc.entries))
	copy(out, rc.entries)
	return out
}

// firstUserText returns the first user text block of a request, or "".
func firstUserText(req agent.MessagesRequest) string {
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		for _, b := range m.Content {
			if b.Type == "text" && b.Text != "" {
				return b.Text
			}
		}
	}
	return ""
}

// firstReplyText returns the first text block of a response, or "".
func firstReplyText(resp agent.MessagesResponse) string {
	for _, b := range resp.Content {
		if b.Type == "text" && b.Text != "" {
			return b.Text
		}
	}
	return ""
}

// toolNames extracts the advertised tool names for the transcript.
func toolNames(tools []agent.Tool) []string {
	if len(tools) == 0 {
		return nil
	}
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name)
	}
	return out
}

// ScenarioRun is the raw outcome of running ONE scenario through the core: the
// terminal Resolution, the captured transcript, and the call count. The grader
// (grader.go) turns this into a graded ScenarioResult. Kept separate so the
// runner stays free of grading policy.
type ScenarioRun struct {
	Scenario       LoadedScenario
	TerminalAction string
	TerminalReason string
	ForceEscalated bool
	RouteID        string
	ModelCalls     int
	Transcript     []TranscriptEntry
	WallMillis     int64
	// SeedErr is non-empty when the per-scenario live ToolRunner could not be
	// seeded (a genuine store failure). On ModeReal this is a DEGRADED run — the
	// agent investigated without the scenario's live tools — and the harness can
	// surface it rather than silently scoring an empty-toolbox verdict.
	SeedErr string
}

// findingFromScenario builds a core finding.Finding from a scenario's finding:
// block. finding.Type = scenario.Detector so the floor's family routes match
// (the floor keys on finding.Type, §floor docs). Actor/source come from the
// finding metadata; reason is the title (the human-readable headline the model
// reads, boxed as untrusted). All scalars are plain strings — the cascade boxes
// them in USER_DATA markers before they reach the model.
func findingFromScenario(s *exam.Scenario) finding.Finding {
	f := finding.Finding{
		Severity: s.Difficulty, // retained for completeness; not graded
	}
	if s.Finding != nil {
		f.ID = s.Finding.ID
		f.Severity = s.Finding.Severity
		f.Reason = s.Finding.Title
		f.Source = "detector:" + s.Finding.Detector
		f.Actor = metaString(s.Finding.Metadata, "actor")
	}
	// Type drives the floor's hard-constraint routing. Prefer the scenario's
	// top-level detector (the canonical family); fall back to the finding block.
	f.Type = s.Detector
	if f.Type == "" && s.Finding != nil {
		f.Type = s.Finding.Detector
	}
	if f.Source == "" {
		f.Source = "detector:" + f.Type
	}
	// Carry the events + baseline as evidence JSON for provenance (the cascade
	// surfaces telemetry through the ToolRunner, not finding.Evidence, but
	// stashing it keeps the finding self-describing for transcript review).
	if ev, err := json.Marshal(map[string]any{
		"event_ids": findingEventIDs(s),
		"category":  s.Category,
	}); err == nil {
		f.Evidence = ev
	}
	f.Timestamp = time.Now().UTC()
	return f
}

func findingEventIDs(s *exam.Scenario) []string {
	if s.Finding == nil {
		return nil
	}
	return s.Finding.EventIDs
}

func metaString(m exam.FindingMetadata, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// RunScenario runs one scenario through the portable core IN-PROCESS against the
// supplied Client, capturing the full transcript. The Client is the
// {cannedbackend ⇄ real} pivot — RunScenario never decides which; the caller does.
//
// LIVE TOOLS ARE WIRED PER SCENARIO when liveTools is true. opts carries the
// per-tier model ids; its Tools field (the ToolRunner) is OVERRIDDEN here with a
// per-scenario runner backed by the REAL core/tools over THIS scenario's events +
// baseline + finding. This is the whole point of the parity run: on ModeReal the
// live agent must investigate against the scenario's OWN telemetry — search-events
// returns the scenario's events (folding §3.8 matched_rules), check-baseline
// returns the scenario's frequencies, search-findings returns the scenario's
// finding stream. Each scenario sees ONLY its own data (per-scenario isolation,
// §4.1). A caller that pre-set opts.Tools is intentionally ignored: a shared/static
// runner would leak telemetry across scenarios and make the number meaningless.
//
// liveTools is false for the MERGE-GATE (ModeCanned): golden responses prove the
// grader pipeline, not the model's tool use, and the live ToolEmpty fail-safe
// would inject model-independent escalations that have nothing to do with what a
// golden response is testing. On ModeReal liveTools is true and a real per-scenario
// runner is ALWAYS wired — the run NEVER silently investigates with an empty
// toolbox (the very gap this closes). If liveTools is true but the runner cannot
// be seeded (a genuine store failure), opts.Tools is left unchanged and the
// failure is recorded in SeedErr so the harness surfaces a degraded run rather
// than scoring an empty-toolbox verdict as if it were real.
//
// The per-scenario store lives in a temp dir cleaned up before RunScenario returns.
func RunScenario(ctx context.Context, client agent.Client, ls LoadedScenario, opts agent.CascadeOptions, liveTools bool) ScenarioRun {
	rc := &recordingClient{inner: client}
	f := findingFromScenario(ls.Scenario)

	// Pin the AGENT floor's corpus root PER-SCENARIO via CascadeOptions.RepoRoot
	// (threaded explicitly through ResolveFindingWith) instead of letting the
	// cascade read the process-global agent.repoRootOverride. The eval repo root
	// (resolved once here) IS the agent corpus root — same repo tree — so the
	// pre-LLM floor reads exactly this scenario's pinned corpus with NO shared
	// global the harness's per-test cleanup could clear mid-resolve. If the caller
	// already pinned opts.RepoRoot, keep it.
	if opts.RepoRoot == "" {
		if root, err := RepoRoot(); err == nil {
			opts.RepoRoot = root
		}
	}

	// Build the per-scenario live ToolRunner over the scenario's own telemetry.
	// The store lives in a temp dir torn down when the scenario completes.
	var seedErr string
	if liveTools {
		tmpDir, err := os.MkdirTemp("", "mallcop-eval-scenario-*")
		if err != nil {
			seedErr = fmt.Sprintf("mkdir temp store: %v", err)
		} else {
			defer os.RemoveAll(tmpDir)
			repoRoot, rrErr := RepoRoot()
			if rrErr != nil {
				// The §3.8 rule fold needs the corpus root; without it search-events
				// still returns the scenario's events (matched_rules stays empty).
				repoRoot = ""
			}
			runner, rErr := newScenarioToolRunner(tmpDir, repoRoot, ls.Scenario)
			if rErr != nil {
				seedErr = rErr.Error()
			} else {
				opts.Tools = runner
			}
		}
	}

	start := time.Now()
	res := agent.ResolveFindingWith(ctx, rc, f, opts)
	wall := time.Since(start)

	transcript := rc.transcript()
	return ScenarioRun{
		Scenario:       ls,
		TerminalAction: terminalActionString(res.Action),
		TerminalReason: res.Reason,
		ForceEscalated: res.ForceEscalated,
		RouteID:        res.RouteID,
		ModelCalls:     len(transcript),
		Transcript:     transcript,
		WallMillis:     wall.Milliseconds(),
		SeedErr:        seedErr,
	}
}

// terminalActionString maps the core Action to the grader's vocabulary. The
// cascade's ActionProceed is a RESOLVED-as-benign terminal (see cascade.go); the
// grader compares against expected.chain_action which is "resolved"/"escalated".
func terminalActionString(a agent.Action) string {
	switch a {
	case agent.ActionProceed:
		return "resolved"
	case agent.ActionEscalated:
		return "escalated"
	default:
		return string(a)
	}
}
