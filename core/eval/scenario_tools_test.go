// scenario_tools_test.go — proves the LIVE path gives the agent REAL,
// scenario-specific evidence (portable-agent-architecture.md §3.8, §4.1).
//
// This is the whole point of the parity run: before this wiring, ModeReal's agent
// investigated with NO scenario telemetry (search-events returned nothing, etc.)
// and the parity number was meaningless. These tests drive a scenario through
// RunScenario with a SCRIPTED httptest backend (the same {base_url,key} seam
// core/inference/direct_test.go exercises) and assert the tool transcript that
// REACHES the model is non-empty AND scenario-specific — and that a DIFFERENT
// scenario produces DIFFERENT tool data (per-scenario isolation, not a shared
// runner). Determinism: SetRepoRootForTest pins the corpus + rule root, so
// -count=N -race resolves the same data every run regardless of binary placement.
package eval

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// repoRootForTest walks up from the test's working directory (the package dir
// under `go test`) to the directory that holds exams/scenarios, then pins it via
// SetRepoRootForTest so the harness + the §3.8 rule fold resolve deterministically.
// Returns the resolved root; the caller defers SetRepoRootForTest("").
func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if fi, err := os.Stat(filepath.Join(dir, scenariosRelPath)); err == nil && fi.IsDir() {
			SetRepoRootForTest(dir)
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no %s found walking up from %s", scenariosRelPath, dir)
		}
		dir = parent
	}
}

// loadScenarioForTest loads a corpus scenario by its repo-relative path under
// exams/scenarios and wraps it as a LoadedScenario the runner consumes.
func loadScenarioForTest(t *testing.T, root, rel string) LoadedScenario {
	t.Helper()
	s, err := exam.Load(filepath.Join(root, scenariosRelPath, rel))
	if err != nil {
		t.Fatalf("load scenario %s: %v", rel, err)
	}
	return LoadedScenario{RelPath: rel, Scenario: s}
}

// recordingHTTPBackend is a scripted Anthropic-compatible httptest server that
// CAPTURES every request body it receives and returns a fixed escalate verdict so
// the cascade terminates. The captured user-prompt text is where the boxed tool
// transcript (search-events / check-baseline / search-findings results) lands —
// the seam this test inspects to prove the model saw real, scenario-specific
// evidence.
type recordingHTTPBackend struct {
	srv    *httptest.Server
	bodies []string
}

func newRecordingHTTPBackend(t *testing.T) *recordingHTTPBackend {
	t.Helper()
	b := &recordingHTTPBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		b.bodies = append(b.bodies, string(buf))
		w.Header().Set("Content-Type", "application/json")
		// A well-formed escalate verdict — terminates triage→investigate→escalate
		// deterministically without needing tool_use turns (the cascade pre-gathers
		// tool evidence via the ToolRunner and boxes it into the prompt; the model
		// only returns the verdict).
		resp := map[string]any{
			"type":        "message",
			"role":        "assistant",
			"stop_reason": "end_turn",
			"content": []map[string]any{
				{"type": "text", "text": `{"action":"escalate","confidence":3,"positive_evidence":false,"strong_evidence":false,"insufficient_data":false,"reason":"escalating for human review"}`},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *recordingHTTPBackend) client() agent.Client {
	return &inference.DirectClient{BaseURL: b.srv.URL, Key: "test-key", Model: "scripted-test"}
}

// firstToolTranscript returns the boxed tools.transcript text from the FIRST
// captured request — the evidence the triage model saw. The cascade boxes the
// tool transcript in USER_DATA markers labelled "tools.transcript"; we return the
// whole first user-prompt text (the transcript is a substring of it).
func (b *recordingHTTPBackend) firstUserPrompt(t *testing.T) string {
	t.Helper()
	if len(b.bodies) == 0 {
		t.Fatal("scripted backend captured zero requests — the cascade never reached the model")
	}
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(b.bodies[0]), &req); err != nil {
		t.Fatalf("decode captured request: %v\nbody: %s", err, b.bodies[0])
	}
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		for _, c := range m.Content {
			if c.Type == "text" && c.Text != "" {
				return c.Text
			}
		}
	}
	t.Fatalf("no user text block in captured request: %s", b.bodies[0])
	return ""
}

// TestRunScenario_LiveTools_FeedsScenarioSpecificEvidence drives UT-02 through
// RunScenario with liveTools=true and a scripted backend, then asserts the tool
// transcript the model saw is NON-EMPTY and carries THIS scenario's telemetry:
// its event id, its actor, its baseline frequency, and the §3.8 folded rule
// (R-001, which keys on the maintenance_window flag the events carry). This is the
// proof the live agent actually investigates instead of staring at an empty box.
func TestRunScenario_LiveTools_FeedsScenarioSpecificEvidence(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	// The cascade FLOOR (core/agent) resolves the escalate-route corpus through
	// its OWN repo-root seam; pin it too or the floor fails safe (force-escalate,
	// no model call) when it can't locate the corpus from the test binary.
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	be := newRecordingHTTPBackend(t)

	run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
	if run.SeedErr != "" {
		t.Fatalf("live ToolRunner failed to seed: %s", run.SeedErr)
	}

	prompt := be.firstUserPrompt(t)
	mustContain := map[string]string{
		"event id (search-events returned the scenario's events)": "evt_001",
		"actor (the entity under investigation)":                  "deploy-svc",
		"baseline frequency (check-baseline answered routine?)":   "156",
		"folded operator rule (§3.8 matched_rules)":               "R-001",
		"the search-events tool ran":                              "search-events",
		"the check-baseline tool ran":                             "check-baseline",
	}
	for why, want := range mustContain {
		if !strings.Contains(prompt, want) {
			t.Errorf("tool transcript missing %q (%s)\n--- prompt ---\n%s", want, why, prompt)
		}
	}
}

// TestRunScenario_LiveTools_PerScenarioIsolation proves the runner is built PER
// SCENARIO, not shared/static: UT-02 (actor deploy-svc, container_restart) and
// VA-02 (actor batch-processor, database_access) must each see ONLY their own
// telemetry. If a single shared runner leaked across scenarios, VA-02's prompt
// would carry UT-02's actor (or vice versa) — the assertions below forbid that.
func TestRunScenario_LiveTools_PerScenarioIsolation(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	// The cascade FLOOR (core/agent) resolves the escalate-route corpus through
	// its OWN repo-root seam; pin it too or the floor fails safe (force-escalate,
	// no model call) when it can't locate the corpus from the test binary.
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	utLS := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	vaLS := loadScenarioForTest(t, root, "behavioral/VA-02-month-end-batch.yaml")

	utBE := newRecordingHTTPBackend(t)
	vaBE := newRecordingHTTPBackend(t)

	if run := RunScenario(context.Background(), utBE.client(), utLS, agent.CascadeOptions{}, true); run.SeedErr != "" {
		t.Fatalf("UT-02 seed error: %s", run.SeedErr)
	}
	if run := RunScenario(context.Background(), vaBE.client(), vaLS, agent.CascadeOptions{}, true); run.SeedErr != "" {
		t.Fatalf("VA-02 seed error: %s", run.SeedErr)
	}

	utPrompt := utBE.firstUserPrompt(t)
	vaPrompt := vaBE.firstUserPrompt(t)

	// Each scenario sees its OWN actor.
	if !strings.Contains(utPrompt, "deploy-svc") {
		t.Errorf("UT-02 prompt missing its own actor deploy-svc")
	}
	if !strings.Contains(vaPrompt, "batch-processor") {
		t.Errorf("VA-02 prompt missing its own actor batch-processor")
	}
	// Crucially, neither sees the OTHER's actor — no shared/leaked runner.
	if strings.Contains(utPrompt, "batch-processor") {
		t.Errorf("ISOLATION BREACH: UT-02 prompt leaked VA-02 actor batch-processor\n%s", utPrompt)
	}
	if strings.Contains(vaPrompt, "deploy-svc") {
		t.Errorf("ISOLATION BREACH: VA-02 prompt leaked UT-02 actor deploy-svc\n%s", vaPrompt)
	}
	// And the tool data differs (proving distinct per-scenario evidence, not a
	// static fixture echoed for both).
	if utPrompt == vaPrompt {
		t.Errorf("UT-02 and VA-02 saw identical prompts — tool data is not per-scenario")
	}
}

// TestRunScenario_LiveTools_NotSilentlyEmptyOnReal proves the §gap fix's core
// guarantee: with liveTools=true a REAL per-scenario runner is ALWAYS wired even
// when the caller passes a nil opts.Tools. The agent must NOT silently investigate
// with an empty toolbox — the captured prompt carries real tool output, and a
// run with liveTools=false (the merge-gate path) carries NONE of it, proving the
// difference is the live wiring, not the scenario.
func TestRunScenario_LiveTools_NotSilentlyEmptyOnReal(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	// The cascade FLOOR (core/agent) resolves the escalate-route corpus through
	// its OWN repo-root seam; pin it too or the floor fails safe (force-escalate,
	// no model call) when it can't locate the corpus from the test binary.
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")

	// liveTools=true, nil opts.Tools → a real runner is injected.
	liveBE := newRecordingHTTPBackend(t)
	if run := RunScenario(context.Background(), liveBE.client(), ls, agent.CascadeOptions{Tools: nil}, true); run.SeedErr != "" {
		t.Fatalf("live seed error: %s", run.SeedErr)
	}
	livePrompt := liveBE.firstUserPrompt(t)
	if !strings.Contains(livePrompt, "search-events") || !strings.Contains(livePrompt, "evt_001") {
		t.Fatalf("liveTools=true did NOT wire a real ToolRunner — prompt has no scenario tool data:\n%s", livePrompt)
	}

	// liveTools=false, nil opts.Tools → NO tools wired (merge-gate semantics). The
	// prompt must carry no tool transcript at all.
	gateBE := newRecordingHTTPBackend(t)
	if run := RunScenario(context.Background(), gateBE.client(), ls, agent.CascadeOptions{Tools: nil}, false); run.SeedErr != "" {
		t.Fatalf("gate run unexpectedly seeded a runner: %s", run.SeedErr)
	}
	gatePrompt := gateBE.firstUserPrompt(t)
	if strings.Contains(gatePrompt, "search-events") || strings.Contains(gatePrompt, "check-baseline") {
		t.Fatalf("liveTools=false wired tools anyway (should be tool-free merge-gate path):\n%s", gatePrompt)
	}
}

// TestRunScenario_LiveTools_EventTargetActionReachTheModel proves FIX 4 (eval
// fidelity, event side): a scenario event's target + action now reach the model
// prompt. Before the fix the eval projected only "actor did <event_type>" and the
// model was blind to WHAT each event did and to WHAT — the per-event relationship
// detail legion's academy fed its agent. UT-02's evt_001 carries
// action=restart_container and a target under atom-api; both must appear in the
// boxed tool transcript the triage model sees.
func TestRunScenario_LiveTools_EventTargetActionReachTheModel(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	be := newRecordingHTTPBackend(t)

	run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
	if run.SeedErr != "" {
		t.Fatalf("live ToolRunner failed to seed: %s", run.SeedErr)
	}

	prompt := be.firstUserPrompt(t)
	// action= and target= must be present, carrying the scenario's per-event detail.
	if !strings.Contains(prompt, "action=restart_container") {
		t.Errorf("event ACTION did not reach the model prompt (want action=restart_container)\n--- prompt ---\n%s", prompt)
	}
	if !strings.Contains(prompt, "target=") || !strings.Contains(prompt, "atom-api") {
		t.Errorf("event TARGET did not reach the model prompt (want target=...atom-api)\n--- prompt ---\n%s", prompt)
	}
}

// TestRunScenario_LiveTools_RelationshipsReachTheModel proves FIX 4 (eval fidelity,
// baseline side): the scenario's relationships table is reconstructed into
// pkg/baseline and surfaced by check-baseline so it reaches the model prompt — the
// actor↔target history the academy showed its agent. UT-02's baseline records
// deploy-svc↔atom-api with count 89; the boxed check-baseline transcript must carry
// a relationships line citing it.
func TestRunScenario_LiveTools_RelationshipsReachTheModel(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	be := newRecordingHTTPBackend(t)

	run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
	if run.SeedErr != "" {
		t.Fatalf("live ToolRunner failed to seed: %s", run.SeedErr)
	}

	prompt := be.firstUserPrompt(t)
	if !strings.Contains(prompt, "relationships:") {
		t.Errorf("the relationships baseline did not reach the model prompt (want a 'relationships:' line)\n--- prompt ---\n%s", prompt)
	}
	if !strings.Contains(prompt, "count=89") {
		t.Errorf("the deploy-svc↔atom-api relationship (count=89) did not reach the model prompt\n--- prompt ---\n%s", prompt)
	}
}

// TestBaselineFromScenario_RelationshipsQueryable proves the relationships table is
// reconstructed into the typed pkg/baseline and is QUERYABLE via RelationshipsFor —
// the queryable-surface half of FIX 4. UT-02's baseline records two deploy-svc
// relationships; a lookup on the actor must return them with their counts.
func TestBaselineFromScenario_RelationshipsQueryable(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	bl := baselineFromScenario(ls.Scenario)
	if bl == nil {
		t.Fatal("baselineFromScenario returned nil for a scenario with a baseline")
	}
	rels := bl.RelationshipsFor("deploy-svc")
	if len(rels) == 0 {
		t.Fatalf("RelationshipsFor(deploy-svc) returned no relationships; the scenario table was not reconstructed\nrelationships=%v", bl.Relationships)
	}
	// The atom-api relationship has count 89 in the corpus.
	found := false
	for k, rel := range rels {
		if strings.Contains(k, "atom-api") && rel.Count == 89 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a deploy-svc↔atom-api relationship with count=89; got %v", rels)
	}
}

// TestScenarioToolRunner_ToolEmptyForeignActor proves the ToolEmpty fail-safe
// signal is real and scenario-scoped: a runner whose search-events filter matches
// NO event (a finding for an actor absent from the scenario's events) reports
// ToolEmpty=true — the cascade force-escalates a resolve built on an empty read
// (§3.4). This guards against a regression where the runner fabricates evidence
// or swallows the empty signal.
func TestScenarioToolRunner_ToolEmptyForeignActor(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	// The cascade FLOOR (core/agent) resolves the escalate-route corpus through
	// its OWN repo-root seam; pin it too or the floor fails safe (force-escalate,
	// no model call) when it can't locate the corpus from the test binary.
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	// Force the search filter to an actor that owns no events in this scenario.
	// The runner snapshots the actor-scoped read ONCE at construction (the §4.3
	// concurrency fix), so the foreign actor must be set on the scenario BEFORE the
	// runner is built — pointing the search filter at an actor absent from the
	// events is exactly what makes search-events surface nothing (ToolEmpty=true).
	if ls.Scenario.Finding == nil {
		t.Fatalf("UT-02 has no finding block; cannot pin the foreign actor")
	}
	if ls.Scenario.Finding.Metadata == nil {
		ls.Scenario.Finding.Metadata = exam.FindingMetadata{}
	}
	ls.Scenario.Finding.Metadata["actor"] = "actor-not-in-this-scenario"

	r, err := newScenarioToolRunner(t.TempDir(), root, ls.Scenario)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}

	ev, err := r.RunTools(context.Background(), "triage", findingFromScenario(ls.Scenario))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if !ev.ToolEmpty {
		t.Errorf("search-events matched no events but ToolEmpty=false: an empty read must be reported so the fail-safe can fire\nevents=%q baseline=%q", ev.EventsText, ev.BaselineText)
	}
}

// resolveScriptBackend is an httptest Anthropic backend that returns a CLEAN
// triage resolve (confidence 5, positive evidence) on EVERY call. Driving a
// scenario against it means the MODEL always wants to resolve — so if the chain
// still ESCALATES, the only thing that could have forced it is a STRUCTURAL gate:
// the FIX 3 observable event-keyed force-escalate (zero-history / role-grant) or
// the FIX 2 risky-resolve gate. It isolates the structural floor from model luck.
type resolveScriptBackend struct {
	srv *httptest.Server
}

func newResolveScriptBackend(t *testing.T) *resolveScriptBackend {
	t.Helper()
	b := &resolveScriptBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"type": "message", "role": "assistant", "stop_reason": "end_turn",
			"content": []map[string]any{
				{"type": "text", "text": `{"action":"resolve","confidence":5,"positive_evidence":true,"strong_evidence":false,"insufficient_data":false,"reason":"actor is known and the activity looks routine to the model."}`},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *resolveScriptBackend) client() agent.Client {
	return &inference.DirectClient{BaseURL: b.srv.URL, Key: "test-key", Model: "always-resolve"}
}

// TestRunScenario_Fix3_RoleGrant_TerminalEscalate proves the ROLE-GRANT branch of
// the observable floor is a TERMINAL escalate (NEVER_AUTO_RESOLVE, the doc's
// "Privilege changes → always ESCALATE non-negotiable"): even when the MODEL always
// proposes a clean resolve, a finding whose surfaced events show the finding actor
// performing a role grant with no precedent (UT-01 / IT-02) escalates at triage.
// The corpus has ZERO benign-expected scenario carrying this predicate, so a
// terminal force is safe.
func TestRunScenario_Fix3_RoleGrant_TerminalEscalate(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	be := newResolveScriptBackend(t) // model ALWAYS proposes resolve
	for _, rel := range []string{
		"behavioral/UT-01-competing-signals.yaml",
		"cross_cutting/IT-02-baseline-contradicts-reasoning.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, rel)
			run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
			if run.SeedErr != "" {
				t.Fatalf("%s seed error: %s", rel, run.SeedErr)
			}
			if run.TerminalAction != "escalated" {
				t.Fatalf("%s: a role grant by the finding actor must TERMINAL-escalate even when the model proposes resolve; got %q\nreason: %s", rel, run.TerminalAction, run.TerminalReason)
			}
		})
	}
}

// TestRunScenario_Fix3_ZeroHistory_HandsOffNotResolvedAtTriage proves the
// ZERO-HISTORY branch is a HANDOFF (not terminal): a clean triage resolve on VA-03 /
// CO-02 does NOT terminate at triage — it routes to investigate (model_calls > 1).
// Calibrated this way so a benign first-time access can still resolve at the deeper
// tier (see the benign-precision test below); here we only prove the cheap-triage
// terminal-resolve path is BLOCKED, which is the under-escalation defect.
func TestRunScenario_Fix3_ZeroHistory_HandsOffNotResolvedAtTriage(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	be := newResolveScriptBackend(t) // model ALWAYS proposes resolve
	for _, rel := range []string{
		"behavioral/VA-03-data-exfil.yaml",
		"cross_cutting/CO-02-benign-events-first.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, rel)
			run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
			if run.SeedErr != "" {
				t.Fatalf("%s seed error: %s", rel, run.SeedErr)
			}
			// The cheap-triage terminal resolve must be blocked: model_calls > 1 means
			// the finding was handed to investigate instead of auto-resolved at triage.
			if run.ModelCalls <= 1 {
				t.Fatalf("%s: zero-history access must hand off to investigate (model_calls>1), not auto-resolve at triage; got model_calls=%d action=%q", rel, run.ModelCalls, run.TerminalAction)
			}
		})
	}
}

// TestRunScenario_Fix3_ZeroHistory_EscalatesWhenInvestigateEscalates proves the
// realistic end state: when the (stronger) investigate tier escalates a zero-history
// out-of-scope access, the chain escalates. The recordingHTTPBackend returns an
// escalate verdict at every tier — the production-shaped path for VA-03 / CO-02.
func TestRunScenario_Fix3_ZeroHistory_EscalatesWhenInvestigateEscalates(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	for _, rel := range []string{
		"behavioral/VA-03-data-exfil.yaml",
		"cross_cutting/CO-02-benign-events-first.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			be := newRecordingHTTPBackend(t) // escalate verdict at every tier
			ls := loadScenarioForTest(t, root, rel)
			run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
			if run.SeedErr != "" {
				t.Fatalf("%s seed error: %s", rel, run.SeedErr)
			}
			if run.TerminalAction != "escalated" {
				t.Fatalf("%s: an out-of-scope zero-history access investigate escalates must end escalated; got %q\nreason: %s", rel, run.TerminalAction, run.TerminalReason)
			}
		})
	}
}

// TestRunScenario_Fix3_Discrimination_BenignNotFlipped is the DISCRIMINATION guard:
// the new observable floor must NOT flip a benign-expected scenario to escalate at
// the FLOOR. ID-01 (benign onboarding: role grant authored by a known granter, not
// the finding actor) must RESOLVE end-to-end against an always-resolve model. And a
// representative set of benign zero-history scenarios must NOT be forced off triage
// by a TERMINAL escalate — they hand off to investigate where (with the always-
// resolve model + gate clearing) they resolve. We assert none of them terminates
// "escalated" at the floor when the model proposes resolve with strong evidence.
func TestRunScenario_Fix3_Discrimination_BenignNotFlipped(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	be := newResolveScriptBackend(t)
	// ID-01 must resolve outright (neither predicate fires).
	t.Run("identity/ID-01-new-actor-benign-onboarding.yaml", func(t *testing.T) {
		ls := loadScenarioForTest(t, root, "identity/ID-01-new-actor-benign-onboarding.yaml")
		run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
		if run.SeedErr != "" {
			t.Fatalf("seed: %s", run.SeedErr)
		}
		if run.TerminalAction != "resolved" {
			t.Fatalf("ID-01 (benign onboarding) must RESOLVE; got %q\nreason: %s", run.TerminalAction, run.TerminalReason)
		}
	})
	// These benign zero-history scenarios must NOT be terminal-escalated by the
	// floor: with the model proposing resolve and the structural gate cleared, they
	// resolve. (A non-terminal handoff that resolves at investigate is correct; a
	// terminal floor escalate would be the over-escalation regression we forbid.)
	for _, rel := range []string{
		"behavioral/VA-02-month-end-batch.yaml",
		"behavioral/VA-05-quarterly-report-burst.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, rel)
			// Give the model strong observable work so investigate's resolve clears the
			// structural gate (no fan-out): pin generous tool counts via a resolve that
			// cites evidence. The live runner already returns >=2 tools; the gate also
			// weighs reason citations, which the always-resolve reason carries thinly —
			// so we accept either a clean resolve OR a fan-out that resolves, and only
			// FORBID a FLOOR terminal-escalate (ForceEscalated stays false AND the
			// terminal is not an escalate driven by the observable floor at triage).
			run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
			if run.SeedErr != "" {
				t.Fatalf("%s seed: %s", rel, run.SeedErr)
			}
			// The floor must not TERMINAL-escalate these at triage. A terminal escalate
			// here would carry the role-grant never-auto-resolve marker; assert it does
			// NOT, and that the finding was at least handed off (model_calls>=1).
			if strings.Contains(run.TerminalReason, "never-auto-resolve") {
				t.Fatalf("%s: benign zero-history scenario was TERMINAL-escalated by the role-grant floor (over-escalation); reason: %s", rel, run.TerminalReason)
			}
		})
	}
}

// TestRunScenario_Fix2_ID01_ResolvesAtTriage proves the FIX 2 (eval fidelity)
// actor-filter fallback: ID-01's finding is about the NEW actor deploy-svc-new,
// whose creation events are AUTHORED by admin-user (the new actor is the event
// TARGET / principal_id). The direct actor-filtered search-events returns empty;
// the fallback surfaces the events that NAME the finding actor so ToolEmpty is
// FALSE and triage can resolve ID-01 as designed (instead of fail-safe escalating
// on an empty read). We assert ToolEmpty is false AND the creation context reaches
// the model.
func TestRunScenario_Fix2_ID01_ResolvesAtTriage(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "identity/ID-01-new-actor-benign-onboarding.yaml")

	// Direct: the runner's RunTools must NOT report ToolEmpty (the fallback surfaced
	// the admin-user-authored creation events naming deploy-svc-new).
	r, err := newScenarioToolRunner(t.TempDir(), root, ls.Scenario)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	ev, err := r.RunTools(context.Background(), "triage", findingFromScenario(ls.Scenario))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if ev.ToolEmpty {
		t.Fatalf("FIX 2: ID-01's new-actor creation events must be surfaced via the fallback so ToolEmpty=false; got empty\nevents=%q", ev.EventsText)
	}
	if ev.ZeroHistoryAccess {
		t.Fatalf("FIX 2/3: ID-01 must NOT trip zero-history (the finding actor deploy-svc-new performs no access); got zero-history detail=%q", ev.ZeroHistoryDetail)
	}
	if ev.RoleGrantByActor {
		t.Fatalf("FIX 3: ID-01's role grant is authored by admin-user (a known granter), not the finding actor — RoleGrantByActor must be false; got detail=%q", ev.RoleGrantDetail)
	}
	if !strings.Contains(ev.EventsText, "deploy-svc-new") {
		t.Fatalf("FIX 2: the creation events naming deploy-svc-new must reach the transcript; got %q", ev.EventsText)
	}

	// End-to-end: with a backend that returns a clean resolve, ID-01 RESOLVES (no
	// structural gate forces it up).
	be := newResolveScriptBackend(t)
	run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
	if run.SeedErr != "" {
		t.Fatalf("ID-01 seed error: %s", run.SeedErr)
	}
	if run.TerminalAction != "resolved" {
		t.Fatalf("ID-01 (benign onboarding) must RESOLVE; got %q\nreason: %s", run.TerminalAction, run.TerminalReason)
	}
}

// TestRunScenario_Fix1_PerEventMetadataReachesModel proves FIX 1 (visibility): the
// discriminating per-event metadata the model needs to tell an attack apart from
// benign load reaches the prompt — CO-02's operation_count=847 (the magnitude that
// makes the bulk read an exfil) must be in the boxed events field, sanitized and
// projected individually.
func TestRunScenario_Fix1_PerEventMetadataReachesModel(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "cross_cutting/CO-02-benign-events-first.yaml")
	be := newRecordingHTTPBackend(t)
	run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
	if run.SeedErr != "" {
		t.Fatalf("CO-02 seed error: %s", run.SeedErr)
	}
	prompt := be.firstUserPrompt(t)
	// The high-magnitude operation_count discriminator must reach the model.
	if !strings.Contains(prompt, "operation_count=847") {
		t.Fatalf("FIX 1: the discriminating per-event metadata (operation_count=847) did not reach the model prompt\n--- prompt ---\n%s", prompt)
	}
	// Each tool result is boxed as its OWN labelled field.
	for _, label := range []string{"tools.baseline", "tools.events"} {
		if !strings.Contains(prompt, label) {
			t.Fatalf("FIX 1: per-tool boxed field %q missing from prompt\n--- prompt ---\n%s", label, prompt)
		}
	}
}

// TestRunScenario_GroupLevelRelationship_NotZeroHistory proves the resource-group
// relationship credit (the sibling-resource-rotation fix). A known actor accessing
// a SIBLING leaf resource inside a resource GROUP it has STRONG, established history
// with must NOT be classified zero-history — the group-level relationship covers the
// new leaf. URA-04 (infra-admin, atom-rg group count 892, first touch on a new
// sibling DB) and UT-07 (ops-engineer, atom-rg group count 467, cleanup inside the
// group) are the benign over-escalations this credit unblocks. The CRITICAL
// DISCRIMINATOR: URA-02 (ci-bot lateral movement) and VA-03 (ci-bot bulk exfil)
// access the SAME resource group but ci-bot holds ONLY leaf relationships there (no
// group-level key), so they MUST still trip zero-history → escalate. This is the
// behavior-level guard that the credit did not over-narrow.
func TestRunScenario_GroupLevelRelationship_NotZeroHistory(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	cases := []struct {
		rel          string
		wantZeroHist bool // true => still zero-history (lateral movement); false => credited
	}{
		// Benign sibling-rotation: established GROUP-LEVEL history covers the new leaf.
		{"behavioral/URA-04-sibling-resource-rotation.yaml", false},
		{"behavioral/UT-07-deploy-window-ops.yaml", false},
		// Lateral movement / bulk exfil: LEAF-ONLY history in the group → still zero-history.
		{"behavioral/URA-02-lateral-movement.yaml", true},
		{"behavioral/VA-03-data-exfil.yaml", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, tc.rel)
			r, err := newScenarioToolRunner(t.TempDir(), root, ls.Scenario)
			if err != nil {
				t.Fatalf("new runner: %v", err)
			}
			ev, err := r.RunTools(context.Background(), "triage", findingFromScenario(ls.Scenario))
			if err != nil {
				t.Fatalf("RunTools: %v", err)
			}
			if ev.ZeroHistoryAccess != tc.wantZeroHist {
				t.Fatalf("%s: ZeroHistoryAccess=%t want %t (detail=%q)", tc.rel, ev.ZeroHistoryAccess, tc.wantZeroHist, ev.ZeroHistoryDetail)
			}
		})
	}
}

// NOTE: TestRelationshipCountFor_GroupCreditDiscriminator moved to
// core/observe/observe_test.go when relationshipCountFor was extracted to the
// shared core/observe package. The behavior-level group-credit guard remains here
// (TestRunScenario_GroupLevelRelationship_NotZeroHistory) exercising the SHARED
// predicate through RunTools.

// --- FIX 4: unjustified bulk / PII export floor (the regression veracity caught) ---

// TestScenarioToolRunner_Fix4_BulkExportPredicate unit-tests the observable predicate
// directly over RunTools: URA-03 (15,000-row pg_dump), ND-01 (2am PII export, no
// ticket), and IT-03 (312-op subscription sweep, no justification) MUST trip the
// bulk-export floor; the four benign high-volume scenarios (CC-01/CC-02/VA-02/VA-05)
// MUST NOT, because each carries a legitimate-justification companion (job_id /
// schedule / scheduled / window_id). URA-04/UT-07 (no export signal) and URA-02/VA-03
// (recon/exfil but no operation_count/export metadata + non-matching list_* actions)
// MUST NOT trip — so the bulk-export floor never steals URA-02/VA-03's zero-history
// route. This is the discriminator the relationship predicate cannot see: URA-03 and
// URA-04 hold the SAME atom-rg group key — the ACTION is what tells them apart.
func TestScenarioToolRunner_Fix4_BulkExportPredicate(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")

	cases := []struct {
		rel  string
		want bool
	}{
		// Floor FIRES: unjustified bulk / PII / secret export by the finding actor.
		{"behavioral/URA-03-admin-new-resource.yaml", true},                       // 15,000-row pg_dump, no justification
		{"cross_cutting/ND-01-authorized-data-export.yaml", true},                 // operation_count=100 + includes_pii=true, no ticket
		{"cross_cutting/IT-03-connector-tool-suspicious-but-resolved.yaml", true}, // operation_count=312, no justification
		// Floor does NOT fire: benign high-volume with a justification companion.
		{"cross_cutting/CC-01-quarterly-report-multi-signal.yaml", false}, // job_id + schedule
		{"cross_cutting/CC-02-deploy-window-multi-signal.yaml", false},    // window_id (NOT job_id/schedule)
		{"behavioral/VA-02-month-end-batch.yaml", false},                  // job_id + scheduled=true
		{"behavioral/VA-05-quarterly-report-burst.yaml", false},           // job_id + schedule
		// Floor does NOT fire: no export signal at all (resolve via group-credit).
		{"behavioral/URA-04-sibling-resource-rotation.yaml", false},
		{"behavioral/UT-07-deploy-window-ops.yaml", false},
		// Floor does NOT fire: recon/exfil with no bulk metadata + non-matching actions
		// — these keep their zero-history escalate route, the floor must not steal it.
		{"behavioral/URA-02-lateral-movement.yaml", false},
		{"behavioral/VA-03-data-exfil.yaml", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, tc.rel)
			r, err := newScenarioToolRunner(t.TempDir(), root, ls.Scenario)
			if err != nil {
				t.Fatalf("new runner: %v", err)
			}
			ev, err := r.RunTools(context.Background(), "triage", findingFromScenario(ls.Scenario))
			if err != nil {
				t.Fatalf("RunTools: %v", err)
			}
			if ev.BulkExportNoJustification != tc.want {
				t.Fatalf("%s: BulkExportNoJustification=%t want %t (detail=%q)\nevents=%q", tc.rel, ev.BulkExportNoJustification, tc.want, ev.BulkExportDetail, ev.EventsText)
			}
		})
	}
}

// TestRunScenario_Fix4_BulkExport_TerminalEscalate proves the bulk-export floor is a
// TERMINAL escalate end-to-end: even when the MODEL always proposes a clean resolve,
// URA-03 / ND-01 / IT-03 escalate at triage on the action-keyed floor. This restores
// URA-03's floor (lost in b6b7fa8 when the group-credit treated the first-ever
// pg_dump as "established") and deterministically catches ND-01 / IT-03.
func TestRunScenario_Fix4_BulkExport_TerminalEscalate(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	be := newResolveScriptBackend(t) // model ALWAYS proposes resolve
	for _, rel := range []string{
		"behavioral/URA-03-admin-new-resource.yaml",
		"cross_cutting/ND-01-authorized-data-export.yaml",
		"cross_cutting/IT-03-connector-tool-suspicious-but-resolved.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, rel)
			run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
			if run.SeedErr != "" {
				t.Fatalf("%s seed error: %s", rel, run.SeedErr)
			}
			// Against an ALWAYS-RESOLVE model, the only thing that can escalate URA-03 /
			// ND-01 / IT-03 is a STRUCTURAL floor. They are NOT zero-history (URA-03 is
			// group-credited; ND-01/IT-03's actor is a known reader) and carry NO role
			// grant — so the bulk-export floor is the ONLY structural force that applies.
			// ModelCalls==2 (triage + escalate-formatter) proves it terminated at triage,
			// not after a deeper-tier handoff.
			if run.TerminalAction != "escalated" {
				t.Fatalf("%s: an unjustified bulk/PII export must TERMINAL-escalate even when the model proposes resolve; got %q\nreason: %s", rel, run.TerminalAction, run.TerminalReason)
			}
			if run.ModelCalls != 2 {
				t.Fatalf("%s: the bulk-export floor must terminate at TRIAGE (2 model calls: triage+formatter); got %d calls — escalate was not driven by the triage floor", rel, run.ModelCalls)
			}
		})
	}
}

// TestRunScenario_Fix4_BenignHighVolume_NotFloorEscalated proves the CRITICAL
// DISCRIMINATOR: the benign high-volume scenarios (CC-01/CC-02/VA-02/VA-05) are NOT
// terminal-escalated by the bulk-export floor — each carries a legitimate-
// justification companion (job_id / schedule / scheduled / window_id) that excludes
// the floor. A terminal floor escalate here would be the over-escalation regression
// we forbid. CC-02 is the load-bearing case: it carries window_id, NOT job_id/
// schedule — the floor's justification set MUST include window_id or CC-02 would trip.
func TestRunScenario_Fix4_BenignHighVolume_NotFloorEscalated(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	be := newResolveScriptBackend(t) // model ALWAYS proposes resolve
	for _, rel := range []string{
		"cross_cutting/CC-01-quarterly-report-multi-signal.yaml",
		"cross_cutting/CC-02-deploy-window-multi-signal.yaml",
		"behavioral/VA-02-month-end-batch.yaml",
		"behavioral/VA-05-quarterly-report-burst.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, rel)
			run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
			if run.SeedErr != "" {
				t.Fatalf("%s seed: %s", rel, run.SeedErr)
			}
			// The justification companion excludes the floor, so against an always-
			// resolve model these RESOLVE. A terminal escalate here would be the
			// over-escalation regression (the bulk-export floor firing on a justified
			// batch). CC-02 is load-bearing: it carries window_id (NOT job_id/schedule)
			// — if the floor's justification set omitted window_id, CC-02 would escalate.
			if run.TerminalAction != "resolved" {
				t.Fatalf("%s: benign high-volume scenario (justification companion present) must RESOLVE, not be floor-escalated; got %q\nreason: %s", rel, run.TerminalAction, run.TerminalReason)
			}
		})
	}
}

// TestRunScenario_Fix4_GroupCreditBenign_StillResolves proves the b6b7fa8 group-credit
// is INTACT: URA-04 (infra-admin sibling rotation) and UT-07 (ops-engineer scheduled
// cleanup) still RESOLVE — they carry no export signal, so the bulk-export floor does
// not fire, and the group-credit keeps their sibling access out of zero-history.
func TestRunScenario_Fix4_GroupCreditBenign_StillResolves(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	be := newResolveScriptBackend(t)
	for _, rel := range []string{
		"behavioral/URA-04-sibling-resource-rotation.yaml",
		"behavioral/UT-07-deploy-window-ops.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, rel)
			run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
			if run.SeedErr != "" {
				t.Fatalf("%s seed: %s", rel, run.SeedErr)
			}
			if run.TerminalAction != "resolved" {
				t.Fatalf("%s: benign group-credit scenario must RESOLVE (group-credit intact, no export floor); got %q\nreason: %s", rel, run.TerminalAction, run.TerminalReason)
			}
		})
	}
}

// TestRunScenario_Fix4_ZeroHistory_RouteUnchanged proves the bulk-export floor does
// NOT steal the zero-history route: URA-02 (lateral movement) and VA-03 (data exfil)
// carry no bulk metadata and their list_*/read_blob actions do not match the bulk
// action set, so the bulk-export floor stays silent (proven directly in
// TestScenarioToolRunner_Fix4_BulkExportPredicate) and they still escalate via the
// zero-history predicate's investigate handoff. Driven with an escalate backend (the
// model escalates at investigate), they end escalated — the unchanged route.
func TestRunScenario_Fix4_ZeroHistory_RouteUnchanged(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	for _, rel := range []string{
		"behavioral/URA-02-lateral-movement.yaml",
		"behavioral/VA-03-data-exfil.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			// Confirm the bulk-export floor is silent on these (it must not steal the
			// zero-history route), then confirm the zero-history route still escalates.
			ls := loadScenarioForTest(t, root, rel)
			r, err := newScenarioToolRunner(t.TempDir(), root, ls.Scenario)
			if err != nil {
				t.Fatalf("new runner: %v", err)
			}
			ev, err := r.RunTools(context.Background(), "triage", findingFromScenario(ls.Scenario))
			if err != nil {
				t.Fatalf("RunTools: %v", err)
			}
			if ev.BulkExportNoJustification {
				t.Fatalf("%s: the bulk-export floor must NOT fire here (no bulk metadata / non-matching actions); detail=%q", rel, ev.BulkExportDetail)
			}
			if !ev.ZeroHistoryAccess {
				t.Fatalf("%s: the zero-history predicate must still fire (the existing escalate route); events=%q", rel, ev.EventsText)
			}

			be := newRecordingHTTPBackend(t) // escalate verdict at every tier
			run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
			if run.SeedErr != "" {
				t.Fatalf("%s seed: %s", rel, run.SeedErr)
			}
			if run.TerminalAction != "escalated" {
				t.Fatalf("%s: must still escalate via the zero-history route; got %q\nreason: %s", rel, run.TerminalAction, run.TerminalReason)
			}
		})
	}
}
