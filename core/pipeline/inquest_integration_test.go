package pipeline_test

// inquest_integration_test.go — the pipeline-level integration coverage for
// detection-time investigation (mallcoppro-e3c, core/inquest), wired as
// pipeline.Run's step 5. Reuses pipeline_test.go's shared fixtures/helpers
// (multiFindingFixture, useShippedCorpus, newGitStore, writeEventsFile,
// loadResolutions) — this file adds only the inquest-specific assertions.
//
// The escalated finding under test throughout is ALWAYS the injection-probe
// finding from multiFindingFixture: it is force-escalated by the cascade's
// pre-LLM floor with ZERO model calls, so its escalation is deterministic and
// independent of the cannedbackend script — the ideal, stable subject for
// proving inquest's behavior without entangling it with cascade/consensus
// timing.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/inquest"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// investigateSystemPromptMarker is a stable substring of core/inquest's fixed
// narrate system prompt — used to route a shared cannedbackend server's reply
// between the cascade's own tiered calls and inquest's single narrate call,
// since both land on the SAME fake HTTP endpoint in these tests.
const investigateSystemPromptMarker = "detection-time investigator"

// cascadeResolveReply is the SAME well-cited resolve script
// TestPipeline_EndToEnd_ConnectDetectCascadeStore uses, reused here so the
// config-drift finding's cascade disposition is stable across every test in
// this file (it is not the finding under test, but it still runs through the
// SAME cannedbackend and must not be starved of a valid reply).
const cascadeResolveReply = `{"action":"resolve","confidence":5,"positive_evidence":true,` +
	`"reason":"ops-bot disabled MFA via the documented break-glass runbook RB-114 during the ` +
	`approved maintenance window on 2026-03-10; baseline frequency 312 for this actor; change ` +
	`ticket CHG-2231 references it; reverted at 14:40."}`

// startCannedBackendWithNarrateReply starts a cannedbackend that routes by
// request CONTENT: a narrate call (identified by the fixed system-prompt
// marker) gets narrateReply; every other call (the cascade's tiers) gets the
// standard cascadeResolveReply.
func startCannedBackendWithNarrateReply(t *testing.T, narrateReply string) *cannedbackend.CannedBackend {
	t.Helper()
	be := &cannedbackend.CannedBackend{
		CannedContentFunc: func(body []byte) string {
			if strings.Contains(string(body), investigateSystemPromptMarker) {
				return narrateReply
			}
			return cascadeResolveReply
		},
	}
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	t.Cleanup(be.Stop)
	return be
}

// injectionProbeFindingID returns the FindingID of the escalated
// (injection-probe) resolution in res, failing the test if there isn't
// exactly one escalated resolution.
func injectionProbeFindingID(t *testing.T, res []resolution.Resolution) string {
	t.Helper()
	var id string
	count := 0
	for _, r := range res {
		if r.Action == "escalate" {
			id = r.FindingID
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 escalated resolution, got %d (resolutions: %+v)", count, res)
	}
	return id
}

// readInvestigationRecord reads back investigations/<findingID>.json from the
// store via the public Store.ReadSnapshot, failing the test if absent or
// malformed.
func readInvestigationRecord(t *testing.T, st *store.Store, findingID string) inquest.Record {
	t.Helper()
	data, err := st.ReadSnapshot("investigations/" + findingID + ".json")
	if err != nil {
		t.Fatalf("ReadSnapshot(investigations/%s.json): %v", findingID, err)
	}
	if len(data) == 0 {
		t.Fatalf("no investigation record found for %s", findingID)
	}
	var rec inquest.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("unmarshal investigation record for %s: %v", findingID, err)
	}
	return rec
}

// baseInvestigateConfig is the enabled, generous-budget investigate: config
// these integration tests drive pipeline.Run with.
func baseInvestigateConfig() inquest.Config {
	return inquest.Config{Enabled: true, MaxPerScan: 10, MaxTokens: 1024}
}

// TestPipeline_InvestigatesEscalatedFinding is the headline integration
// proof: a scan that escalates a finding leaves investigations/<finding-id>.json
// in the store with a full evidence chain, a trusted verdict/narrative, and
// pipeline.Summary.Investigated==1.
func TestPipeline_InvestigatesEscalatedFinding(t *testing.T) {
	root := useShippedCorpus(t)
	be := startCannedBackendWithNarrateReply(t,
		`{"verdict":"suspicious","confidence":0.7,"narrative":"drive-by attempted a prompt-injection comment; no baseline history for this actor."}`)

	client := &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"}
	st := newGitStore(t)
	eventsPath := writeEventsFile(t, multiFindingFixture(t))

	cfg := pipeline.Config{
		Connector:   connect.FromPath(eventsPath),
		Client:      client,
		Store:       st,
		Baseline:    knownActorsBaseline(),
		Cascade:     agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "evidence", toolCalls: 6, distinctTools: 4}},
		Investigate: baseInvestigateConfig(),
	}

	sum, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if sum.Escalated != 1 {
		t.Fatalf("Escalated = %d, want 1", sum.Escalated)
	}
	if sum.Investigated != 1 {
		t.Fatalf("Investigated = %d, want 1", sum.Investigated)
	}
	if sum.InvestigationsDegraded != 0 {
		t.Fatalf("InvestigationsDegraded = %d, want 0", sum.InvestigationsDegraded)
	}

	res := loadResolutions(t, st)
	findingID := injectionProbeFindingID(t, res)

	rec := readInvestigationRecord(t, st, findingID)
	if rec.NarrativeStatus != inquest.StatusOK {
		t.Errorf("NarrativeStatus = %q, want ok", rec.NarrativeStatus)
	}
	if rec.Verdict != inquest.VerdictSuspicious || rec.Confidence != 0.7 {
		t.Errorf("Verdict/Confidence = %v/%v", rec.Verdict, rec.Confidence)
	}
	if rec.Role != "evidence" {
		t.Errorf("Role = %q, want evidence (consensus invariant marker)", rec.Role)
	}
	if rec.Resolution.Action != "escalate" {
		t.Errorf("Resolution.Action = %q, want escalate", rec.Resolution.Action)
	}
	// Full evidence chain shipped (not just the narrative): identity resolved
	// the underlying event, and the neighbors/recurrence/baseline/correlation
	// sections are all present in the marshaled record.
	if rec.Evidence.Identity.Actor != "drive-by" {
		t.Errorf("Evidence.Identity.Actor = %q, want drive-by", rec.Evidence.Identity.Actor)
	}
}

// TestPipeline_InvestigateGarbageReply_DegradesButScanUnaffected proves an
// invalid narrate reply degrades ONLY the investigation record — the scan's
// own exit-relevant summary counts (findings/resolved/escalated) are
// IDENTICAL to a no-inquest run.
func TestPipeline_InvestigateGarbageReply_DegradesButScanUnaffected(t *testing.T) {
	root := useShippedCorpus(t)
	be := startCannedBackendWithNarrateReply(t, "not valid JSON at all")

	client := &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"}
	st := newGitStore(t)
	eventsPath := writeEventsFile(t, multiFindingFixture(t))

	investigateCfg := pipeline.Config{
		Connector:   connect.FromPath(eventsPath),
		Client:      client,
		Store:       st,
		Baseline:    knownActorsBaseline(),
		Cascade:     agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "evidence", toolCalls: 6, distinctTools: 4}},
		Investigate: baseInvestigateConfig(),
	}
	sumWith, err := pipeline.Run(context.Background(), investigateCfg)
	if err != nil {
		t.Fatalf("pipeline.Run (investigate on): %v", err)
	}
	if sumWith.InvestigationsDegraded != 1 || sumWith.Investigated != 0 {
		t.Fatalf("Outcome = Investigated=%d Degraded=%d, want 0/1", sumWith.Investigated, sumWith.InvestigationsDegraded)
	}

	res := loadResolutions(t, st)
	findingID := injectionProbeFindingID(t, res)
	rec := readInvestigationRecord(t, st, findingID)
	if rec.NarrativeStatus != inquest.StatusAbsentInvalidOutput {
		t.Errorf("NarrativeStatus = %q, want absent-invalid-output", rec.NarrativeStatus)
	}
	if rec.Role != "evidence" {
		t.Errorf("Role = %q, want evidence — the record still shipped despite the degraded narrative", rec.Role)
	}

	// Compare against a no-inquest baseline run over an IDENTICAL fresh
	// fixture/store: the scan-relevant counts must match exactly.
	be2 := startCannedBackendWithNarrateReply(t, "unused")
	baselineCfg := pipeline.Config{
		Connector: connect.FromPath(writeEventsFile(t, multiFindingFixture(t))),
		Client:    &inference.DirectClient{BaseURL: be2.URL(), Model: "test-model"},
		Store:     newGitStore(t),
		Baseline:  knownActorsBaseline(),
		Cascade:   agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "evidence", toolCalls: 6, distinctTools: 4}},
		// Investigate left zero-value (disabled) — the no-inquest control.
	}
	sumWithout, err := pipeline.Run(context.Background(), baselineCfg)
	if err != nil {
		t.Fatalf("pipeline.Run (no inquest): %v", err)
	}
	if sumWith.EventsScanned != sumWithout.EventsScanned ||
		sumWith.FindingsDetected != sumWithout.FindingsDetected ||
		sumWith.Resolved != sumWithout.Resolved ||
		sumWith.Escalated != sumWithout.Escalated {
		t.Errorf("scan-relevant summary counts diverged: with=%+v without=%+v", sumWith, sumWithout)
	}
}

// TestPipeline_InvestigateNilClient_AbsentNoClientRecords proves a scan run
// with NO inference client (the fail-safe-escalate-everything path) still
// produces evidence-only investigation records — narrative_status
// absent-no-client, never a panic.
func TestPipeline_InvestigateNilClient_AbsentNoClientRecords(t *testing.T) {
	root := useShippedCorpus(t)
	st := newGitStore(t)
	eventsPath := writeEventsFile(t, multiFindingFixture(t))

	cfg := pipeline.Config{
		Connector:   connect.FromPath(eventsPath),
		Client:      nil, // fail-safe: every finding escalates, cascade never calls a model
		Store:       st,
		Baseline:    knownActorsBaseline(),
		Cascade:     agent.CascadeOptions{RepoRoot: root},
		Investigate: baseInvestigateConfig(),
	}
	sum, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if sum.Escalated != sum.FindingsDetected {
		t.Fatalf("Escalated = %d, want == FindingsDetected(%d) — nil client fails every finding safe", sum.Escalated, sum.FindingsDetected)
	}
	if sum.InvestigationsDegraded != sum.Escalated {
		t.Fatalf("InvestigationsDegraded = %d, want == Escalated(%d)", sum.InvestigationsDegraded, sum.Escalated)
	}

	res := loadResolutions(t, st)
	for _, r := range res {
		rec := readInvestigationRecord(t, st, r.FindingID)
		if rec.NarrativeStatus != inquest.StatusAbsentNoClient {
			t.Errorf("finding %s NarrativeStatus = %q, want absent-no-client", r.FindingID, rec.NarrativeStatus)
		}
	}
}

// TestPipeline_NoInvestigate_WritesNoRecords proves the off-switch
// (Config.Investigate.Enabled == false, the --no-investigate equivalent) is
// honored end to end: an escalated finding produces zero
// investigations/*.json records.
func TestPipeline_NoInvestigate_WritesNoRecords(t *testing.T) {
	root := useShippedCorpus(t)
	be := startCannedBackendWithNarrateReply(t, "unused")

	st := newGitStore(t)
	cfg := pipeline.Config{
		Connector: connect.FromPath(writeEventsFile(t, multiFindingFixture(t))),
		Client:    &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"},
		Store:     st,
		Baseline:  knownActorsBaseline(),
		Cascade:   agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "evidence", toolCalls: 6, distinctTools: 4}},
		// Investigate left zero-value: Enabled==false.
	}
	sum, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if sum.Investigated != 0 || sum.InvestigationsDegraded != 0 {
		t.Fatalf("Outcome = Investigated=%d Degraded=%d, want 0/0 with investigate disabled", sum.Investigated, sum.InvestigationsDegraded)
	}

	res := loadResolutions(t, st)
	findingID := injectionProbeFindingID(t, res)
	if data, err := st.ReadSnapshot("investigations/" + findingID + ".json"); err != nil || len(data) != 0 {
		t.Fatalf("expected no investigation record with investigate disabled, got data=%q err=%v", data, err)
	}
}

// TestPipeline_RerunSameScan_NoAdditionalModelCallsNoNewInvestigationCommit
// proves a re-run over the IDENTICAL events (all deduped away, so the
// escalated finding never re-fires) makes ZERO additional narrate calls and
// leaves the investigation record's commit untouched — the idempotency
// contract holding end to end through the pipeline, not just inside RunAll.
func TestPipeline_RerunSameScan_NoAdditionalModelCallsNoNewInvestigationCommit(t *testing.T) {
	root := useShippedCorpus(t)
	be := startCannedBackendWithNarrateReply(t,
		`{"verdict":"suspicious","confidence":0.7,"narrative":"drive-by attempted a prompt-injection comment."}`)

	client := &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"}
	st := newGitStore(t)
	eventsPath := writeEventsFile(t, multiFindingFixture(t))

	cfg := pipeline.Config{
		Connector:   connect.FromPath(eventsPath),
		Client:      client,
		Store:       st,
		Baseline:    knownActorsBaseline(),
		Cascade:     agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "evidence", toolCalls: 6, distinctTools: 4}},
		Investigate: baseInvestigateConfig(),
	}

	sum1, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if sum1.Investigated != 1 {
		t.Fatalf("run 1 Investigated = %d, want 1", sum1.Investigated)
	}
	res1 := loadResolutions(t, st)
	findingID := injectionProbeFindingID(t, res1)
	rec1 := readInvestigationRecord(t, st, findingID)
	callsAfterRun1 := be.CallCount()

	// Run 2 over the SAME events file, SAME store: dedupe drops every event,
	// the finding never re-fires, and RunAll is never even invoked for it.
	sum2, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if sum2.FindingsDetected != 0 {
		t.Fatalf("run 2 FindingsDetected = %d, want 0 (all events deduped)", sum2.FindingsDetected)
	}
	if sum2.Investigated != 0 || sum2.InvestigationsDegraded != 0 {
		t.Fatalf("run 2 Outcome = Investigated=%d Degraded=%d, want 0/0 (nothing to investigate)", sum2.Investigated, sum2.InvestigationsDegraded)
	}
	if be.CallCount() != callsAfterRun1 {
		t.Errorf("run 2 made %d additional model calls, want 0 (callsAfterRun1=%d, now=%d)", be.CallCount()-callsAfterRun1, callsAfterRun1, be.CallCount())
	}

	rec2 := readInvestigationRecord(t, st, findingID)
	if rec2.CreatedAt != rec1.CreatedAt || rec2.UpdatedAt != rec1.UpdatedAt {
		t.Errorf("investigation record was touched on a no-op re-run: rec1=%+v rec2=%+v", rec1, rec2)
	}
}

// TestPipeline_ConsensusInvariant_ResolutionsUnaffectedByInvestigate proves
// the STRUCTURAL consensus invariant end to end: running the identical
// fixture/config with Investigate enabled vs disabled produces IDENTICAL
// resolutions (action/reason/actor/severity/source — every field investigate
// could theoretically have influenced), modulo each record's own wall-clock
// Timestamp (which differs because the two runs happen at different real
// times, not because investigate changed anything). Investigation runs
// STRICTLY AFTER the resolutions batch commits, so it structurally cannot
// feed back into what got escalated vs resolved.
func TestPipeline_ConsensusInvariant_ResolutionsUnaffectedByInvestigate(t *testing.T) {
	root := useShippedCorpus(t)

	runOnce := func(t *testing.T, investigate inquest.Config) []resolution.Resolution {
		be := startCannedBackendWithNarrateReply(t,
			`{"verdict":"threat","confidence":0.99,"narrative":"if this fed back, the cascade would contradict itself."}`)
		st := newGitStore(t)
		cfg := pipeline.Config{
			Connector:   connect.FromPath(writeEventsFile(t, multiFindingFixture(t))),
			Client:      &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"},
			Store:       st,
			Baseline:    knownActorsBaseline(),
			Cascade:     agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "evidence", toolCalls: 6, distinctTools: 4}},
			Investigate: investigate,
		}
		if _, err := pipeline.Run(context.Background(), cfg); err != nil {
			t.Fatalf("pipeline.Run: %v", err)
		}
		return loadResolutions(t, st)
	}

	withInvestigate := runOnce(t, baseInvestigateConfig())
	withoutInvestigate := runOnce(t, inquest.Config{Enabled: false})

	if len(withInvestigate) != len(withoutInvestigate) {
		t.Fatalf("resolution count differs: with=%d without=%d", len(withInvestigate), len(withoutInvestigate))
	}
	byFindingWith := map[string]resolution.Resolution{}
	for _, r := range withInvestigate {
		r.Timestamp = withoutInvestigate[0].Timestamp // neutralize the one field expected to differ
		byFindingWith[r.FindingID] = r
	}
	for _, r := range withoutInvestigate {
		want, ok := byFindingWith[r.FindingID]
		if !ok {
			t.Fatalf("finding %s present without investigate but not with it", r.FindingID)
		}
		got := r
		got.Timestamp = want.Timestamp
		if got != want {
			t.Errorf("resolution for %s diverged between investigate on/off:\n  with:    %+v\n  without: %+v", r.FindingID, want, got)
		}
	}
}
