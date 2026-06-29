// runner_e2e.go — the END-TO-END scenario runner. Where RunScenario
// (runner.go) injects a SYNTHETIC finding built from the scenario's YAML
// finding: block and calls agent.ResolveFindingWith directly, RunScenarioE2E
// drives the SAME pipeline.Run the production `mallcop scan` command calls
// (cmd/mallcop/scan.go): connect → detect.Detect (the REAL detector fleet) →
// store findings → resolveAll → store resolutions. The finding the cascade
// resolves is WHATEVER core/detect emits over the scenario's raw events — NOT the
// YAML block. Tools come from the PRODUCTION core/toolrun.Runner over the same
// isolated store.
//
// This is the only path that exercises connect+detect+toolrun+store together as a
// real scan does. Everything downstream of the verdict (Grade, median-of-N, the
// classifier, the corpus interlock) is SHARED with -mode real, so the e2e number
// is directly comparable to the -mode real number — but ONLY over the scenarios
// detect actually reproduces. The detect-fidelity accounting (detectfidelity.go)
// measures and surfaces that reproduction gap explicitly; it is the headline
// result e2e exposes and is NEVER silently passed or folded into the pass-rate.
//
// PER-SCENARIO ISOLATION: each scenario gets a FRESH temp git store
// (os.MkdirTemp + gitInit + store.Open), torn down before the next scenario.
// toolrun.Runner re-reads the live store per finding, so a shared store would leak
// scenario A's events/findings into scenario B's tool reads. Workers:1 keeps the
// per-scenario resolve ordering deterministic.
//
// core/eval is the harness layer (not the shipped runtime), so importing
// core/pipeline + core/toolrun + core/connect + core/store here is the intended
// seam — the import-lint bans only vendor SDKs / orchestration / dropped transport
// (see imports_test.go), none of which this adds.
package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/toolrun"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// memConnector is the in-memory connect.Connector seam for the e2e runner: it
// returns the scenario's events (projected to the on-disk event.Event shape via
// eventRecord) without any filesystem fixture. pipeline.Run pulls through this
// exactly as it pulls through the production FileConnector.
type memConnector struct {
	events []event.Event
}

func (m *memConnector) Pull(_ context.Context) ([]event.Event, error) {
	return m.events, nil
}

// compile-time proof memConnector satisfies the pipeline's input seam.
var _ connect.Connector = (*memConnector)(nil)

// E2EOutcome is the per-scenario result of an end-to-end run: the graded
// ScenarioResult (shared shape with -mode real, so the median/classifier spine
// works unchanged) plus the detect-fidelity record that says whether detect even
// reproduced the scenario's expected finding.
type E2EOutcome struct {
	Result   ScenarioResult
	Fidelity DetectFidelityRow
	// Transcript is the captured model exchanges across all findings in this
	// scenario's run (§4.7). Carried so the harness writes artifacts from one source.
	Transcript []TranscriptEntry
}

// RunScenarioE2E runs ONE scenario through the REAL pipeline.Run over a fresh,
// isolated temp git store and returns the graded outcome + detect-fidelity row.
//
// Steps (mirrors cmd/mallcop/scan.go's pipeline.Config, minus the file I/O):
//  1. Fresh temp git store per scenario (seedScenarioStore's gitInit+store.Open
//     pattern, but WITHOUT pre-seeding the finding — detect must produce it).
//  2. baselineFromScenario reconstructs the typed baseline the prod detectors +
//     toolrun read.
//  3. memConnector returns the scenario's eventRecord-projected events.
//  4. recordingClient wraps the supplied Client so the transcript is captured.
//  5. pipeline.Run with Workers:1, ConsensusRuns threaded from opts, and the
//     PROD toolrun.Runner over the same store + baseline.
//  6. Read resolutions back from the store IN-PROCESS (store.Load), map the
//     action string (resolve/escalate → resolved/escalated), classify detect
//     fidelity, build a ScenarioRun, and Grade it.
//  7. Tear down the temp store.
//
// opts carries the per-tier model ids + ConsensusRuns (defaulted ON by harness.Run,
// identical to -mode real). repoRoot pins the §3.8 operator-decisions corpus for
// toolrun (pass the eval RepoRoot; "" lets the binary-walk resolve it).
func RunScenarioE2E(ctx context.Context, client agent.Client, ls LoadedScenario, opts agent.CascadeOptions, repoRoot string) (E2EOutcome, error) {
	s := ls.Scenario

	// (1) Fresh, isolated temp git store per scenario. toolrun re-reads the live
	// store per finding, so isolation is load-bearing — a shared store would leak
	// scenario A's events into scenario B's tool reads.
	tmpDir, err := os.MkdirTemp("", "mallcop-e2e-scenario-*")
	if err != nil {
		return E2EOutcome{}, fmt.Errorf("e2e: mkdir temp store: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	if err := gitInit(tmpDir); err != nil {
		return E2EOutcome{}, fmt.Errorf("e2e: %w", err)
	}
	st, err := store.Open(tmpDir)
	if err != nil {
		return E2EOutcome{}, fmt.Errorf("e2e: open store: %w", err)
	}

	// (2) The typed baseline the prod detectors + toolrun read — the SAME
	// reconstruction the eval scenario runner uses, so detect sees the scenario's
	// known actors / frequency tables / relationships.
	bl := baselineFromScenario(s)

	// (3) In-memory connector over the scenario's events (eventRecord projection).
	memConn := &memConnector{events: scenarioEvents(s)}

	// (4) Capture the transcript across every finding the cascade resolves.
	rc := &recordingClient{inner: client}

	// (5) Drive the REAL pipeline. Workers:1 keeps per-scenario ordering
	// deterministic. The PROD toolrun.Runner gives the cascade the live tool surface
	// over THIS scenario's isolated store + baseline — exactly the object scan.go
	// wires. ConsensusRuns is threaded from opts (defaulted ON by harness.Run).
	start := time.Now()
	_, runErr := pipeline.Run(ctx, pipeline.Config{
		Connector: memConn,
		Client:    rc,
		Store:     st,
		Baseline:  bl,
		Workers:   1,
		Cascade: agent.CascadeOptions{
			TriageModel:          opts.TriageModel,
			InvestigateModel:     opts.InvestigateModel,
			EscalateModel:        opts.EscalateModel,
			ConsensusRuns:        opts.ConsensusRuns,
			ConsensusTemperature: opts.ConsensusTemperature,
			RepoRoot:             repoRoot,
			Tools:                &toolrun.Runner{Store: st, Baseline: bl, RepoRoot: repoRoot},
		},
	})
	wall := time.Since(start)
	if runErr != nil {
		return E2EOutcome{}, fmt.Errorf("e2e: pipeline.Run for %s: %w", s.ID, runErr)
	}

	// (6a) Read back the durable findings + resolutions from the store, in-process.
	emitted, err := loadStoredFindings(st)
	if err != nil {
		return E2EOutcome{}, fmt.Errorf("e2e: load findings for %s: %w", s.ID, err)
	}
	resolutions, err := loadStoredResolutions(st)
	if err != nil {
		return E2EOutcome{}, fmt.Errorf("e2e: load resolutions for %s: %w", s.ID, err)
	}

	// (6b) Classify detect fidelity: did detect reproduce the scenario's expected
	// finding (REPRODUCED), emit a different one (MISMATCH), or nothing (DETECT-MISS)?
	fidelity := classifyDetectFidelity(s, emitted, resolutions)

	// (6c) Build the graded ScenarioRun from the store, NOT from a synthetic
	// resolve. terminalActionFromFidelity maps the matched resolution's store action
	// (resolve/escalate) onto the grader's vocabulary (resolved/escalated).
	terminal, reason, forced := terminalFromFidelity(fidelity, resolutions)
	transcript := rc.transcript()
	run := ScenarioRun{
		Scenario:       ls,
		TerminalAction: terminal,
		TerminalReason: reason,
		ForceEscalated: forced,
		ModelCalls:     len(transcript),
		Transcript:     transcript,
		WallMillis:     wall.Milliseconds(),
	}
	res := Grade(run)

	return E2EOutcome{
		Result:     res,
		Fidelity:   fidelity,
		Transcript: transcript,
	}, nil
}

// scenarioEvents projects a scenario's events into the on-disk event.Event shape
// the connector hands the pipeline (eventRecord is the same projection
// seedScenarioStore uses, so detect reads identical events).
func scenarioEvents(s *exam.Scenario) []event.Event {
	out := make([]event.Event, 0, len(s.Events))
	for _, ev := range s.Events {
		out = append(out, eventRecord(ev))
	}
	return out
}

// loadStoredFindings replays the KindFindings stream the pipeline durably wrote.
// In-process (store.Load reads committed HEAD via git cat-file) — no `git show`
// subprocess. Returns the typed findings detect emitted for this scenario.
func loadStoredFindings(st *store.Store) ([]finding.Finding, error) {
	raws, err := st.Load(store.KindFindings)
	if err != nil {
		return nil, err
	}
	out := make([]finding.Finding, 0, len(raws))
	for _, raw := range raws {
		var f finding.Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("unmarshal finding: %w", err)
		}
		out = append(out, f)
	}
	return out, nil
}

// loadStoredResolutions replays the KindResolutions stream the pipeline durably
// wrote. In-process, same discipline as loadStoredFindings.
func loadStoredResolutions(st *store.Store) ([]resolution.Resolution, error) {
	raws, err := st.Load(store.KindResolutions)
	if err != nil {
		return nil, err
	}
	out := make([]resolution.Resolution, 0, len(raws))
	for _, raw := range raws {
		var r resolution.Resolution
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("unmarshal resolution: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}
