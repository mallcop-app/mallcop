// Command mallcop-academy posts scenario findings into an operational deployment's
// work campfire as work:create items with skill "task:triage", watches for
// terminal work:close messages, and emits per-scenario JSON artifacts.
//
// Usage:
//
//	mallcop-academy \
//	  --target-campfire <id-or-beacon> \
//	  [--scenarios-dir exams/scenarios] \
//	  [--scenario <id>] \
//	  [--output-dir docs/academy/<run-id>] \
//	  [--judge-model <id>] \
//	  [--budget-usd <n>] \
//	  [--max-concurrent <n>] \
//	  [--timeout <duration>] \
//	  [--run-id <id>]
//
// The binary posts one work:create message per scenario to the target campfire,
// then watches for work:close messages and classifies each close as terminal
// (chain complete — resolved/escalated/remediated with no follow-on work:create)
// or intermediate. Terminal closes trigger writing per-scenario JSON artifacts
// to --output-dir.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mallcop-app/mallcop/internal/exam"
)

// ---- Campfire messaging -------------------------------------------------------

// cfMessage is a partial unmarshal of the JSON returned by `cf send --json` or
// one line from `cf read --json --all`.
type cfMessage struct {
	ID        string   `json:"id"`
	Tags      []string `json:"tags"`
	Payload   string   `json:"payload"`
	Timestamp int64    `json:"timestamp"` // Unix nanoseconds; 0 when not present (legacy)
}

// cfSender shells out to the cf binary to send messages and returns the
// message ID from the --json output.
type cfSender struct {
	cfBin  string
	cfHome string // may be empty (uses default ~/.cf)
}

// send posts a message to campfireID with the given tags and returns its ID.
func (s *cfSender) send(campfireID, payload string, tags []string) (string, error) {
	args := []string{"send", campfireID, payload, "--json"}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	if s.cfHome != "" {
		args = append(args, "--cf-home", s.cfHome)
	}
	cmd := exec.Command(s.cfBin, args...)
	cmd.Env = os.Environ()
	if s.cfHome != "" {
		cmd.Env = setEnv(cmd.Env, "CF_HOME", s.cfHome)
	}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExitErr(err, &exitErr); ok {
			return "", fmt.Errorf("cf send: %w\n%s", err, exitErr.Stderr)
		}
		return "", fmt.Errorf("cf send: %w", err)
	}
	var msg cfMessage
	if err := json.Unmarshal(out, &msg); err != nil {
		return "", fmt.Errorf("parse cf send output: %w\nraw: %s", err, out)
	}
	if msg.ID == "" {
		return "", fmt.Errorf("cf send returned empty message ID; raw: %s", out)
	}
	return msg.ID, nil
}

// readAll reads all messages from campfireID and returns them.
func (s *cfSender) readAll(campfireID string) ([]cfMessage, error) {
	args := []string{"read", campfireID, "--json", "--all"}
	if s.cfHome != "" {
		args = append(args, "--cf-home", s.cfHome)
	}
	cmd := exec.Command(s.cfBin, args...)
	cmd.Env = os.Environ()
	if s.cfHome != "" {
		cmd.Env = setEnv(cmd.Env, "CF_HOME", s.cfHome)
	}
	out, err := cmd.Output()
	if err != nil {
		// cf read may return exit 1 when queue is empty — treat as empty.
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var msgs []cfMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		return nil, fmt.Errorf("parse cf read output: %w\nraw: %s", err, out)
	}
	return msgs, nil
}

// ---- Payload shapes -----------------------------------------------------------

// academyFindingPayload is the work:create payload posted to the target campfire.
// Mirrors the sanitized finding shape from exam-seed plus academy_metadata.
type academyFindingPayload struct {
	// Ready convention work:create required fields.
	ID    string `json:"id"`
	Title string `json:"title"`
	Skill string `json:"skill"`

	// Finding content (sanitized — no ground-truth fields).
	Finding findingPayload `json:"finding"`

	// Academy metadata carried alongside the finding.
	AcademyMetadata academyMetadata `json:"academy_metadata"`
}

type findingPayload struct {
	ID       string                 `json:"id"`
	Detector string                 `json:"detector"`
	Title    string                 `json:"title"`
	Severity string                 `json:"severity"`
	EventIDs []string               `json:"event_ids"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type academyMetadata struct {
	ScenarioID string              `json:"scenario_id"`
	RunID      string              `json:"run_id"`
	Expected   *exam.ExpectedResolution `json:"expected,omitempty"`
}

// ---- Per-scenario record ------------------------------------------------------

// ChainEntry records one work item in the disposition chain.
type ChainEntry struct {
	ItemID string `json:"item_id"`
	Skill  string `json:"skill,omitempty"`
	Action string `json:"action,omitempty"`
}

// ScenarioRecord is the per-scenario JSON artifact written to output-dir.
type ScenarioRecord struct {
	ScenarioID      string          `json:"scenario_id"`
	FindingID       string          `json:"finding_id"`
	RunID           string          `json:"run_id"`
	TargetCampfire  string          `json:"target_campfire"`
	PostedAt        time.Time       `json:"posted_at"`
	TerminalAt      *time.Time      `json:"terminal_at,omitempty"`
	WallSeconds     float64         `json:"wall_seconds,omitempty"`
	TerminalAction  string          `json:"terminal_action,omitempty"`
	TerminalItemID  string          `json:"terminal_item_id,omitempty"`
	// StructuralCause carries an academy-side interpretation of the raw close
	// action when the action was normalized to a different security-domain
	// terminal. Example: a worker that exits end_turn without invoking a tool
	// emits action="abandoned" on the wire; the academy normalizes that to
	// terminal_action="escalated" and records structural_cause="abandoned-by-model"
	// so downstream graders can distinguish a real escalation from a model that
	// gave up. Empty when no normalization occurred. (mallcoppro-190)
	StructuralCause string          `json:"structural_cause,omitempty"`
	FullChain       []ChainEntry    `json:"full_chain"`

	// Forge metering: real per-scenario token and call counts from GET /v1/usage.
	// Populated by querying Forge with a [posted_at, terminal_at] time window.
	// Zero when FORGE_API_KEY is absent or Forge is unreachable.
	// With max_concurrent > 1, attribution is approximate (concurrent scenario
	// time windows overlap). Run-level totals (sum across scenarios) are accurate.
	ForgeCalls int     `json:"forge_calls"`
	TokensIn   int64   `json:"tokens_in"`
	TokensOut  int64   `json:"tokens_out"`
	CostUSD    float64 `json:"cost_usd,omitempty"`

	// F4B structural grading block (nil if no expected: block in scenario yaml).
	Structural *StructuralGrade `json:"structural,omitempty"`

	// F4C rubric block (nil if judge not run or unavailable).
	Rubric *JudgeResult `json:"rubric,omitempty"`
}

// RunRecord is the run-level metadata written to run.json.
type RunRecord struct {
	RunID           string    `json:"run_id"`
	TargetCampfire  string    `json:"target_campfire"`
	ScenariosDir    string    `json:"scenarios_dir"`
	ScenarioFilter  string    `json:"scenario_filter,omitempty"`
	ScenarioPrefix  string    `json:"scenario_prefix,omitempty"`
	JudgeModel      string    `json:"judge_model,omitempty"`
	BudgetUSD       float64   `json:"budget_usd,omitempty"`
	MaxConcurrent   int       `json:"max_concurrent"`
	Timeout         string    `json:"timeout"`
	StartedAt       time.Time `json:"started_at"`
}

// ---- Tracked state ------------------------------------------------------------

// trackedScenario holds in-flight state for one scenario.
type trackedScenario struct {
	mu             sync.Mutex
	scenarioID     string
	findingID      string
	// altFindingID is the findingTrackingID (academy-<runID>-<scenarioID>) used as a
	// secondary attribution key. Workers that use the triage→investigate escalation
	// path embed this exact value as the finding_id. Matched with strict equality only
	// — no suffix extraction (mallcoppro-4dc). See matchesFindingTag.
	altFindingID   string
	workItemID     string // cf message ID of the work:create
	postedAt       time.Time
	chain          []ChainEntry
	terminal       bool
	terminalAt     time.Time
	terminalAction string
	terminalItemID string
	// structuralCause is the academy-side interpretation of the raw close action
	// (e.g. "abandoned-by-model" when legion's wire action="abandoned" was
	// normalized to terminal_action="escalated"). Empty when no normalization
	// occurred. Populated by normalizeTerminalAction at the consumption site.
	// (mallcoppro-190)
	structuralCause string

	// F4B grading inputs — accumulated during the watch loop.
	terminalReason      string // reason field from the terminal close payload
	triageCloseAction   string // action from the first task:triage close
	toolsUsedInInvest   bool   // true if any investigate step had tool calls
	maxInvestIterations int    // highest iteration count seen across investigate workers

	// Campfire-sourced usage (mallcoppro-237 A2): accumulated from tool-usage
	// tagged messages posted by resolve-finding / escalate-to-investigator /
	// escalate-to-stage-c on the work campfire. Matched by finding_id during
	// the watch loop. Non-zero when at least one terminal tool call was observed.
	toolUsageCalls     int   // sum of forge_calls fields across tool-usage messages
	toolUsageTokensIn  int64 // sum of tokens_in fields
	toolUsageTokensOut int64 // sum of tokens_out fields

	// seenToolUsageMsgs deduplicates tool-usage campfire messages by message ID.
	// cf readAll re-delivers the entire message history on every poll iteration,
	// so without dedup the same tool-usage message is counted once per poll.
	// (mallcoppro-5119)
	seenToolUsageMsgs map[string]bool

	// F4B/F4C wiring — set after judge runs (single-pass write).
	scenario    interface{} // *exam.Scenario, stored as interface{} to avoid circular import issues
	judgeResult *JudgeResult
}

// ---- Close payload parsing ----------------------------------------------------

// closePayload is a partial unmarshal of a work:close message payload.
// Handles both "action" (new convention) and "resolution" (we automaton-manager
// format). The target field is the msg ID of the original work:create and is
// used when item_id is not present.
type closePayload struct {
	ItemID     string `json:"item_id"`
	Target     string `json:"target"`     // we automaton-manager format: msg ID of work:create
	Action     string `json:"action"`
	Resolution string `json:"resolution"` // we automaton-manager format
	Skill      string `json:"skill"`
}

// resolvedAction returns the terminal action from either the action or
// resolution field, whichever is populated.
func (c closePayload) resolvedAction() string {
	if c.Action != "" {
		return c.Action
	}
	return c.Resolution
}

// resolvedItemID returns the item ID from either item_id or target field.
func (c closePayload) resolvedItemID() string {
	if c.ItemID != "" {
		return c.ItemID
	}
	return c.Target
}

// terminalActions are work:close actions that indicate chain completion.
// Any action not in this set is treated as intermediate (follow-on work expected).
//
// The set is the security-domain terminal vocabulary. Legion may emit
// additional close actions on the wire (e.g. "abandoned" — see
// normalizeTerminalAction) that the academy maps onto this vocabulary
// before classification. Legion's wire format is therefore unchanged by
// this set; mapping happens here.
var terminalActions = map[string]bool{
	"resolved":       true,
	"escalated":      true,
	"remediated":     true,
	"false-positive": true,
	"closed":         true,
}

// normalizeTerminalAction maps a raw work:close action emitted on the wire
// into the academy's security-domain terminal vocabulary, plus an optional
// structural cause that records the original wire action when normalization
// occurred.
//
// Current mappings:
//   - "abandoned" → ("escalated", "abandoned-by-model"): legion (cmd/we)
//     emits action="abandoned" when a worker exits end_turn without invoking
//     a tool (InferResult.ToolCallCount == 0). Treating this as a security-
//     domain escalation lets the chain terminate immediately while preserving
//     the distinction (structural_cause="abandoned-by-model") so graders can
//     tell a real escalation from a model that gave up. This avoids both
//     (a) the 60m lane-wall waits we used to take when abandoned was treated
//     as intermediate (see docs/bakeoff/bakeoff-20260610*), and (b) emitting
//     terminal_action="abandoned" — a value outside the security-domain
//     vocabulary that downstream rubric/grading code does not understand.
//
// Any action not explicitly mapped is passed through unchanged with an empty
// structural cause. Callers should then check terminalActions[normalized] to
// decide whether the close terminates the chain.
//
// (mallcoppro-190)
func normalizeTerminalAction(action string) (normalized string, structuralCause string) {
	switch action {
	case "abandoned":
		return "escalated", "abandoned-by-model"
	default:
		return action, ""
	}
}

// structuralFaultPrefix is the literal prefix legion's EscalateOnStructuralFault
// (fec, legion#343) emits in the reason field of a work:close payload when the
// chain is escalated due to a structural fault (e.g. tool not used). The suffix
// after the prefix is the cause token to be lifted onto
// ScenarioRecord.StructuralCause. Format: "structural-fault: <cause>".
//
// (mallcoppro-2f1)
const structuralFaultPrefix = "structural-fault: "

// parseStructuralFaultReason extracts the cause token from a fec wire-format
// reason field. It returns ("<cause>", true) if reason begins with the
// structural-fault prefix, ("", false) otherwise. Empty causes (the prefix with
// nothing after it) are treated as no-match — we will not synthesize an empty
// structural_cause.
//
// (mallcoppro-2f1)
func parseStructuralFaultReason(reason string) (cause string, ok bool) {
	if !strings.HasPrefix(reason, structuralFaultPrefix) {
		return "", false
	}
	cause = strings.TrimSpace(strings.TrimPrefix(reason, structuralFaultPrefix))
	if cause == "" {
		return "", false
	}
	return cause, true
}

// detectNoTriageInferenceChain inspects a tracked scenario's accumulated chain
// at chain quiescence (wall-timeout exit) and reports whether the chain
// matches the "triage never invoked inference" structural fault: the scenario
// has at least one work:create from the academy + at least one work:close, but
// triage never spawned an investigate work:create AND no resolve-finding tool
// call was observed (forge_calls=0).
//
// Returns true if the scenario should be reclassified as
// terminal_action="escalated" with structural_cause="no-triage-inference".
//
// Caller must hold ts.mu.
//
// (mallcoppro-2f1)
func detectNoTriageInferenceChain(ts *trackedScenario) bool {
	// Detector only runs for posted, non-terminal scenarios. Scenarios that
	// already reached a terminal classification (resolved, normal escalate,
	// abandoned→escalated via 190's normalizer, fec structural-fault via the
	// reason-parser) keep that classification — chain-shape only fires when
	// the chain quiesced WITHOUT any terminal close.
	if ts.workItemID == "" || ts.terminal {
		return false
	}
	// Require at least one work:create + one work:close in the chain. The
	// initial post adds a task:triage work:create; a triage worker that
	// processed the finding and exited would add a task:triage work:close.
	// A chain with neither is not a "no-triage-inference" — it's a posting
	// failure or a worker that never started.
	hasCreate := false
	hasClose := false
	hasInvestigateCreate := false
	for _, ce := range ts.chain {
		if ce.Action == "" {
			hasCreate = true
			if isInvestigateSkill(ce.Skill) {
				hasInvestigateCreate = true
			}
		} else {
			hasClose = true
		}
	}
	if !hasCreate || !hasClose {
		return false
	}
	// Triage spawned an investigate work item → triage DID invoke inference
	// (escalate-to-investigator is a tool call). Not a no-triage-inference
	// chain.
	if hasInvestigateCreate {
		return false
	}
	// resolve-finding tool call observed (forge_calls > 0 via tool-usage
	// messages) → triage DID invoke inference. Not a no-triage-inference
	// chain.
	if ts.toolUsageCalls > 0 {
		return false
	}
	return true
}

// ---- Academy sender interface (for testing) -----------------------------------

// Sender abstracts campfire send/readAll so tests can inject a real isolated
// campfire without constructing the full cfSender.
type Sender interface {
	send(campfireID, payload string, tags []string) (string, error)
	readAll(campfireID string) ([]cfMessage, error)
}

// ---- Core logic ---------------------------------------------------------------

type runArgs struct {
	targetCampfire  string
	scenariosDir    string
	scenarioFilter  string
	scenarioPrefix  string // comma-separated prefixes; if non-empty, only load matching scenarios
	outputDir       string
	fixturesDir     string
	judgeModel      string
	budgetUSD       float64
	maxConcurrent   int
	timeout         time.Duration
	runID           string
	usage           usageFetcher // nil = use noopUsageFetcher
}

func main() {
	if err := mainRun(); err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-academy: %v\n", err)
		os.Exit(1)
	}
}

func mainRun() error {
	var (
		deploymentDir  string
		targetCampfire string
		scenariosDir   string
		scenarioFilter string
		scenarioPrefix string
		outputDir      string
		judgeModel     string
		budgetUSD      float64
		maxConcurrent  int
		timeoutStr     string
		runID          string
	)

	var noJudge bool
	flag.BoolVar(&noJudge, "no-judge", false, "skip the F4C rubric judge (judge runs synchronously per scenario inside the watch loop and blocks; use this when you need terminal pass-rate data without quality scoring — see mallcoppro-707 for the cost-tier eval that uses the judge separately)")
	flag.StringVar(&deploymentDir, "deployment", "", "path to a mallcop deployment dir; reads .mallcop/work-campfire.id and uses .mallcop as CF_HOME (preferred over --target-campfire)")
	flag.StringVar(&targetCampfire, "target-campfire", "", "operational deployment's work campfire ID or beacon (legacy; use --deployment when possible)")
	flag.StringVar(&scenariosDir, "scenarios-dir", "", "directory containing scenario YAML files (default: repo-root/exams/scenarios)")
	flag.StringVar(&scenarioFilter, "scenario", "", "optional: limit to one scenario ID")
	flag.StringVar(&scenarioPrefix, "scenario-prefix", "", "optional: comma-separated list of scenario ID prefixes (e.g. PE,IP,LFD,PI); only scenarios whose IDs start with one of these prefixes are loaded. Enables per-rung PR-time gates targeting <5 min wall-clock (mallcoppro-bab)")
	flag.StringVar(&outputDir, "output-dir", "", "output directory for per-scenario JSON artifacts (default: docs/academy/<run-id>)")
	flag.StringVar(&judgeModel, "judge-model", "", "model for the judge (F4C territory; stored in run.json only)")
	flag.Float64Var(&budgetUSD, "budget-usd", 0, "USD budget cap (advisory, stored in run.json)")
	flag.IntVar(&maxConcurrent, "max-concurrent", 4, "maximum concurrent scenario posts")
	flag.StringVar(&timeoutStr, "timeout", "30m", "per-scenario watch timeout (e.g. 30m, 1h)")
	flag.StringVar(&runID, "run-id", "", "run identifier (default: acad-<timestamp>)")
	flag.Parse()

	// Resolve --deployment into targetCampfire + cfHome before validating.
	// See docs/design/deployment-and-identity.md (mallcop-pro) §Academy harness redesign.
	cfHome := os.Getenv("CF_HOME")
	if deploymentDir != "" {
		absDeploy, err := filepath.Abs(deploymentDir)
		if err != nil {
			return fmt.Errorf("--deployment: %w", err)
		}
		mallcopDir := filepath.Join(absDeploy, ".mallcop")
		cfIDFile := filepath.Join(mallcopDir, "work-campfire.id")
		raw, err := os.ReadFile(cfIDFile)
		if err != nil {
			return fmt.Errorf("--deployment: read %s: %w", cfIDFile, err)
		}
		hexID := strings.TrimSpace(string(raw))
		if hexID == "" {
			return fmt.Errorf("--deployment: %s is empty", cfIDFile)
		}
		if targetCampfire != "" && targetCampfire != hexID {
			return fmt.Errorf("--deployment and --target-campfire conflict (deployment work cf %q vs flag %q)", hexID, targetCampfire)
		}
		targetCampfire = hexID
		cfHome = mallcopDir
	}

	if targetCampfire == "" {
		return fmt.Errorf("--deployment or --target-campfire is required")
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return fmt.Errorf("--timeout: %w", err)
	}

	if runID == "" {
		runID = fmt.Sprintf("acad-%d", time.Now().Unix())
	}

	repoRoot, err := repoRootFromExec()
	if err != nil {
		return fmt.Errorf("determine repo root: %w", err)
	}

	if scenariosDir == "" {
		scenariosDir = filepath.Join(repoRoot, "exams", "scenarios")
	}
	if outputDir == "" {
		outputDir = filepath.Join(repoRoot, "docs", "academy", runID)
	}
	// Fixtures must land where the worker process resolves the chart's
	// relative `exams/fixtures/<RUN_ID>` path — that resolves against the
	// jail's working directory, which is the deployment dir (when running
	// against a --deployment) or the repo root (when running against a raw
	// --target-campfire).
	var fixturesDir string
	if deploymentDir != "" {
		absDeploy, derr := filepath.Abs(deploymentDir)
		if derr != nil {
			return fmt.Errorf("--deployment abs: %w", derr)
		}
		fixturesDir = filepath.Join(absDeploy, "exams", "fixtures", runID)
	} else {
		fixturesDir = filepath.Join(repoRoot, "exams", "fixtures", runID)
	}

	cfBin, err := exec.LookPath("cf")
	if err != nil {
		return fmt.Errorf("cf binary not found on PATH: %w", err)
	}

	sender := &cfSender{cfBin: cfBin, cfHome: cfHome}

	// Wire the Forge usage fetcher. The HTTP fetcher is built before clearing
	// FORGE_API_KEY (which --no-judge does to disable the judge). Usage metering
	// is independent of the judge — both use FORGE_API_KEY but for different purposes.
	var uf usageFetcher
	if f := newHTTPUsageFetcher(); f != nil {
		uf = f
	} else {
		uf = &noopUsageFetcher{}
	}

	if noJudge {
		// Setting FORGE_API_KEY="" for buildJudicator's skip path is the
		// minimum-touch way to disable the judge without changing runArgs.
		os.Setenv("FORGE_API_KEY", "")
	}
	return academy(sender, runArgs{
		targetCampfire: targetCampfire,
		scenariosDir:   scenariosDir,
		scenarioFilter: scenarioFilter,
		scenarioPrefix: scenarioPrefix,
		outputDir:      outputDir,
		fixturesDir:    fixturesDir,
		judgeModel:     judgeModel,
		budgetUSD:      budgetUSD,
		maxConcurrent:  maxConcurrent,
		timeout:        timeout,
		runID:          runID,
		usage:          uf,
	})
}

// academy is the testable core — accepts a Sender so tests can inject an
// isolated campfire.
func academy(sender Sender, args runArgs) error {
	startedAt := time.Now()

	// Load scenarios.
	scenarios, err := loadScenarios(args.scenariosDir, args.scenarioFilter, args.scenarioPrefix)
	if err != nil {
		return err
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenarios found in %s (filter=%q prefix=%q)", args.scenariosDir, args.scenarioFilter, args.scenarioPrefix)
	}

	// Create output directory.
	if err := os.MkdirAll(args.outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// F4C: build judge dispatch. Attempt to wire a judicator for this run.
	// Falls back gracefully if we binary or chart template is unavailable.
	judge := buildJudicator(args)

	// Write run.json.
	runRecord := RunRecord{
		RunID:          args.runID,
		TargetCampfire: args.targetCampfire,
		ScenariosDir:   args.scenariosDir,
		ScenarioFilter: args.scenarioFilter,
		ScenarioPrefix: args.scenarioPrefix,
		JudgeModel:     args.judgeModel,
		BudgetUSD:      args.budgetUSD,
		MaxConcurrent:  args.maxConcurrent,
		Timeout:        args.timeout.String(),
		StartedAt:      startedAt,
	}
	if err := writeJSON(filepath.Join(args.outputDir, "run.json"), runRecord); err != nil {
		return fmt.Errorf("write run.json: %w", err)
	}

	// Build tracked map: scenario_id → *trackedScenario.
	// Also build workItemID → *trackedScenario for watch-loop lookups.
	tracked := make(map[string]*trackedScenario, len(scenarios))
	for _, s := range scenarios {
		// findingID is the per-run-unique finding ID derived from the scenario's
		// base finding ID and the run ID. Suffixing with _<runID> ensures that
		// two bakeoff runs that share the same YAML finding ID (e.g. "fnd_shk_005")
		// produce distinct tracked.findingID values, preventing a work:output with
		// finding:<bare-id> from matching scenarios across runs (mallcoppro-73b).
		//
		// The suffixed ID is also carried into the work:create payload (finding.id)
		// so workers call resolve-finding with the suffixed form, ensuring the
		// finding:<id> tag on work:output is likewise suffixed and unambiguous.
		var actualFindingID string
		if s.Finding.ID != "" {
			actualFindingID = perRunFindingID(s.Finding.ID, args.runID)
		} else {
			actualFindingID = findingTrackingID(args.runID, s.ID)
		}
		// altFindingID is the findingTrackingID (academy-<runID>-<scenarioID>).
		// altFindingID is the findingTrackingID (academy-<runID>-<scenarioID>).
		// Triage workers that call escalate-to-investigator embed this exact form as
		// the finding_id in their work:create payload. Matched with strict equality
		// (mallcoppro-4dc). With timestamp run-IDs, the altFindingID is unique per
		// run, so stale messages from a prior run cannot match.
		altFindingID := findingTrackingID(args.runID, s.ID)
		ts := &trackedScenario{
			scenarioID:        s.ID,
			findingID:         actualFindingID,
			altFindingID:      altFindingID,
			seenToolUsageMsgs: make(map[string]bool),
			scenario:          s, // stored for F4B grading
		}
		tracked[s.ID] = ts
	}

	// SIGTERM handler (mallcoppro-627): when the parent process kills us (e.g.
	// bakeoff harness timeout), flush partial records for all posted-but-non-terminal
	// scenarios so the run produces JSON output rather than silence.
	//
	// The handler uses the same partial-flush logic as the watch-loop timeout path.
	// shuttingDown is checked in the watch loop to suppress redundant flushes.
	var shuttingDown atomic.Bool
	// postMu guards workItemToScenario, runPostedAtMin, and the partial-flush
	// in the SIGTERM handler. Declared here (before the SIGTERM goroutine) so
	// the closure can reference it.
	var postMu sync.Mutex

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	go func() {
		_, ok := <-sigCh
		if !ok {
			return
		}
		if !shuttingDown.CompareAndSwap(false, true) {
			return // already shutting down
		}
		fmt.Fprintf(os.Stderr, "WARN: SIGTERM received — flushing partial scenario records\n")
		postMu.Lock()
		for _, ts := range tracked {
			ts.mu.Lock()
			posted := ts.workItemID != ""
			terminal := ts.terminal
			ts.mu.Unlock()
			if posted && !terminal {
				if err := writeScenarioRecord(ts, args.runID, args.targetCampfire, args.outputDir, args.usage); err != nil {
					fmt.Fprintf(os.Stderr, "WARN: SIGTERM flush: write partial record for %s: %v\n", ts.scenarioID, err)
				}
			}
		}
		postMu.Unlock()
		os.Exit(0)
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
	}()

	// Post work:create messages, respecting max-concurrent.
	sem := make(chan struct{}, args.maxConcurrent)
	var postWG sync.WaitGroup
	// workItemToScenario maps cf message ID → scenario ID.
	workItemToScenario := make(map[string]string)

	// runPostedAtMin is the Unix-nanosecond timestamp of the FIRST successfully
	// posted scenario. Set once (guarded by postMu) in the post goroutine.
	// Used to bound the watch-loop time window: messages outside
	// [runPostedAtMin - 5s, runDeadline + 5s] are skipped before classification.
	// Zero until the first scenario is posted.
	var runPostedAtMin int64

	for _, s := range scenarios {
		postWG.Add(1)
		go func(s *exam.Scenario) {
			defer postWG.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ts := tracked[s.ID]

			// Rung 0 (March cost ladder): hard-constraint short-circuit.
			// If the finding's detector is in the always-escalate set, we
			// emit a synthetic terminal-escalate event and skip the LLM
			// worker dispatch entirely. This costs zero donuts. Findings
			// that don't match fall through to the normal triage path
			// unchanged. See cmd/mallcop-academy/hard_constraints.go.
			if reason, matched := checkHardConstraints(s.Finding.Detector); matched {
				msgID, err := seedHardConstraintEscalate(sender, s, args.runID, args.targetCampfire, reason, ts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "WARN: hard-constraint seed for scenario %s: %v\n", s.ID, err)
					return
				}
				postMu.Lock()
				workItemToScenario[msgID] = s.ID
				postMu.Unlock()

				// Write the terminal record immediately — no watch loop
				// needs to fire. Skip the judge: there is no LLM output
				// to grade, and the judge would only add cost.
				if err := writeScenarioRecord(ts, args.runID, args.targetCampfire, args.outputDir); err != nil {
					fmt.Fprintf(os.Stderr, "WARN: write scenario record for %s: %v\n", s.ID, err)
				}
				fmt.Fprintf(os.Stderr, "scenario %s hard-constraint escalate: detector=%s\n", s.ID, s.Finding.Detector)
				return
			}

			// Materialize per-scenario fixtures so the operational chart's
			// mallcop-investigate-tools (--mode exam --fixture-dir
			// exams/fixtures/<RUN_ID>) can read events.json and baseline.json
			// at the path the chart's tool args expect. Mirrors the retired
			// cmd/exam-seed/materializeFixtures step. Skipped when
			// fixturesDir is empty (mock/test paths build runArgs directly).
			if args.fixturesDir != "" {
				fxDir := filepath.Join(args.fixturesDir, s.ID)
				if err := materializeScenarioFixtures(s, fxDir); err != nil {
					fmt.Fprintf(os.Stderr, "WARN: materialize fixtures for scenario %s: %v\n", s.ID, err)
					return
				}
			}

			msgID, postedAt, err := postFinding(sender, s, args.runID, args.targetCampfire)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN: post finding for scenario %s: %v\n", s.ID, err)
				return
			}
			ts.mu.Lock()
			ts.workItemID = msgID
			ts.postedAt = postedAt
			ts.chain = append(ts.chain, ChainEntry{ItemID: msgID, Skill: "task:triage"})
			ts.mu.Unlock()

			postMu.Lock()
			workItemToScenario[msgID] = s.ID
			// Record the earliest posted-at timestamp as the run window floor.
			// Use the local clock captured in postFinding (before sender.send).
			postedAtNs := postedAt.UnixNano()
			if runPostedAtMin == 0 || postedAtNs < runPostedAtMin {
				runPostedAtMin = postedAtNs
			}
			postMu.Unlock()

			fmt.Fprintf(os.Stderr, "posted scenario %s → cf message %s\n", s.ID, msgID)
		}(s)
	}
	postWG.Wait()

	// Watch loop: poll for work:close messages until all scenarios have
	// terminal dispositions or the timeout expires.
	deadline := time.Now().Add(args.timeout)
	allTerminal := false
	for !allTerminal && time.Now().Before(deadline) {
		msgs, err := sender.readAll(args.targetCampfire)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: read campfire: %v\n", err)
		}

		// Compute time-window bounds for this poll iteration.
		// Defense-in-depth: messages outside [runPostedAtMin-5s, runDeadline+5s]
		// are skipped before classification to prevent cross-run message pickup (mallcoppro-f6b).
		// When runPostedAtMin is zero (no scenario posted yet), the window is not applied.
		// A message with Timestamp==0 also passes through (pre-timestamp cf versions).
		postMu.Lock()
		iterWindowFloor := runPostedAtMin
		iterWindowCeil := runPostedAtMin + args.timeout.Nanoseconds()
		postMu.Unlock()
		const msgWindowSlackNs = int64(5 * time.Second)

		inRunWindow := func(msg cfMessage) bool {
			if iterWindowFloor == 0 || msg.Timestamp == 0 {
				return true
			}
			return msg.Timestamp >= iterWindowFloor-msgWindowSlackNs &&
				msg.Timestamp <= iterWindowCeil+msgWindowSlackNs
		}

		// Build a fresh workItemToScenario map including any new chain items
		// (work:create from escalations) before processing closes.
		// For each work:create that chains from a known scenario item, register
		// both the message ID and the "id" field so downstream closes can be matched.
		//
		// mallcoppro-c6a (security defense, HIGH): after attribution succeeds, if
		// the work:create carries skill:task:investigate (or any investigate skill
		// tag), append a ChainEntry to that scenario's chain. The detector at
		// quiescence reads ts.chain to decide whether triage actually invoked
		// inference. Previously the create message was only registered in
		// workItemToScenario, never in ts.chain — so a triage that DID escalate
		// but whose worker crashed before posting tool-usage / its own close
		// was misclassified as no-triage-inference. Populating ts.chain on
		// attributed investigate-skill work:create closes that misclassification.
		postMu.Lock()
		for _, msg := range msgs {
			if !hasTag(msg.Tags, "work:create") {
				continue
			}
			// Time-window guard: skip out-of-window work:create messages.
			if !inRunWindow(msg) {
				slog.Debug("academy: skipping out-of-window work:create",
					"msg_id", msg.ID, "msg_ts_ns", msg.Timestamp)
				continue
			}
			// Parse work:create payload: look for "id" field (cfWorkCreate format).
			var p struct {
				ID      string `json:"id"`
				ItemID  string `json:"item_id"` // legacy
				Context string `json:"context"`
				Skill   string `json:"skill"`
			}
			if err2 := json.Unmarshal([]byte(msg.Payload), &p); err2 != nil {
				continue
			}
			workCreateID := p.ID
			if workCreateID == "" {
				workCreateID = p.ItemID
			}

			// Register message ID → scenario only if the work:create has a real
			// chain link: either msg.ID is already known (registered at post time),
			// or workCreateID appears as an antecedent in some scenario's chain.
			// The prior "first non-terminal" fallback is removed — assigning unknown
			// work:create messages to an arbitrary scenario caused mis-attribution
			// when multiple scenarios are tracked concurrently (mallcoppro-647).
			if workCreateID != "" {
				if _, known := workItemToScenario[workCreateID]; !known {
					// Check if msg.ID is already mapped (e.g. posted by academy's own sender).
					if scenIDKey, msgKnown := workItemToScenario[msg.ID]; msgKnown {
						workItemToScenario[workCreateID] = scenIDKey
					} else {
						// Walk chains: assign only if workCreateID is an antecedent
						// already present in a scenario's chain (real chain link).
						for scenIDKey, tsRef := range tracked {
							tsRef.mu.Lock()
							var chainMatch bool
							for _, ce := range tsRef.chain {
								if ce.ItemID == workCreateID {
									chainMatch = true
									break
								}
							}
							tsRef.mu.Unlock()
							if chainMatch {
								workItemToScenario[workCreateID] = scenIDKey
								workItemToScenario[msg.ID] = scenIDKey
								break
							}
						}
						// No chain link found. Before giving up, try tag-based attribution
						// (mallcoppro-60e, mallcoppro-c33): triage workers emit investigate
						// work:create items with fresh rd item IDs (not cf-msg-UUIDs), so
						// they never appear in any scenario's chain. Those messages carry a
						// finding:<id> tag scoping them to a specific scenario. If we find
						// such a tag and it matches a tracked scenario (primary or via
						// scenarioID suffix extraction), attribute it via that tag. This
						// preserves the original 647 guard (messages with no finding tag
						// are still rejected).
						if _, nowKnown := workItemToScenario[workCreateID]; !nowKnown {
							var tagFindingID string
							for _, tag := range msg.Tags {
								if strings.HasPrefix(tag, "finding:") {
									tagFindingID = strings.TrimPrefix(tag, "finding:")
									break
								}
							}
							if tagFindingID != "" {
								for scenIDKey, tsRef := range tracked {
									tsRef.mu.Lock()
									// Defense-in-depth (mallcoppro-0f9): never attribute
									// a work:create to a scenario whose post failed.
									// An unposted scenario has no real worker; any
									// matching tag is a ghost from a prior bakeoff run.
									if tsRef.workItemID == "" {
										tsRef.mu.Unlock()
										continue
									}
									match := matchesFindingTag(tsRef, tagFindingID)
									tsRef.mu.Unlock()
									if match {
										workItemToScenario[workCreateID] = scenIDKey
										workItemToScenario[msg.ID] = scenIDKey
										slog.Debug("academy: work:create attributed via finding tag",
											"msg_id", msg.ID,
											"work_create_id", workCreateID,
											"finding_id", tagFindingID,
											"scenario_id", scenIDKey,
										)
										break
									}
								}
							}
						}
						// No chain link and no scoping finding tag — log and skip.
						// Do not assign to an arbitrary scenario (the original 647 guard).
						if _, nowKnown := workItemToScenario[workCreateID]; !nowKnown {
							slog.Info("academy: work:create with no known chain antecedent — skipping assignment",
								"msg_id", msg.ID,
								"work_create_id", workCreateID,
							)
						}
					}
				}
			}

			// mallcoppro-c6a (security defense): if this work:create was
			// attributed to a tracked scenario AND it carries an investigate-skill
			// tag, append a ChainEntry to that scenario's chain. This closes the
			// chain-shape detector misclassification path documented at
			// detectNoTriageInferenceChain (hasInvestigateCreate could never fire
			// because attributed work:create messages were registered only in
			// workItemToScenario and never propagated into ts.chain).
			if workCreateID != "" {
				if scenIDKey, attributed := workItemToScenario[workCreateID]; attributed {
					skill := extractInvestigateSkillFromMessage(msg, p.Skill)
					if skill != "" {
						if tsRef, ok := tracked[scenIDKey]; ok && tsRef != nil {
							tsRef.mu.Lock()
							// Avoid duplicates: a previous poll iteration may
							// have already registered this entry.
							already := false
							for _, ce := range tsRef.chain {
								if ce.ItemID == workCreateID && ce.Action == "" {
									already = true
									break
								}
							}
							if !already {
								tsRef.chain = append(tsRef.chain, ChainEntry{
									ItemID: workCreateID,
									Skill:  skill,
								})
							}
							tsRef.mu.Unlock()
						}
					}
				}
			}
		}
		postMu.Unlock()

		// Pre-pass: accumulate ALL tool-usage messages in the batch BEFORE processing
		// any work:close/work:output messages. This ensures forge_calls is populated
		// before writeScenarioRecord is triggered, regardless of the order in which
		// the campfire delivers tool-usage vs. terminal-close messages (mallcoppro-b87,
		// mallcoppro-632). Tool-usage is tied to the run by finding_id tag, not by
		// timestamp, so it is exempt from the inRunWindow guard.
		for _, msg := range msgs {
			if hasTag(msg.Tags, "tool-usage") {
				accumulateToolUsage(msg, tracked)
			}
		}

		for _, msg := range msgs {
			// Time-window guard: skip messages outside the run's active window.
			// Defense-in-depth on top of the tag-based and chain-link filtering (mallcoppro-f6b).
			if !inRunWindow(msg) {
				slog.Debug("academy: skipping out-of-window message",
					"msg_id", msg.ID,
					"msg_ts_ns", msg.Timestamp,
					"window_floor_ns", iterWindowFloor-msgWindowSlackNs,
					"window_ceil_ns", iterWindowCeil+msgWindowSlackNs,
				)
				continue
			}

			// Accept both work:close and work:output messages.
			// work:close is posted by we automaton-manager (resolution:done always).
			// work:output with action:* tag is posted by resolve-finding tool with
			// the actual finding disposition (escalated/resolved/remediated).
			isClose := hasTag(msg.Tags, "work:close")
			isOutput := hasTag(msg.Tags, "work:output")
			if !isClose && !isOutput {
				continue
			}

			// Parse close/output payload.
			var cp closePayload
			if err := json.Unmarshal([]byte(msg.Payload), &cp); err != nil {
				continue
			}

			// For work:output messages, extract action from tags (action:<val>)
			// if the payload action field is empty.
			if isOutput && cp.Action == "" {
				for _, tag := range msg.Tags {
					if strings.HasPrefix(tag, "action:") {
						cp.Action = strings.TrimPrefix(tag, "action:")
						break
					}
				}
			}

			// For we-format closes: use target as item ID, resolution as action.
			itemID := cp.resolvedItemID()
			action := cp.resolvedAction()

			// Look up scenario via item_id/target in the payload.
			postMu.Lock()
			scenID, ok := workItemToScenario[itemID]
			if !ok {
				// Try the message's own ID.
				scenID, ok = workItemToScenario[msg.ID]
			}
			// For work:output: try matching by finding_id tag or finding_id payload field.
			// This handles resolve-finding emitting action:escalated to the work campfire
			// where the item_id/target fields don't match the original work:create msg.
			if !ok {
				// Extract finding_id from tags (finding:<id>) or payload.
				var foundFindingID string
				for _, tag := range msg.Tags {
					if strings.HasPrefix(tag, "finding:") && !strings.HasPrefix(tag, "finding:annotation") {
						foundFindingID = strings.TrimPrefix(tag, "finding:")
						break
					}
				}
				if foundFindingID == "" {
					var payloadFindingID struct{ FindingID string `json:"finding_id"` }
					if json.Unmarshal([]byte(msg.Payload), &payloadFindingID) == nil {
						foundFindingID = payloadFindingID.FindingID
					}
				}
				// Match against tracked scenario finding IDs (primary + scenario-ID suffix).
				if foundFindingID != "" {
					for scenIDKey, tsRef := range tracked {
						tsRef.mu.Lock()
						// Defense-in-depth (mallcoppro-0f9): never attribute a
						// work:close/output to a scenario whose post failed.
						if tsRef.workItemID == "" {
							tsRef.mu.Unlock()
							continue
						}
						match := matchesFindingTag(tsRef, foundFindingID)
						tsRef.mu.Unlock()
						if match {
							ok = true
							scenID = scenIDKey
							break
						}
					}
				}
			}
			// Also try chain-based lookup.
			if !ok && cp.Action != "" {
				for scenIDKey, tsRef := range tracked {
					tsRef.mu.Lock()
					for _, ce := range tsRef.chain {
						if ce.ItemID == itemID {
							ok = true
							scenID = scenIDKey
							break
						}
					}
					tsRef.mu.Unlock()
					if ok {
						break
					}
				}
			}
			postMu.Unlock()

			if !ok {
				continue
			}

			ts := tracked[scenID]
			if ts == nil {
				continue
			}

			ts.mu.Lock()
			// Add this close to the chain.
			entry := ChainEntry{ItemID: itemID, Skill: cp.Skill, Action: action}
			// Avoid duplicates.
			seen := false
			for _, ce := range ts.chain {
				if ce.ItemID == itemID && ce.Action == action {
					seen = true
					break
				}
			}
			if !seen {
				ts.chain = append(ts.chain, entry)
			}

			// F4B: capture triage close action (first task:triage close seen).
			if ts.triageCloseAction == "" && isTriageSkill(cp.Skill) {
				ts.triageCloseAction = action
			}

			// mallcoppro-190: normalize the raw wire action into the academy's
			// security-domain terminal vocabulary before classification. The
			// raw action (`action`) is still used elsewhere (e.g. chain entry,
			// triage close); only the terminal classification uses `normalized`.
			// Insertion point for future detectors (chain-shape, etc.) is
			// between this normalization and the terminal classification below.
			normalized, structCause := normalizeTerminalAction(action)

			// F4B: capture reason from close payload for mention/no-mention checks.
			if terminalActions[normalized] && ts.terminalReason == "" {
				ts.terminalReason = extractTerminalReason(msg.Payload)
			}

			// Classify as terminal: terminal action AND no follow-on work:create
			// from this close observed yet.
			if !ts.terminal && terminalActions[normalized] {
				ts.terminal = true
				now := time.Now()
				ts.terminalAt = now
				ts.terminalAction = normalized
				if structCause != "" {
					ts.structuralCause = structCause
				}
				// mallcoppro-2f1: fec wire-format parse. Legion's
				// EscalateOnStructuralFault (legion#343) encodes the structural
				// cause inside the reason field as "structural-fault: <cause>".
				// Lift it onto ts.structuralCause when it isn't already set by
				// 190's normalizer (the normalizer for action="abandoned" takes
				// precedence). This unifies fec's reason-encoded cause and 190's
				// normalizer-derived cause under one structural_cause field.
				if ts.structuralCause == "" {
					if cause, fec := parseStructuralFaultReason(ts.terminalReason); fec {
						ts.structuralCause = cause
					}
				}
				ts.terminalItemID = itemID
				ts.mu.Unlock()

				// F4C: run judge BEFORE writing the record so quality_floor is
				// populated in the single-pass write. If the judge is unavailable
				// or fails, judgeResult is set to the unavailable sentinel so that
				// quality_floor reflects "unavailable" rather than "pending".
				if judge != nil {
					jr, judgeErr := judge.spawnAndCollect(scenID, ts.findingID, args.targetCampfire)
					if judgeErr != nil {
						fmt.Fprintf(os.Stderr, "WARN: judge for scenario %s: %v\n", scenID, judgeErr)
						jr = judgeUnavailable(judgeErr.Error())
					}
					ts.mu.Lock()
					ts.judgeResult = jr
					ts.mu.Unlock()
				}

				// Write per-scenario JSON.
				if err := writeScenarioRecord(ts, args.runID, args.targetCampfire, args.outputDir, args.usage); err != nil {
					fmt.Fprintf(os.Stderr, "WARN: write scenario record for %s: %v\n", scenID, err)
				} else {
					if structCause != "" {
						fmt.Fprintf(os.Stderr, "scenario %s terminal: action=%s (raw=%s, cause=%s) item=%s\n",
							scenID, normalized, action, structCause, itemID)
					} else {
						fmt.Fprintf(os.Stderr, "scenario %s terminal: action=%s item=%s\n",
							scenID, normalized, itemID)
					}
				}
			} else {
				ts.mu.Unlock()
			}
		}

		// Check if all posted scenarios are terminal.
		allTerminal = true
		for _, ts := range tracked {
			ts.mu.Lock()
			posted := ts.workItemID != ""
			terminal := ts.terminal
			ts.mu.Unlock()
			if posted && !terminal {
				allTerminal = false
				break
			}
		}

		if !allTerminal {
			time.Sleep(2 * time.Second)
		}
	}

	if !allTerminal {
		fmt.Fprintf(os.Stderr, "WARN: timeout reached — some scenarios did not reach terminal state\n")
		// Chain-shape detector (mallcoppro-2f1). Quiescence event: the watch
		// loop exited because the wall timeout fired before all scenarios
		// reached a terminal close. For each posted, non-terminal scenario,
		// inspect the accumulated chain. If it matches the "no triage
		// inference" structural fault (work:create + work:close from triage
		// only, no investigate spawn, no resolve-finding tool call), grade
		// the scenario as terminal_action="escalated" with
		// structural_cause="no-triage-inference" before the partial-record
		// write. This converts a silent "forge_calls=0 + terminal_action=null"
		// outcome into a structured grading signal for bakeoff F4B.
		//
		// Detector runs at quiescence ONLY (here, post-loop) — not on every
		// message arrival in the watch loop — so a normal chain mid-flight is
		// never misclassified while still in progress.
		// Two-phase: first run the chain-shape detector (which may flip some
		// non-terminal scenarios to terminal with structural_cause set), then
		// write a record for every posted-but-not-yet-written scenario.
		// chainShapeFlipped tracks scenarios the detector promoted so the
		// partial-record write loop knows to include them.
		chainShapeFlipped := make(map[string]bool)
		for _, ts := range tracked {
			ts.mu.Lock()
			if detectNoTriageInferenceChain(ts) {
				now := time.Now()
				ts.terminal = true
				ts.terminalAt = now
				ts.terminalAction = "escalated"
				ts.structuralCause = "no-triage-inference"
				// terminalItemID intentionally left empty: there is no
				// terminal close message; the academy synthesized the
				// classification at chain quiescence.
				chainShapeFlipped[ts.scenarioID] = true
				fmt.Fprintf(os.Stderr, "scenario %s chain-shape: action=escalated cause=no-triage-inference\n",
					ts.scenarioID)
			}
			ts.mu.Unlock()
		}

		// Write partial records for non-terminal scenarios. Scenarios the
		// chain-shape detector just promoted to terminal must also write
		// here — they had not written on the message-arrival path because
		// no terminal close ever arrived.
		for _, ts := range tracked {
			ts.mu.Lock()
			posted := ts.workItemID != ""
			terminal := ts.terminal
			ts.mu.Unlock()
			if posted && (!terminal || chainShapeFlipped[ts.scenarioID]) {
				if err := writeScenarioRecord(ts, args.runID, args.targetCampfire, args.outputDir, args.usage); err != nil {
					fmt.Fprintf(os.Stderr, "WARN: write partial scenario record for %s: %v\n", ts.scenarioID, err)
				}
			}
		}
	}

	// Write aggregate report.md.
	if err := writeAggregateReport(args.runID, args.outputDir, scenarios, tracked); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: write aggregate report: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "academy run %s complete: %d scenarios posted\n", args.runID, len(scenarios))
	return nil
}

// ---- Scenario posting ---------------------------------------------------------

// postFinding posts a work:create message for a scenario finding to the target
// campfire. Returns the cf message ID and the time posted.
func postFinding(sender Sender, s *exam.Scenario, runID, campfireID string) (string, time.Time, error) {
	fid := findingTrackingID(runID, s.ID)

	// Use the per-run-unique finding ID in the payload so workers call
	// resolve-finding with the suffixed form. This ensures the finding:<id>
	// tag on any work:output is likewise suffixed, making cross-run collision
	// impossible. If the base finding ID is empty, fall back to the tracking ID.
	var payloadFindingID string
	if s.Finding.ID != "" {
		payloadFindingID = perRunFindingID(s.Finding.ID, runID)
	} else {
		payloadFindingID = fid
	}

	fp := findingPayload{
		ID:       payloadFindingID,
		Detector: s.Finding.Detector,
		Title:    s.Finding.Title,
		Severity: s.Finding.Severity,
		EventIDs: s.Finding.EventIDs,
		Metadata: filterAcademyMetadata(s.Finding.Metadata),
	}

	payload := academyFindingPayload{
		ID:      fid,
		Title:   s.Finding.Title,
		Skill:   "task:triage",
		Finding: fp,
		AcademyMetadata: academyMetadata{
			ScenarioID: s.ID,
			RunID:      runID,
			Expected:   s.ExpectedResolution,
		},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal payload: %w", err)
	}

	now := time.Now()
	tags := []string{
		"work:create",
		"task:triage",
		"academy:scenario",
		"scenario:" + s.ID,
		"run:" + runID,
	}
	msgID, err := sender.send(campfireID, string(payloadJSON), tags)
	if err != nil {
		return "", time.Time{}, err
	}
	return msgID, now, nil
}

// findingTrackingID returns the deterministic finding-tracking ID for a
// scenario within a run: academy-<run-id>-<scenario-id>.
func findingTrackingID(runID, scenarioID string) string {
	return "academy-" + runID + "-" + scenarioID
}

// perRunFindingID returns a per-run-unique finding ID by suffixing the base
// finding ID with the run ID: <base>_<runID>. This prevents cross-run
// finding-ID collisions when multiple bakeoff runs share the same YAML
// scenario file (and therefore the same s.Finding.ID). Allowed characters in
// the suffix are alphanumeric plus '-' and '_'; a runID like "bk-lane1" is
// safe. The base is the original finding ID from the scenario YAML (e.g.
// "fnd_shk_005"). The suffixed form is used in tracked.findingID AND in the
// work:create finding.id payload so workers call resolve-finding with it.
func perRunFindingID(baseFindingID, runID string) string {
	return baseFindingID + "_" + runID
}

// filterAcademyMetadata passes through finding metadata for academy use.
// For now we pass through all metadata fields since the academy is posting
// to its own isolated campfire and ground-truth filtering is the exam-seed's
// responsibility for the exam pipeline.
func filterAcademyMetadata(m exam.FindingMetadata) map[string]interface{} {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---- Watch-loop helpers (grading) --------------------------------------------

// isTriageSkill returns true if the skill name maps to a triage skill.
func isTriageSkill(skill string) bool {
	return skill == "task:triage" || skill == "exam:scenario"
}

// isInvestigateSkill returns true if the skill name maps to an investigate skill.
func isInvestigateSkill(skill string) bool {
	return skill == "task:investigate" || skill == "task:deep-investigate" ||
		skill == "task:investigate-merge"
}

// extractInvestigateSkillFromMessage returns the investigate skill name (e.g.
// "task:investigate") if the work:create message advertises one — either
// through a skill:* tag on the message or via the payload's parsed skill field.
// Returns "" if no investigate skill is present.
//
// mallcoppro-c6a: used by the work:create attribution path to decide whether
// to append a ChainEntry to the matched scenario's chain. Without this, the
// chain-shape detector's hasInvestigateCreate branch is structurally always
// false (see detectNoTriageInferenceChain).
func extractInvestigateSkillFromMessage(msg cfMessage, payloadSkill string) string {
	// Prefer a skill:* tag (canonical on triage's escalate-to-investigator output).
	for _, tag := range msg.Tags {
		if strings.HasPrefix(tag, "skill:") {
			skill := strings.TrimPrefix(tag, "skill:")
			if isInvestigateSkill(skill) {
				return skill
			}
		}
	}
	// Fallback: parsed skill field from the payload (handoff helpers that
	// haven't been migrated to the tag-style yet).
	if isInvestigateSkill(payloadSkill) {
		return payloadSkill
	}
	return ""
}

// ---- Tool-usage accumulation (mallcoppro-237 A2) --------------------------------

// toolUsagePayload is the JSON payload shape of a tool-usage message posted by
// resolve-finding / escalate-to-investigator / escalate-to-stage-c.
type toolUsagePayload struct {
	ForgeCalls int    `json:"forge_calls"`
	TokensIn   int64  `json:"tokens_in"`
	TokensOut  int64  `json:"tokens_out"`
	FindingID  string `json:"finding_id"`
	ItemID     string `json:"item_id"`
}

// accumulateToolUsage processes a tool-usage tagged campfire message and adds
// its forge_calls/tokens_in/tokens_out to the matching scenario's accumulators.
// Matching is done via finding_id tag (finding:<id>) or the payload finding_id field.
// Called from the watch loop for every message tagged tool-usage.
// tracked must not be held under any scenario lock when called.
//
// Dedup: cf readAll re-delivers the entire campfire history on every poll iteration.
// Without dedup, the same tool-usage message increments toolUsageCalls on each poll,
// causing forge_calls to grow as N×actual (mallcoppro-5119). Each message is
// deduplicated by msg.ID via ts.seenToolUsageMsgs before incrementing counters.
// Messages with an empty ID (pre-timestamp campfire versions) are counted without
// dedup to preserve backward compatibility.
func accumulateToolUsage(msg cfMessage, tracked map[string]*trackedScenario) {
	if msg.Payload == "" {
		return
	}
	var p toolUsagePayload
	if err := json.Unmarshal([]byte(msg.Payload), &p); err != nil {
		return
	}
	if p.ForgeCalls == 0 {
		return
	}

	// Extract finding_id from tags first (finding:<id>), then payload field.
	findingID := p.FindingID
	if findingID == "" {
		for _, tag := range msg.Tags {
			if strings.HasPrefix(tag, "finding:") && !strings.HasPrefix(tag, "finding:annotation") {
				findingID = strings.TrimPrefix(tag, "finding:")
				break
			}
		}
	}
	if findingID == "" {
		return
	}

	for _, ts := range tracked {
		ts.mu.Lock()
		// Guard (mallcoppro-0f9 + mallcoppro-4dc): if the scenario's cf post
		// failed, workItemID is empty and no real worker ever ran for this scenario.
		// Attributing tool-usage to it would produce ghost forge_calls from prior
		// bakeoff runs. With 4dc's strict matchesFindingTag (no scenarioID fallback)
		// + timestamped run-ids, this guard is defense-in-depth.
		// Drop the message and log it so future debugging is easy.
		if ts.workItemID == "" {
			slog.Debug("dropping tool-usage for unposted scenario",
				"scenario_id", ts.scenarioID,
				"msg_id", msg.ID,
			)
			ts.mu.Unlock()
			continue
		}
		match := matchesFindingTag(ts, findingID)
		if match && msg.ID != "" {
			// Dedup: skip if we've already counted this message (mallcoppro-5119).
			// Only dedup when msg.ID is non-empty; pre-ID messages pass through.
			if ts.seenToolUsageMsgs == nil {
				ts.seenToolUsageMsgs = make(map[string]bool)
			}
			if ts.seenToolUsageMsgs[msg.ID] {
				ts.mu.Unlock()
				return
			}
			ts.seenToolUsageMsgs[msg.ID] = true
		}
		if match {
			ts.toolUsageCalls += p.ForgeCalls
			ts.toolUsageTokensIn += p.TokensIn
			ts.toolUsageTokensOut += p.TokensOut
		}
		ts.mu.Unlock()
		if match {
			return
		}
	}
}

// matchesFindingTag reports whether tagFindingID refers to ts.
// ts.mu must be held by the caller.
//
// Strict exact matching only (mallcoppro-4dc). Two forms are checked:
//
//  1. Primary: exact match against ts.findingID (perRunFindingID or findingTrackingID
//     format, depending on whether s.Finding.ID was set).
//
//  2. Alt: exact match against ts.altFindingID (findingTrackingID format, always set).
//     Workers that use the triage→investigate escalation path embed the current
//     run's altFindingID exactly; this is safe to match.
//
// The scenarioID-suffix fallback from mallcoppro-c33 is intentionally removed.
// With timestamp-embedded run-IDs (bk-<lane>-<YYYYMMDD-HHMMSS>), stale messages
// from a prior run carry a different timestamp in their finding tag and will NOT
// match either ts.findingID or ts.altFindingID. Cross-run ghost attribution is
// therefore impossible without the fallback. The 647 guard is preserved: tags
// without a "finding:" prefix never reach this function.
func matchesFindingTag(ts *trackedScenario, tagFindingID string) bool {
	if ts.findingID == tagFindingID {
		return true
	}
	if ts.altFindingID != "" && ts.altFindingID == tagFindingID {
		return true
	}
	return false
}

// ---- JSON output helpers ------------------------------------------------------

// writeScenarioRecord writes a ScenarioRecord to
// <outputDir>/<scenarioID>.json.
// F4B: computes structural grading from the scenario's expected: block.
// F4C: includes the judge rubric if already collected (single-pass: judge runs
// before this function is called on the terminal close path).
func writeScenarioRecord(ts *trackedScenario, runID, targetCampfire, outputDir string, uf ...usageFetcher) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	rec := ScenarioRecord{
		ScenarioID:     ts.scenarioID,
		FindingID:      ts.findingID,
		RunID:          runID,
		TargetCampfire: targetCampfire,
		PostedAt:       ts.postedAt,
		FullChain:      ts.chain,
	}
	if ts.terminal {
		t := ts.terminalAt
		rec.TerminalAt = &t
		rec.WallSeconds = ts.terminalAt.Sub(ts.postedAt).Seconds()
		rec.TerminalAction = ts.terminalAction
		rec.TerminalItemID = ts.terminalItemID
		rec.StructuralCause = ts.structuralCause
	}

	// Forge metering: prefer campfire-sourced usage (mallcoppro-237 A2) over the
	// HTTP billing API fetcher. The campfire path reads tool-usage messages posted
	// by resolve-finding/escalate-to-investigator/escalate-to-stage-c, which counts
	// forge_calls as 1 per terminal tool invocation. This avoids the 403 returned by
	// GET /v1/usage for customer keys (GET /v1/usage requires RoleTenant auth;
	// mallcop-sk-* keys are customer-tier and will 403 — mallcoppro-d93).
	//
	// Priority:
	//   1. Campfire-accumulated data (ts.toolUsageCalls > 0): nonzero, use directly.
	//      Short-circuits the HTTP fetcher — no RoleTenant key needed.
	//   2. HTTP fetcher: only attempted when MALLCOP_FORGE_USAGE_HTTP_KEY is set
	//      (the fetcher is non-nil only when that env var is present). When both
	//      campfire data and the HTTP key are absent, forge_calls stays 0 and the
	//      canary signals the run as suspect (mallcoppro-d93).
	if ts.toolUsageCalls > 0 {
		rec.ForgeCalls = ts.toolUsageCalls
		rec.TokensIn = ts.toolUsageTokensIn
		rec.TokensOut = ts.toolUsageTokensOut
		// CostUSD not available from campfire path (no billing access); left zero.
	} else if len(uf) > 0 && uf[0] != nil {
		until := time.Now()
		if ts.terminal {
			until = ts.terminalAt
		}
		usage, err := uf[0].fetch(ts.postedAt, until)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: forge usage for scenario %s: %v\n", ts.scenarioID, err)
		} else {
			rec.ForgeCalls = usage.ForgeCalls
			rec.TokensIn = usage.TokensIn
			rec.TokensOut = usage.TokensOut
			rec.CostUSD = usage.CostUSD
		}
	} else {
		// No campfire tool-usage and no tenant key — forge_calls stays 0.
		// The canary (canary_check_lane in run-bakeoff.sh) will flag the run
		// if non-HC scenarios uniformly have forge_calls=0 (mallcoppro-d93).
		slog.Info("forge usage: no campfire tool-usage and no MALLCOP_FORGE_USAGE_HTTP_KEY; forge_calls stays 0",
			"scenario_id", ts.scenarioID)
	}

	// F4C: attach rubric if collected.
	rec.Rubric = ts.judgeResult

	// F4B: compute structural grade if the scenario has an expected: block.
	if s, ok := ts.scenario.(*exam.Scenario); ok && s != nil && s.ExpectedResolution != nil {
		rubricScore := 0
		judgeRan := false
		if ts.judgeResult != nil {
			judgeRan = true
			rubricScore = ts.judgeResult.Rubric.InvestigationThoroughness
		}
		grade := computeStructuralGrade(
			s.ExpectedResolution,
			ts.terminalAction,
			ts.terminalReason,
			ts.triageCloseAction,
			ts.toolsUsedInInvest,
			ts.maxInvestIterations,
			rubricScore,
			judgeRan,
		)
		rec.Structural = &grade
	}

	return writeJSON(filepath.Join(outputDir, ts.scenarioID+".json"), rec)
}

// writeJSON marshals v to indented JSON and writes it to path.
func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ---- Scenario loader ----------------------------------------------------------

// loadScenarios walks dir for *.yaml files and loads them via exam.Load.
// If filter is non-empty, only the scenario with that ID is returned.
// If prefix is non-empty, it is treated as a comma-separated list of ID
// prefixes; only scenarios whose IDs start with one of those prefixes are
// included. prefix and filter may be combined — filter takes precedence (a
// single-scenario filter is not further constrained by prefix). Prefix
// matching enables per-rung PR-time gates (mallcoppro-bab).
func loadScenarios(dir, filter, prefix string) ([]*exam.Scenario, error) {
	// Parse prefix list once.
	var prefixes []string
	if prefix != "" {
		for _, p := range strings.Split(prefix, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				prefixes = append(prefixes, p)
			}
		}
	}

	var paths []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, "_") {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}

	var scenarios []*exam.Scenario
	for _, p := range paths {
		s, err := exam.Load(p)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", p, err)
		}
		// --scenario exact-match filter takes priority; no prefix check needed.
		if filter != "" {
			if s.ID == filter {
				scenarios = append(scenarios, s)
			}
			continue
		}
		// --scenario-prefix filter: include only scenarios whose IDs start with
		// one of the requested prefixes. No prefix = include all.
		if len(prefixes) > 0 {
			matched := false
			for _, pfx := range prefixes {
				if strings.HasPrefix(s.ID, pfx) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		scenarios = append(scenarios, s)
	}
	return scenarios, nil
}

// ---- Watch-loop helpers -------------------------------------------------------

// hasTag returns true if tag is in tags.
func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// watchCF runs `cf read --follow --tag work:close --json` and calls handler for
// each line that parses as a cfMessage. Returns when ctx is cancelled or the
// process exits. Used in production; tests use readAll polling instead.
func watchCF(cfBin, cfHome, campfireID string, handler func(cfMessage)) error {
	args := []string{"read", campfireID, "--follow", "--json", "--tag", "work:close"}
	if cfHome != "" {
		args = append(args, "--cf-home", cfHome)
	}
	cmd := exec.Command(cfBin, args...)
	cmd.Env = os.Environ()
	if cfHome != "" {
		cmd.Env = setEnv(cmd.Env, "CF_HOME", cfHome)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("cf read pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cf read start: %w", err)
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg cfMessage
		if err := json.Unmarshal([]byte(line), &msg); err == nil {
			handler(msg)
		}
	}
	return cmd.Wait()
}

// ---- Utilities ----------------------------------------------------------------

// setEnv returns a copy of env with key=val set (replacing any existing entry).
func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			result = append(result, e)
		}
	}
	return append(result, key+"="+val)
}

// asExitErr type-asserts err to *exec.ExitError.
func asExitErr(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// repoRootFromExec resolves the repo root by walking up from the binary
// location or working directory for a go.mod file naming this module.
func repoRootFromExec() (string, error) {
	// Try binary location first.
	exe, err := os.Executable()
	if err == nil {
		if root := walkGoMod(filepath.Dir(exe)); root != "" {
			return root, nil
		}
	}
	// Try runtime caller location (useful under `go test`).
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		// cmd/mallcop-academy/main.go → ../.. → repo root
		root := filepath.Join(filepath.Dir(filename), "..", "..")
		if abs, err := filepath.Abs(root); err == nil {
			if walkGoMod(abs) != "" {
				return abs, nil
			}
		}
	}
	// Fallback: walk from cwd.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if root := walkGoMod(cwd); root != "" {
		return root, nil
	}
	return "", fmt.Errorf("could not locate mallcop-legion repo root (no matching go.mod found)")
}

func walkGoMod(start string) string {
	dir := start
	for {
		modPath := filepath.Join(dir, "go.mod")
		if b, err := os.ReadFile(modPath); err == nil {
			if strings.Contains(string(b), "module github.com/mallcop-app/mallcop") {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// Ensure watchCF is not flagged as dead code — it's production path.
var _ = watchCF

// fixtureEvents is the on-disk shape of events.json read by
// mallcop-investigate-tools in --mode exam.
type fixtureEvents struct {
	Events []exam.Event `json:"events"`
}

// fixtureBaseline is the on-disk shape of baseline.json read by
// mallcop-investigate-tools in --mode exam.
type fixtureBaseline struct {
	KnownEntities   exam.KnownEntities                `json:"known_entities"`
	FrequencyTables map[string]int                    `json:"frequency_tables,omitempty"`
	Relationships   map[string]exam.RelationshipEntry `json:"relationships,omitempty"`
}

// materializeScenarioFixtures writes events.json and baseline.json to dir
// so the operational chart's investigate tools can read them. Mirrors the
// retired cmd/exam-seed/materializeFixtures function (lost in F4D).
func materializeScenarioFixtures(s *exam.Scenario, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	evts := fixtureEvents{Events: s.Events}
	if err := writeFixtureJSON(filepath.Join(dir, "events.json"), evts); err != nil {
		return fmt.Errorf("write events.json: %w", err)
	}

	var bl fixtureBaseline
	if s.Baseline != nil {
		bl = fixtureBaseline{
			KnownEntities:   s.Baseline.KnownEntities,
			FrequencyTables: s.Baseline.FrequencyTables,
			Relationships:   s.Baseline.Relationships,
		}
	}
	if err := writeFixtureJSON(filepath.Join(dir, "baseline.json"), bl); err != nil {
		return fmt.Errorf("write baseline.json: %w", err)
	}

	return nil
}

// writeFixtureJSON marshals v to indented JSON and writes it to path.
func writeFixtureJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
