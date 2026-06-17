// scenario_id.go — resolves the originating academy scenario item ID for the
// current worker invocation.
//
// # Why this exists
//
// mallcop-investigate-tools needs to find a scenario YAML and the per-scenario
// fixture subdir from MALLCOP_ITEM_ID. The legion runtime sets MALLCOP_ITEM_ID
// to the rd ID of the work item the current worker is executing.
//
// For triage workers spawned directly by mallcop-academy, MALLCOP_ITEM_ID IS
// the academy item ID (shape `academy-<run-id>-<scenario-id>`). The
// `academy-` prefix lets resolveFindingFamilyFromScenario and
// resolveScenarioFixtureDir locate the scenario YAML and fixture subdir.
//
// For investigate (and downstream) workers spawned via the chain-handoff
// tools (escalate-to-investigator, escalate-to-stage-c, escalate-to-deep,
// create-investigate-merge), legion's apiToolEnv exports MALLCOP_ITEM_ID set
// to the NEW handoff item ID (e.g. `mallcoppro-305`). That ID does NOT carry
// the `academy-` prefix, so the resolvers return "" and every fixture-based
// tool falls back to the run-level fixture dir, which contains no
// baseline.json or events.json. The result: empty envelopes, blind workers,
// IT-03 fails and ID-03 escapes only by accident.
//
// # Resolution priority
//
//  1. MALLCOP_SCENARIO_ITEM_ID env var — explicit override, useful for tests
//     and for any future legion build that learns to pass the scenario ID
//     through worker env directly.
//  2. The current item's rd context (`scenario_item_id=academy-...`) — the
//     handoff tools embed this when they create the downstream item, so the
//     scenario ID propagates forward through arbitrarily-deep chains
//     (triage → investigate → escalate-to-deep → merge) without needing
//     legion to plumb additional env vars. Looked up via `rd show
//     <MALLCOP_ITEM_ID> --json`.
//  3. MALLCOP_ITEM_ID — preserves legacy behavior for triage workers and
//     for any direct-spawn worker whose item ID is itself an `academy-...`
//     ID.
//
// # Security note
//
// os/exec is used here (not in main.go) so the NoNetworkImports security
// invariant continues to scan main.go cleanly. The rd binary is the same
// binary used by tools_f1g.go's chain-handoff path, so this introduces no
// new attack surface beyond what F1G already requires.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// resolveScenarioItemIDFn is the indirection point so tests can substitute
// the rd-show implementation. Production code uses the default (rd CLI
// shell-out); tests inject a fake.
var resolveScenarioItemIDFn = defaultResolveScenarioItemID

// resolveScenarioItemID returns the academy scenario item ID for the current
// worker invocation, or "" when none can be resolved.
//
// Callers fall back to "" the same way they would handle "no scenario
// context": resolveScenarioFixtureDir returns "", resolveFindingFamilyFromScenario
// returns "", and the binary uses the run-level fixture dir with empty
// matched_rules.
//
// No memoization. In production each tool invocation is a fresh subprocess,
// so the rd shell-out fires at most twice per binary run (fixture-dir +
// finding-family). In tests, multiple calls across t.Setenv boundaries must
// see live env values — caching would surface stale results across cases.
func resolveScenarioItemID() string {
	return resolveScenarioItemIDFn()
}

// scenarioItemIDForHandoff returns the scenario item ID to embed in a new
// downstream work item's context. It exists so the chain-handoff tools
// (escalate-to-investigator, escalate-to-stage-c, escalate-to-deep,
// create-investigate-merge) write a stable academy id forward without each
// caller re-implementing the priority.
//
// The function ALWAYS returns a non-empty string when any resolution path
// fires — falling back to the worker's own MALLCOP_ITEM_ID if no scenario
// override and no rd-context token can be found. This preserves the legacy
// behavior for triage-originated chains, where MALLCOP_ITEM_ID IS the
// academy id.
func scenarioItemIDForHandoff() string {
	return resolveScenarioItemID()
}

// defaultResolveScenarioItemID implements the production resolution order.
func defaultResolveScenarioItemID() string {
	// 1. Explicit env override wins.
	if v := strings.TrimSpace(os.Getenv("MALLCOP_SCENARIO_ITEM_ID")); v != "" {
		return v
	}

	// 2. Look up the current item's rd context and extract
	// scenario_item_id=<academy-...> if the handoff tools wrote it.
	itemID := strings.TrimSpace(os.Getenv("MALLCOP_ITEM_ID"))
	if itemID == "" {
		return ""
	}
	if scenarioID := scenarioIDFromRDContext(itemID); scenarioID != "" {
		return scenarioID
	}

	// 3. Legacy fallback: triage workers are spawned with MALLCOP_ITEM_ID
	// already set to the academy ID, so just return it.
	return itemID
}

// scenarioIDFromRDContext shells out to `rd show <itemID> --json` and parses
// the returned `context` field for a `scenario_item_id=<academy-...>`
// fragment. Returns "" on any error or when the field is absent — callers
// fall back to MALLCOP_ITEM_ID.
//
// The rd shell-out and JSON decode are intentionally simple: each tool
// invocation runs in a fresh subprocess and at most two callsites consult
// the resolver, so the duplicate shell-out is cheap enough not to warrant
// memoization (see resolveScenarioItemID's doc-comment).
func scenarioIDFromRDContext(itemID string) string {
	rdBin, err := exec.LookPath("rd")
	if err != nil {
		return ""
	}
	cmd := exec.Command(rdBin, "show", itemID, "--json") // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	var raw struct {
		Context string `json:"context"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return ""
	}
	return extractScenarioItemIDFromContext(raw.Context)
}

// extractScenarioItemIDFromContext parses the `scenario_item_id=<value>`
// token out of an rd item context string. The handoff tools write contexts
// of the form `skill=task:investigate finding_id=fnd_x reason=... scenario_item_id=academy-... parent_item_id=...`,
// so we split on whitespace and find the matching key=value pair.
//
// Returns "" when the token is absent or the value is empty. The value is
// not further validated — callers (resolveScenarioFixtureDir and
// resolveFindingFamilyFromScenario) already enforce the `academy-` prefix.
func extractScenarioItemIDFromContext(ctx string) string {
	if ctx == "" {
		return ""
	}
	const key = "scenario_item_id="
	for _, tok := range strings.Fields(ctx) {
		if strings.HasPrefix(tok, key) {
			return strings.TrimSpace(tok[len(key):])
		}
	}
	return ""
}

