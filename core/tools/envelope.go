// envelope.go — the one-shape-always tool envelope and self-resolving config
// root, the two cross-cutting pieces of the tool-contract discipline
// (portable-agent-architecture.md §3.3, §3.5).
//
// # Envelope (§3.3, §3.4)
//
// Every tool that the agent calls returns the SAME JSON shape on EVERY call.
// Every key is present every time — empty arrays / empty strings, never an
// omitted field, never a bare null, never a conditional branch on input. A tool
// with "nothing to return" returns the canonical envelope with empty slices and
// a notes string, NOT an error and NOT a "no results" string. Errors are
// reserved for genuine schema violations (nil store, malformed record JSON).
//
// # Self-resolving config root (§3.5)
//
// Tools locate their static config (the operator-decisions rule corpus,
// fixtures) by walking UP from the binary's own location to a project marker —
// never from the current working directory (the agent runner sets CWD to a
// sandbox / worktree / /tmp) and never from an env var that "should be set" by
// the parent (the sandbox inherits a clean env). An env-var override is accepted
// as a LAST resort, but the walk is the primary path. This kills the entire
// class of "tool silently returns empty because it looked in the wrong place"
// failures (bug #1 and bug #6 in the brief).
package tools

import (
	"errors"
	"os"
	"path/filepath"
)

// SearchEventsEnvelope is the canonical wrapped output of the search-events
// tool. The same shape is returned on every call:
//
//   - Events is the matched event set (empty slice, never nil, on no matches).
//   - MatchedRules is the operator-decisions rules that match the returned
//     events' finding family + metadata (empty slice, never nil). Folding the
//     rule lookup into search-events is the §3.8 fix: the model reliably calls
//     search-events and reliably ignores a standalone lookup-rules, so the rule
//     data rides along on the tool the model already drives.
//   - FilterApplied echoes the effective filter back for transparency, so the
//     consumer can see what actually constrained the result (including a
//     date-fallback that disabled the time window).
//   - Notes is free-form: empty string on the happy path, an explanation when
//     something non-obvious happened (date filter excluded everything and was
//     dropped; finding family unknown so no rules matched; rule corpus
//     unreadable so matching was skipped). Never the channel for an error.
//
// Every field carries a json tag and is always populated — JSON marshalling
// never omits a key.
type SearchEventsEnvelope struct {
	Events        []EventView    `json:"events"`
	MatchedRules  []OperatorRule `json:"matched_rules"`
	FilterApplied FilterApplied  `json:"filter_applied"`
	Notes         string         `json:"notes"`
}

// EventView is the per-event projection returned in the envelope. It is a flat,
// stable view over the typed event.Event — id / source / type / actor /
// timestamp (RFC3339, empty when zero). Payload is omitted from the view to
// keep the envelope flat and the schema fixed; consumers that need the raw
// payload read the store directly.
type EventView struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	Type      string `json:"type"`
	Actor     string `json:"actor"`
	Timestamp string `json:"timestamp"`
}

// FilterApplied echoes the filter that actually constrained the result. Actor /
// Source / Type are the equality filters as supplied. Since / Until are the
// time-window bounds as supplied (RFC3339, empty when unbounded). Effective
// reports how the time window was applied: "applied" when it constrained the
// result, "none" when no time bound was supplied, and "dropped" when the window
// excluded every candidate and the date-hallucination fallback discarded it
// (§3.6).
type FilterApplied struct {
	Actor     string `json:"actor"`
	Source    string `json:"source"`
	Type      string `json:"type"`
	Since     string `json:"since"`
	Until     string `json:"until"`
	Effective string `json:"effective"`
}

// findConfigRoot locates the project root that holds the static config corpora
// by walking UP from the binary's own location to a project marker. It checks,
// in order at each level, for any of: the operator-decisions rule corpus
// (agents/rules/operator-decisions.yaml), a go.mod, or a .git directory. The
// first level that carries any marker is the config root.
//
// Resolution order (§3.5):
//
//  1. The walk up from os.Executable() — the PRIMARY path. CWD-independent and
//     env-independent, so it survives the agent runner relocating CWD to a
//     sandbox / worktree / /tmp and stripping the environment.
//  2. MALLCOP_REPO_ROOT env override — accepted only as a last resort when the
//     walk fails to find a marker (e.g. `go test` builds the binary into a temp
//     dir with no project marker above it). The override is checked AFTER the
//     walk so a stale/wrong env var cannot shadow a correct walk result.
//
// Returns an error only when neither the walk nor the override locate a marker.
func findConfigRoot() (string, error) {
	// Primary path: walk up from the binary location.
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for {
			if hasProjectMarker(dir) {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break // reached filesystem root
			}
			dir = parent
		}
	}

	// Last resort: explicit env override. Only consulted when the walk found no
	// marker — never allowed to shadow a successful walk.
	if v := os.Getenv("MALLCOP_REPO_ROOT"); v != "" {
		if abs, err := filepath.Abs(v); err == nil {
			return abs, nil
		}
		return v, nil
	}

	return "", errors.New("findConfigRoot: no project marker (agents/rules/operator-decisions.yaml, go.mod, or .git) found walking up from binary, and MALLCOP_REPO_ROOT unset")
}

// hasProjectMarker reports whether dir carries any recognised project-root
// marker: the shipped rule corpus, a go.mod, or a .git directory.
func hasProjectMarker(dir string) bool {
	markers := []string{
		filepath.Join("agents", "rules", "operator-decisions.yaml"),
		"go.mod",
		".git",
	}
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return false
}
