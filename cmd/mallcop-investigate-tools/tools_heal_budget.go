// tools_heal_budget.go — Per-attempt and per-day budget gate for the
// embedded self-extension engine (donut spend cap).
//
// Design source: docs/design/heal-broaden.md §10 constraint C5, §4.5.
//
// # Constraint C5 (non-negotiable from §10 ruling)
//
//   - Per-attempt token cap: 150,000 tokens.
//   - Per-attempt wall cap: 20 minutes (context.WithTimeout).
//   - Per-day attempts per finding class: 20.
//   - 3 consecutive failures → freeze that class for 1 hour.
//   - 5 consecutive failures → freeze for the day.
//   - Resets at UTC 00:00 (new file path per date).
//
// State is persisted at ~/.cache/mallcop/heal-budget-<utc-date>.json.
// Tests override the cache dir via MALLCOP_HEAL_BUDGET_DIR env var.
//
// This file does NOT register a dispatchActionTool case. It is a library
// consumed by the embedded self-extension engine (its metered inference spend cap).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Budget gate limits (C5).
const (
	healBudgetDailyCapPerClass      = 20
	healBudgetTokenCapPerAttempt    = 150_000
	healBudgetWallCapPerAttempt     = 20 * time.Minute
	healBudgetFreezeHours           = 1 // consecutive failure freeze duration
	healBudgetConsecFailFreeze      = 3 // consecutive failures → 1h freeze
	healBudgetConsecFailDailyFreeze = 5 // consecutive failures → daily freeze
)

// BudgetClassEntry tracks per-class counters for a single UTC day.
type BudgetClassEntry struct {
	AttemptsToday       int   `json:"attempts_today"`
	ConsecutiveFailures int   `json:"consecutive_failures"`
	FreezeUntilUnix     int64 `json:"freeze_until_unix"`
}

// BudgetGate holds the daily budget state for all finding classes.
type BudgetGate struct {
	Date    string                       `json:"date"`
	Classes map[string]*BudgetClassEntry `json:"classes"`

	// filePath is the path this gate was loaded from (not serialized).
	filePath string

	// nowFn is the clock function for testability. Defaults to time.Now.
	nowFn func() time.Time
}

// now returns the current time using the configured clock function.
func (bg *BudgetGate) now() time.Time {
	if bg.nowFn != nil {
		return bg.nowFn()
	}
	return time.Now().UTC()
}

// healBudgetCacheDir returns the directory for budget files. Override with
// MALLCOP_HEAL_BUDGET_DIR for tests.
func healBudgetCacheDir() (string, error) {
	if v := os.Getenv("MALLCOP_HEAL_BUDGET_DIR"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".cache", "mallcop"), nil
}

// healBudgetFilePath returns the path for the daily budget file.
// The date is derived from the current UTC clock, or from the MALLCOP_HEAL_BUDGET_DATE
// env var (used for deterministic testing without real time.Now manipulation).
func healBudgetFilePath() (string, error) {
	cacheDir, err := healBudgetCacheDir()
	if err != nil {
		return "", err
	}
	date := healBudgetDateString(time.Now().UTC())
	return filepath.Join(cacheDir, "heal-budget-"+date+".json"), nil
}

// healBudgetDateString formats a UTC time as YYYY-MM-DD for file naming.
func healBudgetDateString(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// loadBudgetGate reads ~/.cache/mallcop/heal-budget-<today-utc>.json and
// returns a *BudgetGate. Creates a fresh gate if the file is absent.
// The filePath field is populated so RecordAttempt knows where to persist.
func loadBudgetGate() (*BudgetGate, error) {
	return loadBudgetGateAt(time.Now().UTC())
}

// loadBudgetGateAt loads the budget gate for the given UTC date.
// Separated from loadBudgetGate to allow testing with a fixed date.
func loadBudgetGateAt(now time.Time) (*BudgetGate, error) {
	cacheDir, err := healBudgetCacheDir()
	if err != nil {
		return nil, err
	}

	date := healBudgetDateString(now)
	path := filepath.Join(cacheDir, "heal-budget-"+date+".json")

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Fresh gate for today.
			bg := &BudgetGate{
				Date:     date,
				Classes:  map[string]*BudgetClassEntry{},
				filePath: path,
			}
			return bg, nil
		}
		return nil, fmt.Errorf("read budget file %q: %w", path, err)
	}

	var bg BudgetGate
	if err := json.Unmarshal(data, &bg); err != nil {
		return nil, fmt.Errorf("parse budget file %q: %w", path, err)
	}
	if bg.Classes == nil {
		bg.Classes = map[string]*BudgetClassEntry{}
	}
	bg.filePath = path
	return &bg, nil
}

// classEntry returns the BudgetClassEntry for findingClass, creating it if absent.
func (bg *BudgetGate) classEntry(findingClass string) *BudgetClassEntry {
	if e, ok := bg.Classes[findingClass]; ok {
		return e
	}
	e := &BudgetClassEntry{}
	bg.Classes[findingClass] = e
	return e
}

// CanAttempt returns nil if a new attempt is permitted for findingClass, or a
// structured error describing why it is denied:
//
//   - "daily_cap_reached": attempts_today >= healBudgetDailyCapPerClass.
//   - "frozen_until <ts>": class is frozen until a future timestamp.
//   - "daily_freeze": class is frozen for the rest of the day.
func (bg *BudgetGate) CanAttempt(findingClass string) error {
	now := bg.now()
	e := bg.classEntry(findingClass)

	// Daily cap.
	if e.AttemptsToday >= healBudgetDailyCapPerClass {
		return fmt.Errorf("daily_cap_reached: finding class %q has reached the daily cap of %d attempts",
			findingClass, healBudgetDailyCapPerClass)
	}

	// Freeze check.
	if e.FreezeUntilUnix > 0 {
		freezeUntil := time.Unix(e.FreezeUntilUnix, 0).UTC()

		// End-of-day UTC = midnight at the start of tomorrow.
		today := now.UTC().Format("2006-01-02")
		endOfDay, _ := time.Parse("2006-01-02", today)
		endOfDay = endOfDay.Add(24 * time.Hour) // next midnight = end of today

		if freezeUntil.Equal(endOfDay) || freezeUntil.After(endOfDay) {
			// Daily freeze.
			return fmt.Errorf("daily_freeze: finding class %q is frozen for the rest of the day (until %s)",
				findingClass, freezeUntil.Format(time.RFC3339))
		}

		// Timed freeze.
		if now.Before(freezeUntil) {
			return fmt.Errorf("frozen_until %s: finding class %q is frozen until %s",
				freezeUntil.Format(time.RFC3339), findingClass, freezeUntil.Format(time.RFC3339))
		}
		// Freeze has expired — clear it.
		e.FreezeUntilUnix = 0
	}

	return nil
}

// RecordAttempt increments counters, applies freezes if streak hits threshold,
// and persists the updated gate to disk.
//
//   - success=true: increments attempts_today, resets consecutive_failures.
//   - success=false: increments attempts_today and consecutive_failures;
//     applies hourly freeze at threshold 3, daily freeze at threshold 5.
//
// tokens is the actual token count used (informational; stored for future
// telemetry extensions; not currently written to the per-class entry but
// available for the caller to check against PerAttemptTokenCap).
func (bg *BudgetGate) RecordAttempt(findingClass string, success bool, tokens int) error {
	_ = tokens // reserved for future telemetry; not stored in per-class entry in v1
	now := bg.now()
	e := bg.classEntry(findingClass)

	e.AttemptsToday++

	if success {
		e.ConsecutiveFailures = 0
	} else {
		e.ConsecutiveFailures++

		switch {
		case e.ConsecutiveFailures >= healBudgetConsecFailDailyFreeze:
			// 5+ consecutive failures → freeze for the rest of the day.
			today := now.UTC().Format("2006-01-02")
			endOfDay, _ := time.Parse("2006-01-02", today)
			endOfDay = endOfDay.Add(24 * time.Hour) // next midnight
			e.FreezeUntilUnix = endOfDay.Unix()

		case e.ConsecutiveFailures >= healBudgetConsecFailFreeze:
			// 3+ consecutive failures → freeze for 1 hour.
			e.FreezeUntilUnix = now.Add(healBudgetFreezeHours * time.Hour).Unix()
		}
	}

	return bg.persist()
}

// PerAttemptTimeout returns the wall-clock cap for a single heal attempt (C5).
func (bg *BudgetGate) PerAttemptTimeout() time.Duration {
	return healBudgetWallCapPerAttempt
}

// PerAttemptTokenCap returns the token cap for a single heal attempt (C5).
func (bg *BudgetGate) PerAttemptTokenCap() int {
	return healBudgetTokenCapPerAttempt
}

// persist writes the BudgetGate to its file path, creating the directory if needed.
func (bg *BudgetGate) persist() error {
	if bg.filePath == "" {
		return errors.New("budget gate has no file path — was it created via loadBudgetGate?")
	}
	if err := os.MkdirAll(filepath.Dir(bg.filePath), 0o755); err != nil {
		return fmt.Errorf("create budget cache dir: %w", err)
	}
	data, err := json.MarshalIndent(bg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal budget gate: %w", err)
	}
	if err := os.WriteFile(bg.filePath, data, 0o644); err != nil {
		return fmt.Errorf("write budget file %q: %w", bg.filePath, err)
	}
	return nil
}
