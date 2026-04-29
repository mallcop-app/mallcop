// tools_heal_budget_test.go — Tests for heal-broaden budget gate (mallcoppro-f8f).
//
// All tests use t.TempDir() for isolation and override MALLCOP_HEAL_BUDGET_DIR
// so they never touch ~/.cache/mallcop.
package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// setTempBudgetDir sets MALLCOP_HEAL_BUDGET_DIR to a fresh temp dir and
// registers cleanup. Returns the temp dir path.
func setTempBudgetDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MALLCOP_HEAL_BUDGET_DIR", dir)
	return dir
}

// newGateAt creates a BudgetGate for the given time (using loadBudgetGateAt)
// and injects a fixed clock so all operations use the same instant.
func newGateAt(t *testing.T, now time.Time) *BudgetGate {
	t.Helper()
	bg, err := loadBudgetGateAt(now)
	if err != nil {
		t.Fatalf("loadBudgetGateAt: %v", err)
	}
	bg.nowFn = func() time.Time { return now }
	return bg
}

// TestBudgetGate_UnderCap_AllowsAttempt verifies that a fresh gate allows an
// attempt and that PerAttemptTimeout / PerAttemptTokenCap return the expected
// C5 limits.
func TestBudgetGate_UnderCap_AllowsAttempt(t *testing.T) {
	setTempBudgetDir(t)
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	bg := newGateAt(t, now)

	if err := bg.CanAttempt("log_format_drift"); err != nil {
		t.Fatalf("expected nil for fresh gate, got: %v", err)
	}
	if bg.PerAttemptTimeout() != healBudgetWallCapPerAttempt {
		t.Errorf("PerAttemptTimeout = %v, want %v", bg.PerAttemptTimeout(), healBudgetWallCapPerAttempt)
	}
	if bg.PerAttemptTokenCap() != healBudgetTokenCapPerAttempt {
		t.Errorf("PerAttemptTokenCap = %d, want %d", bg.PerAttemptTokenCap(), healBudgetTokenCapPerAttempt)
	}
}

// TestBudgetGate_AtCap_DailyCapReached verifies that the 21st attempt is
// rejected with daily_cap_reached.
func TestBudgetGate_AtCap_DailyCapReached(t *testing.T) {
	setTempBudgetDir(t)
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	bg := newGateAt(t, now)

	// Record 20 successful attempts (at cap).
	for i := 0; i < healBudgetDailyCapPerClass; i++ {
		if err := bg.RecordAttempt("log_format_drift", true, 1000); err != nil {
			t.Fatalf("RecordAttempt[%d]: %v", i, err)
		}
	}

	err := bg.CanAttempt("log_format_drift")
	if err == nil {
		t.Fatal("expected daily_cap_reached on attempt 21, got nil")
	}
	if !strings.Contains(err.Error(), "daily_cap_reached") {
		t.Fatalf("expected 'daily_cap_reached' in error, got: %v", err)
	}
}

// TestBudgetGate_3ConsecutiveFails_TriggersHourFreeze verifies that 3
// consecutive failures freeze the class for 1 hour.
func TestBudgetGate_3ConsecutiveFails_TriggersHourFreeze(t *testing.T) {
	setTempBudgetDir(t)
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	bg := newGateAt(t, now)

	// Record 3 consecutive failures.
	for i := 0; i < healBudgetConsecFailFreeze; i++ {
		if err := bg.RecordAttempt("parser_schema_mismatch", false, 5000); err != nil {
			t.Fatalf("RecordAttempt[%d]: %v", i, err)
		}
	}

	e := bg.Classes["parser_schema_mismatch"]
	if e == nil {
		t.Fatal("class entry not found after RecordAttempt")
	}
	if e.FreezeUntilUnix <= 0 {
		t.Fatal("expected FreezeUntilUnix > 0 after 3 consecutive failures")
	}
	freezeUntil := time.Unix(e.FreezeUntilUnix, 0).UTC()
	if !freezeUntil.After(now) {
		t.Fatalf("freeze_until %v is not after now %v", freezeUntil, now)
	}

	// CanAttempt must return frozen_until error.
	err := bg.CanAttempt("parser_schema_mismatch")
	if err == nil {
		t.Fatal("expected frozen_until error, got nil")
	}
	if !strings.Contains(err.Error(), "frozen_until") {
		t.Fatalf("expected 'frozen_until' in error, got: %v", err)
	}
}

// TestBudgetGate_5ConsecutiveFails_TriggersDailyFreeze verifies that 5
// consecutive failures freeze the class for the rest of the day (daily freeze).
func TestBudgetGate_5ConsecutiveFails_TriggersDailyFreeze(t *testing.T) {
	setTempBudgetDir(t)
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	bg := newGateAt(t, now)

	// Record 5 consecutive failures.
	for i := 0; i < healBudgetConsecFailDailyFreeze; i++ {
		if err := bg.RecordAttempt("detector_gap", false, 8000); err != nil {
			t.Fatalf("RecordAttempt[%d]: %v", i, err)
		}
	}

	e := bg.Classes["detector_gap"]
	if e == nil {
		t.Fatal("class entry not found after RecordAttempt")
	}
	if e.FreezeUntilUnix <= 0 {
		t.Fatal("expected FreezeUntilUnix > 0 after 5 consecutive failures")
	}

	// The freeze_until_unix must be at end-of-day (next midnight UTC).
	freezeUntil := time.Unix(e.FreezeUntilUnix, 0).UTC()
	endOfDay := time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC) // next midnight
	if !freezeUntil.Equal(endOfDay) {
		t.Fatalf("expected freeze_until = %v (end of day), got %v", endOfDay, freezeUntil)
	}

	// CanAttempt must return daily_freeze error.
	err := bg.CanAttempt("detector_gap")
	if err == nil {
		t.Fatal("expected daily_freeze error, got nil")
	}
	if !strings.Contains(err.Error(), "daily_freeze") {
		t.Fatalf("expected 'daily_freeze' in error, got: %v", err)
	}
}

// TestBudgetGate_SuccessResetsConsecutiveFailures verifies that a success
// after consecutive failures resets the consecutive_failures counter to 0.
func TestBudgetGate_SuccessResetsConsecutiveFailures(t *testing.T) {
	setTempBudgetDir(t)
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	bg := newGateAt(t, now)

	// Two consecutive failures.
	for i := 0; i < 2; i++ {
		if err := bg.RecordAttempt("log_format_drift", false, 2000); err != nil {
			t.Fatalf("RecordAttempt[%d] failure: %v", i, err)
		}
	}
	e := bg.Classes["log_format_drift"]
	if e.ConsecutiveFailures != 2 {
		t.Fatalf("expected ConsecutiveFailures=2, got %d", e.ConsecutiveFailures)
	}

	// One success resets the counter.
	if err := bg.RecordAttempt("log_format_drift", true, 3000); err != nil {
		t.Fatalf("RecordAttempt success: %v", err)
	}
	if e.ConsecutiveFailures != 0 {
		t.Fatalf("expected ConsecutiveFailures=0 after success, got %d", e.ConsecutiveFailures)
	}
}

// TestBudgetGate_UTCMidnightReset verifies that loading the budget gate for
// two different UTC dates produces independent counters.
func TestBudgetGate_UTCMidnightReset(t *testing.T) {
	setTempBudgetDir(t)

	day1 := time.Date(2026, 4, 29, 23, 59, 0, 0, time.UTC)
	day2 := time.Date(2026, 4, 30, 0, 1, 0, 0, time.UTC) // next UTC day

	// Record 5 attempts on day1.
	bg1 := newGateAt(t, day1)
	for i := 0; i < 5; i++ {
		if err := bg1.RecordAttempt("log_format_drift", true, 1000); err != nil {
			t.Fatalf("day1 RecordAttempt[%d]: %v", i, err)
		}
	}
	e1 := bg1.Classes["log_format_drift"]
	if e1.AttemptsToday != 5 {
		t.Fatalf("day1: expected AttemptsToday=5, got %d", e1.AttemptsToday)
	}

	// Load gate for day2 — must be a fresh counter (different file path).
	bg2 := newGateAt(t, day2)
	if bg2.Date != "2026-04-30" {
		t.Fatalf("day2 gate has wrong date: %q, want 2026-04-30", bg2.Date)
	}
	e2 := bg2.Classes["log_format_drift"]
	if e2 != nil && e2.AttemptsToday != 0 {
		t.Fatalf("day2: expected fresh counter (AttemptsToday=0), got %d", e2.AttemptsToday)
	}
	// CanAttempt on day2 must succeed (no carry-over from day1).
	if err := bg2.CanAttempt("log_format_drift"); err != nil {
		t.Fatalf("day2 CanAttempt: expected nil, got: %v", err)
	}
}

// TestBudgetGate_PersistsToFile verifies that a second loadBudgetGateAt call
// after RecordAttempt reads back the persisted counters.
func TestBudgetGate_PersistsToFile(t *testing.T) {
	setTempBudgetDir(t)
	now := time.Date(2026, 4, 29, 10, 0, 0, 0, time.UTC)

	bg := newGateAt(t, now)
	if err := bg.RecordAttempt("capability_seed_drift", true, 12345); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	// Verify the file was created.
	cacheDir := os.Getenv("MALLCOP_HEAL_BUDGET_DIR")
	files, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected budget file to be written, directory is empty")
	}

	// Load fresh gate from disk — must see prior counters.
	bg2 := newGateAt(t, now)
	e2 := bg2.Classes["capability_seed_drift"]
	if e2 == nil {
		t.Fatal("class entry missing after reload")
	}
	if e2.AttemptsToday != 1 {
		t.Fatalf("expected AttemptsToday=1 after reload, got %d", e2.AttemptsToday)
	}
}
