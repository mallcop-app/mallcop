// tools_idempotency_test.go — tests for the resolve-finding / escalate-to-
// investigator idempotency guard (mallcoppro-fix5).
//
// Setup mirrors tools_f1g_test.go: each test stands up an isolated cf home +
// campfire and exercises dispatchActionTool with MALLCOP_CAMPFIRE_ID pointed
// at the test campfire. The guard reads the engagement campfire via cf read
// --json --all so all of these tests skip when cf is not on PATH (CI runners
// have cf; sandboxed local runs may not).
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestResolveFinding_AllowsFirstCall confirms the guard does not interfere
// with the FIRST terminal close — the call must succeed, post work:output,
// and return the expected JSON output. This pins the baseline behaviour so a
// future refactor of the guard cannot silently block the legitimate first
// call.
func TestResolveFinding_AllowsFirstCall(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-idem-001","action":"resolved","reason":"first close — guard must allow this through."}`,
			"MALLCOP_CAMPFIRE_ID", campfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("first resolve-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result["finding_id"] != "fnd-idem-001" {
		t.Errorf("finding_id = %v, want fnd-idem-001", result["finding_id"])
	}
	if result["action"] != "resolved" {
		t.Errorf("action = %v, want resolved", result["action"])
	}

	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(msgs, "work:output") {
		t.Errorf("expected work:output tag after first resolve-finding; got %d messages", len(msgs))
	}
	if !hasTagInMessages(msgs, "action:resolved") {
		t.Errorf("expected action:resolved tag after first resolve-finding")
	}
}

// TestResolveFinding_RejectsDuplicate reproduces the CO-02 race in miniature:
// fire resolve-finding twice on the same finding_id and assert the second call
// is rejected with an error that names the prior action.
func TestResolveFinding_RejectsDuplicate(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	// First call: legitimate close.
	_ = captureStdout(t, func() {
		err := runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-dup-001","action":"resolved","reason":"first close — should land."}`,
			"MALLCOP_CAMPFIRE_ID", campfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Fatalf("first resolve-finding: unexpected error: %v", err)
		}
	})

	// Second call with a DIFFERENT verdict — guard must reject before the
	// duplicate work:output gets posted.
	var secondErr error
	_ = captureStdout(t, func() {
		secondErr = runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-dup-001","action":"escalated","reason":"stray late call from a confused worker."}`,
			"MALLCOP_CAMPFIRE_ID", campfireID,
			"CF_HOME", cfHome,
		)
	})

	if secondErr == nil {
		t.Fatal("expected idempotency error on second resolve-finding for same finding_id; got nil")
	}
	if !strings.Contains(secondErr.Error(), "already closed") {
		t.Errorf("expected 'already closed' in error; got %q", secondErr.Error())
	}
	if !strings.Contains(secondErr.Error(), "fnd-dup-001") {
		t.Errorf("expected finding_id 'fnd-dup-001' in error; got %q", secondErr.Error())
	}
	if !strings.Contains(secondErr.Error(), "resolved") {
		t.Errorf("expected prior action 'resolved' in error; got %q", secondErr.Error())
	}

	// Verify the campfire only has ONE action:escalated tag count of zero —
	// i.e. the second call did NOT leak a work:output.
	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if hasTagInMessages(msgs, "action:escalated") {
		t.Error("second resolve-finding leaked action:escalated tag despite idempotency guard")
	}
}

// TestEscalateToInvestigator_RejectsDuplicate verifies the same guard fires on
// the chain-handoff path: after a successful escalate-to-investigator, a second
// terminal call (resolve-finding here) on the same finding_id is rejected.
func TestEscalateToInvestigator_RejectsDuplicate(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, workCampfireID := newTestCampfire(t, cfBin)
	// In production the engagement campfire (MALLCOP_CAMPFIRE_ID) and the work
	// campfire (MALLCOP_WORK_CAMPFIRE_ID) are distinct. cfWorkCreate writes
	// work:create to the WORK campfire, so for this test the engagement
	// campfire must equal the work campfire — otherwise the prior work:create
	// is invisible to the guard. This matches the operational fallback where
	// legion collapses the two campfires.
	engagementCampfireID := workCampfireID

	// First call: legitimate handoff to task:investigate.
	_ = captureStdout(t, func() {
		err := runToolWithEnv(t, "escalate-to-investigator",
			`{"finding_id":"fnd-esc-dup-001","reason":"unfamiliar IP — needs investigation."}`,
			"MALLCOP_CAMPFIRE_ID", engagementCampfireID,
			"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
			"MALLCOP_ITEM_ID", "triage-item-abc",
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Fatalf("first escalate-to-investigator: unexpected error: %v", err)
		}
	})

	// Second call: stray resolve-finding for the same finding. Guard must
	// reject it because a prior chain-handoff already locked the finding.
	var secondErr error
	_ = captureStdout(t, func() {
		secondErr = runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-esc-dup-001","action":"resolved","reason":"late call after escalate already fired."}`,
			"MALLCOP_CAMPFIRE_ID", engagementCampfireID,
			"CF_HOME", cfHome,
		)
	})
	if secondErr == nil {
		t.Fatal("expected idempotency error on resolve-finding after prior escalate-to-investigator; got nil")
	}
	if !strings.Contains(secondErr.Error(), "already closed") {
		t.Errorf("expected 'already closed' in error; got %q", secondErr.Error())
	}
	if !strings.Contains(secondErr.Error(), "task:investigate") {
		t.Errorf("expected 'task:investigate' (handoff verb) in error; got %q", secondErr.Error())
	}

	// And the converse: a second escalate-to-investigator call on the same
	// finding is also rejected (race-on-race).
	var thirdErr error
	_ = captureStdout(t, func() {
		thirdErr = runToolWithEnv(t, "escalate-to-investigator",
			`{"finding_id":"fnd-esc-dup-001","reason":"second handoff — should be rejected."}`,
			"MALLCOP_CAMPFIRE_ID", engagementCampfireID,
			"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
			"MALLCOP_ITEM_ID", "triage-item-abc",
			"CF_HOME", cfHome,
		)
	})
	if thirdErr == nil {
		t.Fatal("expected idempotency error on second escalate-to-investigator; got nil")
	}
	if !strings.Contains(thirdErr.Error(), "already closed") {
		t.Errorf("expected 'already closed' in error; got %q", thirdErr.Error())
	}
}

// TestIdempotencyGuard_FailOpenOnMissingEngagementCampfire confirms the
// fail-open contract: when MALLCOP_CAMPFIRE_ID is unset we cannot enforce a
// scope, so the guard MUST return nil and let the caller proceed (or fail on
// its own requireEnv check, depending on the tool).
func TestIdempotencyGuard_FailOpenOnMissingEngagementCampfire(t *testing.T) {
	// MALLCOP_CAMPFIRE_ID intentionally unset.
	t.Setenv("MALLCOP_CAMPFIRE_ID", "")
	if err := idempotencyGuard("resolve-finding", "fnd-x"); err != nil {
		t.Errorf("expected nil (fail-open) when MALLCOP_CAMPFIRE_ID is empty; got %v", err)
	}
}

// TestIdempotencyGuard_HonorsSkipEnv confirms the MALLCOP_SKIP_IDEMPOTENCY=1
// opt-out works. This is the escape hatch for unit tests in other packages
// and for explicit operator overrides; production worker jails must never set
// it. The check must short-circuit BEFORE any campfire I/O.
func TestIdempotencyGuard_HonorsSkipEnv(t *testing.T) {
	t.Setenv("MALLCOP_CAMPFIRE_ID", "0000000000000000000000000000000000000000000000000000000000000000")
	t.Setenv("MALLCOP_SKIP_IDEMPOTENCY", "1")
	if err := idempotencyGuard("resolve-finding", "fnd-x"); err != nil {
		t.Errorf("expected nil when MALLCOP_SKIP_IDEMPOTENCY=1; got %v", err)
	}
}
