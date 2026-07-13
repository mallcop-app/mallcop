package detect

import (
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// attribution_gap_test.go — mallcoppro-45f: proves two GENERAL event-type
// vocabulary gaps that caused a more specific detector's signal to go unrecognized
// entirely, letting the blanket new-actor detector be the ONLY thing that fired
// (an attribution mismatch, not a detection miss). Both fixes widen a detector's
// recognized event-type set to a real-world synonym / sibling signal shape — no
// scenario ID, actor name, or expected outcome is referenced by the detector code
// or by these tests (R9: general mechanism, not a family-match rule).

// TestNewExternalAccess_RecognizesOrgMemberAddedSynonym proves new-external-access
// now recognizes "org.member_added" (verb-noun order) as the same signal as
// "org.add_member" (noun-verb order) — a genuine non-approved external grant on
// either spelling must escalate. Uses fresh actor/grantee names distinct from any
// corpus scenario.
func TestNewExternalAccess_RecognizesOrgMemberAddedSynonym(t *testing.T) {
	ev := event.Event{
		ID: "syn-1", Source: "github", Type: "org.member_added",
		Actor: "release-admin", Timestamp: ts(16, 20),
		Payload: raw(t, map[string]any{
			"action": "add_member",
			"metadata": map[string]any{
				"member":     "unvetted-vendor-77",
				"permission": "write",
				// deliberately NO approval-signal key (vendor_approved/ticket/etc.)
			},
		}),
	}
	findings := Detect([]event.Event{ev}, &baseline.Baseline{})
	var found *string
	for _, f := range findings {
		if f.Type == "new-external-access" {
			a := f.Actor
			found = &a
		}
	}
	if found == nil {
		t.Fatalf("new-external-access did NOT fire on org.member_added; findings: %+v", findings)
	}
	if *found != "release-admin" {
		t.Errorf("new-external-access Actor = %q, want the performer %q", *found, "release-admin")
	}
}

// TestNewExternalAccess_MemberAddedStillHonorsApproval proves the synonym
// recognition did not bypass the existing approval-signal suppression: an
// org.member_added grant CARRYING an approval signal (e.g. a ticket reference)
// stays silent, same as org.add_member always has.
func TestNewExternalAccess_MemberAddedStillHonorsApproval(t *testing.T) {
	ev := event.Event{
		ID: "syn-2", Source: "github", Type: "org.member_added",
		Actor: "release-admin", Timestamp: ts(16, 21),
		Payload: raw(t, map[string]any{
			"action": "add_member",
			"metadata": map[string]any{
				"member": "approved-contractor-9",
				"ticket": "HR-2026-9999",
			},
		}),
	}
	findings := Detect([]event.Event{ev}, &baseline.Baseline{})
	for _, f := range findings {
		if f.Type == "new-external-access" {
			t.Fatalf("new-external-access fired on an APPROVED org.member_added grant: %+v", f)
		}
	}
}

// TestAuthFailureBurst_RecognizesMFAFailureBurst proves auth-failure-burst now
// owns genuine MFA-challenge brute-force/MFA-bombing bursts (5+ mfa_failure with
// no eventual success) — previously this signal was invisible to every detector
// except the blanket new-actor catch-all.
func TestAuthFailureBurst_RecognizesMFAFailureBurst(t *testing.T) {
	var evs []event.Event
	for i := 0; i < 6; i++ {
		evs = append(evs, event.Event{
			ID: "mfab-" + itoa(i), Source: "azure", Type: "mfa_failure",
			Actor: "target-user-42", Timestamp: ts(16, 22),
			Payload: raw(t, map[string]any{
				"metadata": map[string]any{"failure_reason": "incorrect_otp"},
			}),
		})
	}
	findings := Detect(evs, &baseline.Baseline{})
	var found bool
	for _, f := range findings {
		if f.Type == "auth-failure-burst" && f.Actor == "target-user-42" {
			found = true
		}
	}
	if !found {
		t.Fatalf("auth-failure-burst did NOT fire on a 6-failure MFA burst with no success; findings: %+v", findings)
	}
}

// TestAuthFailureBurst_MFAEnrollmentStruggleStaysBenign proves the new MFA
// recognition does NOT over-escalate a short, resolved struggle (below threshold,
// terminated by mfa_enrollment_complete) — the general shape AF-05 exercises, with
// a different actor/count to keep the assertion about the MECHANISM, not the
// scenario.
func TestAuthFailureBurst_MFAEnrollmentStruggleStaysBenign(t *testing.T) {
	evs := []event.Event{
		{ID: "mfae-0", Source: "azure", Type: "mfa_failure", Actor: "new-hire-dana", Timestamp: ts(16, 23)},
		{ID: "mfae-1", Source: "azure", Type: "mfa_failure", Actor: "new-hire-dana", Timestamp: ts(16, 23)},
		{ID: "mfae-2", Source: "azure", Type: "mfa_enrollment_complete", Actor: "new-hire-dana", Timestamp: ts(16, 24)},
	}
	findings := Detect(evs, &baseline.Baseline{KnownActors: []string{"new-hire-dana"}})
	for _, f := range findings {
		if f.Type == "auth-failure-burst" {
			t.Fatalf("auth-failure-burst fired on a below-threshold, resolved MFA enrollment: %+v", f)
		}
	}
}
