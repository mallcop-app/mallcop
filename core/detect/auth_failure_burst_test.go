package detect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// afEvent builds a login event of the given type at minute offset `min` past a
// fixed base time, carrying an optional source IP in its nested metadata.
func afEvent(id, evType, actor, ip string, min int) event.Event {
	payload := map[string]any{"action": "login_attempt", "target": "acme/auth"}
	if ip != "" {
		payload["metadata"] = map[string]any{"ip": ip}
	}
	raw, _ := json.Marshal(payload)
	return event.Event{
		ID:        id,
		Source:    "azure",
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 23, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute),
		Payload:   raw,
	}
}

func afBaseline() *baseline.Baseline { return &baseline.Baseline{} }

// countSpray returns the number of distributed-spray findings (Actor=="multiple")
// among a detector result set.
func countSpray(fs []finding.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Actor == "multiple" {
			n++
		}
	}
	return n
}

// TestAuthFailureBurst_DistributedSprayFires is the mallcoppro-bcc mechanism: five
// distinct accounts each fail ONE login from a distinct IP inside a tight window.
// No account trips the per-actor threshold, so only the cross-actor aggregation
// surfaces the coordinated campaign — exactly ONE spray finding, attributed to
// "multiple".
func TestAuthFailureBurst_DistributedSprayFires(t *testing.T) {
	evs := []event.Event{
		afEvent("e1", "login_failure", "admin-user", "198.51.100.11", 1),
		afEvent("e2", "login_failure", "ci-bot", "198.51.100.22", 3),
		afEvent("e3", "login_failure", "deploy-svc", "198.51.100.33", 5),
		afEvent("e4", "login_failure", "org-owner", "198.51.100.44", 7),
		afEvent("e5", "login_failure", "tf-automation", "198.51.100.55", 9),
	}
	got := (authFailureBurstDetector{}).Detect(evs, afBaseline())
	if countSpray(got) != 1 {
		t.Fatalf("expected exactly 1 distributed-spray finding, got %d: %+v", countSpray(got), got)
	}
	var spray finding.Finding
	for _, f := range got {
		if f.Actor == "multiple" {
			spray = f
		}
	}
	if spray.Type != "auth-failure-burst" || spray.Severity != "critical" {
		t.Fatalf("spray finding shape wrong: %+v", spray)
	}
	var ev map[string]any
	if err := json.Unmarshal(spray.Evidence, &ev); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if ev["accounts_affected"] != float64(5) || ev["distinct_ips"] != float64(5) {
		t.Errorf("evidence accounts/ips = %v/%v, want 5/5", ev["accounts_affected"], ev["distinct_ips"])
	}
}

// TestAuthFailureBurst_BenignRecoveryNoSpray proves the benign single-actor
// fat-finger (three failures from one IP, ending in success) triggers NEITHER the
// per-actor burst (below threshold, ends in success) NOR the distributed spray
// (one actor, one IP — below the cross-actor thresholds).
func TestAuthFailureBurst_BenignRecoveryNoSpray(t *testing.T) {
	evs := []event.Event{
		afEvent("e1", "login_failure", "alice", "203.0.113.1", 1),
		afEvent("e2", "login_failure", "alice", "203.0.113.1", 2),
		afEvent("e3", "login_failure", "alice", "203.0.113.1", 3),
		afEvent("e4", "login_success", "alice", "203.0.113.1", 4),
	}
	got := (authFailureBurstDetector{}).Detect(evs, afBaseline())
	if len(got) != 0 {
		t.Fatalf("expected NO findings for a benign single-actor recovery, got %d: %+v", len(got), got)
	}
}

// TestAuthFailureBurst_TwoActorsBelowSprayThreshold proves the calibration floor:
// two accounts from two IPs is under sprayMinActors/sprayMinDistinctIP and must
// NOT be treated as a coordinated campaign (the false-positive guard between an
// isolated pair of failures and a real spray).
func TestAuthFailureBurst_TwoActorsBelowSprayThreshold(t *testing.T) {
	evs := []event.Event{
		afEvent("e1", "login_failure", "alice", "203.0.113.1", 1),
		afEvent("e2", "login_failure", "bob", "203.0.113.2", 3),
	}
	if got := (authFailureBurstDetector{}).Detect(evs, afBaseline()); countSpray(got) != 0 {
		t.Fatalf("expected NO spray finding for 2 actors, got %d: %+v", countSpray(got), got)
	}
}

// TestAuthFailureBurst_SprayNeedsTightWindow proves the temporal correlation is
// real: five accounts each failing once, but spread hours apart (never three
// inside one 15-minute window), is NOT a coordinated spray.
func TestAuthFailureBurst_SprayNeedsTightWindow(t *testing.T) {
	evs := []event.Event{
		afEvent("e1", "login_failure", "a", "198.51.100.11", 0),
		afEvent("e2", "login_failure", "b", "198.51.100.22", 60),
		afEvent("e3", "login_failure", "c", "198.51.100.33", 120),
		afEvent("e4", "login_failure", "d", "198.51.100.44", 180),
		afEvent("e5", "login_failure", "e", "198.51.100.55", 240),
	}
	if got := (authFailureBurstDetector{}).Detect(evs, afBaseline()); countSpray(got) != 0 {
		t.Fatalf("expected NO spray finding when failures are spread across hours, got %d: %+v", countSpray(got), got)
	}
}

// TestAuthFailureBurst_PerActorBurstStillFires proves the original per-actor
// brute-force path is untouched: one actor accruing six failures with no success
// still fires its own auth-failure-burst finding (and no spray).
func TestAuthFailureBurst_PerActorBurstStillFires(t *testing.T) {
	var evs []event.Event
	for i := 0; i < 6; i++ {
		evs = append(evs, afEvent("e", "login_failure", "attacker", "10.0.0.1", i))
	}
	got := (authFailureBurstDetector{}).Detect(evs, afBaseline())
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 per-actor burst finding, got %d: %+v", len(got), got)
	}
	if got[0].Actor != "attacker" {
		t.Fatalf("per-actor finding actor = %q, want attacker", got[0].Actor)
	}
}
