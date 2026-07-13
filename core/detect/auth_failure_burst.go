package detect

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(authFailureBurstDetector{}) }

type authFailureBurstDetector struct{}

func (authFailureBurstDetector) Name() string { return "auth-failure-burst" }

const (
	// authBurstThreshold is the minimum same-actor auth-failure count that marks
	// a brute-force / credential-stuffing burst. The corpus emits a representative
	// slice of the burst (AF-03: 6 failures), so a threshold of 5 separates a real
	// burst from a benign fat-finger (AF-01: 3 failures then success).
	authBurstThreshold = 5

	// A DISTRIBUTED password spray (Midnight Blizzard low-and-slow) spreads failed
	// logins across MANY accounts from MANY IPs so no single account trips
	// authBurstThreshold. The per-actor loop above is blind to it: every actor has
	// one failure. The aggregate signal is the cross-actor correlation — N distinct
	// accounts each failing from a distinct source IP inside a tight window. The
	// thresholds are calibrated between the benign single-actor recoveries (AF-01 /
	// AF-04: one actor, one IP) and the coordinated campaign (AF-02: 5 accounts, 5
	// IPs, 9 minutes): three-of-each cleanly separates them.
	spraySameWindow    = 15 * time.Minute
	sprayMinActors     = 3
	sprayMinDistinctIP = 3
)

// authFailureEventTypes are the event types that carry a FAILED authentication
// challenge attempt. login_failure is the password-challenge form; mfa_failure is
// the same "failed proof of identity" signal for a second-factor challenge (TOTP/
// push code entered wrong) — recognizing both means a genuine MFA-based brute-force
// or MFA-bombing burst (5+ mfa_failures with no eventual success) is owned by
// auth-failure-burst rather than going undetected (mallcoppro-45f).
var authFailureEventTypes = map[string]bool{
	"login_failure": true,
	"mfa_failure":   true,
}

// authSuccessEventTypes are the TERMINAL event types that resolve a same-actor
// failure run as benign recovery: the account owner (or new-hire enrolling a
// device) eventually succeeded. login_success pairs with login_failure;
// mfa_enrollment_complete is the terminal success of an MFA enrollment flow that
// starts with mfa_failure attempts (a struggled-but-successful authenticator setup,
// not an attack).
var authSuccessEventTypes = map[string]bool{
	"login_success":           true,
	"mfa_enrollment_complete": true,
}

// Detect groups auth-failure events (see authFailureEventTypes) by actor and fires
// when an actor accrues authBurstThreshold or more failures WITHOUT a terminal
// success (see authSuccessEventTypes) — the brute-force signature. A short run of
// failures that ENDS in a success is a benign fat-finger / password-reset recovery
// / MFA-enrollment struggle (AF-01, AF-04, AF-05) and is NOT escalated. Fires on
// ev.Actor (the performing identity the finding metadata names).
func (authFailureBurstDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	type actorState struct {
		failures   int
		succeeded  bool
		firstEvent event.Event
	}
	states := map[string]*actorState{}
	order := []string{}

	for _, ev := range events {
		switch {
		case authFailureEventTypes[ev.Type]:
			st := states[ev.Actor]
			if st == nil {
				st = &actorState{firstEvent: ev}
				states[ev.Actor] = st
				order = append(order, ev.Actor)
			}
			st.failures++
		case authSuccessEventTypes[ev.Type]:
			if st := states[ev.Actor]; st != nil {
				// A terminal success after the failures resolves the burst: the
				// account owner recovered (or completed MFA enrollment). Mark it
				// benign.
				st.succeeded = true
			}
		}
	}

	var out []finding.Finding
	for _, actor := range order {
		st := states[actor]
		if st.failures < authBurstThreshold {
			continue
		}
		if st.succeeded {
			// Failures ended in a successful login — benign recovery, not a burst.
			continue
		}
		meta := payloadMeta(st.firstEvent.Payload)
		evidence, _ := json.Marshal(map[string]any{
			"actor":         actor,
			"failure_count": st.failures,
			"ip":            metaStr(meta, "ip", "source_ip"),
			"reason":        metaStr(meta, "reason"),
			"event_id":      st.firstEvent.ID,
		})
		out = append(out, finding.Finding{
			ID:        "finding-" + st.firstEvent.ID,
			Source:    "detector:auth-failure-burst",
			Severity:  "high",
			Type:      "auth-failure-burst",
			Actor:     actor,
			Timestamp: st.firstEvent.Timestamp,
			Reason: fmt.Sprintf(
				"authentication failure burst: %q accrued %d failed logins with no successful login",
				actor, st.failures,
			),
			Evidence: evidence,
		})
	}

	if spray := detectDistributedSpray(events); spray != nil {
		out = append(out, *spray)
	}
	return out
}

// detectDistributedSpray finds a low-and-slow password spray: many DISTINCT
// accounts each failing to log in from a DISTINCT source IP inside a tight window,
// where no single account trips the per-actor burst threshold. It slides a window
// over the login_failure events (sorted by time) and fires ONCE when any window
// holds at least sprayMinActors distinct actors AND sprayMinDistinctIP distinct
// source IPs — the cross-actor correlation the per-actor loop cannot see.
//
// General mechanism (calibrated thresholds + cross-actor aggregation), NOT a
// per-scenario rule: the benign single-actor recoveries stay below sprayMinActors
// and never match; a coordinated campaign across many accounts/IPs does. The
// finding actor is "multiple" (the canonical cross-actor marker the finding
// metadata names) since no single identity owns the campaign.
func detectDistributedSpray(events []event.Event) *finding.Finding {
	type fail struct {
		ts    time.Time
		actor string
		ip    string
		ev    event.Event
	}
	var fails []fail
	for _, ev := range events {
		if ev.Type != "login_failure" {
			continue
		}
		meta := payloadMeta(ev.Payload)
		fails = append(fails, fail{
			ts:    ev.Timestamp.UTC(),
			actor: ev.Actor,
			ip:    metaStr(meta, "ip", "source_ip"),
			ev:    ev,
		})
	}
	if len(fails) < sprayMinActors {
		return nil
	}
	sort.SliceStable(fails, func(i, j int) bool { return fails[i].ts.Before(fails[j].ts) })

	// Slide a window anchored on each failure; a window covers [anchor, anchor+W].
	for i := range fails {
		windowEnd := fails[i].ts.Add(spraySameWindow)
		actors := map[string]struct{}{}
		ips := map[string]struct{}{}
		var members []fail
		for j := i; j < len(fails); j++ {
			if fails[j].ts.After(windowEnd) {
				break
			}
			members = append(members, fails[j])
			actors[fails[j].actor] = struct{}{}
			if fails[j].ip != "" {
				ips[fails[j].ip] = struct{}{}
			}
		}
		if len(actors) >= sprayMinActors && len(ips) >= sprayMinDistinctIP {
			first := members[0].ev
			acct := sortedKeys(actors)
			evidence, _ := json.Marshal(map[string]any{
				"pattern":           "distributed-spray",
				"accounts_affected": len(actors),
				"distinct_ips":      len(ips),
				"failure_count":     len(members),
				"accounts":          acct,
				"event_id":          first.ID,
			})
			return &finding.Finding{
				ID:        "finding-spray-" + first.ID,
				Source:    "detector:auth-failure-burst",
				Severity:  "critical",
				Type:      "auth-failure-burst",
				Actor:     "multiple",
				Timestamp: first.Timestamp,
				Reason: fmt.Sprintf(
					"distributed authentication failure spray: %d accounts failed from %d distinct IPs within %s (coordinated low-and-slow campaign)",
					len(actors), len(ips), spraySameWindow,
				),
				Evidence: evidence,
			}
		}
	}
	return nil
}

// sortedKeys returns a set's members sorted ascending (never nil), so spray
// evidence is deterministic for a fixed input.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
