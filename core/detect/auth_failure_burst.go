package detect

import (
	"encoding/json"
	"fmt"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(authFailureBurstDetector{}) }

type authFailureBurstDetector struct{}

func (authFailureBurstDetector) Name() string { return "auth-failure-burst" }

const (
	// authBurstThreshold is the minimum same-actor login_failure count that marks
	// a brute-force / credential-stuffing burst. The corpus emits a representative
	// slice of the burst (AF-03: 6 failures), so a threshold of 5 separates a real
	// burst from a benign fat-finger (AF-01: 3 failures then success).
	authBurstThreshold = 5
)

// Detect groups login_failure events by actor and fires when an actor accrues
// authBurstThreshold or more failures WITHOUT a terminal login_success — the
// brute-force signature. A short run of failures that ENDS in a success is a
// benign fat-finger / password-reset recovery (AF-01, AF-04) and is NOT escalated.
// Fires on ev.Actor (the performing identity the finding metadata names).
func (authFailureBurstDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	type actorState struct {
		failures   int
		succeeded  bool
		firstEvent event.Event
	}
	states := map[string]*actorState{}
	order := []string{}

	for _, ev := range events {
		switch ev.Type {
		case "login_failure":
			st := states[ev.Actor]
			if st == nil {
				st = &actorState{firstEvent: ev}
				states[ev.Actor] = st
				order = append(order, ev.Actor)
			}
			st.failures++
		case "login_success":
			if st := states[ev.Actor]; st != nil {
				// A terminal success after the failures resolves the burst: the
				// account owner recovered. Mark it benign.
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
	return out
}
