package detect

import (
	"encoding/json"
	"fmt"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(unusualLoginDetector{}) }

type unusualLoginDetector struct{}

func (unusualLoginDetector) Name() string { return "unusual-login" }

func (unusualLoginDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if f := unusualLoginEvaluate(ev, bl); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// loginPayload is the expected structure inside Event.Payload for login events.
type loginPayload struct {
	IP  string `json:"ip"`
	Geo string `json:"geo"`
}

// unusualLoginEvaluate returns a Finding if the event is unusual, or nil if it
// is benign or not a login event.
// This is a pure function: no I/O, no globals mutated.
func unusualLoginEvaluate(ev event.Event, bl *baseline.Baseline) *finding.Finding {
	if ev.Type != "login" {
		return nil
	}

	var lp loginPayload
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &lp)
	}

	evidence, _ := json.Marshal(map[string]string{
		"ip":       lp.IP,
		"geo":      lp.Geo,
		"event_id": ev.ID,
	})

	if !bl.HasUser(ev.Actor) {
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:unusual-login",
			Severity:  "high",
			Type:      "unusual-login",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    "login from unrecognized user account",
			Evidence:  evidence,
		}
	}

	if bl.KnownIP(ev.Actor, lp.IP) {
		// Known user, known IP — benign.
		return nil
	}

	if bl.KnownGeo(ev.Actor, lp.Geo) {
		// Known user, new IP, but geo is familiar — low severity.
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:unusual-login",
			Severity:  "low",
			Type:      "unusual-login",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("login from new IP in known region (%s)", lp.Geo),
			Evidence:  evidence,
		}
	}

	// Known user, unknown IP, unknown geo — high severity.
	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:unusual-login",
		Severity:  "high",
		Type:      "unusual-login",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    fmt.Sprintf("login from unknown location (IP: %s, geo: %s)", lp.IP, lp.Geo),
		Evidence:  evidence,
	}
}
