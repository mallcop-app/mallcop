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

// loginPayload is the resolved login discriminator set, read from BOTH the corpus
// shape (ip under payload.metadata) and a flat connector shape via the
// metadata-first payloadMeta fallback. The corpus login events carry metadata.ip
// and NO geo.
type loginPayload struct {
	IP  string
	Geo string
}

// readLoginPayload resolves ip/geo from an event payload, tolerating both the
// nested (payload.metadata.ip) and flat (payload.ip) layouts.
func readLoginPayload(payload []byte) loginPayload {
	meta := payloadMeta(payload)
	return loginPayload{
		IP:  metaStr(meta, "ip", "source_ip", "client_ip"),
		Geo: metaStr(meta, "geo", "location", "region"),
	}
}

// unusualLoginEvaluate returns a Finding if the event is unusual, or nil if it
// is benign or not a login event.
// This is a pure function: no I/O, no globals mutated.
func unusualLoginEvaluate(ev event.Event, bl *baseline.Baseline) *finding.Finding {
	if ev.Type != "login" {
		return nil
	}

	lp := readLoginPayload(ev.Payload)

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

	// OVER-FIRE GATE (eval fidelity): a known user whose baseline profile carries
	// NO known IPs and NO known geos gives us no basis to call this login's IP/geo
	// "unknown" — every login would spuriously fire 'high'. The corpus seeds known
	// actors with an EMPTY UserProfile (no per-actor IP history), so without this
	// gate unusual-login over-fires on every known-actor login across UT/BG/IT/TD/
	// CO/PI/AF scenarios, masking the expected detector and over-escalating benign
	// resolves. When there is no profile data to compare against, defer: an unknown
	// actor is still surfaced (the HasUser branch above), but a known actor with no
	// IP/geo baseline yields no unusual-login finding.
	if !bl.HasLoginProfile(ev.Actor) {
		return nil
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
