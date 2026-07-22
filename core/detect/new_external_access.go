package detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(newExternalAccessDetector{}) }

type newExternalAccessDetector struct{}

func (newExternalAccessDetector) Name() string { return "new-external-access" }

// externalAccessEventTypes are the grant/trust event types that can introduce an
// external principal: GitHub collaborator/member adds, outside-collaborator adds,
// and Azure AD federation/domain-trust changes. "org.member_added" is carried
// alongside "org.add_member" as the same signal under GitHub's other verb-order
// naming convention (event.action vs action.event) — a connector emitting either
// spelling for an org-membership grant must be recognized identically; this is a
// naming-synonym, not a new signal (mallcoppro-45f).
var externalAccessEventTypes = map[string]bool{
	"repo.add_collaborator":        true,
	"org.add_member":               true,
	"org.member_added":             true,
	"org.add_outside_collaborator": true,
	"trust_added":                  true,
	"domain_trust":                 true,
	"federation_settings_update":   true,
	"directory_settings_update":    true,
}

// Detect emits a finding when the performing actor grants access to an EXTERNAL
// principal (a collaborator/member/external grantee, or a new federated domain
// trust) with no approval signal. It fires on ev.Actor — the performing identity,
// which is the actor the scenario's finding metadata names.
func (newExternalAccessDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	emitted := make(map[string]bool)
	var out []finding.Finding
	for _, ev := range events {
		if f := newExternalAccessEvaluate(ev, emitted); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func newExternalAccessEvaluate(ev event.Event, emitted map[string]bool) *finding.Finding {
	if !externalAccessEventTypes[ev.Type] {
		return nil
	}
	meta := payloadMeta(ev.Payload)

	// A grant is APPROVED (and thus benign) when it carries any sanctioning signal
	// (see payload_meta.go's hasApprovalSignal — shared with config_drift.go's
	// iam_policy_attach gate so the approval-signal vocabulary cannot diverge
	// between the two detectors that both need to recognize it).
	if hasApprovalSignal(ev.Payload) {
		return nil
	}

	// Identify the external grantee. A federation/domain-trust change names a new
	// external domain; a collaborator/member add names the granted principal.
	grantee := metaStr(meta, "collaborator", "member", "external_user", "domain", "domain_name")
	if grantee == "" {
		return nil
	}

	dedupKey := ev.Actor + ":" + ev.Type + ":" + grantee
	if emitted[dedupKey] {
		return nil
	}
	emitted[dedupKey] = true

	permission := metaStr(meta, "permission", "role")
	// member is the raw AWS AssumeRole trust boundary (the assumed role's
	// ARN, from aws.go's payload "member" key) and is present ONLY for
	// AWS cross-account trust_added events. A domain-only trust_added
	// (e.g. M365 "Set federation settings on domain.", which carries
	// domain/domain_name but no member) leaves this empty. assemble.go's
	// resolveGrantDirection reads this to pick the correct direction
	// convention for the two event shapes that both use event_type
	// "trust_added" (mallcoppro-15e).
	member := metaStr(meta, "member")
	evidence, _ := json.Marshal(map[string]string{
		"actor":      ev.Actor,
		"grantee":    grantee,
		"permission": permission,
		"event_type": ev.Type,
		"target":     metaStr(meta, "target", "repo", "org"),
		"member":     member,
		"event_id":   ev.ID,
	})

	reason := fmt.Sprintf("external access granted: %q added external principal %q", ev.Actor, grantee)
	switch {
	case ev.Type == "trust_added" && member != "":
		// AWS cross-account AssumeRole trust: the assumed role (grantee) is
		// the GRANTOR — its trust boundary was exercised — and the calling
		// principal (ev.Actor) is the GRANTEE — it newly gained the
		// capability to assume the role. This is the OPPOSITE of the
		// actor-is-grantor convention every other branch here uses, and it
		// must agree with assemble.go's resolveGrantDirection flip for this
		// exact shape (mallcoppro-15e) — Reason and the assembled
		// identity.grantor/grantee fields flow into the same narrate
		// document, and a mismatch reads as a backwards trust direction in
		// the live console (mallcoppro-dc2, live-proven on the v0.17.0
		// replay). Do NOT apply this flip to the M365 domain-only
		// trust_added shape below (member == "") — it has no assumed-role
		// trust boundary to flip around.
		reason = fmt.Sprintf("external trust added: %q added %q to its trust relationship, granting it the ability to assume the role", grantee, ev.Actor)
	case strings.Contains(ev.Type, "federation") || strings.Contains(ev.Type, "trust") || strings.Contains(ev.Type, "directory"):
		reason = fmt.Sprintf("external trust added: %q configured federation/domain trust for %q", ev.Actor, grantee)
	}

	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:new-external-access",
		Severity:  "critical",
		Type:      "new-external-access",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    reason,
		Evidence:  evidence,
		EventIDs:  []string{ev.ID},
	}
}
