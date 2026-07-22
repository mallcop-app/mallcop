package detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(configDriftDetector{}) }

type configDriftDetector struct{}

func (configDriftDetector) Name() string { return "config-drift" }

func (configDriftDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if f := configDriftEvaluate(ev, bl); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// configDriftRule maps an event type to its detection rule.
type configDriftRule struct {
	evType   string
	severity string
	// applies additionally gates the rule when non-nil: the rule only fires
	// when this returns true for the event's resolved payload. nil (the
	// default, every pre-existing rule) means "always applies" — the rule
	// fires on evType match alone, exactly as before this field was added.
	//
	// WHY THIS EXISTS (the security-vs-ops crux, mallcoppro-192): several
	// infra-subversion classes share an event type with their ROUTINE
	// authorized counterpart — e.g. a `disableLocalAuth` flip is dangerous in
	// ONE direction (re-enabling local/shared-key auth) and a hardening
	// improvement in the other; a `consistency_level_change` is dangerous
	// only when it WEAKENS the level. applies is what tells those two
	// directions apart from the SAME event type, exactly like
	// priv_escalation.go's isElevated() distinguishes a role GRANT (elevates)
	// from a role REMOVAL (narrows, does not elevate) on the same
	// role_assignment event type. This is detector CODE reading fields off
	// the payload — it decides whether config-drift emits a finding AT ALL.
	// It is NOT a consensus-layer force-escalate rule (HARD INVARIANT,
	// feedback_mallcop_consensus_not_rules): it never touches the committee's
	// escalate/resolve vote once a finding exists, and it never patches a
	// specific scenario by keyword/family match — it encodes the general
	// semantic (which direction of THIS event type is dangerous), so it
	// applies uniformly to every event of that type, not just the ones in
	// the eval corpus.
	applies func(ev event.Event, cp configPayload) bool
	reason  func(ev event.Event, cp configPayload) string
}

// configRules defines the known configuration change event types and their
// associated severities.
var configRules = []configDriftRule{
	// Audit log tampering — critical (defender's eyes).
	{
		evType:   "audit_log_disabled",
		severity: "critical",
		reason: func(ev event.Event, _ configPayload) string {
			return fmt.Sprintf("audit logging disabled by %q", ev.Actor)
		},
	},
	{
		evType:   "audit_trail_delete",
		severity: "critical",
		reason: func(ev event.Event, _ configPayload) string {
			return fmt.Sprintf("audit trail deleted by %q", ev.Actor)
		},
	},
	{
		evType:   "cloudtrail_stop",
		severity: "critical",
		reason: func(ev event.Event, _ configPayload) string {
			return fmt.Sprintf("CloudTrail logging stopped by %q", ev.Actor)
		},
	},
	{
		evType:   "log_bucket_delete",
		severity: "critical",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("log storage bucket deleted by %q: %q", ev.Actor, cp.ResourceName)
		},
	},
	// MFA / authentication security changes.
	{
		evType:   "mfa_disabled",
		severity: "high",
		reason: func(ev event.Event, cp configPayload) string {
			target := cp.TargetUser
			if target == "" {
				target = ev.Actor
			}
			return fmt.Sprintf("MFA disabled for user %q by %q", target, ev.Actor)
		},
	},
	{
		evType:   "mfa_requirement_removed",
		severity: "high",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("MFA requirement removed from org/policy by %q", ev.Actor)
		},
	},
	// Security group / firewall changes.
	{
		evType:   "security_group_modify",
		severity: "high",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("security group %q modified by %q: %s", cp.ResourceName, ev.Actor, cp.ChangeDescription)
		},
	},
	{
		evType:   "firewall_rule_add",
		severity: "high",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("firewall rule added by %q: %s", ev.Actor, cp.ChangeDescription)
		},
	},
	// IAM policy changes.
	{
		evType:   "iam_policy_attach",
		severity: "high",
		// Fires unless the event carries an approval signal (ticket/
		// vendor_approved/approved_by/... — hasApprovalSignal, shared with
		// new_external_access.go's AC-04/AC-05 onboarding gate). This is the
		// authorization-surface analogue of the Azure control-plane classes
		// above: a re-scoped connector's write-allowlist/permission-attach
		// event (e.g. a relay's NIP-86 allowpubkey fan-out, mallcoppro-956)
		// reaches config-drift via this SAME event type regardless of whether
		// the grant is a documented onboarding or an undocumented grant to an
		// unexpected principal — the approval signal is what tells them apart,
		// exactly like AC-04's vendor_approved keeps a routine vendor
		// onboarding quiet on new-external-access.
		applies: func(ev event.Event, _ configPayload) bool {
			return !hasApprovalSignal(ev.Payload)
		},
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("IAM policy %q attached to %q by %q", cp.PolicyName, cp.TargetUser, ev.Actor)
		},
	},
	{
		evType:   "iam_policy_create",
		severity: "medium",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("IAM policy %q created by %q", cp.PolicyName, ev.Actor)
		},
	},
	{
		evType:   "iam_role_modify",
		severity: "high",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("IAM role %q modified by %q", cp.ResourceName, ev.Actor)
		},
	},
	// Generic config changes.
	{
		evType:   "config_change",
		severity: "medium",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("configuration changed by %q: %s → %s (%s)", ev.Actor, cp.OldValue, cp.NewValue, cp.ConfigKey)
		},
	},
	{
		evType:   "setting_update",
		severity: "medium",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("setting %q updated by %q", cp.ConfigKey, ev.Actor)
		},
	},
	// Infra-subversion classes (mallcoppro-192): control-plane CHANGE events a
	// re-scoped connector emits routinely (a CI service principal deploying is
	// normal) that must escalate ONLY in their dangerous direction/shape, and
	// stay quiet on the routine authorized counterpart.
	{
		// disableLocalAuth WEAKENING: Azure's disableLocalAuth=true means local
		// (shared-key / connection-string) auth is DISABLED — AAD-only, the
		// secure state. Flipping it to false RE-ENABLES local/shared-key auth,
		// widening the attack surface (a stolen connection string becomes
		// usable again). applies fires only on the dangerous direction
		// (new_value=false); a flip the OTHER way (enabling AAD-only,
		// new_value=true — a hardening change) does not match and is silently
		// quiet, exactly like priv_escalation.go's role-REMOVAL guard.
		evType:   "disable_local_auth_change",
		severity: "high",
		applies: func(_ event.Event, cp configPayload) bool {
			return strings.EqualFold(strings.TrimSpace(cp.NewValue), "false")
		},
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("local/shared-key auth RE-ENABLED (disableLocalAuth -> false) on %q by %q", cp.ResourceName, ev.Actor)
		},
	},
	{
		// diagnosticSettings DELETE: audit-blinding — the resource stops
		// shipping its own activity/diagnostic logs to the log sink. A routine
		// diagnosticSettings UPDATE (different event type, e.g. changing
		// retention or adding a category) is not gated here at all — only the
		// standalone DELETE is inherently dangerous, mirroring the existing
		// audit_trail_delete / log_bucket_delete / cloudtrail_stop entries
		// above (always fires; no direction check needed for a delete).
		evType:   "diagnostic_settings_delete",
		severity: "critical",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("diagnostic settings deleted on %q by %q: audit trail for this resource goes dark", cp.ResourceName, ev.Actor)
		},
	},
	{
		// DNS zone DELETE: domain hijack risk — a deleted zone can be
		// re-registered/re-delegated by an attacker, or in-flight resolution
		// simply breaks for every dependent service. A routine DNS record
		// CHANGE within an existing zone is a distinct event type
		// (dns_record_change) and is not gated — only the zone-level delete is
		// inherently dangerous.
		evType:   "dns_zone_delete",
		severity: "critical",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("DNS zone %q deleted by %q: domain hijack / resolution-outage risk", cp.ResourceName, ev.Actor)
		},
	},
	{
		// Cosmos container DELETE: event-store destruction — the durable
		// finding/resolution stream itself (or any customer data container)
		// is gone. A routine container CREATE/scale (a distinct event type)
		// is not gated — only the delete is inherently dangerous.
		evType:   "cosmos_container_delete",
		severity: "critical",
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("Cosmos container %q deleted by %q: durable store destruction", cp.ResourceName, ev.Actor)
		},
	},
	{
		// Consistency-level WEAKENING: Cosmos consistency levels form a strict
		// strength order (Strong > Bounded Staleness > Session > Consistent
		// Prefix > Eventual). Weakening the DEFAULT level opens the door to
		// stale/out-of-order reads an attacker can exploit (e.g. reading a
		// pre-revocation permission state). applies fires only when the new
		// level ranks STRICTLY weaker than the old one; an unparseable value
		// on either side, an unchanged level, or a STRENGTHENING change (e.g.
		// Eventual -> Session) does not match and stays quiet — the same
		// fail-closed-on-ambiguity discipline consistencyRank documents.
		evType:   "consistency_level_change",
		severity: "high",
		applies: func(_ event.Event, cp configPayload) bool {
			oldRank, oldOK := consistencyRank(cp.OldValue)
			newRank, newOK := consistencyRank(cp.NewValue)
			return oldOK && newOK && newRank < oldRank
		},
		reason: func(ev event.Event, cp configPayload) string {
			return fmt.Sprintf("consistency level weakened on %q by %q: %s -> %s", cp.ResourceName, ev.Actor, cp.OldValue, cp.NewValue)
		},
	},
}

// consistencyLevelRank orders Cosmos DB consistency levels from strongest (4)
// to weakest (0). Keyed lowercase with spaces/hyphens/underscores stripped so
// "Bounded Staleness", "bounded-staleness", and "BoundedStaleness" all
// normalize to the same key — connectors and hand-authored corpus fixtures
// are not guaranteed to agree on casing/punctuation.
var consistencyLevelRank = map[string]int{
	"strong":           4,
	"boundedstaleness": 3,
	"session":          2,
	"consistentprefix": 1,
	"eventual":         0,
}

// consistencyRank normalizes and looks up a consistency-level name's strength
// rank. ok is false for an empty or unrecognized value — the applies
// predicate above treats "cannot confidently parse" as "does not apply"
// (fail-closed on ambiguity, not fail-open to escalate), matching every other
// direction-sensitive rule in this file.
func consistencyRank(level string) (rank int, ok bool) {
	key := strings.ToLower(level)
	key = strings.NewReplacer(" ", "", "-", "", "_", "").Replace(key)
	rank, ok = consistencyLevelRank[key]
	return rank, ok
}

// configPayload is the expected payload for configuration change events.
type configPayload struct {
	ResourceName      string `json:"resource_name"`
	PolicyName        string `json:"policy_name"`
	TargetUser        string `json:"target_user"`
	ConfigKey         string `json:"config_key"`
	OldValue          string `json:"old_value"`
	NewValue          string `json:"new_value"`
	ChangeDescription string `json:"change_description"`
}

// readConfigPayload resolves the config-drift discriminators from an event
// payload, tolerating BOTH on-disk layouts (mirrors priv_escalation.go's
// readPrivPayload): the corpus/eval-seeder shape nests the discriminators
// under payload.metadata (exam scenario events project their `metadata:`
// block that way — see eventRecord), while the production connector shape
// puts them flat at the payload root. payloadMeta's metadata-first fallback
// (core/detect/payload_meta.go) handles the dispatch; metaStr reads each
// field with its snake_case alias. A nil/empty/malformed payload yields a
// zero-value configPayload (every field ""), same as the previous direct
// json.Unmarshal did for a missing payload.
//
// THIS FIXES A LATENT GAP: config_drift previously json.Unmarshal'd ev.Payload
// straight onto configPayload, which only ever populated fields for the FLAT
// production shape. Every corpus/eval scenario (PE-07-style events, this
// item's new infra-subversion scenarios) nests its discriminators under
// `metadata:`, so a rule that reads cp.OldValue/NewValue/ConfigKey (the new
// direction-sensitive rules added for mallcoppro-192, and the pre-existing
// config_change/setting_update/iam_* rules) would have silently seen empty
// strings for every scenario-sourced event and never fired — a data-drop, not
// a detector logic gap. This is a plumbing fix (how a field is read), not a
// change to what any rule decides once it has the field.
func readConfigPayload(payload json.RawMessage) configPayload {
	meta := payloadMeta(payload)
	return configPayload{
		ResourceName:      metaStr(meta, "resource_name", "resource"),
		PolicyName:        metaStr(meta, "policy_name", "policy"),
		TargetUser:        metaStr(meta, "target_user", "principal_id"),
		ConfigKey:         metaStr(meta, "config_key", "key", "setting"),
		OldValue:          metaStr(meta, "old_value", "previous_value"),
		NewValue:          metaStr(meta, "new_value", "value"),
		ChangeDescription: metaStr(meta, "change_description", "description"),
	}
}

// configRuleByEventType indexes configRules by event type for O(1) lookup.
var configRuleByEventType map[string]*configDriftRule

func init() {
	configRuleByEventType = make(map[string]*configDriftRule, len(configRules))
	for i := range configRules {
		configRuleByEventType[configRules[i].evType] = &configRules[i]
	}
}

// configDriftEvaluate returns a Finding if the event represents a
// security-relevant configuration change. Returns nil for benign or
// unrecognised events. This is a pure function: no I/O, no globals mutated.
func configDriftEvaluate(ev event.Event, _ *baseline.Baseline) *finding.Finding {
	rule, ok := configRuleByEventType[strings.ToLower(ev.Type)]
	if !ok {
		return nil
	}

	cp := readConfigPayload(ev.Payload)

	if rule.applies != nil && !rule.applies(ev, cp) {
		return nil
	}

	evidence, _ := json.Marshal(map[string]string{
		"actor":       ev.Actor,
		"source":      ev.Source,
		"event_type":  ev.Type,
		"resource":    cp.ResourceName,
		"policy":      cp.PolicyName,
		"target_user": cp.TargetUser,
		"config_key":  cp.ConfigKey,
		"change":      cp.ChangeDescription,
	})

	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:config-drift",
		Severity:  rule.severity,
		Type:      "config-drift",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    rule.reason(ev, cp),
		Evidence:  evidence,
		EventIDs:  []string{ev.ID},
	}
}
