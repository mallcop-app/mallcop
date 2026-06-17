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
	reason   func(ev event.Event, cp configPayload) string
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

	var cp configPayload
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &cp)
	}

	evidence, _ := json.Marshal(map[string]string{
		"actor":       ev.Actor,
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
	}
}
