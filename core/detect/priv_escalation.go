package detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(privEscalationDetector{}) }

type privEscalationDetector struct{}

func (privEscalationDetector) Name() string { return "priv-escalation" }

// Detect emits one finding per (actor, role) escalation not in the baseline.
// The emitted dedup map is local to this call, mirroring the standalone
// binary's per-process dedup.
func (privEscalationDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	emitted := make(map[string]bool)
	var out []finding.Finding
	for _, ev := range events {
		if f := privEscalationEvaluate(ev, bl, emitted); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// elevationEventTypes are event types that may carry privilege escalation.
var elevationEventTypes = map[string]bool{
	"role_assignment":    true,
	"collaborator_added": true,
	"permission_change":  true,
	"admin_action":       true,
	"member_added":       true,
	// iam_change carries boundary / policy mutations whose elevation lives in the
	// ACTION keyword (DeleteRolePermissionsBoundary), not a role field (PE-06).
	"iam_change": true,
}

// elevatedActionKeywords are action substrings that indicate a privilege
// elevation even when no elevated role/permission field is present — e.g. removing
// an IAM permissions boundary widens effective privilege (PE-06's
// DeleteRolePermissionsBoundary). Matched case-insensitively as substrings.
var elevatedActionKeywords = []string{
	"deleterolepermissionsboundary",
	"deletepermissionsboundary",
	"removepermissionsboundary",
	"putrolepermissionsboundary",
}

// elevatedKeywords are role/permission values that indicate elevated access.
// Matched as case-insensitive SUBSTRINGS (see containsElevatedKeyword) so
// cloud-specific role formats are recognized, not just GitHub/Azure bare names.
var elevatedKeywords = map[string]bool{
	"admin":       true,
	"owner":       true,
	"write":       true,
	"contributor": true,
	"maintainer":  true,
	"editor":      true, // GCP primitive role roles/editor: broad project-wide write
	"fullcontrol": true, // M365 Graph app role, e.g. Sites.FullControl.All
}

// privPayload is the resolved privilege-escalation discriminator set, read from
// BOTH the corpus shape (role under payload.metadata) and the production GitHub
// connector shape (role/role_name flat) via the metadata-first payloadMeta
// fallback. Action is read from the top-level payload (the eval seeder writes
// action at the payload root, not under metadata) for boundary-removal detection.
type privPayload struct {
	RoleName        string
	PermissionLevel string
	TargetUser      string
	Action          string
}

// readPrivPayload resolves the privilege discriminators from an event payload,
// tolerating both on-disk layouts. role: metadata.role (corpus) | role |
// role_name (production). permission: metadata.permission | permission |
// permission_level. target_user: metadata.target_user | target_user |
// principal_id. action: the top-level payload action (boundary-removal keyword).
func readPrivPayload(payload []byte) privPayload {
	var pp privPayload
	if len(payload) == 0 {
		return pp
	}
	// Top-level read for the action (and the production-flat fallthrough below).
	var top map[string]any
	_ = json.Unmarshal(payload, &top)
	if s, ok := top["action"].(string); ok {
		pp.Action = s
	}
	meta := payloadMeta(payload)
	pp.RoleName = metaStr(meta, "role", "role_name")
	pp.PermissionLevel = metaStr(meta, "permission", "permission_level")
	pp.TargetUser = metaStr(meta, "target_user", "principal_id")
	return pp
}

// isElevated returns true when the event indicates privilege elevation.
// admin_action is always elevated; an action carrying a boundary-removal keyword
// is elevated regardless of role fields (PE-06); other types check payload fields.
func isElevated(ev event.Event, pp privPayload) bool {
	if ev.Type == "admin_action" {
		return true
	}
	action := strings.ToLower(pp.Action)
	// A role/permission REMOVAL narrows privilege, it does not elevate it — do not
	// flag it (UT-07's remove_role_assignment of a Contributor role is a benign
	// ops cleanup, not an escalation). The boundary-DELETE keyword below is the
	// deliberate exception: deleting a permissions boundary WIDENS effective
	// privilege, so it is matched before this guard via the keyword loop.
	for _, kw := range elevatedActionKeywords {
		if action != "" && strings.Contains(action, kw) {
			return true
		}
	}
	if strings.HasPrefix(action, "remove") || strings.HasPrefix(action, "revoke") || strings.HasPrefix(action, "delete_role") {
		return false
	}
	for _, val := range []string{pp.RoleName, pp.PermissionLevel} {
		if containsElevatedKeyword(val) {
			return true
		}
	}
	return false
}

// containsElevatedKeyword reports whether a role/permission value carries an
// elevated-access keyword as a SUBSTRING (case-insensitive). Substring, not exact,
// so cloud-specific role formats are recognized: GCP "roles/owner" and Okta
// "Super Admin" both carry a privileged keyword but never exact-matched the bare
// "owner"/"admin" GitHub/Azure form, so priv-escalation silently missed them.
func containsElevatedKeyword(val string) bool {
	lowered := strings.ToLower(val)
	if lowered == "" {
		return false
	}
	for kw := range elevatedKeywords {
		if strings.Contains(lowered, kw) {
			return true
		}
	}
	return false
}

// roleKey derives a stable role identifier from the payload.
func roleKey(ev event.Event, pp privPayload) string {
	if pp.RoleName != "" {
		return strings.ToLower(pp.RoleName)
	}
	if pp.PermissionLevel != "" {
		return strings.ToLower(pp.PermissionLevel)
	}
	return ev.Type
}

// privEscalationEvaluate returns a Finding if the event represents a new
// privilege escalation not already in the baseline. emitted tracks
// (actor:role) pairs already reported.
// This is a pure function with respect to state mutation (emitted is caller-owned).
func privEscalationEvaluate(ev event.Event, bl *baseline.Baseline, emitted map[string]bool) *finding.Finding {
	if !elevationEventTypes[ev.Type] {
		return nil
	}

	pp := readPrivPayload(ev.Payload)

	if !isElevated(ev, pp) {
		return nil
	}

	rk := roleKey(ev, pp)

	if bl.IsKnownRole(ev.Actor, rk) {
		return nil
	}

	dedupKey := ev.Actor + ":" + rk
	if emitted[dedupKey] {
		return nil
	}
	emitted[dedupKey] = true

	severity := "high"
	if ev.Type == "admin_action" || strings.Contains(rk, "admin") || strings.Contains(rk, "owner") {
		severity = "critical"
	}

	evidence, _ := json.Marshal(map[string]string{
		"actor":            ev.Actor,
		"role":             rk,
		"event_type":       ev.Type,
		"target_user":      pp.TargetUser,
		"permission_level": pp.PermissionLevel,
		"event_id":         ev.ID,
	})

	reason := fmt.Sprintf("privilege escalation: %q granted %q role on %s", ev.Actor, rk, ev.Source)
	if pp.TargetUser != "" {
		reason = fmt.Sprintf("privilege escalation: %q granted %q to %q on %s", ev.Actor, rk, pp.TargetUser, ev.Source)
	}

	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:priv-escalation",
		Severity:  severity,
		Type:      "priv-escalation",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    reason,
		Evidence:  evidence,
	}
}
