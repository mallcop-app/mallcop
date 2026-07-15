package detect

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() {
	Register(privEscalationDetector{})
	// Publish the built-in tuning snapshot before any scan. ApplyTuning replaces
	// this pointer with a fresh IMMUTABLE snapshot; Detect only ever reads it.
	activePrivEscalationTuning.Store(defaultPrivEscalationTuning())
}

type privEscalationDetector struct{}

func (privEscalationDetector) Name() string { return "priv-escalation" }

// Detect emits one finding per (actor, role, target) escalation not in the
// baseline. The emitted dedup map is local to this call, mirroring the
// standalone binary's per-process dedup.
//
// K7 TUNING ISOLATION: the priv-escalation knob sets are read from an IMMUTABLE
// snapshot loaded ONCE here (loadPrivEscalationTuning) and threaded down to the
// pure evaluators, exactly like events/baseline are passed in read-only. Detect
// never touches the live-mutable package state that ApplyTuning writes, so a
// leaked or concurrent ApplyTuning goroutine can never race a priv-escalation
// read (there is no shared map that is both read here and written there — the
// snapshot's maps are frozen at construction, and ApplyTuning publishes a NEW
// snapshot via an atomic pointer swap).
func (privEscalationDetector) Detect(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	tuning := loadPrivEscalationTuning()
	emitted := make(map[string]bool)
	var out []finding.Finding
	for _, ev := range events {
		if f := privEscalationEvaluate(ev, bl, emitted, tuning); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// privEscalationTuning is an IMMUTABLE snapshot of the priv-escalation knob
// sets. Once constructed it is never mutated: ApplyTuning builds a fresh
// snapshot (widened copy) and publishes it via an atomic pointer swap, and
// Detect loads it once per scan. This is the K7 tuning-isolation half — it
// extends the per-detector input isolation (events/baseline are cloned per
// detector) to cover the tuning state that isolation previously omitted, so no
// shared map is ever read by a detector and written by ApplyTuning at the same
// time.
type privEscalationTuning struct {
	elevationEventTypes    map[string]bool
	elevatedActionKeywords []string
	elevatedKeywords       map[string]bool
}

// activePrivEscalationTuning holds the currently-published immutable snapshot.
// It is seeded in init() with the built-in defaults and only ever replaced
// wholesale (never mutated in place) by ApplyTuning.
var activePrivEscalationTuning atomic.Pointer[privEscalationTuning]

// loadPrivEscalationTuning returns the currently-published snapshot, falling
// back to a fresh built-in snapshot if nothing has been published yet (defensive
// — init() always publishes before any Detect runs). The returned value is
// treated as READ-ONLY.
func loadPrivEscalationTuning() *privEscalationTuning {
	if pt := activePrivEscalationTuning.Load(); pt != nil {
		return pt
	}
	return defaultPrivEscalationTuning()
}

// builtinElevationEventTypes are the built-in event types that may carry
// privilege escalation. They seed the default snapshot and are never mutated.
var builtinElevationEventTypes = map[string]bool{
	"role_assignment":    true,
	"collaborator_added": true,
	"permission_change":  true,
	"admin_action":       true,
	"member_added":       true,
	// iam_change carries boundary / policy mutations whose elevation lives in the
	// ACTION keyword (DeleteRolePermissionsBoundary), not a role field (PE-06).
	"iam_change": true,
}

// builtinElevatedActionKeywords are the built-in action substrings that indicate
// a privilege elevation even when no elevated role/permission field is present —
// e.g. removing an IAM permissions boundary widens effective privilege (PE-06's
// DeleteRolePermissionsBoundary). Matched case-insensitively as substrings.
var builtinElevatedActionKeywords = []string{
	"deleterolepermissionsboundary",
	"deletepermissionsboundary",
	"removepermissionsboundary",
	"putrolepermissionsboundary",
}

// builtinElevatedKeywords are the built-in role/permission values that indicate
// elevated access. Matched as case-insensitive SUBSTRINGS (see
// containsElevatedKeyword) so cloud-specific role formats are recognized, not
// just GitHub/Azure bare names.
var builtinElevatedKeywords = map[string]bool{
	"admin":       true,
	"owner":       true,
	"write":       true,
	"contributor": true,
	"maintainer":  true,
	"editor":      true, // GCP primitive role roles/editor: broad project-wide write
	"fullcontrol": true, // M365 Graph app role, e.g. Sites.FullControl.All
	// AWS managed policy PowerUserAccess grants full access to everything except
	// IAM/Organizations management — a general elevated-role name, promoted from
	// the (now-redundant) detectors/tuning.yaml FN-close entry (PE-08,
	// mallcoppro-a07) so the grant fires out of the box, no tuning knob needed.
	"poweruser": true,
}

// defaultPrivEscalationTuning returns a fresh snapshot seeded from the built-in
// knob sets. Each call allocates its own maps/slice so the returned snapshot
// shares no backing storage with the builtins (or any other snapshot), keeping
// every published snapshot independently immutable.
func defaultPrivEscalationTuning() *privEscalationTuning {
	pt := &privEscalationTuning{
		elevationEventTypes:    make(map[string]bool, len(builtinElevationEventTypes)),
		elevatedActionKeywords: append([]string(nil), builtinElevatedActionKeywords...),
		elevatedKeywords:       make(map[string]bool, len(builtinElevatedKeywords)),
	}
	for k := range builtinElevationEventTypes {
		pt.elevationEventTypes[k] = true
	}
	for k := range builtinElevatedKeywords {
		pt.elevatedKeywords[k] = true
	}
	return pt
}

// clone returns a deep copy of the snapshot: fresh maps and slice so the copy
// shares no backing storage with the receiver. ApplyTuning widens a clone (never
// the live snapshot) and the test snapshot/restore seam round-trips through it.
func (pt *privEscalationTuning) clone() *privEscalationTuning {
	next := &privEscalationTuning{
		elevationEventTypes:    make(map[string]bool, len(pt.elevationEventTypes)),
		elevatedActionKeywords: append([]string(nil), pt.elevatedActionKeywords...),
		elevatedKeywords:       make(map[string]bool, len(pt.elevatedKeywords)),
	}
	for k := range pt.elevationEventTypes {
		next.elevationEventTypes[k] = true
	}
	for k := range pt.elevatedKeywords {
		next.elevatedKeywords[k] = true
	}
	return next
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
// The knob sets are read from the immutable tuning snapshot passed in, never from
// live-mutable package state.
func isElevated(ev event.Event, pp privPayload, tuning *privEscalationTuning) bool {
	if ev.Type == "admin_action" {
		return true
	}
	action := strings.ToLower(pp.Action)
	// A role/permission REMOVAL narrows privilege, it does not elevate it — do not
	// flag it (UT-07's remove_role_assignment of a Contributor role is a benign
	// ops cleanup, not an escalation). The boundary-DELETE keyword below is the
	// deliberate exception: deleting a permissions boundary WIDENS effective
	// privilege, so it is matched before this guard via the keyword loop.
	for _, kw := range tuning.elevatedActionKeywords {
		if action != "" && strings.Contains(action, kw) {
			return true
		}
	}
	if strings.HasPrefix(action, "remove") || strings.HasPrefix(action, "revoke") || strings.HasPrefix(action, "delete_role") {
		return false
	}
	for _, val := range []string{pp.RoleName, pp.PermissionLevel} {
		if containsElevatedKeyword(val, tuning) {
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
// The keyword set comes from the immutable tuning snapshot passed in.
func containsElevatedKeyword(val string, tuning *privEscalationTuning) bool {
	lowered := strings.ToLower(val)
	if lowered == "" {
		return false
	}
	for kw := range tuning.elevatedKeywords {
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

// targetKey derives a stable identifier for the principal RECEIVING the
// granted role/permission (pp.TargetUser, itself resolved from the payload's
// target_user/principal_id fields — see readPrivPayload). Lower-cased, no
// trim, mirroring roleKey's normalization convention exactly. Empty when the
// event carries no explicit target-principal field.
func targetKey(pp privPayload) string {
	return strings.ToLower(pp.TargetUser)
}

// roleTargetKey composes the (role, target) pair into the single string the
// baseline gate and in-scan dedup key are keyed on (mallcoppro-9af, ruled by
// Baron 2026-07-15). Before this the gate/dedup key was actor+role ONLY: once
// (actor, role) was investigated once and baselined, that actor granting the
// SAME role to ANY NEW principal was suppressed forever — a compromised known
// admin re-granting privileges to a fresh attacker principal never re-fired.
// Folding the target in makes the SAME grant (actor, role, target) idempotent
// across re-scans, while a grant of the same role to a NEW target re-fires:
// every admin action deserves scrutiny, because legitimate admin credentials
// get stolen and reused constantly. An event with no explicit target field
// keys as role+":" — unchanged from the pre-9af per-role-only shape for that
// case, since there is no target identity available to distinguish on.
func roleTargetKey(rk, tk string) string {
	return rk + ":" + tk
}

// privEscalationEvaluate returns a Finding if the event represents a new
// privilege escalation not already in the baseline. emitted tracks
// (actor:role:target) triples already reported.
// This is a pure function with respect to state mutation (emitted is caller-owned).
func privEscalationEvaluate(ev event.Event, bl *baseline.Baseline, emitted map[string]bool, tuning *privEscalationTuning) *finding.Finding {
	if !tuning.elevationEventTypes[ev.Type] {
		return nil
	}

	pp := readPrivPayload(ev.Payload)

	if !isElevated(ev, pp, tuning) {
		return nil
	}

	rk := roleKey(ev, pp)
	tk := targetKey(pp)
	gk := roleTargetKey(rk, tk)

	if bl.IsKnownRole(ev.Actor, gk) {
		return nil
	}

	dedupKey := ev.Actor + ":" + gk
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
