package github

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/connect/overlay"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// ghEvent is the subset of a GitHub Event object (the /orgs/{org}/events feed) we
// normalize. payload is kept raw so action-bearing sub-objects can be inspected.
type ghEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	CreatedAt string `json:"created_at"`
	Actor     struct {
		Login string `json:"login"`
	} `json:"actor"`
	Repo struct {
		Name string `json:"name"`
	} `json:"repo"`
	Org struct {
		Login string `json:"login"`
	} `json:"org"`
	Payload json.RawMessage `json:"payload"`
}

// auditEntry is the subset of a GitHub audit-log entry we normalize. Timestamps
// are epoch-ms in @timestamp / created_at.
type auditEntry struct {
	Action     string          `json:"action"`
	Actor      string          `json:"actor"`
	Org        string          `json:"org"`
	Repo       string          `json:"repo"`
	User       string          `json:"user"`
	DocumentID string          `json:"_document_id"`
	Timestamp  json.Number     `json:"@timestamp"`
	CreatedAt  json.Number     `json:"created_at"`
	Raw        json.RawMessage `json:"-"`
}

// normalizedType is the routing gate every detector keys on first. These MUST be
// the EXACT gate constants the detectors in core/detect compare against:
//
//   - "push"                      -> git_oops (also branch_delete/tag_delete)
//   - "member_added"              -> priv_escalation + new_actor (elevation + new principal)
//   - "collaborator_added"        -> priv_escalation
//   - "permission_change"         -> priv_escalation
//   - "collaborator_removed"      -> (benign; no detector gate — inert)
//   - "repo_visibility_changed"   -> (informational)
//   - "repo.add_collaborator"     -> new_external_access
//   - "org.add_member"            -> new_external_access
//   - "org.add_outside_collaborator" -> new_external_access
//   - "secret_scanning_alert"     -> (informational)
//   - "dependabot_alert"          -> (informational)
//   - "code_scanning_alert"       -> (informational)
//   - "github_other"              -> benign catch-all (detectors gate on specific
//     types, so unknowns are inert, never crash)
//
// dependabot_alert / secret_scanning_alert are emitted from TWO sources with
// DIFFERENT payload shapes: the audit-feed echo (classifyAuditAction, below —
// action-bearing synthPayload) and the dedicated alert REST APIs
// (normalizeDependabotAlert et al. — alert-bearing synthPayload with
// signal_class="alert", alert_number, alert_state, severity, …). Same Type
// string, same routing gate; consumers MUST read alert-specific fields
// defensively (they are absent on the audit-feed shape).
//
// Verified against core/detect: priv_escalation.elevationEventTypes,
// new_actor.entityCreationEventTypes, new_external_access.externalAccessEventTypes,
// git_oops gate ("push"/"branch_delete"/"tag_delete").

// Type strings for the three GitHub-native alert families, emitted by
// normalizeDependabotAlert / normalizeCodeScanningAlert /
// normalizeSecretScanningAlert (the dedicated REST alert APIs — see
// pullAlerts in github.go). dependabot_alert and secret_scanning_alert are
// ALSO emitted, with a different (action-bearing) payload shape, from
// classifyAuditAction's audit-feed echoes — see the normalizedType doc above.
const (
	typeDependabotAlert     = "dependabot_alert"
	typeCodeScanningAlert   = "code_scanning_alert"
	typeSecretScanningAlert = "secret_scanning_alert"
)

// eventTypeMap maps GitHub Event object "type" values (the events feed) to the
// normalized vocabulary. Action-qualified GitHub events (MemberEvent.added vs
// removed) are disambiguated in classifyEventType using the payload "action".
var eventTypeMap = map[string]string{
	"PushEvent":                "push",
	"PublicEvent":              "repo_visibility_changed",
	"SecretScanningAlertEvent": "secret_scanning_alert",
}

// auditActionMap ports connector.py:_ACTION_MAP (audit-log action prefixes ->
// normalized types). Longest-prefix / equality match, evaluated in order.
var auditActionMap = []struct{ prefix, ty string }{
	{"org.add_member", "org.add_member"},
	{"org.add_outside_collaborator", "org.add_outside_collaborator"},
	{"repo.add_member", "repo.add_collaborator"},
	{"repo.add_collaborator", "repo.add_collaborator"},
	{"org.remove_member", "collaborator_removed"},
	{"repo.access", "repo_visibility_changed"},
	{"protected_branch.", "branch_protection_changed"},
	{"deploy_key.create", "deploy_key_added"},
	{"oauth_authorization.create", "oauth_app_authorized"},
	{"secret_scanning_alert.create", "secret_scanning_alert"},
	{"dependabot_alert.create", "dependabot_alert"},
	{"git.push", "push"},
	{"team.", "permission_change"},
	{"org.update_member", "permission_change"},
}

// classifyAuditAction maps an audit-log action string to a normalized type.
func classifyAuditAction(action string) string {
	for _, m := range auditActionMap {
		if action == m.prefix || strings.HasPrefix(action, m.prefix) {
			return m.ty
		}
	}
	return defaultEventTy
}

// memberPayload is the action-bearing sub-object of MemberEvent / OrgEvent.
type memberPayload struct {
	Action string `json:"action"`
	Member struct {
		Login string `json:"login"`
	} `json:"member"`
	Membership struct {
		User struct {
			Login string `json:"login"`
		} `json:"user"`
		Role string `json:"role"`
	} `json:"membership"`
}

// classifyEventType maps a GitHub Event object to a normalized type, using the
// already-parsed member payload to disambiguate add/remove on
// MemberEvent/OrgEvent. A zero-valued mp (absent or unparseable payload) falls
// through to the security-relevant default (e.g. "added"), so a corrupt payload
// over-escalates rather than being missed — the fail-safe direction.
func classifyEventType(ghType string, mp memberPayload) string {
	switch ghType {
	case "MemberEvent":
		// repo collaborator add/remove. add -> new external access; remove benign.
		switch mp.Action {
		case "removed":
			return "collaborator_removed"
		default: // "added", "edited"
			return "repo.add_collaborator"
		}
	case "OrgEvent":
		switch mp.Action {
		case "member_removed", "member_invited":
			return "collaborator_removed"
		default: // member_added
			return "org.add_member"
		}
	case "TeamAddEvent":
		return "permission_change"
	}
	if t, ok := eventTypeMap[ghType]; ok {
		return t
	}
	return defaultEventTy
}

// synthPayload is the FLAT per-detector payload the connector emits. It is shaped
// for the detector typed structs: payloadMeta returns this top-level map (no
// "metadata" key), and the detectors read role/permission/target_user/action/ip
// from it (priv_escalation.readPrivPayload, new_external_access metadata reads,
// new_actor payloadMeta). The verbatim GitHub object is preserved under "raw".
type synthPayload struct {
	Action          string          `json:"action,omitempty"`
	Role            string          `json:"role,omitempty"`
	RoleName        string          `json:"role_name,omitempty"`
	Permission      string          `json:"permission,omitempty"`
	PermissionLevel string          `json:"permission_level,omitempty"`
	TargetUser      string          `json:"target_user,omitempty"`
	Collaborator    string          `json:"collaborator,omitempty"`
	DisplayName     string          `json:"display_name,omitempty"`
	PrincipalID     string          `json:"principal_id,omitempty"`
	Repo            string          `json:"repo,omitempty"`
	Org             string          `json:"org,omitempty"`
	Raw             json.RawMessage `json:"raw,omitempty"`
	// ParseError is set when the GitHub payload was present but could not be
	// unmarshaled; it makes a corrupt payload visible in the finding record
	// instead of silently misclassifying the event.
	ParseError string `json:"parse_error,omitempty"`
	// --- Alert-family fields (normalizeDependabotAlert / normalizeCodeScanningAlert
	// / normalizeSecretScanningAlert — the dedicated REST alert APIs, NOT the
	// audit-feed echo). SHARED ALERT CONTRACT: every alert-family event carries
	// SignalClass="alert", AlertNumber, AlertState, Repo (above), and — where the
	// source API provides one — Severity and HTMLURL. Family-specific: Package +
	// Ecosystem (dependabot), Rule (code-scanning), SecretType (secret-scanning).
	// Consumers read these defensively: the audit-feed shape of
	// dependabot_alert/secret_scanning_alert (classifyAuditAction) never sets them.
	SignalClass string `json:"signal_class,omitempty"`
	AlertNumber int    `json:"alert_number,omitempty"`
	AlertState  string `json:"alert_state,omitempty"`
	Severity    string `json:"severity,omitempty"`
	HTMLURL     string `json:"html_url,omitempty"`
	Package     string `json:"package,omitempty"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	SecretType  string `json:"secret_type,omitempty"`
	Rule        string `json:"rule,omitempty"`
	// UnmappedAction carries the RAW source action string whenever this event
	// fell all the way through to the "github_other" default bucket (i.e. no
	// classifier and no learned overlay mapped it). It is the uniform mapping-gap
	// tag the offline UNMAPPED-ACTION collector (core/collect.UnmappedActions)
	// mines to propose closing coverage gaps — event.Event has no Metadata field,
	// so the flat payload is the tag carrier. Empty (omitted) for every mapped
	// event, so it never touches a classified event's record.
	UnmappedAction string `json:"unmapped_action,omitempty"`
}

// normalizeEvent normalizes one GitHub Event object (events feed) to event.Event.
// Returns ok=false when the entry has no usable timestamp (skipped, not
// zero-valued — port connector.py:223-226). ov (may be nil) fills the
// "github_other" default bucket from the learned-mapping overlay; base-wins is
// enforced by Overlay.Apply (a real classification is never overridden).
func normalizeEvent(raw json.RawMessage, org string, ov *overlay.Overlay) (event.Event, bool) {
	var ge ghEvent
	if err := json.Unmarshal(raw, &ge); err != nil {
		return event.Event{}, false
	}
	if ge.CreatedAt == "" {
		return event.Event{}, false
	}
	ts, err := time.Parse(time.RFC3339, ge.CreatedAt)
	if err != nil {
		return event.Event{}, false
	}

	// Parse the member payload (drives add/remove disambiguation). An empty
	// payload is legitimate for many event types; a non-empty payload that fails
	// to parse is surfaced on the event below rather than silently dropped.
	var mp memberPayload
	var parseErr error
	if len(ge.Payload) > 0 {
		parseErr = json.Unmarshal(ge.Payload, &mp)
	}
	normType := classifyEventType(ge.Type, mp)
	// Learned-mapping overlay (github-first): rawAction = the GitHub event type.
	normType = ov.Apply(sourceGitHub, ge.Type, normType)

	actor := ge.Actor.Login
	if actor == "" {
		actor = "unknown"
	}

	// Synthesize the per-detector payload. The "target" of a member/collaborator
	// grant is the added principal; surface it where new-external-access and
	// priv-escalation read it.
	target := mp.Member.Login
	if target == "" {
		target = mp.Membership.User.Login
	}
	sp := synthPayload{
		Action:       mp.Action,
		Role:         mp.Membership.Role,
		RoleName:     mp.Membership.Role,
		TargetUser:   target,
		Collaborator: target,
		Repo:         ge.Repo.Name,
		Org:          orgOr(ge.Org.Login, org),
		Raw:          raw,
	}
	// Mapping-gap tag: only when the event stayed in the default bucket AFTER the
	// overlay had its chance (base-wins means a real classification is never the
	// default here). rawAction for the events feed is the GitHub event "type".
	if normType == defaultEventTy {
		sp.UnmappedAction = ge.Type
	}
	if parseErr != nil {
		sp.ParseError = parseErr.Error()
	}
	payload, _ := json.Marshal(sp)

	return event.Event{
		ID:        makeEventID(ge.ID),
		Source:    sourceGitHub,
		Type:      normType,
		Actor:     actor,
		Timestamp: ts,
		Org:       orgOr(ge.Org.Login, org),
		Payload:   payload,
	}, true
}

// normalizeAuditEntry normalizes one audit-log entry to event.Event. Timestamp is
// epoch-ms (@timestamp, then created_at). Returns ok=false when no timestamp is
// present (skip, do not zero-value). ov (may be nil) fills the "github_other"
// default bucket from the learned-mapping overlay; base-wins is enforced by
// Overlay.Apply.
func normalizeAuditEntry(raw json.RawMessage, org string, ov *overlay.Overlay) (event.Event, bool) {
	var ae auditEntry
	if err := json.Unmarshal(raw, &ae); err != nil {
		return event.Event{}, false
	}
	ms, ok := epochMS(ae.Timestamp, ae.CreatedAt)
	if !ok {
		return event.Event{}, false
	}
	ts := time.UnixMilli(ms).UTC()

	normType := classifyAuditAction(ae.Action)
	// Learned-mapping overlay (github-first): rawAction = the audit action.
	normType = ov.Apply(sourceGitHub, ae.Action, normType)

	actor := ae.Actor
	if actor == "" {
		actor = "unknown"
	}
	target := ae.Repo
	if target == "" {
		target = ae.Org
	}
	sp := synthPayload{
		Action:       ae.Action,
		TargetUser:   ae.User,
		Collaborator: ae.User,
		Repo:         ae.Repo,
		Org:          orgOr(ae.Org, org),
		Raw:          raw,
	}
	// Mapping-gap tag: only when the audit action stayed in the default bucket
	// AFTER the overlay had its chance. rawAction for the audit log is ae.Action.
	if normType == defaultEventTy {
		sp.UnmappedAction = ae.Action
	}
	payload, _ := json.Marshal(sp)

	// Deterministic ID: prefer the audit document id, else a stable composite.
	idSrc := ae.DocumentID
	if idSrc == "" {
		idSrc = ae.Action + "|" + actor + "|" + target
	}

	return event.Event{
		ID:        makeEventID(idSrc),
		Source:    sourceGitHub,
		Type:      normType,
		Actor:     actor,
		Timestamp: ts,
		Org:       orgOr(ae.Org, org),
		Payload:   payload,
	}, true
}

// epochMS resolves an epoch-millisecond timestamp from the first present numeric
// field.
func epochMS(vals ...json.Number) (int64, bool) {
	for _, v := range vals {
		if v == "" {
			continue
		}
		n, err := v.Int64()
		if err == nil && n > 0 {
			return n, true
		}
	}
	return 0, false
}

func orgOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// --- GitHub-native security alerts (dedicated REST APIs) ---------------------
//
// GET /orgs/{org}/dependabot/alerts, /orgs/{org}/code-scanning/alerts,
// /orgs/{org}/secret-scanning/alerts (org-wide; per-repo fallback in
// github.go:pullPerRepoAlerts). These are DIFFERENT from the audit-feed echoes
// classifyAuditAction reads above: the audit feed sees a create-action event
// with the actor who triggered the scan; these APIs return the current alert
// RECORD (state, severity, package/rule/secret-type) — richer, and the only
// source for code-scanning alerts (the audit feed has no code-scanning action).

// actorSystemAlert is the Actor value for every alert-family event: GitHub
// itself raises these (Dependabot/CodeQL/secret-scanning), not a human/bot
// principal, so there is no actor login to attribute — unlike "unknown" (used
// where a login WAS expected but missing), this is a deliberate, always-the-same
// sentinel for a system-generated record.
const actorSystemAlert = "github"

// alertRepo is the repository sub-object present on ORG-WIDE alert list
// responses. The PER-REPO list responses omit it (the repo is already implied
// by the request URL) — repoOr falls back to the caller-supplied repoHint
// ("org/repo") in that case.
type alertRepo struct {
	FullName string `json:"full_name"`
	Name     string `json:"name"`
}

func repoOr(r alertRepo, hint string) string {
	if r.FullName != "" {
		return r.FullName
	}
	if r.Name != "" {
		return r.Name
	}
	return hint
}

// alertTimestamp resolves the event Timestamp for high-water filtering: prefer
// updated_at (state transitions — fixed/dismissed — must be visible to a
// re-scan even though the alert was created outside the lookback window), fall
// back to created_at. Returns ok=false when neither parses (skip, per the
// normalizeEvent/normalizeAuditEntry convention above — never zero-value).
func alertTimestamp(updatedAt, createdAt string) (time.Time, bool) {
	for _, s := range []string{updatedAt, createdAt} {
		if s == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339, s); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

// dependabotAlert is the subset of a GET .../dependabot/alerts list item we
// normalize (https://docs.github.com/rest/dependabot/alerts).
type dependabotAlert struct {
	Number     int       `json:"number"`
	State      string    `json:"state"`
	CreatedAt  string    `json:"created_at"`
	UpdatedAt  string    `json:"updated_at"`
	HTMLURL    string    `json:"html_url"`
	Repository alertRepo `json:"repository"`
	Dependency struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	} `json:"dependency"`
	SecurityVulnerability struct {
		Severity string `json:"severity"`
	} `json:"security_vulnerability"`
}

// normalizeDependabotAlert normalizes one dependabot/alerts list item. repoHint
// fills Repo when the response has no "repository" sub-object (per-repo pull).
func normalizeDependabotAlert(raw json.RawMessage, org, repoHint string) (event.Event, bool) {
	var da dependabotAlert
	if err := json.Unmarshal(raw, &da); err != nil {
		return event.Event{}, false
	}
	ts, ok := alertTimestamp(da.UpdatedAt, da.CreatedAt)
	if !ok {
		return event.Event{}, false
	}
	repo := repoOr(da.Repository, repoHint)
	sp := synthPayload{
		SignalClass: "alert",
		AlertNumber: da.Number,
		AlertState:  da.State,
		Severity:    da.SecurityVulnerability.Severity,
		Repo:        repo,
		Org:         org,
		HTMLURL:     da.HTMLURL,
		Package:     da.Dependency.Package.Name,
		Ecosystem:   da.Dependency.Package.Ecosystem,
		Raw:         raw,
	}
	payload, _ := json.Marshal(sp)

	// Deterministic ID: family + repo + alert number + state — a re-scan of an
	// UNCHANGED alert reproduces the identical ID (store dedup); a state
	// transition (open -> fixed/dismissed) is a DIFFERENT ID, so the transition
	// itself is recorded as a new event rather than silently overwriting the
	// original.
	idSrc := fmt.Sprintf("dependabot_alert|%s|%d|%s", repo, da.Number, da.State)
	return event.Event{
		ID:        makeEventID(idSrc),
		Source:    sourceGitHub,
		Type:      typeDependabotAlert,
		Actor:     actorSystemAlert,
		Timestamp: ts,
		Org:       org,
		Payload:   payload,
	}, true
}

// codeScanningAlert is the subset of a GET .../code-scanning/alerts list item
// we normalize (https://docs.github.com/rest/code-scanning). Severity prefers
// rule.security_severity_level (GHAS's CVSS-derived bucket) and falls back to
// rule.severity (the linter's own note/warning/error) when absent.
type codeScanningAlert struct {
	Number     int       `json:"number"`
	State      string    `json:"state"`
	CreatedAt  string    `json:"created_at"`
	UpdatedAt  string    `json:"updated_at"`
	HTMLURL    string    `json:"html_url"`
	Repository alertRepo `json:"repository"`
	Rule       struct {
		ID                    string `json:"id"`
		Severity              string `json:"severity"`
		SecuritySeverityLevel string `json:"security_severity_level"`
	} `json:"rule"`
}

// normalizeCodeScanningAlert normalizes one code-scanning/alerts list item.
// repoHint fills Repo when the response has no "repository" sub-object
// (per-repo pull).
func normalizeCodeScanningAlert(raw json.RawMessage, org, repoHint string) (event.Event, bool) {
	var ca codeScanningAlert
	if err := json.Unmarshal(raw, &ca); err != nil {
		return event.Event{}, false
	}
	ts, ok := alertTimestamp(ca.UpdatedAt, ca.CreatedAt)
	if !ok {
		return event.Event{}, false
	}
	repo := repoOr(ca.Repository, repoHint)
	severity := ca.Rule.SecuritySeverityLevel
	if severity == "" {
		severity = ca.Rule.Severity
	}
	sp := synthPayload{
		SignalClass: "alert",
		AlertNumber: ca.Number,
		AlertState:  ca.State,
		Severity:    severity,
		Repo:        repo,
		Org:         org,
		HTMLURL:     ca.HTMLURL,
		Rule:        ca.Rule.ID,
		Raw:         raw,
	}
	payload, _ := json.Marshal(sp)

	idSrc := fmt.Sprintf("code_scanning_alert|%s|%d|%s", repo, ca.Number, ca.State)
	return event.Event{
		ID:        makeEventID(idSrc),
		Source:    sourceGitHub,
		Type:      typeCodeScanningAlert,
		Actor:     actorSystemAlert,
		Timestamp: ts,
		Org:       org,
		Payload:   payload,
	}, true
}

// secretScanningAlert is the subset of a GET .../secret-scanning/alerts list
// item we normalize (https://docs.github.com/rest/secret-scanning).
// DELIBERATELY has no "secret" field: the real API response's "secret" key
// carries the ACTUAL LEAKED SECRET VALUE, and this connector must never read it
// into a Go value that could get logged, copied, or re-serialized anywhere
// other than the one-shot redaction pass (redactSecretField) below.
type secretScanningAlert struct {
	Number     int       `json:"number"`
	State      string    `json:"state"`
	CreatedAt  string    `json:"created_at"`
	UpdatedAt  string    `json:"updated_at"`
	HTMLURL    string    `json:"html_url"`
	Repository alertRepo `json:"repository"`
	SecretType string    `json:"secret_type"`
}

// normalizeSecretScanningAlert normalizes one secret-scanning/alerts list item.
// repoHint fills Repo when the response has no "repository" sub-object
// (per-repo pull).
//
// CRITICAL REDACTION: the source API response embeds the leaked secret value
// itself under the "secret" key. Raw is set to redactSecretField(raw), NEVER
// the verbatim raw bytes — see redactSecretField's doc comment and
// TestSecretScanningRedaction (normalize_alerts_test.go) for the explicit proof.
func normalizeSecretScanningAlert(raw json.RawMessage, org, repoHint string) (event.Event, bool) {
	var sa secretScanningAlert
	if err := json.Unmarshal(raw, &sa); err != nil {
		return event.Event{}, false
	}
	ts, ok := alertTimestamp(sa.UpdatedAt, sa.CreatedAt)
	if !ok {
		return event.Event{}, false
	}
	repo := repoOr(sa.Repository, repoHint)
	sp := synthPayload{
		SignalClass: "alert",
		AlertNumber: sa.Number,
		AlertState:  sa.State,
		Repo:        repo,
		Org:         org,
		HTMLURL:     sa.HTMLURL,
		SecretType:  sa.SecretType,
		Raw:         redactSecretField(raw),
	}
	payload, _ := json.Marshal(sp)

	idSrc := fmt.Sprintf("secret_scanning_alert|%s|%d|%s", repo, sa.Number, sa.State)
	return event.Event{
		ID:        makeEventID(idSrc),
		Source:    sourceGitHub,
		Type:      typeSecretScanningAlert,
		Actor:     actorSystemAlert,
		Timestamp: ts,
		Org:       org,
		Payload:   payload,
	}, true
}

// redactSecretField returns raw with the top-level "secret" key's value
// replaced by a fixed marker. GitHub's secret-scanning alert API embeds the
// ACTUAL LEAKED SECRET VALUE in this field (see
// https://docs.github.com/rest/secret-scanning) — it MUST NEVER reach the
// stored event payload, which flows into findings, investigation transcripts,
// and any downstream export. Fails CLOSED: if the raw bytes don't parse as a
// JSON object, the whole raw object is replaced (never passed through
// un-redacted on a parse error) — the redaction can be wrong in the direction
// of dropping too much, never in the direction of leaking the secret.
func redactSecretField(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return json.RawMessage(`{"redacted":"unparseable secret-scanning payload"}`)
	}
	if _, ok := m["secret"]; ok {
		m["secret"] = json.RawMessage(`"[REDACTED]"`)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage(`{"redacted":"re-marshal failure"}`)
	}
	return out
}
