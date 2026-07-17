package detect

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { Register(alertSignalDetector{}) }

type alertSignalDetector struct{}

func (alertSignalDetector) Name() string { return "alert-signal" }

// alertEventTypes are the GitHub-native alert Types this detector gates on. They
// share a common shape marker in the payload ("signal_class":"alert" — see
// alertPayload) that is intended to generalize to future non-GitHub alert
// producers (guardduty_finding, cloudwatch_alarm, sentry_issue, datadog_alert;
// mallcoppro-ee9). Until those land, only these three GitHub types exist.
//
// Before this detector, events of these Types gated NO detector — they were
// inert ("informational-only"; see connect/github/normalize.go's routing-gate
// doc comment). This detector is what makes them triageable.
var alertEventTypes = map[string]bool{
	"dependabot_alert":      true,
	"code_scanning_alert":   true,
	"secret_scanning_alert": true,
}

// alertCorrelationWindow bounds how far apart (in EITHER direction) a raw
// activity event may sit from an alert's timestamp to count as corroborating
// it. 72h (3 days) is a "recent activity" look-back long enough to catch a
// dependency bump or a push that happens shortly before OR after GitHub raises
// the alert (alert creation commonly lags the triggering activity), while still
// being a bounded, principled window rather than "anywhere in the corpus."
const alertCorrelationWindow = 72 * time.Hour

// alertEvidenceEventIDCap bounds how many correlated event IDs ride along in a
// single finding's evidence (mirrors unusualTimingEventIDCap's rationale: sample
// the corroborating set without inflating the payload when many events match).
const alertEvidenceEventIDCap = 15

// alertPayload unifies the field shapes of the TWO producers that emit
// alertEventTypes today:
//
//  1. The audit-feed classifier (connect/github/normalize.go:normalizeAuditEntry,
//     synthPayload) — SPARSE. It carries action/target_user/collaborator/repo/
//     org/raw, but no alert_number, alert_state, severity, package, ecosystem,
//     secret_type, or rule: the audit log only tells us an alert of some kind
//     was created, not its detail.
//  2. A dedicated alert-API collector (built in parallel) — FLAT and rich:
//     signal_class/alert_number/alert_state/severity/repo/html_url/package/
//     ecosystem/secret_type/rule.
//
// A single json.Unmarshal into this struct populates whichever subset of
// fields the producer actually emitted; fields the OTHER producer would have
// set stay zero-valued. Every read of this struct MUST treat an empty field as
// "unknown," never as "zero" or "false" — see alertSeverity, the correlation
// rules, and alertDescribe for the degrade-gracefully handling this requires.
type alertPayload struct {
	// Dedicated-API collector (flat) shape.
	SignalClass string     `json:"signal_class"`
	AlertNumber flexString `json:"alert_number"`
	AlertState  string     `json:"alert_state"`
	Severity    string     `json:"severity"`
	Repo        string     `json:"repo"`
	HTMLURL     string     `json:"html_url"`
	Package     string     `json:"package"`
	Ecosystem   string     `json:"ecosystem"`
	SecretType  string     `json:"secret_type"`
	Rule        string     `json:"rule"`

	// Audit-feed classifier (sparse synthPayload) shape.
	Action       string `json:"action"`
	TargetUser   string `json:"target_user"`
	Collaborator string `json:"collaborator"`
	Org          string `json:"org"`
}

// flexString unmarshals a JSON string OR a JSON number into a Go string, so a
// producer's choice of encoding for a numeric-looking field (alert_number)
// never fails the surrounding struct's unmarshal. This package's established
// defensive pattern is to ignore unmarshal errors and let the rest of the
// struct populate (see dependencyTamperEvaluate); flexString extends that
// tolerance to the field itself, rather than losing the whole payload to a
// single type mismatch.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		*f = flexString(n.String())
		return nil
	}
	// Unknown shape (object, array, null): leave zero-valued. Never propagate —
	// this field is never worth failing the whole event over.
	return nil
}

// alertCorrelationMatch is the result of a correlation rule finding at least
// one concrete corroborating event. eventIDs is never empty when a match is
// non-nil — the HARD RULE this detector must never violate is that every
// escalation carries concrete correlated-event evidence, not a family-match
// guess.
type alertCorrelationMatch struct {
	rule     string
	eventIDs []string
}

// Detect surfaces one finding per DISTINCT alert (deduped by alert id+state,
// see alertDedupKey) in the corpus: a base finding with severity mapped from
// the alert's own severity (or a documented per-type floor when the source
// carries none), escalated to "critical" with correlated-event evidence when
// one of the two correlation rules fires. bl is unused: alert triage does not
// need the actor-hours/relationship baseline other detectors key on.
func (alertSignalDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	type alertInstance struct {
		ev  event.Event
		ap  alertPayload
		key string
	}

	seen := map[string]bool{}
	var alerts []alertInstance
	for _, ev := range events {
		if !alertEventTypes[ev.Type] {
			continue
		}
		var ap alertPayload
		if len(ev.Payload) > 0 {
			_ = json.Unmarshal(ev.Payload, &ap) // defensive: never crash on a malformed payload
		}
		key := alertDedupKey(ev, ap)
		if seen[key] {
			continue // same alert (id+state) already produced a finding this scan
		}
		seen[key] = true
		alerts = append(alerts, alertInstance{ev: ev, ap: ap, key: key})
	}
	if len(alerts) == 0 {
		return nil
	}

	// Deterministic output order regardless of corpus ordering.
	sort.SliceStable(alerts, func(i, j int) bool {
		if !alerts[i].ev.Timestamp.Equal(alerts[j].ev.Timestamp) {
			return alerts[i].ev.Timestamp.Before(alerts[j].ev.Timestamp)
		}
		return alerts[i].key < alerts[j].key
	})

	out := make([]finding.Finding, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, alertSignalFindingFor(a.ev, a.ap, a.key, events))
	}
	return out
}

// alertDedupKey identifies ONE alert instance so a re-scan (or a corpus that
// accumulates the same alert across multiple polls/audit entries) collapses to
// a single finding instead of multiplying. It prefers the dedicated-API
// collector's stable identity — repo+alert_number are unique together, and
// alert_state is included so a REAL lifecycle transition (open -> fixed) is a
// distinct key and gets its own finding, not silently merged into the earlier
// one. The sparse audit-feed shape carries neither field, so it falls back to
// the event's own ID (already a stable identity for that specific audit-log
// entry per connect/github/normalize.go:normalizeAuditEntry — the document id
// when present, else a deterministic composite); re-ingesting the same entry
// yields the same event ID, so this still collapses duplicates. Every
// component is sanitized individually (reusing depSanitizeID) and joined with
// "-" so the result is safe to use directly as a finding ID suffix.
func alertDedupKey(ev event.Event, ap alertPayload) string {
	if strings.TrimSpace(string(ap.AlertNumber)) != "" {
		return strings.Join([]string{
			depSanitizeID(ev.Type),
			depSanitizeID(ap.Repo),
			depSanitizeID(string(ap.AlertNumber)),
			depSanitizeID(ap.AlertState),
		}, "-")
	}
	id := ev.ID
	if id == "" {
		// Degenerate input: no alert number AND no event id. Fall back to a
		// composite that is at least unique to THIS occurrence, rather than
		// collapsing every ID-less alert of the same Type into one record.
		id = ev.Actor + "-" + ev.Timestamp.UTC().Format("20060102T150405.000000000Z")
	}
	return depSanitizeID(ev.Type) + "-" + depSanitizeID(id)
}

// alertSeverity resolves the Finding severity for an alert event.
//
//  1. If the payload carries its own severity string, normalize known
//     spellings (GitHub advisory severities are exactly critical/high/medium/
//     low; "moderate" is accepted as a CVSS-style alias for medium) and use it
//     verbatim — the alert says what it is, so we report that, not a guess.
//  2. If the payload is silent (the sparse audit-feed shape carries no
//     severity field at all; and GitHub's API itself exposes no severity for
//     secret-scanning alerts even via the dedicated collector), fall back to a
//     documented PER-TYPE FLOOR, never a per-alert guess:
//     secret_scanning_alert defaults to "high" because a live leaked credential
//     is high-impact by construction, independent of any metadata GitHub
//     supplies; dependabot_alert/code_scanning_alert default to "medium" — the
//     same neutral "flag for review" tier dependency-tamper's
//     unexpected-direct-dependency rule already uses in this package for an
//     unknown-risk signal.
//
// Returns the resolved severity and whether it came from the alert's own field
// (derived=true) or the type-level floor (derived=false); callers surface that
// provenance in evidence (severity_source) so a floored severity is never
// silently presented as if GitHub reported it.
func alertSeverity(alertType, raw string) (sev string, derived bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return "critical", true
	case "high":
		return "high", true
	case "medium", "moderate":
		return "medium", true
	case "low":
		return "low", true
	}
	if alertType == "secret_scanning_alert" {
		return "high", false
	}
	return "medium", false
}

// alertRepoScope returns the best available "same repo" proxy for an event:
// the payload's own "repo" field when present (both alertPayload's dedicated-
// API shape and the audit-feed synthPayload use the key "repo", so
// payloadMeta's generic top-level-map read finds it for either), else the
// event's Org. Dependency-change events (dependency_add/dependency_update)
// currently carry NO repo field at all (see cmd/detector-dependency-tamper/
// testdata/events.jsonl) — only Org — so falling back to Org is what makes
// rule 1's correlation possible at all for them, and is prefixed so it is
// never confused with a real repo value. Returns "" when neither is known —
// callers must treat that as "unknown," never as a wildcard match.
func alertRepoScope(ev event.Event) string {
	if repo := metaStr(payloadMeta(ev.Payload), "repo"); repo != "" {
		return repo
	}
	if ev.Org != "" {
		return "org:" + ev.Org
	}
	return ""
}

// withinAlertWindow reports whether b falls within alertCorrelationWindow of a,
// in either direction.
func withinAlertWindow(a, b time.Time) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= alertCorrelationWindow
}

// collectCorrelatedEventIDs scans the whole corpus for events (other than
// alertEv itself) within alertCorrelationWindow of alertEv's timestamp that
// satisfy match, and returns their IDs sorted by (timestamp, id) and capped at
// alertEvidenceEventIDCap. Returns nil when nothing matches — callers use that
// as "this correlation rule did not fire," never inventing evidence.
func collectCorrelatedEventIDs(alertEv event.Event, events []event.Event, match func(ev event.Event) bool) []string {
	type candidate struct {
		id string
		ts time.Time
	}
	var cands []candidate
	for _, ev := range events {
		if ev.ID == alertEv.ID {
			continue
		}
		if !withinAlertWindow(alertEv.Timestamp, ev.Timestamp) {
			continue
		}
		if !match(ev) {
			continue
		}
		cands = append(cands, candidate{id: ev.ID, ts: ev.Timestamp})
	}
	if len(cands) == 0 {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if !cands[i].ts.Equal(cands[j].ts) {
			return cands[i].ts.Before(cands[j].ts)
		}
		return cands[i].id < cands[j].id
	})
	if len(cands) > alertEvidenceEventIDCap {
		cands = cands[:alertEvidenceEventIDCap]
	}
	ids := make([]string, len(cands))
	for i, c := range cands {
		ids[i] = c.id
	}
	return ids
}

// correlateDependencyChange is correlation RULE 1: a dependabot_alert
// corroborated by a dependency_add/dependency_update touching the SAME package
// (case-insensitive) within the SAME repo/org scope, inside the correlation
// window, is concrete evidence the vulnerable dependency was actively
// (re)introduced or bumped around the time the alert fired — "vulnerable
// dependency actively changed," not dismissed or ignored.
//
// Returns nil (never guesses) when the alert payload carries no package — the
// sparse audit-feed shape has none, so this rule is a no-op for it, exactly
// the "skip correlation" degradation the spec requires — or when no
// dependency-change event matches.
func correlateDependencyChange(alertEv event.Event, ap alertPayload, events []event.Event) *alertCorrelationMatch {
	pkg := strings.TrimSpace(ap.Package)
	if pkg == "" {
		return nil
	}
	scope := alertRepoScope(alertEv)

	ids := collectCorrelatedEventIDs(alertEv, events, func(ev event.Event) bool {
		if ev.Type != "dependency_add" && ev.Type != "dependency_update" {
			return false
		}
		var dp depPayload
		if len(ev.Payload) > 0 {
			_ = json.Unmarshal(ev.Payload, &dp)
		}
		if !strings.EqualFold(strings.TrimSpace(dp.Package), pkg) {
			return false
		}
		depScope := alertRepoScope(ev)
		if scope != "" && depScope != "" && scope != depScope {
			return false // both scopes known and disagree — not the same repo/org
		}
		return true
	})
	if len(ids) == 0 {
		return nil
	}
	return &alertCorrelationMatch{rule: "vulnerable-dependency-actively-changed", eventIDs: ids}
}

// correlateSecretActivity is correlation RULE 2: a secret_scanning_alert
// corroborated by a push or secret_access performed by the SAME actor inside
// the correlation window is concrete evidence of recent activity around the
// leak — "leaked secret with recent activity."
//
// Returns nil (never guesses) when the alert has no usable actor identity
// ("" or "unknown" — the audit-feed and dedicated-API producers both fall back
// to "unknown" for a missing actor) or when no push/secret_access event by
// that actor matches.
func correlateSecretActivity(alertEv event.Event, events []event.Event) *alertCorrelationMatch {
	actor := strings.TrimSpace(alertEv.Actor)
	if actor == "" || strings.EqualFold(actor, "unknown") {
		return nil
	}

	ids := collectCorrelatedEventIDs(alertEv, events, func(ev event.Event) bool {
		if ev.Type != "push" && ev.Type != "secret_access" {
			return false
		}
		return ev.Actor == actor
	})
	if len(ids) == 0 {
		return nil
	}
	return &alertCorrelationMatch{rule: "leaked-secret-with-recent-activity", eventIDs: ids}
}

// alertRepoDisplay renders the best available human-readable repo/scope label
// for Reason strings: the alert's own repo field, else its Org, else an
// explicit "unknown repo" rather than an empty string.
func alertRepoDisplay(alertEv event.Event, ap alertPayload) string {
	if ap.Repo != "" {
		return ap.Repo
	}
	if alertEv.Org != "" {
		return alertEv.Org
	}
	return "unknown repo"
}

// alertDescribe renders the alert-type-specific detail clause for the Reason
// string, preferring the dedicated-API collector's flat fields and falling
// back to an honest "detail unavailable" clause when they are absent (sparse
// audit-feed shape) — never fabricating a package/rule/secret-type name.
func alertDescribe(alertEv event.Event, ap alertPayload) string {
	switch alertEv.Type {
	case "dependabot_alert":
		if ap.Package != "" {
			eco := ap.Ecosystem
			if eco == "" {
				eco = "unknown ecosystem"
			}
			return fmt.Sprintf("vulnerable dependency %q (%s)", ap.Package, eco)
		}
		return "vulnerable dependency (advisory detail unavailable from this event source)"
	case "code_scanning_alert":
		if ap.Rule != "" {
			return fmt.Sprintf("code scanning finding %q", ap.Rule)
		}
		return "code scanning finding (rule detail unavailable from this event source)"
	case "secret_scanning_alert":
		if ap.SecretType != "" {
			return fmt.Sprintf("leaked secret (%s)", ap.SecretType)
		}
		return "leaked secret (type detail unavailable from this event source)"
	default:
		return "security alert"
	}
}

// alertCorrelationLabel renders a correlation rule identifier as the
// human-readable phrase from the spec.
func alertCorrelationLabel(rule string) string {
	switch rule {
	case "vulnerable-dependency-actively-changed":
		return "vulnerable dependency actively changed"
	case "leaked-secret-with-recent-activity":
		return "leaked secret with recent activity"
	default:
		return rule
	}
}

// alertSignalFindingFor builds the ONE finding for a single deduped alert
// instance: base severity from alertSeverity, then correlation dispatched by
// alert Type (code_scanning_alert has no correlation rule defined by the spec
// and stays base-only). An escalation ALWAYS carries the corroborating event
// IDs in evidence (correlated_event_ids) — never an evidence-free severity
// bump (the standing no-family-match-force-escalate invariant).
func alertSignalFindingFor(alertEv event.Event, ap alertPayload, key string, events []event.Event) finding.Finding {
	sev, derived := alertSeverity(alertEv.Type, ap.Severity)

	var match *alertCorrelationMatch
	switch alertEv.Type {
	case "dependabot_alert":
		match = correlateDependencyChange(alertEv, ap, events)
	case "secret_scanning_alert":
		match = correlateSecretActivity(alertEv, events)
		// code_scanning_alert: no correlation rule defined (spec names exactly
		// two rules); base-only, same as any alert type this detector doesn't
		// yet know how to corroborate.
	}

	scope := alertRepoDisplay(alertEv, ap)
	detail := alertDescribe(alertEv, ap)

	var reason string
	if match != nil {
		sev = "critical" // corroborated-with-evidence ceiling, see doc comment above
		reason = fmt.Sprintf(
			"%s on %s: %s — ESCALATED (%s), corroborated by %d correlated event(s)",
			alertEv.Type, scope, detail, alertCorrelationLabel(match.rule), len(match.eventIDs),
		)
	} else {
		sevNote := ""
		if !derived {
			sevNote = ", severity not reported by the source — flagged at the review floor"
		}
		reason = fmt.Sprintf("%s on %s (%s severity%s): %s", alertEv.Type, scope, sev, sevNote, detail)
	}

	evidence := alertEvidenceJSON(alertEv, ap, sev, derived, match)

	return finding.Finding{
		ID:        "finding-" + key,
		Source:    "detector:alert-signal",
		Severity:  sev,
		Type:      "alert-signal",
		Actor:     alertEv.Actor,
		Timestamp: alertEv.Timestamp,
		Reason:    reason,
		Evidence:  evidence,
	}
}

// alertEvidenceJSON builds the evidence blob. Every field the payload actually
// supplied is included (omitted otherwise, never zero-filled/guessed);
// severity_source discloses whether severity came from the alert ("alert") or
// this detector's documented floor ("policy-default"); an escalation always
// carries correlation_rule + correlated_event_ids with concrete event IDs.
func alertEvidenceJSON(alertEv event.Event, ap alertPayload, sev string, derived bool, match *alertCorrelationMatch) json.RawMessage {
	m := map[string]any{
		"actor":           alertEv.Actor,
		"alert_type":      alertEv.Type,
		"alert_event_id":  alertEv.ID,
		"repo":            alertRepoDisplay(alertEv, ap),
		"severity":        sev,
		"severity_source": severitySourceLabel(derived),
		"escalated":       match != nil,
	}
	if s := strings.TrimSpace(string(ap.AlertNumber)); s != "" {
		m["alert_number"] = s
	}
	if ap.AlertState != "" {
		m["alert_state"] = ap.AlertState
	}
	if ap.Package != "" {
		m["package"] = ap.Package
	}
	if ap.Ecosystem != "" {
		m["ecosystem"] = ap.Ecosystem
	}
	if ap.SecretType != "" {
		m["secret_type"] = ap.SecretType
	}
	if ap.Rule != "" {
		m["rule"] = ap.Rule
	}
	if ap.HTMLURL != "" {
		m["html_url"] = ap.HTMLURL
	}
	if match != nil {
		m["correlation_rule"] = match.rule
		m["correlated_event_ids"] = match.eventIDs
	}
	b, _ := json.Marshal(m)
	return b
}

// severitySourceLabel renders alertSeverity's derived bool as the evidence
// string consumers (chat investigation, triage UI) read.
func severitySourceLabel(derived bool) string {
	if derived {
		return "alert"
	}
	return "policy-default"
}
