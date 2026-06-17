// hardconstraints.go — the ONLY gate before any model call, now DATA-DRIVEN.
//
// History: this gate began as a hardcoded Go map of dangerous families. The
// operator rejected a static auto-escalate map. The floor that ships reads its
// always-escalate routes from a MUTABLE corpus (agents/rules/operator-
// decisions.yaml, `escalate_routes`) — see router.go. The Go code here is the
// routing MECHANISM (normalize → match → escalate) and the volume
// circuit-breaker; the POLICY (which families always escalate) is data an
// operator extends without a code change.
//
// Ported originally from the Python per-finding hard-constraint gate
// (src/mallcop/resolution_rules.py: check_hard_constraints + ALWAYS_ESCALATE_
// DETECTORS) and the boundary-violation volume circuit-breaker
// (src/mallcop/budget.py: check_circuit_breaker). The dangerous-family policy
// now lives in the YAML seed instead of Go constants.
//
// These are hard security constraints that models fail to enforce reliably.
// Moving the routing to deterministic code (and the policy to versioned data)
// guarantees 100% compliance: a finding matching an always-escalate route is
// escalated to a human in code, with no model in the loop and no donuts spent.
// The model literally never sees it.
package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// Action is the deterministic disposition the floor assigns a finding.
type Action string

const (
	// ActionEscalated means: surface to a human. The floor only ever emits this.
	ActionEscalated Action = "escalated"
	// ActionProceed means: not hard-constrained; continue to model routing.
	ActionProceed Action = "proceed"
)

// Resolution is the deterministic outcome of the pre-LLM floor for one finding.
// It is the only thing the floor returns; the model is never consulted to build
// it.
type Resolution struct {
	// ForceEscalated is true when an always-escalate route fired. When true,
	// Action is always ActionEscalated and Reason explains which route tripped.
	ForceEscalated bool
	Action         Action
	Reason         string
	// Family is the normalized, canonical finding family that matched (or the
	// normalized input family when nothing matched).
	Family string
	// RouteID is the id of the escalate_routes corpus rule that fired (empty when
	// nothing matched). It makes the data-driven decision auditable: an operator
	// can trace an escalation back to the exact corpus route.
	RouteID string
}

// circuitBreakerFamily marks the synthetic meta-finding emitted by
// CheckCircuitBreaker. It is itself a seeded always-escalate route (E-006) so a
// tripped breaker is surfaced to a human and never routed to the model.
const circuitBreakerFamily = "mallcop-budget"

// familyAliases maps known evasions / aliases of a dangerous signature onto its
// canonical family — a normalization aid retained from the original floor so a
// finding family is canonicalized consistently on the proceed (benign) path
// too. The authoritative alias→route mapping for the FLOOR lives in the corpus
// (`escalate_routes[].aliases`); this map only normalizes the canonical family
// name reported back to the caller. Keys are already case-folded and
// separator-normalized (see normalizeFamily).
var familyAliases = map[string]string{
	// priv-escalation aliases
	"privilegeescalation":      "priv-escalation",
	"privesc":                  "priv-escalation",
	"privilegeesc":             "priv-escalation",
	"rolegrant":                "priv-escalation",
	"permissionboundarychange": "priv-escalation",
	// injection-probe aliases
	"promptinjection":  "injection-probe",
	"injectionattempt": "injection-probe",
	"injection":        "injection-probe",
	// secrets-exposure aliases (singular / "leak" phrasings)
	"secretexposure":  "secrets-exposure",
	"secretsexposure": "secrets-exposure",
	"secretleak":      "secrets-exposure",
	"secretsleak":     "secrets-exposure",
	"credentialleak":  "secrets-exposure",
	// boundary-violation aliases
	"boundarybreach":       "boundary-violation",
	"accessboundarybreach": "boundary-violation",
	// log-format-drift aliases
	"parsermismatch":           "log-format-drift",
	"logdrift":                 "log-format-drift",
	"unmatchedeventratiospike": "log-format-drift",
	"logtampering":             "log-format-drift",
}

// normalizeFamily reduces a raw finding family to a canonical name when it
// matches a known dangerous signature (directly or by alias), or returns the
// trimmed lower-cased input otherwise. This is the BYPASS hardening on the
// REPORTED family: case folding, whitespace trimming, and separator stripping
// collapse "  Injection-Probe ", "PRIV-ESCALATION", and "secrets_exposure" onto
// their canonical forms. The actual escalate DECISION is made by the router's
// trigger-set match (router.go), which folds the corpus aliases the same way.
func normalizeFamily(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	stripped := stripSeparators(trimmed)
	if canon, ok := familyAliases[stripped]; ok {
		return canon
	}
	return trimmed
}

// stripSeparators removes hyphens, underscores, spaces and tabs and lower-cases
// the rest, so separator/case variants of a family collapse to one key.
func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		switch r {
		case '-', '_', ' ', '\t', '\n', '\r', '.', '/', ':':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// checkHardConstraints is the ONLY gate before any model call. It is now
// data-driven: it loads the always-escalate routes from the operator-decisions
// corpus and force-escalates any finding that matches one — no model, no I/O
// beyond the one corpus read, no network.
//
// It returns (forceEscalate, resolution):
//   - forceEscalate=true with an escalated Resolution when the finding matches a
//     corpus escalate_route. The caller MUST NOT call the model in this case.
//   - forceEscalate=false with a proceed Resolution otherwise; the caller may
//     route the finding to the model.
//
// Fail-safe on corpus load error: if the corpus is present but unparseable, the
// floor cannot trust its policy, so it force-escalates rather than waving the
// finding through to the model (never fail open). A MISSING corpus is treated as
// an empty floor (no routes) — the resolve-gate fail-safe downstream still
// covers unparseable/ambiguous findings.
func checkHardConstraints(f finding.Finding) (bool, Resolution) {
	repoRoot, rootErr := resolveRepoRoot()
	if rootErr != nil {
		// Cannot even locate the corpus — fail safe: escalate, do not guess.
		return true, Resolution{
			ForceEscalated: true,
			Action:         ActionEscalated,
			Family:         normalizeFamily(f.Type),
			Reason: fmt.Sprintf(
				"Hard constraint (fail-safe): cannot locate escalate-route corpus (%v); "+
					"escalating for human review rather than routing to the model", rootErr),
		}
	}

	routes, err := loadEscalateRoutes(repoRoot)
	if err != nil {
		// Corpus present but broken — fail safe: escalate, do not route to model.
		return true, Resolution{
			ForceEscalated: true,
			Action:         ActionEscalated,
			Family:         normalizeFamily(f.Type),
			Reason: fmt.Sprintf(
				"Hard constraint (fail-safe): escalate-route corpus unparseable (%v); "+
					"escalating for human review rather than routing to the model", err),
		}
	}

	if route, ok := matchEscalateRoute(routes, f); ok {
		reason := strings.TrimSpace(route.Reason)
		if reason == "" {
			reason = fmt.Sprintf(
				"Hard constraint: route %s (%s) always requires human review "+
					"(deterministic escalation, no LLM involved)", route.ID, route.Family)
		}
		return true, Resolution{
			ForceEscalated: true,
			Action:         ActionEscalated,
			Family:         normalizeFamily(f.Type),
			RouteID:        route.ID,
			Reason:         reason,
		}
	}

	return false, Resolution{
		ForceEscalated: false,
		Action:         ActionProceed,
		Family:         normalizeFamily(f.Type),
	}
}

// BudgetConfig carries the single knob the volume circuit-breaker needs: the max
// finding count that may be handled autonomously before the breaker trips.
// Ported from src/mallcop/budget.py BudgetConfig.max_findings_for_actors.
type BudgetConfig struct {
	// MaxFindingsForActors is the inclusive ceiling. A run with strictly MORE
	// findings than this trips the breaker.
	MaxFindingsForActors int
}

// CheckCircuitBreaker ports src/mallcop/budget.py check_circuit_breaker.
//
// When the number of findings exceeds MaxFindingsForActors, it returns a
// synthetic CRITICAL meta-finding (family "mallcop-budget") describing the trip.
// That meta-finding matches the seeded E-006 escalate_route (see
// checkHardConstraints), so a tripped breaker is surfaced to a human and never
// routed to the model. When the count is at or under the threshold it returns
// nil — no breaker.
//
// The breaker is a volume defense: a flood of findings (e.g. an attacker
// generating noise to drown a real boundary violation) must not be quietly
// auto-handled. It halts autonomous processing and escalates.
func CheckCircuitBreaker(findings []finding.Finding, cfg BudgetConfig) *finding.Finding {
	if len(findings) <= cfg.MaxFindingsForActors {
		return nil
	}

	breakdown := map[string]int{}
	for _, f := range findings {
		breakdown[f.Severity]++
	}
	parts := make([]string, 0, len(breakdown))
	for sev, n := range breakdown {
		parts = append(parts, fmt.Sprintf("%s=%d", sev, n))
	}

	return &finding.Finding{
		ID:        "meta_circuit_breaker",
		Source:    "mallcop-budget",
		Type:      circuitBreakerFamily,
		Severity:  "critical",
		Timestamp: time.Now().UTC(),
		Reason: fmt.Sprintf(
			"Volume circuit breaker triggered: %d findings exceed threshold %d (severity breakdown: %s)",
			len(findings), cfg.MaxFindingsForActors, strings.Join(parts, " ")),
	}
}
