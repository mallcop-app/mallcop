// Package observe holds the THREE pure observable force-escalate predicates the
// cascade's structural-confidence gate scores, plus every helper / threshold /
// map they read — extracted VERBATIM from core/eval/scenario_tools.go so that the
// eval scenarioToolRunner AND the production core/toolrun.Runner call ONE shared
// implementation and get BYTE-IDENTICAL booleans + details.
//
// THE DIVERGENCE THIS CLOSES (the veracity flag): before this package the
// observable predicates lived only in core/eval. The production cascade reached
// tools through the SAME agent.ToolRunner seam but had no live runner — and any
// future prod runner that re-implemented these predicates could drift from the
// eval's, silently breaking the validated 83.9% / 2-missed-attacks number. With
// the predicates as FREE functions here, a single change moves both runners
// together: there is exactly one source of truth.
//
// PURITY / IMPORT DISCIPLINE: every function here is pure over its inputs —
// (actor string, *baseline.Baseline, []tools.EventView) — exactly what BOTH
// runners already hold. The package imports ONLY core/tools (for tools.EventView)
// and pkg/baseline (for baseline.Relationship/Baseline). It MUST NOT import
// core/agent, core/eval, core/store, core/pipeline, exam, or any orchestration /
// transport / vendor SDK (see imports_test.go). It opens no store, makes no
// inference call, and touches no shared mutable state.
//
// EXTRACTION-NOT-REWRITE: the bodies below are the eval bodies moved verbatim —
// every comparison, threshold, map entry, and edge case preserved so behavior is
// byte-identical. The only mechanical change is the method receiver (r.actor →
// the actor parameter, r.baseline → the b parameter); the logic is untouched.
package observe

import (
	"strconv"
	"strings"

	"github.com/mallcop-app/mallcop/core/tools"
	"github.com/mallcop-app/mallcop/pkg/baseline"
)

// roleGrantEventTypes / roleGrantActions are the privilege/role-grant event
// signatures the FIX 3 (b) predicate keys on. A surfaced event whose type or action
// is one of these is a role grant. Compared after separator-stripping + lower-case.
var roleGrantEventTypes = map[string]struct{}{
	"roleassignment":  {},
	"roleassign":      {},
	"permissiongrant": {},
	"privilegegrant":  {},
}

var roleGrantActions = map[string]struct{}{
	"addroleassignment": {},
	"assignrole":        {},
	"grantrole":         {},
	"grantpermission":   {},
}

// ZeroHistoryAccess (FIX 3a) reports whether the finding actor, in the surfaced
// events, accessed a target with which it has ZERO relationship history (no
// relationship record, or a record with count 0). VA-03: ci-bot reads storage
// targets absent from its (deploy-only) relationship set. CO-02: deploy-svc
// bulk-reads a target outside its established relationships. VA-01 is NOT caught:
// every deploy target is in deploy-svc's relationships with a positive count.
//
// It considers only events AUTHORED BY the finding actor (the actor under
// investigation actually performed the access) and only events carrying a target
// (a login/health-check with no resource target is not an "access"). The first
// zero-history target found is named in the detail for the audit trail.
func ZeroHistoryAccess(actor string, b *baseline.Baseline, events []tools.EventView) (bool, string) {
	if actor == "" || b == nil {
		return false, ""
	}
	rels := b.RelationshipsFor(actor)
	al := strings.ToLower(strings.TrimSpace(actor))
	for _, ev := range events {
		if !strings.EqualFold(ev.Actor, actor) {
			continue
		}
		target := strings.TrimSpace(ev.Target)
		if target == "" {
			continue
		}
		if relationshipCountFor(rels, al, target) == 0 {
			return true, actor + " → " + target + " (no relationship history)"
		}
	}
	return false, ""
}

// establishedGroupRelationshipFloor is the minimum relationship count an actor
// must hold AT THE RESOURCE-GROUP LEVEL for a sibling-leaf access inside that
// group to count as established (not zero-history). The two benign-hard scenarios
// that this credit unblocks carry group-level counts well above it (URA-04
// infra-admin: 892; UT-07 ops-engineer: 467), and the lateral-movement attacks
// carry NO group-level entry at all (ci-bot's atom-rg history in URA-02 / VA-03 is
// only LEAF entries — containerApps/containerRegistries — never a "<...>/
// resourceGroups/atom-rg" key), so the discriminator is really the EXISTENCE of an
// established group-level relationship. The floor is a conservative guard so a
// single incidental group-scoped touch cannot manufacture group-wide trust; it is
// set far below the legitimate counts (467/892) yet above one-off noise.
const establishedGroupRelationshipFloor = 25

// relationshipCountFor returns the historical relationship count for the
// (actor, target) pair, or 0 when the actor has NO established relationship
// covering that target. The scenario keys relationships as "<actor>:<target>".
//
// DISCRIMINATION (not blunter escalation), in two tiers:
//
//  1. SAME-RESOURCE (leaf) credit: a relationship covers an event target when its
//     target segment is the SAME RESOURCE — an exact match, OR one is a path-prefix
//     of the other at a segment boundary (a relationship with the storage ACCOUNT
//     atomstorage01 covers a read on atomstorage01/containers/financial: a new
//     container under an established account is not "zero history"). This separates
//     VA-02 / VA-05 (a known batch/report actor reading a NEW container under an
//     account it ALREADY accesses — established, RESOLVE) from VA-03 (ci-bot reading
//     storageAccounts it has NEVER touched — its leaf relationships are all
//     containerRegistries/containerApps, none sharing a resource prefix with the
//     storage targets — zero history, ESCALATE).
//
//  2. RESOURCE-GROUP credit (this fix): an established relationship recorded AT the
//     resource-group path "<sub>/resourceGroups/<rg>" (count >= the established
//     floor) covers ANY leaf resource inside that same group. This is what an
//     owner/manager of the group has: the actor rotates through resources it owns,
//     so first-touch on a newly provisioned SIBLING leaf is expected, not lateral
//     movement. URA-04 (infra-admin manages atom-rg, group count 892, first access
//     to atom-db-staging) and UT-07 (ops-engineer manages atom-rg, group count 467,
//     cleanup deletes inside it) RESOLVE on this. The discriminator that keeps
//     lateral movement escalating: the credit requires an EXPLICIT group-level
//     relationship key. URA-02 / VA-03 ci-bot has only LEAF entries inside atom-rg
//     (no "<...>/resourceGroups/atom-rg" key), so it gets NO group credit and stays
//     zero-history → ESCALATE. Sharing only the subscription / resourceGroup PATH
//     via prefix is still NOT enough on its own (sameResource rejects it); the actor
//     must have an actual, established group-scoped relationship.
//
// actorLower is the pre-lowercased finding actor.
func relationshipCountFor(rels map[string]baseline.Relationship, actorLower, target string) int {
	tl := strings.ToLower(strings.TrimSpace(target))
	// Tier 1: exact + same-resource (leaf) credit.
	for key, rel := range rels {
		kl := relationshipKeyTarget(key, actorLower)
		if kl == "" {
			continue
		}
		if kl == tl || sameResource(kl, tl) {
			return rel.Count
		}
	}
	// Tier 2: resource-group credit. The actor holds an ESTABLISHED relationship at
	// the resource-group level that contains this target → a sibling-leaf access in a
	// group the actor manages is established, not zero-history.
	for key, rel := range rels {
		if rel.Count < establishedGroupRelationshipFloor {
			continue
		}
		kl := relationshipKeyTarget(key, actorLower)
		if kl == "" {
			continue
		}
		if groupRelationshipCovers(kl, tl) {
			return rel.Count
		}
	}
	return 0
}

// relationshipKeyTarget isolates the target portion of an "<actor>:<target>"
// relationship key (lower-cased, trimmed). It strips the actor prefix when present,
// else splits on the first ':'. Returns "" when there is no target portion.
func relationshipKeyTarget(key, actorLower string) string {
	keyTarget := key
	if idx := strings.Index(strings.ToLower(key), actorLower+":"); idx == 0 {
		keyTarget = key[len(actorLower)+1:]
	} else if i := strings.IndexByte(key, ':'); i >= 0 {
		keyTarget = key[i+1:]
	}
	return strings.ToLower(strings.TrimSpace(keyTarget))
}

// groupRelationshipCovers reports whether relTarget is a RESOURCE-GROUP-level path
// ("<sub>/resourceGroups/<rg>", i.e. it STOPS at the resource group with no deeper
// resource segment) that CONTAINS the accessed target (target descends into that
// same group at a segment boundary). Both args are lower-cased.
//
// This is the precise complement of sameResource's "must extend past the group"
// rule: sameResource deliberately refuses to credit a group-level prefix as a
// concrete-resource match (so a NEW resource in a known group is zero-history under
// the leaf rule); groupRelationshipCovers is the SEPARATE, narrower credit that
// fires ONLY for an explicit established group-level relationship — the manager case.
// It does NOT fire for a leaf relationship (those have depth past the group, so
// relationshipIsGroupLevel is false), keeping VA-03 / URA-02 (leaf-only history)
// zero-history.
func groupRelationshipCovers(relTarget, target string) bool {
	if !relationshipIsGroupLevel(relTarget) {
		return false
	}
	// The accessed target must be a STRICT descendant of the group path (a deeper
	// resource inside the group), bounded at a segment boundary so "atom-rg" does not
	// spuriously cover "atom-rg-2".
	return strings.HasPrefix(target, relTarget+"/")
}

// relationshipIsGroupLevel reports whether a resource path is exactly a resource-
// group path: it contains a "resourceGroups/<rg>" pair and STOPS there (no concrete
// resource segment after the group name). That is the shape of a manager/owner's
// group-scoped relationship. A leaf relationship (one segment past the group, e.g.
// ".../resourceGroups/atom-rg/containerApps/atom-api") is NOT group-level — so a
// deploy-only actor's leaf history never grants group-wide credit.
func relationshipIsGroupLevel(path string) bool {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		if strings.EqualFold(s, "resourceGroups") {
			// Group-level iff the path ends at the <rg> name: segment i is
			// "resourceGroups", i+1 is the group name, and there is nothing after it.
			return len(segs) == i+2
		}
	}
	return false
}

// sameResource reports whether two lower-cased resource paths refer to the same
// underlying resource: one is a segment-boundary prefix of the other, with the
// shared prefix extending PAST the resourceGroup level (so a relationship to a
// concrete resource covers a sub-path of it, but merely sharing the
// subscription/resourceGroup does not). "/"-delimited segment boundaries only —
// "atomstorage01" must not match "atomstorage011".
func sameResource(a, b string) bool {
	if a == b {
		return true
	}
	short, long := a, b
	if len(short) > len(long) {
		short, long = long, short
	}
	// long must start with short followed by a path separator (segment boundary).
	if !strings.HasPrefix(long, short+"/") {
		return false
	}
	// The shared prefix must reach a concrete resource, not stop at the resource
	// group. Require the prefix to contain more path depth than "<sub>/resourceGroups
	// /<rg>" — i.e. at least one segment AFTER the resourceGroup name. This stops a
	// brand-new resource in a known group from counting as established access.
	return resourceDepthPastGroup(short)
}

// resourceDepthPastGroup reports whether a resource path descends to at least a
// concrete resource past the "<...>/resourceGroups/<rg>" prefix (or carries no
// resourceGroups segment at all, e.g. an "acme-corp/tenant" style path, in which
// case two segments are enough to name a resource). It prevents a relationship that
// only reaches the resource-group level from "covering" arbitrary new resources
// inside that group.
func resourceDepthPastGroup(path string) bool {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		if strings.EqualFold(s, "resourceGroups") || strings.EqualFold(s, "resourcegroups") {
			// Need: resourceGroups(i) / <rg>(i+1) / <resourceType-or-name>(i+2)
			return len(segs) >= i+3
		}
	}
	// No resourceGroups segment: a 2+ segment path already names a resource.
	return len(segs) >= 2
}

// RoleGrantByActor (FIX 3b) reports whether the surfaced events show the FINDING
// ACTOR performing a role-grant / privilege event (event_type role_assignment, or
// action add_role_assignment) for which it has NO baseline history of granting
// roles. UT-01 / IT-02: admin-user (the finding actor) grants a role with a
// role_assignment baseline frequency of 0. ID-01 is NOT caught: there the role
// grant is authored by admin-user (a KNOWN role-granter with frequency 28), NOT by
// the finding actor deploy-svc-new — so the finding actor performed no grant.
func RoleGrantByActor(actor string, b *baseline.Baseline, events []tools.EventView) (bool, string) {
	if actor == "" {
		return false, ""
	}
	for _, ev := range events {
		if !strings.EqualFold(ev.Actor, actor) {
			continue
		}
		if !isRoleGrantEvent(ev) {
			continue
		}
		// The finding actor performed a role grant. Force-escalate UNLESS the actor
		// has an established baseline history of granting roles (a known role-granter
		// doing a routine grant is not the under-escalation case). The baseline
		// frequency for the role-grant event type captures "has this actor granted
		// roles before"; 0 (or absent) => no precedent => escalate.
		if ActorRoleGrantFrequency(actor, b) == 0 {
			return true, actor + " performed " + ev.Type + "/" + ev.Action + " with no baseline role-grant history"
		}
	}
	return false, ""
}

// isRoleGrantEvent reports whether an event is a role-grant / privilege event by
// its type or action (separator-stripped, lower-cased). Keyed on the EVENT, never
// on the detector family.
func isRoleGrantEvent(ev tools.EventView) bool {
	if _, ok := roleGrantEventTypes[stripSep(ev.Type)]; ok {
		return true
	}
	if _, ok := roleGrantActions[stripSep(ev.Action)]; ok {
		return true
	}
	return false
}

// ActorRoleGrantFrequency returns the finding actor's baseline frequency for
// role-grant event types, summed across the role-grant type keys. A frequency
// table key has the shape "<source>:<event_type>:<actor>" or "<source>:<event_type>"
// (the exam seeds the latter); we sum any key whose event_type segment is a
// role-grant type AND that references the actor. 0 means "no role-grant precedent".
func ActorRoleGrantFrequency(actor string, b *baseline.Baseline) int {
	if b == nil {
		return 0
	}
	al := strings.ToLower(strings.TrimSpace(actor))
	total := 0
	for key, v := range b.FrequencyTables {
		kl := strings.ToLower(key)
		if !strings.Contains(kl, al) {
			continue
		}
		parts := strings.Split(key, ":")
		if len(parts) < 2 {
			continue
		}
		if _, ok := roleGrantEventTypes[stripSep(parts[1])]; ok {
			total += v
		}
	}
	return total
}

// --- FIX 4 (OBSERVABLE FORCE-ESCALATE): unjustified bulk / PII export. ---------
//
// THE DEFECT THIS CLOSES (the regression veracity caught in b6b7fa8): the
// group-credit relationship predicate cannot distinguish URA-04 (benign sibling
// maintenance, admin owns the atom-rg group-level key count 156) from URA-03
// (compromised admin's first-ever 15,000-row pg_dump from atom-db-prod, SAME group
// key). The relationship is identical; the DISCRIMINATOR IS THE ACTION. A
// high-volume read / PII / secret export with NO legitimate-justification companion
// is a data-exfiltration indicator regardless of how established the actor's
// relationship is — so it is keyed on the ACTION the actor performed, never on the
// relationship and never on the detector family.

// bulkExportOpCountFloor is the operation_count above which a read/export is "bulk".
// Set below ND-01 (100/101) and IT-03 (312) so both trip, well above any benign
// per-event count in the corpus (CC-01/CC-02/VA-02/VA-05 carry NO operation_count
// at all — their high volume is implicit in the finding title, not a per-event
// field — so this floor cannot reach them even before the justification exclusion).
const bulkExportOpCountFloor = 50

// bulkExportRowsFloor is the rows_affected above which an export is "bulk". URA-03's
// pg_dump exports 15000 rows; set far below it and above incidental small reads.
const bulkExportRowsFloor = 1000

// bulkExportActions are the action / event-type signatures that ARE a bulk read or
// export on their own (separator-stripped, lower-cased), independent of any volume
// field — URA-03 export_data / pg_dump, ND-01 list_users / get_user_details,
// IT-03 list_resources. Compared after stripSep.
var bulkExportActions = map[string]struct{}{
	"exportdata":     {},
	"pgdump":         {},
	"dumpdata":       {},
	"bulkexport":     {},
	"bulkread":       {},
	"listusers":      {},
	"getuserdetails": {},
	"listresources":  {},
}

// justificationKeys are the legitimate-operation companion fields. ANY surfaced
// event in the finding carrying a non-empty (or true) value for one of these
// EXCLUDES the bulk-export floor: a scheduled batch / ticketed maintenance / release
// window is a coherent operational pattern, not an unexplained export. CC-01/VA-02/
// VA-05 carry job_id+schedule(+scheduled); CC-02 carries window_id (NOT job_id/
// schedule — verified, see the test) — so all four benign high-volume scenarios are
// excluded. The boolean-shaped flags (scheduled / post_deploy / includes_pii is NOT
// here — pii is a SIGNAL, not a justification) count only when their value is "true".
var justificationKeys = []string{
	"job_id",
	"ticket_id",
	"schedule",
	"scheduled",
	"maintenance_window",
	"window_id",
	"post_deploy",
}

// justificationBoolKeys are the justification fields whose presence counts ONLY when
// the value is truthy ("true"). A literal scheduled:"false" is not a justification.
var justificationBoolKeys = map[string]struct{}{
	"scheduled":   {},
	"post_deploy": {},
}

// BulkExportNoJustification (FIX 4) reports whether the surfaced events show a
// HIGH-VOLUME read / PII / secret export performed by the finding actor with NO
// legitimate-justification companion event. It is a TERMINAL escalate (the
// discriminator is the ACTION, model-independent): it restores URA-03's floor and
// catches ND-01 (2am PII export, no ticket) + IT-03 (bulk subscription sweep, no
// justification). It does NOT fire when a justification companion is present, so the
// benign high-volume scenarios (CC-01/CC-02/VA-02/VA-05) are excluded.
//
// The justification scan is over ALL surfaced events (not just the bulk event):
// CC-02's release_started companion carries window_id on a DIFFERENT event than the
// volume burst, and the doc's "no business justification" test is at the FINDING
// level — "is there ANY explanation in this finding's events". The bulk-signal scan
// is restricted to events AUTHORED BY the finding actor (the actor under
// investigation actually performed the export).
func BulkExportNoJustification(actor string, events []tools.EventView) (bool, string) {
	if actor == "" {
		return false, ""
	}
	// (1) A justification companion ANYWHERE in the finding's events excludes the
	// floor — a coherent scheduled/ticketed/release operation, not an unexplained
	// export. Checked first so a justified batch never escalates here.
	if eventsCarryJustification(events) {
		return false, ""
	}
	// (2) The finding actor performed a bulk read / PII / secret export.
	for _, ev := range events {
		if !strings.EqualFold(ev.Actor, actor) {
			continue
		}
		if sig, why := bulkExportSignal(ev); sig {
			return true, actor + " performed " + why + " with no legitimate-justification companion (no schedule/ticket/job/maintenance_window)"
		}
	}
	return false, ""
}

// eventsCarryJustification reports whether ANY event carries a non-empty
// legitimate-operation companion field (job_id / ticket_id / schedule /
// maintenance_window / window_id, or a truthy scheduled / post_deploy). The
// boolean-shaped flags count only when "true".
func eventsCarryJustification(events []tools.EventView) bool {
	for _, ev := range events {
		for _, k := range justificationKeys {
			v, ok := ev.Metadata[k]
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if _, isBool := justificationBoolKeys[k]; isBool {
				if !strings.EqualFold(v, "true") {
					continue
				}
			}
			return true
		}
	}
	return false
}

// bulkExportSignal reports whether ONE event is a high-volume read / PII / secret
// export, and a short human reason for the audit trail. Signalled by ANY of:
// operation_count >= floor, rows_affected >= floor, export_format present,
// includes_pii=true, or a bulk/dump/export action/type. Keyed on the EVENT, never on
// the detector family.
func bulkExportSignal(ev tools.EventView) (bool, string) {
	if v, ok := ev.Metadata["operation_count"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= bulkExportOpCountFloor {
			return true, "bulk read (operation_count=" + v + ")"
		}
	}
	if v, ok := ev.Metadata["rows_affected"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= bulkExportRowsFloor {
			return true, "bulk export (rows_affected=" + v + ")"
		}
	}
	if v, ok := ev.Metadata["export_format"]; ok && strings.TrimSpace(v) != "" {
		return true, "data export (export_format=" + v + ")"
	}
	if v, ok := ev.Metadata["includes_pii"]; ok && strings.EqualFold(strings.TrimSpace(v), "true") {
		return true, "PII export (includes_pii=true)"
	}
	if _, ok := bulkExportActions[stripSep(ev.Action)]; ok {
		return true, "bulk/export action (" + ev.Action + ")"
	}
	if _, ok := bulkExportActions[stripSep(ev.Type)]; ok {
		return true, "bulk/export event (" + ev.Type + ")"
	}
	return false, ""
}

// stripSep lower-cases and removes separators (-, _, space, .) so "role_assignment",
// "role-assignment", and "Role Assignment" all fold to "roleassignment". Shared
// helper used by isRoleGrantEvent / ActorRoleGrantFrequency and bulkExportSignal.
func stripSep(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch r {
		case '-', '_', ' ', '.':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
