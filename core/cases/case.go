// Package cases COLLAPSES recurring escalated findings — the SAME (finding
// type, actor, primary entity) recurring across scans — into one durable Case
// object per cluster, projected to store/cases.json (mallcoppro-554).
//
// CONSENSUS INVARIANT (structural, not policy): this package NEVER decides
// whether a finding escalates. Collapse's only input, Escalation, carries no
// Action/Reason/Confidence field to act on — it is structurally incapable of
// computing or overriding a disposition, only projecting an occurrence the
// committee ALREADY escalated (core/agent's any-escalate-wins consensus gate)
// into a cluster. There is no write path from this package back into
// findings/resolutions/directives, and nothing here reads a Case's Count or
// CadenceSecs to short-circuit a future decision — a future change that lets
// recurrence count auto-escalate without a model call would reintroduce
// exactly the forbidden family-match-bypasses-consensus pattern this package
// is built to avoid.
//
// core/cases is PURE: no store, no CLI, no time.Now() (Collapse takes every
// timestamp as an argument) — Collapse is a deterministic function of its
// inputs, so re-running it over identical input reproduces byte-identical
// JSON, the property store.Store.WriteSnapshot's no-op check depends on.
package cases

import "time"

// SchemaVersion is the current cases.json record schema version. Bump ONLY on
// a breaking change; readers tolerate unknown fields.
const SchemaVersion = 1

// Key clusters escalated findings: the same (Type, Actor, Entity) triple is
// one recurring case, regardless of which scan or which individual finding ID
// produced each occurrence.
type Key struct {
	Type   string `json:"type"`
	Actor  string `json:"actor"`
	Entity string `json:"entity"`
}

// Case is one cluster's durable, cross-scan projection: how many times this
// (type, actor, entity) has recurred, at what cadence, and which findings
// contributed. Collapse only ever moves a Case from "open" to "recurring" —
// it never closes or ages one out (that lifecycle is explicitly OUT of scope
// for this item; see mallcoppro-48d/aa7/309/86d/42e/a51).
type Case struct {
	SchemaVersion int       `json:"schema_version"`
	CaseID        string    `json:"case_id"`
	Key           Key       `json:"key"`
	Status        string    `json:"status"` // "open" | "recurring"
	Severity      string    `json:"severity"`
	Count         int       `json:"count"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	// CadenceSecs is the median inter-arrival time, in seconds, over the last
	// (up to) 20 contributing findings with a resolvable timestamp. 0 when
	// fewer than 2 timestamps resolved. Meaningless (near-zero or huge) when
	// contributing findings carry a zero-value Timestamp — a fixture/connector
	// that omits an event's timestamp will not produce a trustworthy cadence.
	CadenceSecs float64  `json:"cadence_secs,omitempty"`
	FindingIDs  []string `json:"finding_ids"`
}
