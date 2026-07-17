// Package inquest is detection-time investigation (mallcoppro-e3c): after a
// scan ESCALATES a finding, RunAll assembles a deterministic evidence chain
// (identity, neighbor events, recurrence cadence, baseline known-ness, and
// scan-schedule correlation — assemble.go, pure Go, no model) and makes ONE
// metered narrate call (narrate.go) to produce an operator-facing narrative,
// then commits the whole thing to investigations/<finding-id>.json in the
// store (record.go's Record).
//
// CONSENSUS INVARIANT (structural, not policy): this package is called by
// core/pipeline strictly AFTER the resolutions stream is durably committed
// (see core/pipeline.Run's step 5). It holds no write path to
// findings/resolutions/directives or the findings.json snapshot — every
// Record carries role:"evidence" in-band, and Verdict/Confidence here are the
// INVESTIGATOR's own assessment, never the committee's disposition (owned by
// core/agent's consensus gate). No investigation outcome — including "benign,
// high confidence" — ever downgrades, suppresses, or re-resolves an
// escalation. This is enforced structurally: nothing in this package's public
// surface writes to any of those streams, and imports_test.go bans the only
// package (core/agent's ResolveFindingWith) that could reach the cascade.
//
// FAILURE SEMANTICS: RunAll NEVER returns an error the caller propagates — a
// bug, a model failure, or a store I/O error here degrades ONE record
// (narrative_status != "ok", the deterministic evidence still ships); it never
// aborts, delays past its own 60s-per-call budget, or loses the scan's core
// output. See inquest.go's package-level RunAll doc for the full contract.
package inquest

import (
	"encoding/json"
)

// SchemaVersion is the current investigations/<finding-id>.json schema
// version. Bump ONLY on a breaking change; readers tolerate unknown fields. A
// record found with an OLDER schema version is treated as refresh-eligible
// (see inquest.go's idempotency check), never as a fatal read error.
const SchemaVersion = 1

// Verdict is the INVESTIGATOR's own assessment — NOT the cascade committee's
// disposition (core/agent's consensus gate owns that, mallcoppro-09a). Record
// carries role:"evidence" precisely so this distinction survives on disk.
type Verdict string

const (
	VerdictBenign     Verdict = "benign"
	VerdictSuspicious Verdict = "suspicious"
	VerdictThreat     Verdict = "threat"
	// VerdictUnassessed is the record's verdict whenever NarrativeStatus is
	// anything other than "ok" — the deterministic evidence still shipped, but
	// nothing (model or otherwise) assessed it.
	VerdictUnassessed Verdict = "unassessed"
)

// NarrativeStatus enumerates why (or whether) Narrative/Verdict/Confidence are
// populated. "ok" is the only status where the model's verdict is trusted.
// Every other status means the DETERMINISTIC evidence chain still shipped —
// only the narrative degraded.
type NarrativeStatus string

const (
	StatusOK NarrativeStatus = "ok"
	// StatusAbsentModelError covers a transport error, a non-2xx response, a
	// context-deadline, a panic INSIDE the model call itself (after processOne
	// has actually attempted it — see StatusAbsentInternalError for a panic
	// anywhere else), or any other failure BEFORE a reply was parsed.
	StatusAbsentModelError NarrativeStatus = "absent-model-error"
	// StatusAbsentInternalError covers a panic in processOne's OWN code BEFORE
	// any model call was attempted — evidence assembly, prompt building, or
	// (on the no-client/budget branches, where no call is ever attempted) the
	// record write itself. Distinct from StatusAbsentModelError so an inquest
	// bug is never mislabeled as a model/transport failure (mallcoppro-e3c
	// review finding 3).
	StatusAbsentInternalError NarrativeStatus = "absent-internal-error"
	// StatusAbsentInvalidOutput covers a reply that came back but failed the
	// deterministic validation matrix (bad enum, out-of-range confidence,
	// empty/oversized narrative, unparseable JSON).
	StatusAbsentInvalidOutput NarrativeStatus = "absent-invalid-output"
	// StatusAbsentBudget means the per-scan call budget (Config.MaxPerScan) was
	// already exhausted by earlier findings THIS scan — the finding still gets
	// a full evidence-only record, just no model call.
	StatusAbsentBudget NarrativeStatus = "absent-budget"
	// StatusAbsentNoClient means Input.Client was nil — no inference endpoint
	// configured for this scan at all.
	StatusAbsentNoClient NarrativeStatus = "absent-no-client"
	// StatusAbsentDisabled is a DOCUMENTED, structurally-unreachable status: per
	// the config off-switch semantics, a disabled investigate: config writes NO
	// records at all (not even evidence-only), so no record is ever written
	// carrying this value retroactively. Kept in the enum for schema
	// completeness/forward-compat only.
	StatusAbsentDisabled NarrativeStatus = "absent-disabled"
)

// maxRecordBytes is the hard marshal-time cap on one Record's committed JSON
// (the SAME encoding WriteSnapshot uses — see enforceRecordSizeCap). When
// over cap, the neighbor tail is dropped first, then the recurrence prior
// lists — NEVER identity, verdict, confidence, or narrative.
const maxRecordBytes = 96 * 1024

// maxNarrativeBytes bounds Narrative — the modelCall validation matrix rejects
// (as absent-invalid-output) any reply whose narrative exceeds this.
const maxNarrativeBytes = 4096

// ResolutionRef is the cascade's disposition for the finding this record
// investigates, carried for context — NEVER re-derived or re-decided here.
type ResolutionRef struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// Usage carries token accounting for the one narrate call, when the injected
// agent.Client's response surfaces it. The current core/agent.MessagesResponse
// contract carries no usage field, so this is {0,0} today — populated
// wholesale, never estimated/fabricated, the moment that contract gains one.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Record is the full investigations/<finding-id>.json document — see the
// package doc for the consensus-invariant discussion of Role/Verdict.
type Record struct {
	SchemaVersion  int    `json:"schema_version"`
	FindingID      string `json:"finding_id"`
	EventID        string `json:"event_id"`
	MallcopVersion string `json:"mallcop_version"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	// Role is hard-coded "evidence" — it documents the consensus invariant
	// in-band, on every record, for any consumer that reads the file directly.
	Role       string        `json:"role"`
	Resolution ResolutionRef `json:"resolution"`
	// Verdict/Confidence are the INVESTIGATOR's own assessment — see the
	// package doc. VerdictUnassessed/0 whenever NarrativeStatus != "ok".
	Verdict         Verdict         `json:"verdict"`
	Confidence      float64         `json:"confidence"`
	Narrative       string          `json:"narrative"`
	NarrativeStatus NarrativeStatus `json:"narrative_status"`
	Model           string          `json:"model"`
	Usage           Usage           `json:"usage"`
	Evidence        Evidence        `json:"evidence"`
}

// marshalRecordForSize renders rec with the EXACT encoding
// store.Store.WriteSnapshot uses internally (json.MarshalIndent with a 2-space
// indent) — the size cap must be enforced against the bytes that actually get
// committed, not a smaller compact encoding that would then grow past the cap
// again once WriteSnapshot re-marshals it.
func marshalRecordForSize(rec Record) ([]byte, error) {
	return json.MarshalIndent(rec, "", "  ")
}

// enforceRecordSizeCap returns rec (possibly trimmed) and its committed-form
// bytes, guaranteed at-or-under maxRecordBytes whenever the trimmable fields
// can reach it. Trim order is fixed and NEVER touches identity, verdict,
// confidence, or narrative — only evidence.neighbors.events (dropped from the
// tail — already sorted nearest-first, so the LEAST relevant neighbors go
// first), then evidence.recurrence.prior_investigations, then
// evidence.recurrence.prior_finding_ids, each trimmed independently.
//
// Each trimmable list is reduced via BISECTION (the longest fitting prefix,
// found by binary search over candidate lengths) rather than a one-at-a-time
// loop: production lists are already small (neighbors capped at 50, priors at
// 20) so either approach is instant there, but bisection keeps this function
// O(log n) marshals even against a pathological input, instead of O(n).
func enforceRecordSizeCap(rec Record) (Record, []byte, error) {
	b, err := marshalRecordForSize(rec)
	if err != nil {
		return rec, nil, err
	}
	if len(b) <= maxRecordBytes {
		return rec, b, nil
	}

	rec, b, ok, err := trimSliceLenToFit(rec, len(rec.Evidence.Neighbors.Events),
		func(r Record, n int) Record { r.Evidence.Neighbors.Events = r.Evidence.Neighbors.Events[:n]; return r })
	if err != nil {
		return rec, nil, err
	}
	if ok {
		return rec, b, nil
	}

	rec, b, ok, err = trimSliceLenToFit(rec, len(rec.Evidence.Recurrence.PriorInvestigations),
		func(r Record, n int) Record {
			r.Evidence.Recurrence.PriorInvestigations = r.Evidence.Recurrence.PriorInvestigations[:n]
			return r
		})
	if err != nil {
		return rec, nil, err
	}
	if ok {
		return rec, b, nil
	}

	rec, b, ok, err = trimSliceLenToFit(rec, len(rec.Evidence.Recurrence.PriorFindingIDs),
		func(r Record, n int) Record {
			r.Evidence.Recurrence.PriorFindingIDs = r.Evidence.Recurrence.PriorFindingIDs[:n]
			return r
		})
	if err != nil {
		return rec, nil, err
	}

	// Best effort: every trimmable list is now empty (ok may still be false).
	// identity/verdict/narrative are bounded by construction (narrative <=
	// maxNarrativeBytes, identity is a handful of scalars) so this should not
	// be reachable in practice; return whatever we have rather than fail the
	// write.
	return rec, b, nil
}

// trimSliceLenToFit binary-searches the largest prefix length n in [0, full]
// such that applying set(rec, n) marshals to at-or-under maxRecordBytes,
// applies it, and returns the resulting record, its marshaled bytes, whether
// it now fits, and any marshal error encountered along the way. n == 0 is
// always tried first (a fully-empty slice is the smallest this trim can make
// the record); if even that does not fit, rec is returned with the slice
// emptied and ok == false, so the caller proceeds to the next trimmable
// field.
func trimSliceLenToFit(rec Record, full int, set func(Record, int) Record) (Record, []byte, bool, error) {
	tryLen := func(n int) (Record, []byte, error) {
		trial := set(rec, n)
		b, err := marshalRecordForSize(trial)
		return trial, b, err
	}

	zeroRec, zeroBytes, err := tryLen(0)
	if err != nil {
		return rec, nil, false, err
	}
	if len(zeroBytes) > maxRecordBytes {
		// Even empty doesn't fit — leave the slice emptied and let the caller
		// move on to the next trimmable field.
		return zeroRec, zeroBytes, false, nil
	}

	lo, hi := 0, full
	bestRec, bestBytes := zeroRec, zeroBytes
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		trial, b, err := tryLen(mid)
		if err != nil {
			return rec, nil, false, err
		}
		if len(b) <= maxRecordBytes {
			lo = mid
			bestRec, bestBytes = trial, b
		} else {
			hi = mid - 1
		}
	}
	return bestRec, bestBytes, true, nil
}
