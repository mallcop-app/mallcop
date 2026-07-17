// inquest.go — the RunAll orchestrator: per-escalated-finding idempotency
// check, budget gate, per-finding panic guard, and the record write.
package inquest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// defaultMaxPerScan is Config.MaxPerScan's fallback when unset/non-positive —
// mirrors core/config.Investigate's default (10).
const defaultMaxPerScan = 10

// defaultModelCallTimeout bounds EACH narrate call — the scan's core output
// can never be delayed past this per finding (failureSemantics §design). The
// actual bound is Config.CallTimeout when set; this is its fallback.
const defaultModelCallTimeout = 60 * time.Second

// Config is core/inquest's OWN copy of the investigate: config block.
// core/config cannot be imported here (see imports_test.go's closed
// allowlist — inquest reaches the model ONLY through the injected
// agent.Client, never a concrete config/transport dependency); the caller
// (core/pipeline, fed by cli/scan.go) maps core/config.Investigate onto this
// struct once per run.
type Config struct {
	// Enabled gates the WHOLE package: false means RunAll writes NO records at
	// all, not even evidence-only (see the off-switch semantics note on
	// StatusAbsentDisabled).
	Enabled bool
	// Model is the model id sent on the narrate request. "" lets the injected
	// agent.Client fall back to its own default (core/inference.DirectClient's
	// documented per-request-wins contract) — the "inherit the scan's resolved
	// model" semantic.
	Model string
	// MaxPerScan bounds the number of METERED narrate calls THIS scan may make
	// (new + degraded-refresh combined). <= 0 uses defaultMaxPerScan.
	MaxPerScan int
	// Retries is carried for schema completeness only. RunAll makes exactly
	// ONE call per finding regardless of this value — retry-until-pass is
	// structurally absent (the hard one-call contract); a failed/invalid reply
	// degrades the record instead of retrying within this scan.
	Retries int
	// NeighborWindow bounds section 2 (NEIGHBORS). <= 0 uses 1h.
	NeighborWindow time.Duration
	// MaxNeighbors caps the neighbor list. <= 0 uses 50.
	MaxNeighbors int
	// CorrelationWindow bounds section 5 (SCAN-SCHEDULE CORRELATION)'s
	// "correlated" gate. <= 0 uses 10m.
	CorrelationWindow time.Duration
	// MaxTokens bounds the narrate call's MaxTokens. <= 0 uses 1024.
	MaxTokens int
	// CallTimeout bounds EACH narrate call's context deadline. <= 0 uses
	// defaultModelCallTimeout (60s — the production default; see
	// failureSemantics §design). Exposed as a config knob (rather than a bare
	// constant) purely so a test can drive a hung-client scenario without a
	// real 60s wait — cli/scan.go leaves this unset in production.
	CallTimeout time.Duration
}

// EscalatedFinding pairs one finding with the cascade resolution that
// escalated it — the ONLY findings RunAll is ever given. A resolved-benign
// finding is never investigated.
type EscalatedFinding struct {
	Finding    finding.Finding
	Resolution ResolutionRef
}

// Input is RunAll's whole input.
type Input struct {
	// Store is the ALREADY-OPEN store this scan wrote findings/resolutions to.
	// Required.
	Store *store.Store
	// Client is the SAME inference seam the cascade used this scan. nil is
	// valid (the scan ran with no inference client configured) and produces
	// StatusAbsentNoClient evidence-only records — never a panic.
	Client agent.Client
	// Findings is this scan's escalated findings, order-independent (RunAll
	// sorts by finding ID for deterministic budget consumption).
	Findings []EscalatedFinding
	// AllEvents is the full known event history this scan gated detection on:
	// priorEvents ++ this scan's deduped batch. The caller (core/pipeline)
	// already holds both — zero extra I/O.
	AllEvents []event.Event
	// Baseline is the SAME baseline the scan gated detection on. nil is
	// treated as an empty baseline.
	Baseline *baseline.Baseline
	// MallcopVersion is a best-effort provenance stamp for the record. Empty
	// when unknown — never fabricated.
	MallcopVersion string
	// Config is the resolved investigate: settings for this run.
	Config Config
}

// Outcome is RunAll's result. RunAll NEVER returns an error the caller
// propagates — see the package doc.
type Outcome struct {
	// Investigated counts findings this run wrote (or refreshed) a record for
	// with NarrativeStatus "ok".
	Investigated int
	// Degraded counts findings this run wrote (or refreshed) a record for with
	// any NarrativeStatus OTHER than "ok" — the deterministic evidence still
	// shipped.
	Degraded int
	// Skipped counts findings whose existing record was already current + ok:
	// zero calls, zero writes. Not surfaced on pipeline.Summary; exists so a
	// caller/test can assert idempotency directly.
	Skipped int
	// Errors carries one human-readable line per degraded/failed record, for
	// the caller to print as a non-fatal warning. Never fails the scan.
	Errors []string
}

// RunAll investigates every finding in in.Findings, at most ONE metered model
// call per finding, budgeted at in.Config.MaxPerScan calls total THIS run,
// and commits a Record to investigations/<finding-id>.json per finding (see
// recordPath). It NEVER returns an error the caller must handle — every
// failure mode (nil store, model failure, panic, marshal error) degrades an
// INDIVIDUAL record; RunAll always returns a valid Outcome.
//
// Idempotency: a finding whose EXISTING record already has the current
// SchemaVersion and NarrativeStatus "ok" is skipped entirely — zero calls,
// zero store reads beyond the one existence check, zero writes. A finding
// whose record is absent, schema-stale, or degraded is (re-)investigated,
// preserving the original CreatedAt on a refresh.
func RunAll(ctx context.Context, in Input) Outcome {
	var out Outcome

	if !in.Config.Enabled {
		// Off-switch: no records at all, not even evidence-only.
		return out
	}
	if in.Store == nil {
		out.Errors = append(out.Errors, "inquest: nil store — skipped every finding")
		return out
	}
	if len(in.Findings) == 0 {
		return out
	}

	maxPerScan := in.Config.MaxPerScan
	if maxPerScan <= 0 {
		maxPerScan = defaultMaxPerScan
	}

	// Deterministic order: a re-run of the same scan budgets identically
	// regardless of upstream map/slice iteration order.
	findings := append([]EscalatedFinding(nil), in.Findings...)
	sort.Slice(findings, func(i, j int) bool { return findings[i].Finding.ID < findings[j].Finding.ID })

	callsUsed := 0
	for _, ef := range findings {
		investigated, degraded, skipped, errMsg := processOne(ctx, in, ef, maxPerScan, &callsUsed)
		out.Investigated += investigated
		out.Degraded += degraded
		out.Skipped += skipped
		if errMsg != "" {
			out.Errors = append(out.Errors, errMsg)
		}
	}
	return out
}

// processOne handles exactly one finding under a panic guard: any panic
// during evidence assembly, prompt building, or record write converts to a
// degraded record rather than propagating (crashing the scan).
func processOne(ctx context.Context, in Input, ef EscalatedFinding, maxPerScan int, callsUsed *int) (investigated, degraded, skipped int, errMsg string) {
	defer func() {
		if r := recover(); r != nil {
			errMsg = appendErr(errMsg, fmt.Sprintf("inquest: panic investigating %s: %v", ef.Finding.ID, r))
			// Best-effort: still write a minimal degraded record so the
			// operator sees SOMETHING rather than silence. A second panic here
			// (this only marshals/writes a small struct) is swallowed — it
			// must never escape and abort the scan.
			func() {
				defer func() { _ = recover() }()
				rec := minimalDegradedRecord(ef, in.MallcopVersion, StatusAbsentModelError)
				_, _ = writeRecord(in.Store, rec)
			}()
			degraded = 1
		}
	}()

	existing, found, rerr := readExistingRecord(in.Store, ef.Finding.ID)
	if rerr != nil {
		errMsg = appendErr(errMsg, fmt.Sprintf("inquest: read existing record for %s: %v", ef.Finding.ID, rerr))
	}
	if found && existing.SchemaVersion == SchemaVersion && existing.NarrativeStatus == StatusOK {
		return 0, 0, 1, errMsg
	}

	ev := assemble(in.Store, in.AllEvents, in.Baseline, ef, in.Config)

	rec := Record{
		SchemaVersion:  SchemaVersion,
		FindingID:      ef.Finding.ID,
		EventID:        underlyingEventID(ef.Finding.ID),
		MallcopVersion: in.MallcopVersion,
		CreatedAt:      nowRFC3339(),
		UpdatedAt:      nowRFC3339(),
		Role:           "evidence",
		Resolution:     ef.Resolution,
		Verdict:        VerdictUnassessed,
		Evidence:       ev,
	}
	if found {
		rec.CreatedAt = existing.CreatedAt // preserve on refresh
	}

	switch {
	case in.Client == nil:
		rec.NarrativeStatus = StatusAbsentNoClient
		degraded = 1
	case *callsUsed >= maxPerScan:
		rec.NarrativeStatus = StatusAbsentBudget
		degraded = 1
	default:
		userDoc, buildErr := buildUserMessage(ef.Finding, ef.Resolution, ev)
		if buildErr != nil {
			rec.NarrativeStatus = StatusAbsentInvalidOutput
			degraded = 1
			errMsg = appendErr(errMsg, fmt.Sprintf("inquest: build prompt for %s: %v", ef.Finding.ID, buildErr))
			break
		}
		*callsUsed++
		timeout := in.Config.CallTimeout
		if timeout <= 0 {
			timeout = defaultModelCallTimeout
		}
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		res := narrate(callCtx, in.Client, in.Config.Model, in.Config.MaxTokens, userDoc)
		cancel()

		rec.NarrativeStatus = res.Status
		rec.Model = res.Model
		rec.Usage = res.Usage
		if res.Status == StatusOK {
			rec.Verdict = res.Verdict
			rec.Confidence = res.Confidence
			rec.Narrative = res.Narrative
			investigated = 1
		} else {
			degraded = 1
			if res.Err != nil {
				errMsg = appendErr(errMsg, fmt.Sprintf("inquest: narrate %s: %v", ef.Finding.ID, res.Err))
			}
		}
	}

	if _, werr := writeRecord(in.Store, rec); werr != nil {
		errMsg = appendErr(errMsg, fmt.Sprintf("inquest: write record for %s: %v", ef.Finding.ID, werr))
	}
	return investigated, degraded, 0, errMsg
}

// recordPath is the store path a finding's investigation record lives at.
func recordPath(findingID string) string {
	return "investigations/" + findingID + ".json"
}

// readExistingRecord reads back the current record for findingID, if any.
func readExistingRecord(st *store.Store, findingID string) (Record, bool, error) {
	data, err := st.ReadSnapshot(recordPath(findingID))
	if err != nil {
		return Record{}, false, err
	}
	if len(data) == 0 {
		return Record{}, false, nil
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}

// writeRecord applies the record size cap and commits rec via WriteSnapshot
// (a full-document replace, CAS-retried, byte-identical no-op — a refresh
// that changes nothing costs no commit).
func writeRecord(st *store.Store, rec Record) (string, error) {
	rec, _, err := enforceRecordSizeCap(rec)
	if err != nil {
		return "", err
	}
	return st.WriteSnapshot(recordPath(rec.FindingID), rec)
}

// minimalDegradedRecord builds the smallest valid Record for the panic-guard
// fallback write: no evidence (assembly itself may be what panicked), an
// honest degraded status.
func minimalDegradedRecord(ef EscalatedFinding, mallcopVersion string, status NarrativeStatus) Record {
	now := nowRFC3339()
	return Record{
		SchemaVersion:   SchemaVersion,
		FindingID:       ef.Finding.ID,
		EventID:         underlyingEventID(ef.Finding.ID),
		MallcopVersion:  mallcopVersion,
		CreatedAt:       now,
		UpdatedAt:       now,
		Role:            "evidence",
		Resolution:      ef.Resolution,
		Verdict:         VerdictUnassessed,
		NarrativeStatus: status,
	}
}

// underlyingEventID is a BEST-EFFORT provenance stamp only — identity
// assembly resolves the real underlying event via tools.GetRawEvent (which
// applies the full "finding-" leniency itself); this is not used for any
// lookup. Finding ids are "finding-"+event.ID, optionally with a
// "-"+createdEntity suffix (core/detect/new_actor.go) — stripping only the
// "finding-" prefix is exact for the common case and a documented
// approximation for the suffixed one.
func underlyingEventID(findingID string) string {
	return strings.TrimPrefix(findingID, "finding-")
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// appendErr chains a new message onto an existing one (used when BOTH the
// existing-record read AND the processing step produce a warning for the same
// finding), separated by "; ".
func appendErr(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}
