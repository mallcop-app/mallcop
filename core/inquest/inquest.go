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
	// OwnedEntities is the operator's configured owned accounts/roles/relays
	// (mallcoppro-995, mirrors core/config.Org.Owned — cli/scan.go maps that
	// onto this field once per run), fed to section 6 (ORG CONTEXT) so a
	// recurring, baseline-known, owned-account actor resolves with its
	// relationship named instead of narrating as an unknown external actor.
	// nil is the safe absent default — no evidence is ever marked owned.
	OwnedEntities []OwnedEntity
}

// OwnedEntity is core/inquest's OWN copy of core/config.OwnedEntity (same
// closed-allowlist reason as Config's doc comment above — core/config cannot
// be imported here). Match is substring-matched against a finding's
// caller/target/actor identity fields; Name/Relationship are the
// plain-language labels the narrate prompt is instructed to use.
type OwnedEntity struct {
	Match        string
	Name         string
	Relationship string
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
	// shipped. ALSO counts a finding skipped after a transient error reading
	// its existing record (readExistingRecord's error path in processOne) —
	// that case writes NO record at all (protecting budget and CreatedAt);
	// it is still tallied here so the operator sees it rather than silence.
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
// recordPath). It NEVER returns an error the caller must handle, AND IT NEVER
// PANICS OUT — every failure mode (nil store, model failure, panic, marshal
// error) degrades an INDIVIDUAL record via processOne's own per-finding
// guard; a panic anywhere else in RunAll's OWN body (the deterministic-order
// setup below, or any future code added to this function) is caught by the
// top-level defer/recover immediately below and converted into the Outcome
// accumulated so far plus a warning line, never propagated into the caller
// (core/pipeline.Run — see pipeline.go's RunAll call site doc). This makes
// failureSemantics' "the whole inquest step is panic-guarded" claim literally
// true: there is no code path in this package that can crash the scan.
//
// Idempotency: a finding whose EXISTING record already has the current
// SchemaVersion and NarrativeStatus "ok" is skipped entirely — zero calls,
// zero store reads beyond the one existence check, zero writes. A finding
// whose record is absent, schema-stale, or degraded is (re-)investigated,
// preserving the original CreatedAt on a refresh.
func RunAll(ctx context.Context, in Input) (out Outcome) {
	defer func() {
		if r := recover(); r != nil {
			out.Errors = append(out.Errors, fmt.Sprintf(
				"inquest: panic in RunAll outside any single finding's guard: %v — returning the %d investigated/%d degraded/%d skipped accumulated before the panic",
				r, out.Investigated, out.Degraded, out.Skipped))
		}
	}()

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

	if runAllPanicHookForTest != nil {
		runAllPanicHookForTest()
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

// runAllPanicHookForTest, when non-nil, is invoked exactly once per RunAll
// call, immediately after setup (maxPerScan resolution) and BEFORE the
// sort/slice-copy step — the only seam a test can use to force a panic in
// RunAll's OWN body (as opposed to inside one finding's processOne, which
// panickingClient already covers) and prove the top-level defer/recover above
// actually catches it. Always nil in production.
var runAllPanicHookForTest func()

// processOne handles exactly one finding under a panic guard: any panic
// during evidence assembly, prompt building, or record write converts to a
// degraded record rather than propagating (crashing the scan). modelCallAttempted
// tracks whether the panic happened during/after the actual model call (an
// honest StatusAbsentModelError) or strictly BEFORE it — evidence assembly,
// prompt building — which is inquest's OWN bug and must never be mislabeled
// as a model failure (StatusAbsentInternalError instead; review finding 3a).
// priorCreatedAt/havePriorCreatedAt are captured from the pre-panic
// existing-record read (below) so the panic-guard fallback record preserves a
// known CreatedAt rather than resetting it to now() (review finding 3b).
func processOne(ctx context.Context, in Input, ef EscalatedFinding, maxPerScan int, callsUsed *int) (investigated, degraded, skipped int, errMsg string) {
	var modelCallAttempted bool
	var priorCreatedAt string
	var havePriorCreatedAt bool

	defer func() {
		if r := recover(); r != nil {
			errMsg = appendErr(errMsg, fmt.Sprintf("inquest: panic investigating %s: %v", ef.Finding.ID, r))
			status := StatusAbsentInternalError
			if modelCallAttempted {
				status = StatusAbsentModelError
			}
			// Best-effort: still write a minimal degraded record so the
			// operator sees SOMETHING rather than silence. A second panic here
			// (this only marshals/writes a small struct) is swallowed — it
			// must never escape and abort the scan.
			func() {
				defer func() { _ = recover() }()
				rec := minimalDegradedRecord(ef, in.MallcopVersion, status)
				if havePriorCreatedAt {
					rec.CreatedAt = priorCreatedAt
				}
				_, _ = writeRecord(in.Store, rec)
			}()
			degraded = 1
		}
	}()

	existing, found, rerr := readExistingRecord(in.Store, ef.Finding.ID)
	if rerr != nil {
		// Transient read error (e.g. a git-pull/read hiccup) — existing may
		// hold a perfectly good record we simply can't verify right now.
		// SKIP this finding for THIS scan entirely: no assembly, no metered
		// call, no write. Burning a call and resetting CreatedAt on a finding
		// that may already have a good record would be worse than doing
		// nothing; the next scan retries the read. Never invent a success.
		return 0, 1, 0, appendErr(errMsg, fmt.Sprintf("inquest: read existing record for %s: %v — skipped this scan (no call, no write) to protect budget and CreatedAt", ef.Finding.ID, rerr))
	}
	if found {
		priorCreatedAt = existing.CreatedAt
		havePriorCreatedAt = true
	}
	if found && existing.SchemaVersion == SchemaVersion && existing.NarrativeStatus == StatusOK {
		return 0, 0, 1, errMsg
	}

	if processOnePanicHookForTest != nil {
		processOnePanicHookForTest(ef.Finding.ID)
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
		modelCallAttempted = true // from here on, a panic is an honest model-error, not inquest's own bug
		res := narrate(callCtx, in.Client, in.Config.Model, in.Config.MaxTokens, userDoc, ev)
		cancel()

		rec.NarrativeStatus = res.Status
		rec.Model = res.Model
		rec.Usage = res.Usage
		if res.Status == StatusOK {
			rec.Verdict = res.Verdict
			rec.Confidence = res.Confidence
			rec.Narrative = res.Narrative
			rec.ContractNotes = res.ContractNotes
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

// processOnePanicHookForTest, when non-nil, is invoked once per finding
// immediately BEFORE evidence assembly (strictly before any model call could
// ever be attempted) — the seam a test uses to force an assembly-time panic
// and prove it gets the honest StatusAbsentInternalError label (never
// StatusAbsentModelError) and preserves a known prior CreatedAt. Always nil
// in production.
var processOnePanicHookForTest func(findingID string)

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
// honest degraded status (StatusAbsentInternalError for a panic before the
// model call was attempted, StatusAbsentModelError for one during/after —
// see processOne's modelCallAttempted). CreatedAt defaults to now() here
// (the "brand new record" case); the caller overwrites it with a known prior
// CreatedAt when processOne captured one before the panic, so a refresh never
// silently resets it.
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
