package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mallcop-app/mallcop/core/collect"
	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
)

// CollectSchemaVersion is the collect-envelope wire-format version. It is the
// STABLE PROCESS BOUNDARY between mallcop (this repo) and the mallcop-pro
// proposer: mallcop-pro must NOT import mallcop (separate Go modules), so it
// consumes the collectors as JSON over `mallcop collect --json` and duplicates
// the MappingGap / GapCandidate structs on its side. Bump this on any
// backwards-incompatible change to the envelope shape, exactly as
// selfgate.GateSchemaVersion versions the validate-proposal wire format.
const CollectSchemaVersion = 1

// collectReport is the single versioned JSON envelope `mallcop collect --json`
// emits. It carries the two offline collector outputs verbatim (they are
// already json-taggable, module-boundary-stable data structs). The proposer
// decodes this shape; mapping_gaps / gap_candidates are always non-null arrays
// so the consumer never has to special-case a JSON null.
type collectReport struct {
	SchemaVersion int                    `json:"schema_version"`
	MappingGaps   []collect.MappingGap   `json:"mapping_gaps"`
	GapCandidates []collect.GapCandidate `json:"gap_candidates"`
}

// runCollect implements `mallcop collect`: run the OFFLINE, DETERMINISTIC
// feedstock collectors (core/collect) over a completed scan's store and emit
// the coverage gaps as a single versioned JSON envelope. It is a pure read of
// the store — NO inference, NO network, NO spend — and is the stable
// process-boundary the mallcop-pro proposer consumes to build add-only
// coverage proposals.
//
// Two collector outputs cross the boundary:
//
//	mapping_gaps    — collect.UnmappedActions(st): raw source actions that fell
//	                  through to a connector's "<source>_other" default bucket,
//	                  ranked by frequency, each carrying the closed
//	                  SuggestedVocabulary (detect.KnownEventTypes) the proposer
//	                  may map onto.
//	gap_candidates  — collect.DetectorGaps(st, rows): detection gaps. WITHOUT
//	                  --fidelity this yields the STORE-PURE kinds only
//	                  (override_fp + dissent). The detect_miss kind is a real
//	                  false-negative derived from exam-detect fidelity rows,
//	                  which the store cannot produce on its own — supply it via
//	                  --fidelity (see below).
//
// The detect_miss fidelity dependency (D1): `mallcop exam-detect --json` emits
// an ExamDetectReport (must_fire / must_not_fire rows), NOT the
// []eval.DetectFidelityRow that DetectorGaps needs (keyed on the scenario's
// expected chain_action). DetectFidelityRow is an exam-CORPUS artifact — the
// per-scenario detect-fidelity report produced by the e2e eval mode — not
// something derivable from a customer store. So `mallcop collect` scopes to the
// store-pure gaps by default, and detect_miss coverage is OPT-IN: pass
// --fidelity <json> pointing at a JSON array of []eval.DetectFidelityRow (the
// `rows` block of a detect-fidelity dump). Absent the flag, detect_miss gaps
// are simply not surfaced — they are not silently faked.
//
// Exit codes mirror `scan` / `detect` / `status`:
//
//	0  Collected (gaps may be present — collect reports, it does not gate)
//	2  Failure (missing/unreadable store, bad --fidelity file)
func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	storePath := fs.String("store", "", "Path to the git-repo store written by `mallcop scan` (required)")
	fidelityPath := fs.String("fidelity", "", "Optional JSON file: an array of eval.DetectFidelityRow (the `rows` of an exam-detect fidelity dump) — enables the detect_miss gap kind the store cannot produce")
	jsonOut := fs.Bool("json", false, "Emit the versioned JSON envelope (schema_version, mapping_gaps, gap_candidates)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *storePath == "" {
		return fmt.Errorf("collect: --store is required (the git-repo path written by `mallcop scan`)")
	}

	// Fail-loud on a missing store / non-git path (exit 2): store.Open rejects a
	// path that is not a git repository. A store that opens but has no records is
	// NOT an error — it yields an empty envelope (no gaps), which is legitimate
	// signal for the proposer.
	st, err := store.Open(*storePath)
	if err != nil {
		return fmt.Errorf("collect: open store %q: %w", *storePath, err)
	}

	mappingGaps, err := collect.UnmappedActions(st)
	if err != nil {
		return fmt.Errorf("collect: unmapped actions: %w", err)
	}

	// The detect_miss kind is opt-in via --fidelity. Without it, DetectorGaps(st,
	// nil) yields the store-pure override_fp + dissent kinds only.
	var rows []eval.DetectFidelityRow
	if *fidelityPath != "" {
		raw, err := os.ReadFile(*fidelityPath)
		if err != nil {
			return fmt.Errorf("collect: read fidelity file %q: %w", *fidelityPath, err)
		}
		if err := json.Unmarshal(raw, &rows); err != nil {
			return fmt.Errorf("collect: decode fidelity file %q as []eval.DetectFidelityRow: %w", *fidelityPath, err)
		}
	}

	gapCandidates, err := collect.DetectorGaps(st, rows)
	if err != nil {
		return fmt.Errorf("collect: detector gaps: %w", err)
	}

	// Coerce nil slices to empty so the envelope's arrays are never JSON null —
	// the proposer decodes a stable [] contract. UnmappedActions already returns
	// a non-nil slice; DetectorGaps may return nil when there are no gaps.
	if mappingGaps == nil {
		mappingGaps = []collect.MappingGap{}
	}
	if gapCandidates == nil {
		gapCandidates = []collect.GapCandidate{}
	}

	report := collectReport{
		SchemaVersion: CollectSchemaVersion,
		MappingGaps:   mappingGaps,
		GapCandidates: gapCandidates,
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("collect: encode envelope: %w", err)
		}
		return nil
	}

	printCollectReport(*storePath, report)
	return nil
}

// printCollectReport renders the human-readable summary (non-JSON mode).
func printCollectReport(storePath string, r collectReport) {
	fmt.Printf("Store:          %s\n", storePath)
	fmt.Printf("Mapping gaps:   %d\n", len(r.MappingGaps))
	for _, g := range r.MappingGaps {
		action := g.RawAction
		if action == "" {
			action = "(unknown)"
		}
		fmt.Printf("  %4dx %s/%s\n", g.Count, g.Source, action)
	}
	fmt.Printf("Gap candidates: %d\n", len(r.GapCandidates))
	for _, g := range r.GapCandidates {
		fmt.Printf("  %-11s %s %s %s\n", g.Kind, g.Source, g.DetectorFamily, g.Severity)
	}
}
