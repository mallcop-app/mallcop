// customerexam.go — the CUSTOMER-TREE exam-detect mode (mallcoppro-cc3e).
//
// ValidateProposal's stage 3 (runTreeExam in validate.go) grades an authored
// detector that lives in THIS repo's own core/detect/authored/ tree: it is
// compiled straight into the proposal tree's own cmd/mallcop binary, an
// in-process build. With WASM sidecar delivery (merged: detecthost/,
// pkg/detectorhost, cli/sidecars.go — mallcoppro-f70 / PR #142), a detector
// need not live in this repo's tree at all, or be compiled into cmd/mallcop —
// it can be authored anywhere, built standalone to a wasip1 .wasm module, and
// deployed as a sidecar the STATIC mallcop core discovers at runtime. The
// self-extension gate must be able to grade THAT shape too: a detector
// submitted from a customer-shaped repo (its own source tree, possibly its own
// go.mod, never imported by cmd/mallcop's own package graph).
//
// EVAL-GATE GROUND-TRUTH INVARIANT (ruled mallcoppro-2fd): the gate must
// exercise the artifact that actually deploys — the compiled .wasm running
// inside the REAL detecthost/wazero host — never the detector linked
// in-process. RunCustomerTreeExam holds this the same way runTreeExam holds it
// for the in-tree lane: by staying on the SUBPROCESS side of the JSON seam.
// core/selfgate is $0-pure and does not import core/eval, detecthost, or
// core/detect (TestSelfgateImportsNoInferenceOrCommittee enforces this) — so
// this package has no in-process shortcut available even if someone wanted
// one. Grading happens by execing examRepoTree's OWN `mallcop` binary with
// `exam-detect --json --sidecar-src <detectorSrcDir>`; that flag (cli/
// examdetect.go + cli/sidecars.go's buildAndRegisterSourceSidecar) is what
// actually builds detectorSrcDir under GOOS=wasip1 GOARCH=wasm and loads the
// resulting module through detecthost.NewRuntime/Load before RunExamDetect
// runs core/detect (which now includes the sidecar) over the pinned corpus.
//
// Unlike ValidateProposal's stage 3, there is no base tree to diff against
// here — a customer detector proposal is graded PASS/FAIL against the corpus
// directly (does it prove itself: it fires where labeled, stays silent where
// labeled not to), not as a monotonic widen over a sibling base report. Callers
// that need the widen contract (no regression / coverage +1 / no new firings)
// get it for free once a customer detector is promoted into this repo's own
// authored tree and validated the ordinary way through ValidateProposal.
package selfgate

import "fmt"

// CustomerExamRow mirrors examRow (see validate.go) as an EXPORTED type: the
// wire shape mallcop-pro (or any other out-of-package caller) can consume.
// examRow itself stays unexported/package-private — it is the JSON shape
// `mallcop exam-detect --json` emits, decoded locally so selfgate never
// imports core/eval (see validate.go's package doc); CustomerExamRow is the
// public-facing copy of exactly the same fields for THIS entry point's result.
type CustomerExamRow struct {
	// ScenarioID is the scenario's YAML id.
	ScenarioID string `json:"scenario_id"`
	// MustFire lists the detector family tokens that must appear among the
	// emitted findings' families (normalized lowercase).
	MustFire []string `json:"must_fire"`
	// MustNotFire lists the detector family tokens that must be absent.
	MustNotFire []string `json:"must_not_fire"`
	// Emitted lists the family token of every finding detect emitted for this
	// scenario, in emission order (duplicates preserved).
	Emitted []string `json:"emitted"`
	// Pass is true when every must_fire family is present and every
	// must_not_fire family is absent.
	Pass bool `json:"pass"`
}

// CustomerExamTotals aggregates a CustomerExamReport run.
type CustomerExamTotals struct {
	Labeled   int `json:"labeled"`
	Unlabeled int `json:"unlabeled"`
	Passed    int `json:"passed"`
	Failed    int `json:"failed"`
}

// CustomerExamReport is the full grading result for one customer-tree
// detector: one row per labeled corpus scenario plus totals. There is no
// base/head diff here (see the package doc) — Passed/Failed is the PASS/FAIL
// grade against the corpus directly.
type CustomerExamReport struct {
	Rows   []CustomerExamRow  `json:"rows"`
	Totals CustomerExamTotals `json:"totals"`
}

// RunCustomerTreeExam grades a CUSTOMER-authored detector: Go source living at
// detectorSrcDir — a standalone package anywhere on disk (a customer's own
// separate repo/module, or any directory outside examRepoTree's own
// core/detect/authored/ tree) implementing core/detect.Detector via
// github.com/mallcop-app/mallcop/pkg/detectorhost — against examRepoTree's
// OWN pinned exam corpus (exams/scenarios under examRepoTree).
//
// See the package doc for the ground-truth invariant this preserves: grading
// happens by building detectorSrcDir to a wasip1 .wasm module and running it
// through the REAL detecthost/wazero host inside examRepoTree's own
// `mallcop exam-detect --json --sidecar-src` subprocess — the exact artifact
// and host a real deployment uses, never an in-process Go link.
//
// The error return is OPERATIONAL only (detectorSrcDir does not build, the
// corpus in examRepoTree cannot be resolved, the subprocess hangs past its
// wall-clock bound, ...) — a detector that builds and runs but fails some
// labeled scenarios is a normal CustomerExamReport with Totals.Failed > 0, not
// an error.
func RunCustomerTreeExam(examRepoTree, detectorSrcDir string) (CustomerExamReport, error) {
	report, detail, err := runTreeExamWithSidecarSrc(examRepoTree, detectorSrcDir)
	if err != nil {
		if detail != "" {
			return CustomerExamReport{}, fmt.Errorf("selfgate: customer-tree exam-detect (detector src %s): %w (%s)", detectorSrcDir, err, detail)
		}
		return CustomerExamReport{}, fmt.Errorf("selfgate: customer-tree exam-detect (detector src %s): %w", detectorSrcDir, err)
	}
	return toCustomerExamReport(report), nil
}

// toCustomerExamReport copies the package-private examReport wire shape into
// the exported CustomerExamReport this entry point returns.
func toCustomerExamReport(r examReport) CustomerExamReport {
	out := CustomerExamReport{
		Rows: make([]CustomerExamRow, 0, len(r.Rows)),
		Totals: CustomerExamTotals{
			Labeled:   r.Totals.Labeled,
			Unlabeled: r.Totals.Unlabeled,
			Passed:    r.Totals.Passed,
			Failed:    r.Totals.Failed,
		},
	}
	for _, row := range r.Rows {
		out.Rows = append(out.Rows, CustomerExamRow{
			ScenarioID:  row.ScenarioID,
			MustFire:    append([]string{}, row.MustFire...),
			MustNotFire: append([]string{}, row.MustNotFire...),
			Emitted:     append([]string{}, row.Emitted...),
			Pass:        row.Pass,
		})
	}
	return out
}
