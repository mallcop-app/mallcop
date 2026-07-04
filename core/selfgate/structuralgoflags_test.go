// structuralgoflags_test.go — PROOF tests for mallcoppro-a08: stage 2
// (structuralStage) needs GOFLAGS=-mod=mod in customer-tree mode ONLY.
//
// Background (rd 7ee7 live leg round 4, 100% reproducible): a customer-shaped
// (THIN-EMBED) repo's go.mod pins github.com/mallcop-app/mallcop, but go.sum
// may legitimately be incomplete — nothing imported the framework packages
// (pkg/event, pkg/finding, pkg/baseline, pkg/detectorhost) until the authored
// sidecar under test did. Stage 3 (customerTreeExamStage /
// buildAndRegisterSourceSidecar, cli/sidecars.go) already sets
// GOFLAGS=-mod=mod for exactly this reason; stage 2 (structuralStage) was
// missed when mallcoppro-97b added customer-tree mode, so `go build ./...`
// hard-failed with "missing go.sum entry" BEFORE stage 3 ever ran — blocking
// every customer-tree authoring run regardless of detector quality.
//
// Invariant 10 (ground-source testing): every fixture here is a REAL git repo
// with a REAL local `replace` back to the repo under test, graded by a REAL
// `go build ./...` subprocess — nothing mocked.
package selfgate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildCustomerShapedRepoNoGoSumPrecompute is buildCustomerShapedRepo's THIN
// sibling: it deliberately SKIPS the `go mod tidy` precompute step that
// fixture uses to keep go.sum complete across base and head. This is the
// EXACT bug shape (rd 7ee7): go.mod pins mallcop via a local replace; go.sum
// is either absent or covers only what the bare, detector-less base module
// needs (nothing, since it imports nothing yet) — a THIN-EMBED customer repo
// that never ran `go mod tidy` for the framework surface because nothing had
// imported it yet. base = go.mod/README only, no go.sum. head = adds
// detectorSrc, which imports pkg/{baseline,detectorhost,event,finding} for
// the FIRST time in this repo's history.
func buildCustomerShapedRepoNoGoSumPrecompute(t *testing.T, detectorSrc string) (dir, base, head string) {
	t.Helper()
	mallcopRoot := repoUnderTest(t)
	dir = t.TempDir()
	mustGit(t, dir, "init", "-q")

	goMod := `module example.com/customer-fixture-thin

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => ` + mallcopRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write customer repo go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("customer deployment repo (THIN-EMBED, no go.sum precompute)\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	// Deliberately NO go.sum, NO `go mod tidy` — this is the whole point of
	// the fixture. base has go.mod but no go.sum at all.
	base = commitAll(t, dir, "base: THIN-EMBED scaffold, go.mod only (no go.sum precompute)")

	detDir := filepath.Join(dir, "detectors", "widget-leak")
	if err := os.MkdirAll(detDir, 0o755); err != nil {
		t.Fatalf("mkdir detectors/widget-leak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(detDir, "main.go"), []byte(detectorSrc), 0o644); err != nil {
		t.Fatalf("write detector main.go: %v", err)
	}
	head = commitAll(t, dir, "proposal: add widget-leak detector (first import of the framework surface)")
	return dir, base, head
}

// TestStructuralStage_CustomerTreeModeFixesIncompleteGoSum is the DIRECT
// mechanism proof: the SAME materialized head tree (a real customer-shaped
// worktree with an absent go.sum and a valid sidecar importing the framework
// packages) is run through structuralStage twice — once with
// customerTreeMode=false (byte-for-byte what every call site passed before
// this fix; this is the RED proof, reproducing rd 7ee7's "missing go.sum
// entry" failure) and once with customerTreeMode=true (the GREEN proof, this
// fix). Calling both against the identical tree in one test is a stronger,
// faster proof than reverting the source: it demonstrates the flag alone
// flips the outcome, with nothing else in the fixture changed.
func TestStructuralStage_CustomerTreeModeFixesIncompleteGoSum(t *testing.T) {
	clearInferenceEnv(t)
	customerDir, _, head := buildCustomerShapedRepoNoGoSumPrecompute(t, customerFixtureDetectorMainSrc)

	headTree := filepath.Join(t.TempDir(), "headtree")
	if err := addWorktree(customerDir, headTree, head); err != nil {
		t.Fatalf("materialize head worktree: %v", err)
	}
	t.Cleanup(func() { removeWorktree(customerDir, headTree) })

	// Sanity: the fixture really has no go.sum at head — otherwise this test
	// would prove nothing.
	if _, err := os.Stat(filepath.Join(headTree, "go.sum")); err == nil {
		t.Fatal("fixture invariant broken: go.sum must be ABSENT at head for this proof to mean anything")
	}

	// ---- RED: customerTreeMode=false reproduces rd 7ee7 --------------------
	redFindings, redEvidence, err := structuralStage(headTree, false)
	if err != nil {
		t.Fatalf("structuralStage (customerTreeMode=false): operational error: %v", err)
	}
	if !hasFinding(redFindings, RuleStructuralBuild) {
		t.Fatalf("customerTreeMode=false must FAIL with a %s finding (the rd 7ee7 bug reproduced) — got findings=%+v evidence=%q",
			RuleStructuralBuild, redFindings, redEvidence)
	}
	if !containsAny(findingDetails(redFindings), "missing go.sum entry") {
		t.Fatalf("expected the RuleStructuralBuild finding to name the missing go.sum entry, got %+v", redFindings)
	}

	// ---- GREEN: customerTreeMode=true (this fix) ----------------------------
	greenFindings, greenEvidence, err := structuralStage(headTree, true)
	if err != nil {
		t.Fatalf("structuralStage (customerTreeMode=true): operational error: %v", err)
	}
	if hasFinding(greenFindings, RuleStructuralBuild) {
		t.Fatalf("customerTreeMode=true must PASS (GOFLAGS=-mod=mod) — got findings=%+v evidence=%q", greenFindings, greenEvidence)
	}
	if !strings.Contains(greenEvidence, "OK in head tree") {
		t.Fatalf("expected clean build evidence, got %q", greenEvidence)
	}

	// go.sum must still not exist as a COMMITTED file in the source repo —
	// -mod=mod's env is scoped to the one build subprocess, so any go.sum it
	// computes lands only in the disposable worktree's filesystem, never back
	// in the customer's git history.
	if data, err := os.ReadFile(filepath.Join(customerDir, "go.sum")); err == nil {
		t.Fatalf("go.sum must not have been committed to the source repo by the fix, found: %s", data)
	}
}

// TestValidateProposal_CustomerTreeModeStructuralPassesEndToEnd proves the
// WIRING: Options.ExamRepo != "" reaches structuralStage through
// ValidateProposal exactly as it already reaches customerTreeExamStage (the
// same opts.ExamRepo != "" boolean, never derived from tree content) — a
// full, real ValidateProposal run over the exact incomplete-go.sum fixture
// now clears BOTH stage 2 (structural) and stage 3 (exam-detect) using the
// well-behaved detector.
func TestValidateProposal_CustomerTreeModeStructuralPassesEndToEnd(t *testing.T) {
	clearInferenceEnv(t)
	examTree := buildReferenceExamTree(t)
	customerDir, base, head := buildCustomerShapedRepoNoGoSumPrecompute(t, customerFixtureDetectorMainSrc)

	res, err := ValidateProposal(customerDir, base, head, Options{ExamRepo: examTree})
	if err != nil {
		t.Fatalf("ValidateProposal (customer-tree mode, incomplete go.sum): %v", err)
	}
	requireStageNames(t, res, StageGuard, StageStructural, StageExamDetect)
	structStage := res.Stages[1]
	if !structStage.Passed || len(structStage.Findings) != 0 {
		t.Fatalf("structural stage must PASS on a customer-tree proposal with an incomplete go.sum, got %+v", structStage)
	}
	if !res.Passed {
		t.Fatalf("well-behaved customer detector on a thin (no go.sum precompute) repo must pass the whole gate, got %+v", res)
	}
}

// TestValidateProposal_DefaultModeStructuralStaysStrictOnMissingGoSumEntry is
// the OTHER direction (mandatory per mallcoppro-a08): the DEFAULT (in-tree)
// lane — Options.ExamRepo == "", validating mallcop's own repo, e.g. for
// contribute-back — must NOT relax go.sum verification. A real clone of the
// repo under test with ONE go.sum entry deliberately removed (a genuinely
// incomplete go.sum, the same class of defect a supply-chain manipulation or
// dependency drift would produce) must STILL FAIL structural, proving this
// fix is scoped to customer-tree mode only and never globally sets
// GOFLAGS=-mod=mod.
//
// The corrupted go.sum is committed identically at base AND head (a
// self-diff, base==head — the same technique
// TestValidateProposal_DefaultModeFailsLoudlyOnCustomerShapedTree uses) so
// Guard's RuleProtectedPath (go.sum is a protectedFiles entry — ANY base/head
// CHANGE to it is denied) never fires: there is no go.sum delta to detect,
// only a pre-existing broken go.sum in the tree stage 2 must catch.
func TestValidateProposal_DefaultModeStructuralStaysStrictOnMissingGoSumEntry(t *testing.T) {
	clearInferenceEnv(t)
	clone := cloneRepo(t)

	goSum := readRepoFile(t, clone, "go.sum")
	corrupted := replaceOnce(t, goSum,
		"gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=\n",
		"")
	writeRepoFile(t, clone, "go.sum", corrupted)
	corruptSHA := commitAll(t, clone, "corrupt go.sum: remove the gopkg.in/yaml.v3 h1 entry (fixture only)")

	res, err := ValidateProposal(clone, corruptSHA, corruptSHA, Options{})
	if err != nil {
		t.Fatalf("ValidateProposal (default/in-tree mode, self-diff): operational error: %v", err)
	}
	requireStageNames(t, res, StageGuard, StageStructural)
	structStage := res.Stages[1]
	if structStage.Passed {
		t.Fatalf("default (in-tree) lane must STILL FAIL structural on a genuinely incomplete go.sum — the fix must not globally relax verification. got %+v", structStage)
	}
	if !containsAny(findingDetails(structStage.Findings), "missing go.sum entry") {
		t.Fatalf("expected a missing go.sum entry finding, got %+v", structStage.Findings)
	}
	if res.Passed {
		t.Fatal("GateResult.Passed must be false when structural fails")
	}
}

// ---- small local helpers -----------------------------------------------------

func hasFinding(findings []GuardFinding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func findingDetails(findings []GuardFinding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.Detail
	}
	return out
}

func containsAny(haystacks []string, needle string) bool {
	for _, h := range haystacks {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}
