// seed_findings_test.go — mallcoppro-9af6: formatSeedFindings had ZERO test
// coverage before this fix, and boxed the ENTIRE seed findings array through
// agent.WrapUntrusted's single-scalar 1024-byte SILENT cap — a realistic
// multi-finding seed got cut mid-JSON with no indication anything was
// dropped (a live session even had the model say "the last finding ID is
// cut off"). The fix switches to agent.WrapUntrustedToolResult (the same
// 64KB-budget, visibly-marked-truncation boxing mallcoppro-a1e added for
// tool_result payloads). These tests prove: (1) a realistic multi-finding
// seed that exceeds the OLD 1024-byte cap survives intact under the new
// budget, and (2) a seed that even exceeds the NEW 64KB budget is truncated
// with a VISIBLE marker, never silently.
package investigate

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// buildRealisticSeedFindings returns n SeededFinding records shaped like real
// on-screen findings (non-trivial Reason text, a handful of event_ids each) —
// large enough in aggregate that n=7 comfortably exceeds the old 1024-byte
// single-scalar cap, while any individual finding stays small.
func buildRealisticSeedFindings(n int) []SeededFinding {
	seed := make([]SeededFinding, 0, n)
	for i := 0; i < n; i++ {
		seed = append(seed, SeededFinding{
			ID:       fmt.Sprintf("finding-evt_%040d-suspicious", i),
			Type:     "unusual-login",
			Source:   "detector:unusual-login",
			Actor:    fmt.Sprintf("actor-%03d", i),
			Severity: "high",
			Reason: fmt.Sprintf(
				"login from unknown location (IP: 203.0.113.%d, geo: unknown) — actor has no prior "+
					"login profile on record and this session originated outside every previously "+
					"observed geo for the account, which is itself unusual given the account's "+
					"established pattern of activity", i,
			),
			EventIDs: []string{
				fmt.Sprintf("evt_%040d", i),
				fmt.Sprintf("evt_%040d", i+1000),
			},
		})
	}
	return seed
}

// TestFormatSeedFindings_RealisticMultiFindingSeedNeverSilentlyTruncated is
// the mallcoppro-9af6 regression test: feed formatSeedFindings 7+ realistic
// findings whose combined JSON exceeds the OLD 1024-byte silent cap by a wide
// margin, and assert the output is either complete (every finding id present
// verbatim) or visibly marked as truncated — never silently cut mid-JSON.
func TestFormatSeedFindings_RealisticMultiFindingSeedNeverSilentlyTruncated(t *testing.T) {
	seed := buildRealisticSeedFindings(7)

	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if len(raw) <= 1024 {
		t.Fatalf("test fixture invalid: seed JSON is %d bytes, must exceed the OLD 1024-byte "+
			"single-scalar cap to prove anything (mallcoppro-9af6's whole point)", len(raw))
	}
	t.Logf("seed JSON is %d bytes (old cap was 1024)", len(raw))

	got := formatSeedFindings(seed)

	if strings.Contains(got, "TOOL_RESULT_TRUNCATED") {
		// Visible truncation is an acceptable outcome (mallcoppro-a1e's
		// documented behavior for an over-budget tool result) — it is exactly
		// NOT the silent cut this test guards against.
		t.Log("seed was visibly truncated (within the 64KB budget for this fixture, unexpected but not a failure)")
		return
	}

	// No truncation marker: every finding's id must appear verbatim. A
	// silent mid-JSON cut would drop the tail findings entirely with no
	// trace — this is the exact bug mallcoppro-9af6 fixes.
	for _, f := range seed {
		if !strings.Contains(got, f.ID) {
			t.Errorf("finding id %q missing from seed block and no truncation marker present — "+
				"data was silently dropped:\n%s", f.ID, got)
		}
	}
	// The boundary markers must still be present exactly once each — the
	// injection-defense boxing must survive regardless of size.
	if strings.Count(got, "[USER_DATA_BEGIN]") != 1 {
		t.Errorf("want exactly one [USER_DATA_BEGIN], output:\n%s", got)
	}
	if strings.Count(got, "[USER_DATA_END]") != 1 {
		t.Errorf("want exactly one [USER_DATA_END], output:\n%s", got)
	}
}

// TestFormatSeedFindings_OverNewBudgetTruncatesVisibly proves that even the
// enlarged 64KB budget has a ceiling, and crossing it produces the VISIBLE
// [TOOL_RESULT_TRUNCATED] marker (agent.WrapUntrustedToolResult's contract) —
// never a silent cut, at any size.
func TestFormatSeedFindings_OverNewBudgetTruncatesVisibly(t *testing.T) {
	// 400 findings, each with a long Reason, comfortably exceeds 64KB when
	// marshaled.
	seed := buildRealisticSeedFindings(400)

	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if len(raw) <= 64*1024 {
		t.Fatalf("test fixture invalid: seed JSON is %d bytes, must exceed the 64KB "+
			"WrapUntrustedToolResult budget to prove the visible-truncation path", len(raw))
	}

	got := formatSeedFindings(seed)

	if !strings.Contains(got, "TOOL_RESULT_TRUNCATED") {
		t.Fatalf("seed JSON (%d bytes) exceeds the 64KB budget but output carries no visible "+
			"truncation marker — this would be a SILENT cut, exactly what mallcoppro-9af6/mallcoppro-a1e "+
			"exist to prevent", len(raw))
	}
	if strings.Count(got, "[USER_DATA_BEGIN]") != 1 || strings.Count(got, "[USER_DATA_END]") != 1 {
		t.Errorf("boundary markers malformed even under truncation, output tail:\n%s", got[max0(len(got)-200):])
	}
}

// TestFormatSeedFindings_SmallSeedPassesThroughIntact proves the common
// case (a small on-screen seed, well under any cap) is unaffected by the
// mallcoppro-9af6 boxing switch: complete, no truncation marker, standard
// boundary framing.
func TestFormatSeedFindings_SmallSeedPassesThroughIntact(t *testing.T) {
	seed := buildRealisticSeedFindings(1)
	got := formatSeedFindings(seed)

	if strings.Contains(got, "TOOL_RESULT_TRUNCATED") {
		t.Fatalf("a single small finding must never be truncated, got:\n%s", got)
	}
	if !strings.Contains(got, seed[0].ID) {
		t.Errorf("finding id %q missing from output:\n%s", seed[0].ID, got)
	}
	if !strings.Contains(got, "CONTEXT — the operator is looking at the finding(s)") {
		t.Errorf("missing the grounding preamble, output:\n%s", got)
	}
}

// TestFormatSeedFindings_EmptySeedReturnsEmptyString proves the un-seeded
// Ask/CLI path is unchanged: no findings in means "" out, no boxing at all.
func TestFormatSeedFindings_EmptySeedReturnsEmptyString(t *testing.T) {
	if got := formatSeedFindings(nil); got != "" {
		t.Errorf("formatSeedFindings(nil) = %q, want \"\"", got)
	}
	if got := formatSeedFindings([]SeededFinding{}); got != "" {
		t.Errorf("formatSeedFindings([]) = %q, want \"\"", got)
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
