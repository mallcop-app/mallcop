// id_lenience_test.go — unit tests for the git-style unique-prefix id
// resolver (mallcoppro-448) shared by get_raw_event, search_events, and
// search_findings.
package tools

import (
	"strings"
	"testing"
)

// ---- resolveIDPrefixMulti ---------------------------------------------------

func TestResolveIDPrefixMulti_UniqueMatch(t *testing.T) {
	pool := []string{"cafe1234abcd", "feedaced1111", "0000000000aa"}
	matched, ambiguous, total := resolveIDPrefixMulti("feedac", []string{"feedac"}, pool)
	if matched != "feedaced1111" {
		t.Errorf("matched = %q, want %q", matched, "feedaced1111")
	}
	if ambiguous != nil {
		t.Errorf("ambiguous = %v, want nil", ambiguous)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
}

func TestResolveIDPrefixMulti_CaseInsensitive(t *testing.T) {
	pool := []string{"CAFE1234abcd"}
	matched, _, _ := resolveIDPrefixMulti("cafe1", []string{"cafe1"}, pool)
	if matched != "cafe1234abcd" {
		t.Errorf("matched = %q, want lowercased %q", matched, "cafe1234abcd")
	}
}

func TestResolveIDPrefixMulti_Ambiguous(t *testing.T) {
	pool := []string{"cafe1111aaaa", "cafe2222bbbb", "feedaced1111"}
	matched, ambiguous, total := resolveIDPrefixMulti("cafe", []string{"cafe"}, pool)
	if matched != "" {
		t.Errorf("matched = %q, want \"\" (ambiguous)", matched)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(ambiguous) != 2 {
		t.Fatalf("ambiguous = %v, want 2 candidates", ambiguous)
	}
	joined := strings.Join(ambiguous, ",")
	if !strings.Contains(joined, "cafe1111aaaa") || !strings.Contains(joined, "cafe2222bbbb") {
		t.Errorf("ambiguous candidates = %v, want both cafe1111aaaa and cafe2222bbbb", ambiguous)
	}
}

// TestResolveIDPrefixMulti_CapsAmbiguousCandidates proves an ambiguous match
// against many stored ids is capped at maxAmbiguousIDCandidates in the
// returned slice, while total reports the FULL match count.
func TestResolveIDPrefixMulti_CapsAmbiguousCandidates(t *testing.T) {
	pool := make([]string, 15)
	for i := range pool {
		pool[i] = "cafe" + string(rune('a'+i)) + "234567890"
	}
	matched, ambiguous, total := resolveIDPrefixMulti("cafe", []string{"cafe"}, pool)
	if matched != "" {
		t.Errorf("matched = %q, want \"\" (ambiguous)", matched)
	}
	if total != 15 {
		t.Errorf("total = %d, want 15", total)
	}
	if len(ambiguous) != maxAmbiguousIDCandidates {
		t.Errorf("len(ambiguous) = %d, want capped at %d", len(ambiguous), maxAmbiguousIDCandidates)
	}
}

// TestResolveIDPrefixMulti_ShortPrefixRejected proves a requested id shorter
// than minIDPrefixLen never resolves, even when it would otherwise uniquely
// (or ambiguously) match — the length floor is checked FIRST.
func TestResolveIDPrefixMulti_ShortPrefixRejected(t *testing.T) {
	pool := []string{"cafe1234abcd"}
	requested := "caf" // 3 chars, one under minIDPrefixLen
	if len(requested) >= minIDPrefixLen {
		t.Fatalf("test fixture invalid: %q is not shorter than minIDPrefixLen=%d", requested, minIDPrefixLen)
	}
	matched, ambiguous, total := resolveIDPrefixMulti(requested, []string{requested}, pool)
	if matched != "" || ambiguous != nil || total != 0 {
		t.Errorf("short prefix must be rejected outright: matched=%q ambiguous=%v total=%d", matched, ambiguous, total)
	}
}

// TestResolveIDPrefixMulti_GateAppliesToRawRequestedNotExpandedCandidates
// proves the length gate is checked against the RAW requested id, not each
// expanded lenience candidate. findingIDCandidates unconditionally prepends
// the 8-char literal "finding-", so a naive per-candidate length check would
// let a genuinely short 3-char fragment ("fee") sail through disguised as
// the 11-char candidate "finding-fee" — this proves that does NOT happen.
func TestResolveIDPrefixMulti_GateAppliesToRawRequestedNotExpandedCandidates(t *testing.T) {
	pool := []string{"finding-feedaced1111"}
	requested := "fee" // 3 chars — short on its own
	candidates := findingIDCandidates(requested)
	longCandidateFound := false
	for _, c := range candidates {
		if len(c) >= minIDPrefixLen {
			longCandidateFound = true
		}
	}
	if !longCandidateFound {
		t.Fatalf("test fixture invalid: expected findingIDCandidates(%q) to include a candidate >= minIDPrefixLen", requested)
	}
	matched, ambiguous, total := resolveIDPrefixMulti(requested, candidates, pool)
	if matched != "" || ambiguous != nil || total != 0 {
		t.Errorf("short raw id must be rejected even though an expanded candidate is long enough: matched=%q ambiguous=%v total=%d", matched, ambiguous, total)
	}
}

func TestResolveIDPrefixMulti_NoMatch(t *testing.T) {
	pool := []string{"cafe1234abcd", "feedaced1111"}
	matched, ambiguous, total := resolveIDPrefixMulti("zzzzzzzz", []string{"zzzzzzzz"}, pool)
	if matched != "" || ambiguous != nil || total != 0 {
		t.Errorf("no-match must be zero-value: matched=%q ambiguous=%v total=%d", matched, ambiguous, total)
	}
}

func TestResolveIDPrefixMulti_ExactFullIDStillResolvesAsPrefixOfItself(t *testing.T) {
	// resolveIDPrefixMulti itself has no notion of "exact" vs "prefix" — a
	// full id is simply a (trivial) prefix of itself. Callers rely on this
	// only as a fallback AFTER their own exact-match pass; this test just
	// documents that the resolver alone would still find it.
	pool := []string{"cafe1234abcd"}
	matched, _, total := resolveIDPrefixMulti("cafe1234abcd", []string{"cafe1234abcd"}, pool)
	if matched != "cafe1234abcd" || total != 1 {
		t.Errorf("matched=%q total=%d, want the full id itself", matched, total)
	}
}

// ---- resolveEventIDPrefix / resolveFindingIDPrefix -------------------------

// TestResolveEventIDPrefix_StripsFindingPrefix proves a truncated
// "finding-"-prefixed id resolves against the BARE event pool, mirroring
// eventIDCandidates' exact-match stripping direction.
func TestResolveEventIDPrefix_StripsFindingPrefix(t *testing.T) {
	pool := []string{"cafe1234abcd"}
	matched, _, total := resolveEventIDPrefix("finding-cafe1", pool)
	if matched != "cafe1234abcd" || total != 1 {
		t.Errorf("matched=%q total=%d, want the bare event id via stripped finding- prefix", matched, total)
	}
}

// TestResolveFindingIDPrefix_AddsFindingPrefix proves a truncated BARE hash
// resolves against a "finding-"-prefixed pool, mirroring findingIDCandidates'
// exact-match "finding-"+id direction.
func TestResolveFindingIDPrefix_AddsFindingPrefix(t *testing.T) {
	pool := []string{"finding-cafe1234abcd"}
	matched, _, total := resolveFindingIDPrefix("cafe1", pool)
	if matched != "finding-cafe1234abcd" || total != 1 {
		t.Errorf("matched=%q total=%d, want the finding- prefixed id via bare-hash prefix", matched, total)
	}
}

// ---- ambiguousIDError -------------------------------------------------------

func TestAmbiguousIDError(t *testing.T) {
	err := ambiguousIDError("search-events", "cafe", []string{"cafe1111aaaa", "cafe2222bbbb"}, 2)
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	msg := err.Error()
	for _, want := range []string{"search-events", "cafe", "cafe1111aaaa", "cafe2222bbbb"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q missing %q", msg, want)
		}
	}
}

func TestAmbiguousIDError_NotesTruncationWhenCapped(t *testing.T) {
	capped := make([]string, maxAmbiguousIDCandidates)
	for i := range capped {
		capped[i] = "id"
	}
	err := ambiguousIDError("search-findings", "x", capped, 40)
	if !strings.Contains(err.Error(), "40") {
		t.Errorf("error message %q should mention the full total (40) even when candidates are capped", err.Error())
	}
}
