// finding_test.go — direct unit coverage for ExtractEvidenceEventIDs, the
// mallcoppro-323 backstop extraction helper (core/pipeline and
// cmd/mallcop-finding-context both call it; see the function's own doc
// comment). Named as a test gap by the mallcoppro-323 PR #216 code review —
// this is package-local coverage independent of either consumer.
package finding

import (
	"encoding/json"
	"testing"
)

func TestExtractEvidenceEventIDs_Singleton(t *testing.T) {
	got := ExtractEvidenceEventIDs(json.RawMessage(`{"actor":"mallory","event_id":"evt-1"}`))
	want := []string{"evt-1"}
	if !equalStringSlices(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractEvidenceEventIDs_PluralArray(t *testing.T) {
	got := ExtractEvidenceEventIDs(json.RawMessage(`{"event_ids":["evt-3","evt-1","evt-2"]}`))
	want := []string{"evt-1", "evt-2", "evt-3"} // sorted
	if !equalStringSlices(got, want) {
		t.Errorf("got %v, want %v (sorted)", got, want)
	}
}

func TestExtractEvidenceEventIDs_BothKeysUnionedAndDeduped(t *testing.T) {
	got := ExtractEvidenceEventIDs(json.RawMessage(`{"event_id":"evt-1","event_ids":["evt-1","evt-2"]}`))
	want := []string{"evt-1", "evt-2"}
	if !equalStringSlices(got, want) {
		t.Errorf("got %v, want %v (union + dedup across both keys)", got, want)
	}
}

func TestExtractEvidenceEventIDs_EmptyEvidence(t *testing.T) {
	if got := ExtractEvidenceEventIDs(nil); got != nil {
		t.Errorf("ExtractEvidenceEventIDs(nil) = %v, want nil", got)
	}
	if got := ExtractEvidenceEventIDs(json.RawMessage(``)); got != nil {
		t.Errorf("ExtractEvidenceEventIDs(\"\") = %v, want nil", got)
	}
}

func TestExtractEvidenceEventIDs_NoEventKeysPresent(t *testing.T) {
	got := ExtractEvidenceEventIDs(json.RawMessage(`{"actor":"mallory","pattern":"command-injection-chain","match":"...","rule":"injection-pattern"}`))
	if got != nil {
		t.Errorf("got %v, want nil — exactly the pre-mallcoppro-323 shape of the 5 suffix-ID "+
			"detector families' Evidence blob (no event_id/event_ids key at all)", got)
	}
}

func TestExtractEvidenceEventIDs_MalformedJSON(t *testing.T) {
	if got := ExtractEvidenceEventIDs(json.RawMessage(`not json`)); got != nil {
		t.Errorf("got %v, want nil for malformed evidence (never panics, never errors)", got)
	}
}

func TestExtractEvidenceEventIDs_EmptyStringValuesIgnored(t *testing.T) {
	got := ExtractEvidenceEventIDs(json.RawMessage(`{"event_id":"","event_ids":["","evt-1",""]}`))
	want := []string{"evt-1"}
	if !equalStringSlices(got, want) {
		t.Errorf("got %v, want %v — blank entries must never contribute a spurious id", got, want)
	}
}

func TestExtractEvidenceEventIDs_WrongTypeIgnored(t *testing.T) {
	// event_id as a number (not a string) and event_ids as a bare string (not
	// an array) must both be tolerated as "nothing usable here", never a
	// decode error that drops the whole extraction.
	got := ExtractEvidenceEventIDs(json.RawMessage(`{"event_id":123,"event_ids":"not-an-array"}`))
	if got != nil {
		t.Errorf("got %v, want nil for type-mismatched fields", got)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
