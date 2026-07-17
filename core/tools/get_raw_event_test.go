// get_raw_event_test.go — unit tests for the get-raw-event pure read tool
// (mallcoppro-37d): full-payload return, credential redaction, size cap, and
// "finding-" prefix id leniency (mallcoppro-45c).
package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// rawAssumeRolePayload mirrors the shape mallcoppro-37d's forensics scenario
// describes: a CloudTrail-style AssumeRole record with the caller identity,
// source IP, and session name the operator needs — plus, nested under
// responseElements.credentials, the sessionToken material a stored event may
// still carry from before connector-side redaction (mallcoppro-132) existed.
const rawAssumeRolePayload = `{
  "eventName": "AssumeRole",
  "sourceIPAddress": "203.0.113.7",
  "userIdentity": {
    "arn": "arn:aws:sts::111122223333:assumed-role/forge-proxy/session-abc",
    "type": "AssumedRole"
  },
  "requestParameters": {
    "roleArn": "arn:aws:iam::111122223333:role/forge-proxy",
    "roleSessionName": "session-abc"
  },
  "responseElements": {
    "credentials": {
      "accessKeyId": "ASIAEXAMPLE",
      "sessionToken": "FQoGZXIvYXdzEXAMPLE_SUPER_SECRET_TOKEN",
      "expiration": "2026-07-17T14:00:00Z"
    }
  },
  "nested": {
    "deeper": {
      "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/EXAMPLEKEY"
    }
  }
}`

func seedRawEvent(t *testing.T, s *store.Store, id, payload string) {
	t.Helper()
	ev := event.Event{ID: id, Source: "aws", Type: "assume_role", Actor: "forge-proxy", Payload: json.RawMessage(payload)}
	if _, err := s.Append(store.KindEvents, ev); err != nil {
		t.Fatalf("append event %s: %v", id, err)
	}
}

// TestGetRawEvent_ReturnsFullPayloadWithRedaction proves get_raw_event hands
// back the COMPLETE raw record (the who/what provenance fields search_events
// never projects: userIdentity.arn, sourceIPAddress, roleSessionName) while
// scrubbing sessionToken/secretAccessKey at any depth.
func TestGetRawEvent_ReturnsFullPayloadWithRedaction(t *testing.T) {
	s := newTempStore(t)
	seedRawEvent(t, s, "cafe1234", rawAssumeRolePayload)

	out, err := GetRawEvent(s, GetRawEventInput{ID: "cafe1234"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Found {
		t.Fatal("Found = false, want true")
	}
	if !out.Redacted {
		t.Error("Redacted = false, want true (payload carries sessionToken + secretAccessKey)")
	}
	if out.Notes == "" {
		t.Error("Notes empty, want an explanation that redaction fired")
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Payload, &decoded); err != nil {
		t.Fatalf("Payload is not valid JSON: %v\npayload: %s", err, out.Payload)
	}

	// Provenance fields the model needs (the whole point of this tool) survive
	// untouched.
	if got := decoded["sourceIPAddress"]; got != "203.0.113.7" {
		t.Errorf("sourceIPAddress = %v, want 203.0.113.7", got)
	}
	userIdentity, _ := decoded["userIdentity"].(map[string]any)
	if userIdentity == nil || userIdentity["arn"] != "arn:aws:sts::111122223333:assumed-role/forge-proxy/session-abc" {
		t.Errorf("userIdentity.arn missing or wrong: %v", decoded["userIdentity"])
	}
	reqParams, _ := decoded["requestParameters"].(map[string]any)
	if reqParams == nil || reqParams["roleSessionName"] != "session-abc" {
		t.Errorf("requestParameters.roleSessionName missing or wrong: %v", decoded["requestParameters"])
	}

	// Credential material is scrubbed, at whatever depth it appears.
	creds, _ := decoded["responseElements"].(map[string]any)["credentials"].(map[string]any)
	if creds == nil || creds["sessionToken"] != "[REDACTED]" {
		t.Errorf("responseElements.credentials.sessionToken not redacted: %v", creds)
	}
	deeper, _ := decoded["nested"].(map[string]any)["deeper"].(map[string]any)
	if deeper == nil || deeper["secretAccessKey"] != "[REDACTED]" {
		t.Errorf("nested.deeper.secretAccessKey not redacted: %v", deeper)
	}
	// A sibling field the redaction pass must NOT touch.
	if creds["accessKeyId"] != "ASIAEXAMPLE" {
		t.Errorf("accessKeyId was altered: %v, want unredacted ASIAEXAMPLE", creds["accessKeyId"])
	}
}

// TestGetRawEvent_RedactionIsCaseInsensitive proves the key match on
// sessionToken/secretAccessKey ignores case, per the mallcoppro-37d spec.
func TestGetRawEvent_RedactionIsCaseInsensitive(t *testing.T) {
	s := newTempStore(t)
	seedRawEvent(t, s, "e-case", `{"SessionToken":"abc","SECRETACCESSKEY":"def","other":"keep"}`)

	out, err := GetRawEvent(s, GetRawEventInput{ID: "e-case"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Payload, &decoded); err != nil {
		t.Fatalf("Payload not valid JSON: %v", err)
	}
	if decoded["SessionToken"] != "[REDACTED]" {
		t.Errorf("SessionToken = %v, want [REDACTED]", decoded["SessionToken"])
	}
	if decoded["SECRETACCESSKEY"] != "[REDACTED]" {
		t.Errorf("SECRETACCESSKEY = %v, want [REDACTED]", decoded["SECRETACCESSKEY"])
	}
	if decoded["other"] != "keep" {
		t.Errorf("other = %v, want untouched \"keep\"", decoded["other"])
	}
}

// TestGetRawEvent_SizeCap proves an oversized payload dominated by one huge
// leaf string comes back truncated, at or under the cap (a hard guarantee,
// not best-effort), with Truncated=true and a Notes explanation — NEVER an
// error.
func TestGetRawEvent_SizeCap(t *testing.T) {
	s := newTempStore(t)

	// One enormous leaf plus a handful of small discriminating fields, well
	// over getRawEventPayloadCap (64KB) once serialized.
	huge := strings.Repeat("A", 200*1024)
	payload, err := json.Marshal(map[string]any{
		"actor":       "forge-proxy",
		"eventName":   "AssumeRole",
		"hugeBlobRaw": huge,
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	seedRawEvent(t, s, "e-big", string(payload))

	out, err := GetRawEvent(s, GetRawEventInput{ID: "e-big"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Found {
		t.Fatal("Found = false, want true")
	}
	if !out.Truncated {
		t.Error("Truncated = false, want true for a 200KB leaf value")
	}
	if len(out.Payload) > getRawEventPayloadCap {
		t.Errorf("Payload len = %d, want <= cap %d (hard guarantee)", len(out.Payload), getRawEventPayloadCap)
	}
	if out.Notes == "" {
		t.Error("Notes empty, want an explanation that truncation fired")
	}
	// Still valid, still useful JSON — the small discriminating fields survive.
	var decoded map[string]any
	if err := json.Unmarshal(out.Payload, &decoded); err != nil {
		t.Fatalf("truncated Payload is not valid JSON: %v\npayload prefix: %.200s", err, out.Payload)
	}
	if decoded["actor"] != "forge-proxy" {
		t.Errorf("actor = %v, want forge-proxy to survive truncation", decoded["actor"])
	}
}

// TestGetRawEvent_SizeCap_ManyFieldsGuarantee proves the size cap is a hard
// guarantee even when the payload is a MAP dominated by sheer field COUNT
// rather than any single huge value: 6000 short (~44-byte) string leaves
// serialize to ~366KB, well over getRawEventPayloadCap, and none of those
// leaves are individually long enough for leaf-string truncation
// (truncateLeaves) to touch. Only the final subtree-pruning guarantee pass
// (which can drop whole map entries, not just shorten values) can get this
// under the cap.
func TestGetRawEvent_SizeCap_ManyFieldsGuarantee(t *testing.T) {
	s := newTempStore(t)

	fields := make(map[string]any, 6000)
	for i := 0; i < 6000; i++ {
		fields[fmt.Sprintf("field%04d", i)] = strings.Repeat("x", 44)
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if len(payload) <= getRawEventPayloadCap {
		t.Fatalf("fixture too small: %d bytes, want well over cap %d", len(payload), getRawEventPayloadCap)
	}
	seedRawEvent(t, s, "e-manyfields", string(payload))

	out, err := GetRawEvent(s, GetRawEventInput{ID: "e-manyfields"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Found {
		t.Fatal("Found = false, want true")
	}
	if !out.Truncated {
		t.Error("Truncated = false, want true for a 6000-field object")
	}
	if len(out.Payload) > getRawEventPayloadCap {
		t.Fatalf("Payload len = %d, want <= cap %d (hard guarantee)", len(out.Payload), getRawEventPayloadCap)
	}
	if !json.Valid(out.Payload) {
		t.Fatalf("Payload is not valid JSON: %s", out.Payload)
	}
}

// TestGetRawEvent_SizeCap_HugeArrayGuarantee proves the size cap is a hard
// guarantee for a 40,000-element int array: each element serializes to only
// a few bytes (nowhere near any leaf-string cap), so leaf-string truncation
// is a complete no-op here — only array capping (head + trailing marker)
// gets this under the cap.
func TestGetRawEvent_SizeCap_HugeArrayGuarantee(t *testing.T) {
	s := newTempStore(t)

	nums := make([]int, 40000)
	for i := range nums {
		nums[i] = i
	}
	payload, err := json.Marshal(nums)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if len(payload) <= getRawEventPayloadCap {
		t.Fatalf("fixture too small: %d bytes, want well over cap %d", len(payload), getRawEventPayloadCap)
	}
	seedRawEvent(t, s, "e-hugearray", string(payload))

	out, err := GetRawEvent(s, GetRawEventInput{ID: "e-hugearray"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Found {
		t.Fatal("Found = false, want true")
	}
	if !out.Truncated {
		t.Error("Truncated = false, want true for a 40,000-element array")
	}
	if len(out.Payload) > getRawEventPayloadCap {
		t.Fatalf("Payload len = %d, want <= cap %d (hard guarantee)", len(out.Payload), getRawEventPayloadCap)
	}
	if !json.Valid(out.Payload) {
		t.Fatalf("Payload is not valid JSON: %s", out.Payload)
	}
}

// TestGetRawEvent_SizeCap_MultibyteLeafStaysValidUTF8 proves leaf-string
// truncation cuts at a UTF-8 rune boundary, not a raw byte offset: a huge
// CJK (3-bytes-per-rune in UTF-8) leaf must truncate to a string that
// decodes cleanly, with no U+FFFD replacement character — slicing
// s[:leafCap] by byte offset alone can and does land mid-rune for non-ASCII
// text.
func TestGetRawEvent_SizeCap_MultibyteLeafStaysValidUTF8(t *testing.T) {
	s := newTempStore(t)

	// "漢字" (漢字, "Chinese characters") repeated: each rune is 3
	// bytes in UTF-8, so a byte-offset slice very often lands inside a rune.
	huge := strings.Repeat("漢字", 40*1024) // ~240KB
	payload, err := json.Marshal(map[string]any{
		"actor":    "forge-proxy",
		"hugeBlob": huge,
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	seedRawEvent(t, s, "e-cjk", string(payload))

	out, err := GetRawEvent(s, GetRawEventInput{ID: "e-cjk"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Truncated {
		t.Fatal("Truncated = false, want true for a 240KB CJK leaf")
	}
	if len(out.Payload) > getRawEventPayloadCap {
		t.Fatalf("Payload len = %d, want <= cap %d", len(out.Payload), getRawEventPayloadCap)
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Payload, &decoded); err != nil {
		t.Fatalf("truncated Payload is not valid JSON: %v", err)
	}
	blob, _ := decoded["hugeBlob"].(string)
	if blob == "" {
		// The leaf may have been pruned entirely by the final guarantee pass
		// rather than truncated in place — acceptable, nothing left to
		// UTF-8-check.
		return
	}
	if !utf8.ValidString(blob) {
		t.Fatalf("truncated hugeBlob is not valid UTF-8: %q", blob)
	}
	if strings.ContainsRune(blob, utf8.RuneError) {
		t.Errorf("truncated hugeBlob contains U+FFFD (mid-rune cut): %q", blob)
	}
}

// TestGetRawEvent_SizeCap_NeverLeaksTokenUnderHugeSubtree proves that when a
// sessionToken sits under a subtree big enough to trigger the size-cap
// guarantee pass, redaction (which always runs BEFORE any truncation/
// pruning) has already replaced it with "[REDACTED]" — so the size-cap pass
// can only ever see and prune/replace that marker, never the live secret.
// Either the "[REDACTED]" marker survives verbatim, or the whole subtree
// around it collapses into a "[TRUNCATED: ...]" marker — but the literal
// token value must never appear anywhere in the output.
func TestGetRawEvent_SizeCap_NeverLeaksTokenUnderHugeSubtree(t *testing.T) {
	s := newTempStore(t)

	const liveToken = "FQoGZXIvYXdzEXAMPLE_SUPER_SECRET_TOKEN_DO_NOT_LEAK"

	padding := make(map[string]any, 6000)
	for i := 0; i < 6000; i++ {
		padding[fmt.Sprintf("field%04d", i)] = strings.Repeat("y", 44)
	}
	body := map[string]any{
		"credentials": map[string]any{
			"sessionToken": liveToken,
			"accessKeyId":  "ASIAEXAMPLE",
		},
		"padding": padding,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if len(payload) <= getRawEventPayloadCap {
		t.Fatalf("fixture too small: %d bytes, want well over cap %d", len(payload), getRawEventPayloadCap)
	}
	seedRawEvent(t, s, "e-token-huge", string(payload))

	out, err := GetRawEvent(s, GetRawEventInput{ID: "e-token-huge"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Found {
		t.Fatal("Found = false, want true")
	}
	if len(out.Payload) > getRawEventPayloadCap {
		t.Fatalf("Payload len = %d, want <= cap %d (hard guarantee)", len(out.Payload), getRawEventPayloadCap)
	}
	if !json.Valid(out.Payload) {
		t.Fatalf("Payload is not valid JSON: %s", out.Payload)
	}

	// The hard invariant: the live token substring must never appear,
	// anywhere, under any circumstance.
	if strings.Contains(string(out.Payload), liveToken) {
		t.Fatalf("live sessionToken leaked into output payload: %s", out.Payload)
	}

	// Either the redaction marker is still present (subtree survived
	// unpruned), or it isn't because the whole subtree got collapsed to a
	// size marker — both are acceptable, but one of them must be true.
	hasRedactedMarker := strings.Contains(string(out.Payload), "[REDACTED]")
	hasSizeMarker := strings.Contains(string(out.Payload), "[TRUNCATED:")
	if !hasRedactedMarker && !hasSizeMarker {
		t.Fatalf("expected either a [REDACTED] marker or a [TRUNCATED: ...] marker in output, found neither: %s", out.Payload)
	}
}

// TestGetRawEvent_IDLeniency proves get_raw_event accepts a bare event id
// AND a "finding-"-prefixed id (stripped), consistent with mallcoppro-45c /
// eventIDCandidates.
func TestGetRawEvent_IDLeniency(t *testing.T) {
	s := newTempStore(t)
	seedRawEvent(t, s, "cafe1234", `{"eventName":"AssumeRole"}`)

	for _, id := range []string{"cafe1234", "CAFE1234", "finding-cafe1234", "FINDING-CAFE1234"} {
		out, err := GetRawEvent(s, GetRawEventInput{ID: id})
		if err != nil {
			t.Fatalf("id %q: unexpected error: %v", id, err)
		}
		if !out.Found {
			t.Errorf("id %q: Found = false, want true", id)
		}
		if out.ID != "cafe1234" {
			t.Errorf("id %q: out.ID = %q, want the stored event id %q", id, out.ID, "cafe1234")
		}
	}
}

// TestGetRawEvent_NotFound proves an id that resolves to no event is NOT an
// error — the §3.4 empty-is-data discipline — so the model can self-recover
// rather than the tool call failing outright.
func TestGetRawEvent_NotFound(t *testing.T) {
	s := newTempStore(t)
	seedRawEvent(t, s, "cafe1234", `{"eventName":"AssumeRole"}`)

	out, err := GetRawEvent(s, GetRawEventInput{ID: "nonexistent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Found {
		t.Error("Found = true, want false for an id that matches no event")
	}
	if out.Notes == "" {
		t.Error("Notes empty, want an explanation for the miss")
	}
	if string(out.Payload) != "null" {
		t.Errorf("Payload = %s, want the literal JSON null", out.Payload)
	}
}

func TestGetRawEvent_NilStore(t *testing.T) {
	if _, err := GetRawEvent(nil, GetRawEventInput{ID: "x"}); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestGetRawEvent_EmptyID(t *testing.T) {
	s := newTempStore(t)
	if _, err := GetRawEvent(s, GetRawEventInput{ID: ""}); err == nil {
		t.Fatal("expected error for empty id")
	}
}
