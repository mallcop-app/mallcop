// get_raw_event_test.go — unit tests for the get-raw-event pure read tool
// (mallcoppro-37d): full-payload return, credential redaction, size cap, and
// "finding-" prefix id leniency (mallcoppro-45c).
package tools

import (
	"encoding/json"
	"strings"
	"testing"

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

// TestGetRawEvent_SizeCap proves an oversized payload comes back truncated,
// under (or acceptably close to) the cap, with Truncated=true and a Notes
// explanation — NEVER an error.
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
	if len(out.Payload) > getRawEventPayloadCap*2 {
		// Generous slack: the contract is "never an error, best-effort under
		// cap", not a byte-exact guarantee — but it must be dramatically
		// smaller than the untouched 200KB+ input.
		t.Errorf("Payload len = %d, want well under original ~200KB (cap is %d)", len(out.Payload), getRawEventPayloadCap)
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
