package inquest

import (
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestAssembleIdentity_NewFormatFlatKeys proves identity extraction prefers
// the NEW FORMAT flat keys (caller/session_name/source_ip/target) and records
// the exact field path each value came from.
func TestAssembleIdentity_NewFormatFlatKeys(t *testing.T) {
	s := newTempStore(t)
	seedEvent(t, s, event.Event{
		ID: "evt-new-1", Source: "aws", Type: "assume_role", Actor: "forge-proxy",
		Timestamp: time.Now(),
		Payload: rawEventPayload(t, map[string]any{
			"caller":       "arn:aws:iam::111122223333:role/mallcop-bedrock-relay",
			"session_name": "session-abc",
			"source_ip":    "203.0.113.7",
			"target":       "mallcop-bedrock-relay",
		}),
	})
	f := finding.Finding{ID: "finding-evt-new-1", Actor: "forge-proxy", Type: "assume_role"}

	out := assembleIdentity(s, f)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	if out.Caller != "arn:aws:iam::111122223333:role/mallcop-bedrock-relay" {
		t.Errorf("Caller = %q", out.Caller)
	}
	if out.SessionName != "session-abc" {
		t.Errorf("SessionName = %q", out.SessionName)
	}
	if out.SourceIP != "203.0.113.7" {
		t.Errorf("SourceIP = %q", out.SourceIP)
	}
	if out.Target != "mallcop-bedrock-relay" {
		t.Errorf("Target = %q", out.Target)
	}
	want := map[string]string{
		"caller": "payload.caller", "session_name": "payload.session_name",
		"source_ip": "payload.source_ip", "target": "payload.target",
	}
	for k, v := range want {
		if out.FieldPaths[k] != v {
			t.Errorf("FieldPaths[%q] = %q, want %q", k, out.FieldPaths[k], v)
		}
	}
}

// TestAssembleIdentity_OldFormatRawFallback proves identity extraction falls
// back to the OLD FORMAT raw CloudTrail-style paths when the new flat keys
// are absent, and records THOSE field paths.
func TestAssembleIdentity_OldFormatRawFallback(t *testing.T) {
	s := newTempStore(t)
	seedEvent(t, s, event.Event{
		ID: "evt-old-1", Source: "aws", Type: "assume_role", Actor: "forge-proxy",
		Timestamp: time.Now(),
		Payload: rawEventPayload(t, map[string]any{
			"raw": map[string]any{
				"sourceIPAddress": "203.0.113.7",
				"userIdentity": map[string]any{
					"arn": "arn:aws:sts::111122223333:assumed-role/mallcop-bedrock-relay/session-abc",
				},
				"requestParameters": map[string]any{
					"roleSessionName": "session-abc",
				},
			},
		}),
	})
	f := finding.Finding{ID: "finding-evt-old-1", Actor: "forge-proxy", Type: "assume_role"}

	out := assembleIdentity(s, f)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	if out.Caller != "arn:aws:sts::111122223333:assumed-role/mallcop-bedrock-relay/session-abc" {
		t.Errorf("Caller = %q", out.Caller)
	}
	if out.FieldPaths["caller"] != "payload.raw.userIdentity.arn" {
		t.Errorf("FieldPaths[caller] = %q", out.FieldPaths["caller"])
	}
	if out.SessionName != "session-abc" || out.FieldPaths["session_name"] != "payload.raw.requestParameters.roleSessionName" {
		t.Errorf("SessionName = %q FieldPaths[session_name] = %q", out.SessionName, out.FieldPaths["session_name"])
	}
	if out.SourceIP != "203.0.113.7" || out.FieldPaths["source_ip"] != "payload.raw.sourceIPAddress" {
		t.Errorf("SourceIP = %q FieldPaths[source_ip] = %q", out.SourceIP, out.FieldPaths["source_ip"])
	}
	// No new-format target and no old-format target fallback -> empty, no path.
	if out.Target != "" {
		t.Errorf("Target = %q, want empty (no old-format fallback defined)", out.Target)
	}
	if _, ok := out.FieldPaths["target"]; ok {
		t.Errorf("FieldPaths[target] should be absent, got %q", out.FieldPaths["target"])
	}
}

// TestAssembleIdentity_SessionIssuerFallback proves caller falls back to
// userIdentity.sessionContext.sessionIssuer.arn when userIdentity.arn itself
// is absent (the assumed-role case where only the issuing role's ARN is
// present).
func TestAssembleIdentity_SessionIssuerFallback(t *testing.T) {
	s := newTempStore(t)
	seedEvent(t, s, event.Event{
		ID: "evt-issuer-1", Source: "aws", Type: "assume_role", Actor: "forge-proxy",
		Timestamp: time.Now(),
		Payload: rawEventPayload(t, map[string]any{
			"raw": map[string]any{
				"userIdentity": map[string]any{
					"sessionContext": map[string]any{
						"sessionIssuer": map[string]any{
							"arn": "arn:aws:iam::111122223333:role/mallcop-bedrock-relay",
						},
					},
				},
			},
		}),
	})
	f := finding.Finding{ID: "finding-evt-issuer-1", Actor: "forge-proxy", Type: "assume_role"}

	out := assembleIdentity(s, f)
	if out.Caller != "arn:aws:iam::111122223333:role/mallcop-bedrock-relay" {
		t.Errorf("Caller = %q", out.Caller)
	}
	if out.FieldPaths["caller"] != "payload.raw.userIdentity.sessionContext.sessionIssuer.arn" {
		t.Errorf("FieldPaths[caller] = %q", out.FieldPaths["caller"])
	}
}

// TestAssembleIdentity_NotFound proves a finding whose underlying event does
// not exist degrades this section (Error set), never panics.
func TestAssembleIdentity_NotFound(t *testing.T) {
	s := newTempStore(t)
	f := finding.Finding{ID: "finding-does-not-exist", Actor: "someone"}
	out := assembleIdentity(s, f)
	if out.Error == "" {
		t.Fatal("expected a non-empty Error for a finding with no underlying event")
	}
}

// poisonedPayload mirrors core/tools/get_raw_event_test.go's rawAssumeRolePayload:
// a CloudTrail-style AssumeRole record carrying the caller identity PLUS, at
// two different depths, credential material (sessionToken, secretAccessKey)
// that tools.GetRawEvent's redaction must scrub before this package ever sees
// it. secretToken is the literal marker string this test asserts never
// survives, at any depth, into the marshaled Record or the narrate prompt.
const secretToken = "FQoGZXIvYXdzEXAMPLE_SUPER_SECRET_TOKEN"

func poisonedPayload() string {
	return `{
  "caller": "arn:aws:iam::111122223333:role/mallcop-bedrock-relay",
  "session_name": "session-abc",
  "source_ip": "203.0.113.7",
  "raw": {
    "responseElements": {
      "credentials": {
        "accessKeyId": "ASIAEXAMPLE1234567",
        "sessionToken": "` + secretToken + `",
        "expiration": "2026-07-17T14:00:00Z"
      }
    },
    "nested": {
      "deeper": {
        "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/EXAMPLEKEY"
      }
    }
  }
}`
}

// TestPoisonedPayload_TokenNeverSurvives proves the poisoned sessionToken
// bytes never appear ANYWHERE — not in assembleIdentity's own output, not in
// a fully marshaled Record, and not in the narrate prompt built from it. This
// holds STRUCTURALLY because assembleIdentity reads through
// tools.GetRawEvent, which redacts sessionToken/secretAccessKey at any depth
// before this package ever sees the payload — this test proves the
// redaction's guarantee actually propagates end-to-end through this package,
// not just at the tools.GetRawEvent boundary.
func TestPoisonedPayload_TokenNeverSurvives(t *testing.T) {
	s := newTempStore(t)
	seedEvent(t, s, event.Event{
		ID: "evt-poison-1", Source: "aws", Type: "assume_role", Actor: "forge-proxy",
		Timestamp: time.Now(),
		Payload:   []byte(poisonedPayload()),
	})
	f := finding.Finding{
		ID: "finding-evt-poison-1", Actor: "forge-proxy", Type: "assume_role",
		Timestamp: time.Now(), Reason: "AssumeRole into mallcop-bedrock-relay",
	}

	identity := assembleIdentity(s, f)
	if strings.Contains(identity.Caller+identity.SessionName+identity.SourceIP+identity.Target, secretToken) {
		t.Fatal("secret token leaked into IdentityEvidence's own fields")
	}

	ev := Evidence{Identity: identity}
	rec := Record{
		SchemaVersion: SchemaVersion, FindingID: f.ID, Role: "evidence",
		Verdict: VerdictUnassessed, Evidence: ev,
	}
	recBytes, err := marshalRecordForSize(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if strings.Contains(string(recBytes), secretToken) {
		t.Fatalf("secret token leaked into the marshaled Record:\n%s", recBytes)
	}

	prompt, err := buildUserMessage(f, ResolutionRef{Action: "escalate", Reason: "test"}, ev)
	if err != nil {
		t.Fatalf("buildUserMessage: %v", err)
	}
	if strings.Contains(prompt, secretToken) {
		t.Fatalf("secret token leaked into the narrate prompt:\n%s", prompt)
	}

	// Sanity: the caller identity DID resolve (the test isn't vacuously
	// passing because nothing was extracted at all).
	if identity.Caller == "" {
		t.Fatal("expected identity.Caller to resolve from the new-format flat key")
	}
}
