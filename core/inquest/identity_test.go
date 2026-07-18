package inquest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/tools"
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

// TestAssembleIdentity_EventIDsResolvesWhenIDLenienceCannot proves the
// mallcoppro-323 fix: a finding shaped like the 5 suffix-ID detector families
// (Finding.ID = "finding-"+ev.ID+"-<suffix>") still resolves identity when
// Finding.EventIDs carries the real event id directly — even for a suffix
// long enough (many "-"-joined segments) that id-lenience's OWN widened
// eventIDCandidates (core/tools/id_lenience.go's bounded
// eventIDSuffixStripBound progressive-strip backstop, added alongside this
// same mallcoppro-323 fix) still cannot recover the bare event id from the
// compound id alone. EventIDs is the AUTHORITATIVE, unambiguous linkage;
// id-lenience's suffix stripping is a best-effort, BOUNDED backstop for an
// id a model echoes from earlier conversation context — it is not, and was
// never meant to be, a substitute for a detector recording real linkage.
func TestAssembleIdentity_EventIDsResolvesWhenIDLenienceCannot(t *testing.T) {
	s := newTempStore(t)
	seedEvent(t, s, event.Event{
		ID: "evt_ab12cd34ef56", Source: "github", Type: "push", Actor: "mallory",
		Timestamp: time.Now(),
		Payload: rawEventPayload(t, map[string]any{
			"caller":    "arn:aws:iam::111122223333:role/attacker",
			"source_ip": "203.0.113.99",
		}),
	})
	// A suffix-ID shape with MORE hyphen-joined segments than id-lenience's
	// eventIDSuffixStripBound (6): "-inj-a-b-c-d-e-f" is 7 segments, so the
	// widened eventIDCandidates strip loop bottoms out at
	// "evt_ab12cd34ef56-inj" — one segment short of the bare event id — and
	// genuinely cannot recover it, by construction of the bound.
	f := finding.Finding{
		ID:       "finding-evt_ab12cd34ef56-inj-a-b-c-d-e-f",
		Actor:    "mallory",
		Type:     "injection-probe",
		EventIDs: []string{"evt_ab12cd34ef56"},
	}

	// Control: prove the OLD f.ID-only path genuinely cannot resolve this
	// shape even WITH id-lenience's widened suffix-stripping backstop — the
	// suffix has more segments than eventIDSuffixStripBound allows it to
	// strip through.
	fallback, err := tools.GetRawEvent(s, tools.GetRawEventInput{ID: f.ID})
	if err != nil {
		t.Fatalf("unexpected error probing the fallback path: %v", err)
	}
	if fallback.Found {
		t.Fatal("precondition violated: the suffixed finding id unexpectedly resolved via f.ID alone — " +
			"this test no longer proves what it claims")
	}

	out := assembleIdentity(s, f)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s (EventIDs should have resolved the event)", out.Error)
	}
	if out.SourceIP != "203.0.113.99" {
		t.Errorf("SourceIP = %q, want 203.0.113.99 — identity should have resolved via f.EventIDs[0]", out.SourceIP)
	}
	if out.Caller != "arn:aws:iam::111122223333:role/attacker" {
		t.Errorf("Caller = %q", out.Caller)
	}
}

// seedGrantEvent seeds a minimal event so a grant finding's identity section
// resolves cleanly, then returns the finding whose Evidence carries the grant
// blob under test. The event payload is irrelevant to grant-direction
// resolution (which reads f.Evidence, not the event) — it exists only so
// assembleIdentity does not degrade with a "no underlying event" Error, proving
// the two paths coexist.
func seedGrantEvent(t *testing.T, s *store.Store, id, actor, typ, evidence string) finding.Finding {
	t.Helper()
	seedEvent(t, s, event.Event{
		ID: id, Source: "aws", Type: "trust_added", Actor: actor,
		Timestamp: time.Now(),
		Payload:   rawEventPayload(t, map[string]any{"caller": actor}),
	})
	return finding.Finding{
		ID: "finding-" + id, Actor: actor, Type: typ,
		Timestamp: time.Now(), EventIDs: []string{id},
		Evidence: json.RawMessage(evidence),
	}
}

// TestAssembleIdentity_GrantDirection_TrustAdded is the LOAD-BEARING regression
// test for the AWS cross-account AssumeRole inversion (mallcoppro-15e). The
// detector's evidence records actor=the CALLING principal (forge-proxy) and
// grantee=the ASSUMED role (mallcop-bedrock-relay), but the trust DIRECTION is
// the opposite: mallcop-bedrock-relay is the grantor (its trust boundary was
// exercised) and forge-proxy is the grantee (it gained the capability). If a
// future edit collapses the trust_added branch into the others, this test must
// fail loudly rather than let the backwards direction reach a live console.
func TestAssembleIdentity_GrantDirection_TrustAdded(t *testing.T) {
	s := newTempStore(t)
	const forgeProxy = "arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy"
	const relay = "arn:aws:iam::458526671706:role/mallcop-bedrock-relay"
	f := seedGrantEvent(t, s, "evt-trust-1", forgeProxy, "new-external-access",
		`{"actor":"`+forgeProxy+`","grantee":"`+relay+`","event_type":"trust_added"}`)

	out := assembleIdentity(s, f)
	if out.Grantor != relay {
		t.Errorf("Grantor = %q, want the ASSUMED role %q (the trust boundary exercised — grantor, NOT the caller)", out.Grantor, relay)
	}
	if out.Grantee != forgeProxy {
		t.Errorf("Grantee = %q, want the CALLING principal %q (it newly gained the capability — grantee)", out.Grantee, forgeProxy)
	}
	if out.Capability == "" {
		t.Error("Capability is empty; want a non-empty plain-language capability for a trust_added grant")
	}
	if out.FieldPaths["grantor"] == "" || out.FieldPaths["grantee"] == "" {
		t.Errorf("FieldPaths[grantor]=%q FieldPaths[grantee]=%q, both should be populated", out.FieldPaths["grantor"], out.FieldPaths["grantee"])
	}
}

// TestAssembleIdentity_GrantDirection_TrustAddedPermission proves a trust_added
// grant carrying an explicit permission uses it verbatim as the capability.
func TestAssembleIdentity_GrantDirection_TrustAddedPermission(t *testing.T) {
	s := newTempStore(t)
	f := seedGrantEvent(t, s, "evt-trust-2", "caller-arn", "new-external-access",
		`{"actor":"caller-arn","grantee":"role-arn","permission":"bedrock:InvokeModel","event_type":"trust_added"}`)
	out := assembleIdentity(s, f)
	if out.Grantor != "role-arn" || out.Grantee != "caller-arn" {
		t.Errorf("Grantor/Grantee = %q/%q, want role-arn/caller-arn (flipped)", out.Grantor, out.Grantee)
	}
	if out.Capability != "bedrock:InvokeModel" {
		t.Errorf("Capability = %q, want the explicit permission verbatim", out.Capability)
	}
}

// TestAssembleIdentity_GrantDirection_GitHubCollaborator proves the GitHub
// collaborator/member add shape is NOT flipped: the performing actor is the
// grantor, the added principal is the grantee, and the permission is the
// capability.
func TestAssembleIdentity_GrantDirection_GitHubCollaborator(t *testing.T) {
	s := newTempStore(t)
	f := seedGrantEvent(t, s, "evt-collab-1", "repo-admin", "new-external-access",
		`{"actor":"repo-admin","grantee":"newcollab","event_type":"repo.add_collaborator","permission":"write"}`)
	out := assembleIdentity(s, f)
	if out.Grantor != "repo-admin" {
		t.Errorf("Grantor = %q, want repo-admin (NOT flipped for collaborator adds)", out.Grantor)
	}
	if out.Grantee != "newcollab" {
		t.Errorf("Grantee = %q, want newcollab", out.Grantee)
	}
	if !strings.Contains(out.Capability, "write") {
		t.Errorf("Capability = %q, want it to mention the granted role %q", out.Capability, "write")
	}
}

// TestAssembleIdentity_GrantDirection_PrivEscalation proves the priv-escalation
// shape maps actor=grantor, target_user=grantee, role=capability.
func TestAssembleIdentity_GrantDirection_PrivEscalation(t *testing.T) {
	s := newTempStore(t)
	f := seedGrantEvent(t, s, "evt-priv-1", "admin1", "priv-escalation",
		`{"actor":"admin1","role":"admin","target_user":"newadmin","event_type":"admin_action"}`)
	out := assembleIdentity(s, f)
	if out.Grantor != "admin1" {
		t.Errorf("Grantor = %q, want admin1", out.Grantor)
	}
	if out.Grantee != "newadmin" {
		t.Errorf("Grantee = %q, want newadmin (the target_user receiving the role)", out.Grantee)
	}
	if !strings.Contains(out.Capability, "admin") {
		t.Errorf("Capability = %q, want it to mention the granted role %q", out.Capability, "admin")
	}
}

// TestAssembleIdentity_GrantDirection_NotApplicable proves a non-grant finding
// type carries NO grant direction and does not fail — the identity section
// stays clean, no grantor/grantee/capability keys, no Error.
func TestAssembleIdentity_GrantDirection_NotApplicable(t *testing.T) {
	s := newTempStore(t)
	f := seedGrantEvent(t, s, "evt-login-1", "someone", "unusual-login",
		`{"actor":"someone","grantee":"else","event_type":"trust_added"}`)
	out := assembleIdentity(s, f)
	if out.Grantor != "" || out.Grantee != "" || out.Capability != "" {
		t.Errorf("Grantor/Grantee/Capability = %q/%q/%q, want all empty for a non-grant finding type", out.Grantor, out.Grantee, out.Capability)
	}
	for _, k := range []string{"grantor", "grantee", "capability"} {
		if _, ok := out.FieldPaths[k]; ok {
			t.Errorf("FieldPaths[%q] should be absent for a non-grant finding", k)
		}
	}
	if out.Error != "" {
		t.Errorf("Error = %q, want empty — an unrecognized type is not a failure", out.Error)
	}
}

// TestAssembleIdentity_GrantDirection_MalformedEvidence proves fault isolation:
// a grant-aware finding whose Evidence is empty/invalid degrades ONLY the grant
// sub-fields, not the whole identity section (Error stays empty).
func TestAssembleIdentity_GrantDirection_MalformedEvidence(t *testing.T) {
	s := newTempStore(t)
	for _, tc := range []struct {
		name     string
		evidence string
	}{
		{"empty", ``},
		{"invalid_json", `{not json`},
		{"unrecognized_event_type", `{"actor":"a","grantee":"b","event_type":"who_knows"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := seedGrantEvent(t, s, "evt-mal-"+tc.name, "actor-x", "new-external-access", tc.evidence)
			out := assembleIdentity(s, f)
			if out.Grantor != "" || out.Grantee != "" || out.Capability != "" {
				t.Errorf("Grantor/Grantee/Capability = %q/%q/%q, want all empty", out.Grantor, out.Grantee, out.Capability)
			}
			if out.Error != "" {
				t.Errorf("Error = %q, want empty — a malformed grant blob must degrade only the grant sub-fields", out.Error)
			}
		})
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
