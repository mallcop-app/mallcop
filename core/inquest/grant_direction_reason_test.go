package inquest

import (
	"regexp"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// quotedStrings extracts every %q-quoted substring from a Reason string, in
// order of appearance — e.g. `external trust added: "a" added "b" to ...`
// yields []string{"a", "b"}.
var quotedStringPattern = regexp.MustCompile(`"([^"]*)"`)

func quotedStrings(s string) []string {
	matches := quotedStringPattern.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

// newExternalAccessDetectorFor returns the registered "new-external-access"
// detector from core/detect's live registry, failing the test if it is
// missing (a renamed or de-registered detector should fail loudly here
// rather than silently skip this regression).
func newExternalAccessDetectorFor(t *testing.T) detect.Detector {
	t.Helper()
	for _, d := range detect.Detectors() {
		if d.Name() == "new-external-access" {
			return d
		}
	}
	t.Fatal(`detect.Detectors() has no "new-external-access" detector registered`)
	return nil
}

// TestGrantDirection_ReasonAgreesWithIdentity is the LOAD-BEARING regression
// test for mallcoppro-dc2: it runs the REAL new-external-access detector
// (core/detect/new_external_access.go) end to end — not a hand-built
// evidence blob — then resolves the SAME finding's grant direction via
// resolveGrantDirection (the function assemble.go's identity section and the
// narrate document both read). f.Reason and the assembled grantor/grantee
// fields flow into the SAME narrate document; if they disagree in direction,
// the console states the trust relationship backwards even though the
// structured identity fields are correct (exactly what shipped in the
// v0.17.0 replay this item fixes).
//
// Both new_external_access.go's Reason-building switch AND
// resolveGrantDirection's switch use the sentence shape "X added Y" /
// "X ... for Y" — grantor named first, grantee named second — for every
// branch, including the AWS AssumeRole flip. So the cross-cutting invariant
// this test enforces, for ANY trust_added shape, is: the first %q-quoted
// token in f.Reason equals resolveGrantDirection's grantor, and the second
// equals its grantee. A future edit that updates one side's wording but not
// the other's direction convention breaks this regardless of the exact
// phrasing chosen.
func TestGrantDirection_ReasonAgreesWithIdentity(t *testing.T) {
	d := newExternalAccessDetectorFor(t)

	cases := []struct {
		name string
		ev   event.Event
	}{
		{
			// AWS cross-account AssumeRole: member is set (the assumed
			// role's ARN). resolveGrantDirection FLIPS this shape — the
			// assumed role (relay) is the grantor, the calling principal
			// (forgeProxy) is the grantee. This is the exact shape that
			// shipped backwards on the v0.17.0 replay.
			name: "aws_assume_role_member_set",
			ev: event.Event{
				ID: "evt-dc2-aws-1", Source: "aws", Type: "trust_added",
				Actor:     "arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy",
				Timestamp: time.Now(),
				Payload: rawEventPayload(t, map[string]any{
					"member": "arn:aws:iam::458526671706:role/mallcop-bedrock-relay",
				}),
			},
		},
		{
			// M365 domain-only federation trust: no member field. This
			// shape must stay UNFLIPPED — the configuring admin is the
			// grantor, the named domain is the grantee.
			name: "m365_domain_only_no_member",
			ev: event.Event{
				ID: "evt-dc2-m365-1", Source: "azure", Type: "trust_added",
				Actor:     "admin@contoso.onmicrosoft.com",
				Timestamp: time.Now(),
				Payload: rawEventPayload(t, map[string]any{
					"domain": "evil.example.com",
				}),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := d.Detect([]event.Event{tc.ev}, &baseline.Baseline{})
			if len(findings) != 1 {
				t.Fatalf("Detect() returned %d findings, want 1", len(findings))
			}
			f := findings[0]

			grantor, grantee, _ := resolveGrantDirection(f)
			if grantor == "" || grantee == "" {
				t.Fatalf("resolveGrantDirection returned empty grantor/grantee for finding %+v", f)
			}

			quoted := quotedStrings(f.Reason)
			if len(quoted) < 2 {
				t.Fatalf("f.Reason = %q has fewer than 2 quoted tokens; want at least [grantor, grantee]", f.Reason)
			}
			if quoted[0] != grantor {
				t.Errorf("f.Reason names %q first, but resolveGrantDirection says the GRANTOR is %q — "+
					"Reason and the assembled identity fields disagree on trust direction (mallcoppro-dc2). Reason=%q",
					quoted[0], grantor, f.Reason)
			}
			if quoted[1] != grantee {
				t.Errorf("f.Reason names %q second, but resolveGrantDirection says the GRANTEE is %q — "+
					"Reason and the assembled identity fields disagree on trust direction (mallcoppro-dc2). Reason=%q",
					quoted[1], grantee, f.Reason)
			}
		})
	}
}
