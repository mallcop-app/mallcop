package redact

import (
	"strings"
	"testing"
)

// TestRedact proves the exact subkey and any other mallcop-sk-* token is
// scrubbed from a transcript.
func TestRedact(t *testing.T) {
	sk := "mallcop-sk-abc123_-XYZ"
	other := "mallcop-sk-someOtherKey999"
	transcript := "connecting with " + sk + " then leaked " + other + " end"

	out := Redact(transcript, sk)
	if strings.Contains(out, "mallcop-sk") {
		t.Errorf("Redact left a mallcop-sk token: %q", out)
	}
	if strings.Contains(out, sk) {
		t.Errorf("Redact left the exact subkey: %q", out)
	}
	if strings.Contains(out, other) {
		t.Errorf("Redact left another mallcop-sk key: %q", out)
	}
	if !strings.Contains(out, redactedMarker) {
		t.Errorf("Redact did not insert the marker: %q", out)
	}

	// Empty subkey still scrubs the pattern.
	out2 := Redact("token "+other+" here", "")
	if strings.Contains(out2, "mallcop-sk") {
		t.Errorf("Redact with empty subkey left a token: %q", out2)
	}
}

// TestRedactVendorKeys proves the BYOI hygiene: the EXACT vendor key handed to
// Redact is scrubbed regardless of shape, and a SIBLING vendor key emitted by
// nested tooling (not the exact one) is caught by the extended regexp — while a
// mallcop-sk-* key is still redacted whole (no dangling "mallcop-" prefix).
func TestRedactVendorKeys(t *testing.T) {
	// (1) Exact BYOI key of a vendor shape is scrubbed by the exact-string pass.
	exact := "sk-ant-api03-LEAKEDoftheexactkey123456"
	out := Redact("auth: Bearer "+exact, exact)
	if strings.Contains(out, exact) || strings.Contains(out, "sk-ant") {
		t.Errorf("exact vendor key not scrubbed: %q", out)
	}

	// (2) A SIBLING sk-ant-* key we were NOT handed is caught by the regexp.
	sibling := "sk-ant-api03-SIBLINGkeyneverpassed987654"
	out = Redact("nested tool leaked "+sibling, "")
	if strings.Contains(out, sibling) || strings.Contains(out, "sk-ant") {
		t.Errorf("sibling vendor key not scrubbed by regexp: %q", out)
	}

	// (3) A conservative bare sk-<20+ alnum> key is caught.
	bare := "sk-" + strings.Repeat("A1b2", 8) // 32 alnum chars
	out = Redact("key="+bare, "")
	if strings.Contains(out, bare) {
		t.Errorf("bare sk- vendor key not scrubbed: %q", out)
	}

	// (4) A mallcop key is still redacted WHOLE — the bare-sk alternative must not
	// nibble the tail and leave a dangling "mallcop-" prefix.
	mk := "mallcop-sk-abcdefghijklmnopqrstuvwxyz0123"
	out = Redact("using "+mk, "")
	if strings.Contains(out, "mallcop-sk") {
		t.Errorf("mallcop key not scrubbed: %q", out)
	}
	if strings.Contains(out, "mallcop-"+redactedMarker) {
		t.Errorf("mallcop key redacted only partially (dangling prefix): %q", out)
	}

	// (5) Ordinary prose with a short "sk-" is NOT over-redacted.
	prose := "the task sk-002 is done"
	if got := Redact(prose, ""); got != prose {
		t.Errorf("Redact over-redacted prose: %q → %q", prose, got)
	}
}
