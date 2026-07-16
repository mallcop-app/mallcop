package opencode

import (
	"strings"
	"testing"
)

// TestSidecarPromptDocumentsRealEventAPI proves the sidecar (customerShaped)
// authoring prompt carries the REAL pkg/event.Event API (,
// round-6 LIVE evidence): Payload is a json.RawMessage FIELD, read via
// json.Unmarshal, never a Payload(...) method call. This is the belt half of
// the belt-and-suspenders fix (the other half routes the CODE-authoring lane
// to a stronger coder — see the routing tests in adapter_ccc_test.go) — a
// coder that hallucinated ev.Payload("action") as a method failed go
// build/go vet at the sound gate before any behavior was even graded.
func TestSidecarPromptDocumentsRealEventAPI(t *testing.T) {
	a := &Adapter{Lane: "heal"}
	gap := TrustedGap{
		DetectorID:   "authored-widget-leak",
		EventType:    "customer.widget-secret-exposed",
		TargetFamily: "widget-leak",
		Severity:     "high",
		Actor:        "cust-actor",
		Source:       "connector:github",
	}
	p := a.BuildTaskPrompt(gap, true /* customerShaped */)

	for _, want := range []string{
		// States the REAL field, not a method.
		"Payload   json.RawMessage",
		"Payload is a json.RawMessage",
		"FIELD",
		// States the required read pattern.
		"json.Unmarshal(ev.Payload, &m)",
		"FIELD, not a method",
		// The full real Event field set (from mallcop pkg/event/event.go),
		// so no coder has to guess any of them either.
		"ID        string",
		"Source    string",
		"Type      string",
		"Actor     string",
		"Timestamp time.Time",
		"Org       string",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("sidecar prompt missing Event API guidance %q", want)
		}
	}

	// The reference exemplar embedded in the prompt must itself demonstrate
	// the real API — json.Unmarshal, never a method-call payload example.
	if !strings.Contains(p, "json.Unmarshal(ev.Payload, &payload)") {
		t.Error("sidecar exemplar must demonstrate json.Unmarshal(ev.Payload, ...) reading the payload")
	}
	if strings.Contains(p, `ev.Payload("action")`) {
		t.Error("sidecar prompt must NOT contain a method-call payload example (ev.Payload(\"action\"))")
	}
	// Broader guard: no "Payload(" call-shaped occurrence anywhere in the
	// prompt at all (the exact hallucination shape observed live).
	if strings.Contains(p, "Payload(\"") {
		t.Error("sidecar prompt must NOT contain any Payload(\"...\") method-call-shaped example")
	}
}

// TestInTreePromptUnaffected proves the in-tree (customerShaped=false) prompt
// still targets its ORIGINAL own-package shape — this fix only enriches the
// sidecar branch, per 's scope.
func TestInTreePromptUnaffected(t *testing.T) {
	a := &Adapter{Lane: "heal"}
	gap := TrustedGap{DetectorID: "authored-x", EventType: "e", TargetFamily: "f"}
	p := a.BuildTaskPrompt(gap, false)
	if strings.Contains(p, "json.RawMessage") {
		t.Error("in-tree prompt should not need the sidecar's Payload API guidance (it doesn't use Payload)")
	}
}
