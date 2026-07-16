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

// TestInTreePromptLabelsDetectorNameAndWidenContract is the mallcoppro-6b9
// regression guard for the IN-TREE lane — the lane the live 4a1 measurement
// exercised, where 10/10 written proposals across three models were rejected at
// gate stage exam-detect (rule exam-detect-new-firing).
//
// It pins BOTH proven defects:
//   - DEFECT 2 (family-token contradiction): the prompt must tell the model to
//     label its scenarios with the DETECTOR NAME (== finding.Type, the token the
//     grader matches — core/eval/detectfidelity.go findingFamilyToken), NEVER
//     the finding family. The trap was --target-family deploy-burst (docs)
//     differing from the detector id authored-deploy-burst; a must_fire label
//     of "deploy-burst" never matches the emitted Type "authored-deploy-burst",
//     so the new scenario fails.
//   - DEFECT 1 (over-broad trigger): the prompt must state the monotonic-widen
//     contract (the gate runs the FULL corpus at base+head; the detector must
//     not newly fire on any pre-existing scenario) and point at a tight-trigger
//     reference, instead of the old "fire on every event of this type, stay
//     SILENT on everything else" instruction that models implemented literally.
func TestInTreePromptLabelsDetectorNameAndWidenContract(t *testing.T) {
	a := &Adapter{Lane: "heal"}
	// TargetFamily DELIBERATELY differs from the detector name — the exact 4a1
	// trap.
	gap := TrustedGap{
		DetectorID:   "authored-deploy-burst",
		EventType:    "github.deployment",
		TargetFamily: "deploy-burst",
		Severity:     "high",
		Actor:        "ci-bot",
		Source:       "connector:github",
	}
	p := a.BuildTaskPrompt(gap, false)

	// (a) The label the prompt tells the model to write is the DETECTOR NAME,
	// and the old family-labelling instruction is gone.
	if !strings.Contains(p, "naming the DETECTOR NAME") {
		t.Error("in-tree prompt must instruct the must_fire/must_not_fire label to be the detector name")
	}
	if strings.Contains(p, "naming family") {
		t.Error("in-tree prompt still tells the model to label scenarios with the finding family (the 6b9 contradiction)")
	}
	// The detector id is the label/finding.Type token (quoted by %q).
	if !strings.Contains(p, `"authored-deploy-burst"`) {
		t.Error("in-tree prompt should name the detector id as the finding.Type / label token")
	}

	// (b) The widen contract is stated explicitly, names the concrete
	// pre-existing scenario a naive trigger widens onto, and points at a tight
	// reference. The old fire-on-every-event framing is gone.
	for _, want := range []string{
		"WIDEN CONTRACT",
		"widens must be monotonic",
		"VA-01-deploy-burst",
		"deployflood/deployflood.go",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("in-tree prompt missing widen/tight-trigger language %q", want)
		}
	}
	if strings.Contains(p, "stay SILENT on everything else") {
		t.Error("in-tree prompt still carries the fire-on-every-event instruction (stay SILENT on everything else)")
	}
}

// TestSidecarPromptLabelsDetectorNameNotFamily proves the SIDECAR
// (customerShaped=true) lane carries the SAME mallcoppro-6b9 fix: the rendered
// expected_detection labels — and the embedded exemplar scenarios — are the
// DETECTOR NAME (== finding.Type), never the finding family, even when
// TargetFamily differs. It also pins the latent sidecar variant of defect 1
// (the Detect requirement previously stated finding.Type == the EVENT type).
func TestSidecarPromptLabelsDetectorNameNotFamily(t *testing.T) {
	a := &Adapter{Lane: "heal"}
	gap := TrustedGap{
		DetectorID:   "authored-widget-leak",
		EventType:    "customer.widget-secret-exposed",
		TargetFamily: "widget-leak", // DIFFERS from the detector name
		Severity:     "high",
		Actor:        "cust-actor",
		Source:       "connector:github",
	}
	p := a.BuildTaskPrompt(gap, true)

	// The rendered scenario labels are the detector name, never the family.
	if !strings.Contains(p, "expected_detection.must_fire: [authored-widget-leak]") {
		t.Error("sidecar must_fire label must be the detector name")
	}
	if strings.Contains(p, "must_fire: [widget-leak]") || strings.Contains(p, "must_not_fire: [widget-leak]") {
		t.Error("sidecar prompt still labels scenarios with the finding family (the 6b9 contradiction)")
	}
	// The embedded exemplar scenarios demonstrate label == finding.Type (the
	// exemplar detector's own Type), never the old misleading example-family.
	if strings.Contains(p, "example-family") {
		t.Error("sidecar exemplar scenarios still use the misleading example-family label")
	}
	if !strings.Contains(p, "must_fire:\n  - authored-synthetic-marker") {
		t.Error("sidecar must-fire exemplar should label with the exemplar detector's own finding.Type")
	}
	// finding.Type is the detector name, NOT the event type (the latent sidecar
	// half of defect 1).
	if !strings.Contains(p, `Type == "authored-widget-leak"`) {
		t.Error("sidecar Detect requirement must state finding.Type is the detector name, not the event type")
	}
	// The widen contract is present in the sidecar lane too.
	if !strings.Contains(p, "newly fire on ANY pre-existing reference scenario") {
		t.Error("sidecar prompt should state the reference-corpus monotonic-widen rule")
	}
}
