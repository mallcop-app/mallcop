package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubInferenceServer returns an httptest server that answers POST /v1/messages
// with a single text content block carrying replyText — the minimal
// Anthropic-style shape DirectClient decodes. It lets the free-text extraction
// path be proven end-to-end against a real HTTP round-trip (no mocked client),
// with the model's reply fully controlled by the test.
func stubInferenceServer(t *testing.T, replyText string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// Prove the extraction system prompt is actually sent (the SAME prompt as
		// the chat surface) — a regression that dropped it would break the contract.
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "structured self-extension proposal") {
			t.Errorf("request did not carry the extraction system prompt: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"content": []map[string]string{{"type": "text", "text": replyText}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestImproveFlagsMode_EmitsProposalNoInference proves flags mode structures a
// proposal from --detector-id/--event-type with NO inference call (no endpoint
// configured), emitting an in_scope, propose-only envelope.
func TestImproveFlagsMode_EmitsProposalNoInference(t *testing.T) {
	// Ensure no inference endpoint leaks in from the environment — flags mode must
	// not need one.
	t.Setenv(envInferenceURL, "")

	out, err := withStdout(t, func() error {
		return runImprove([]string{
			"--detector-id", "self-owner-grant-off-hours",
			"--event-type", "github.permission.grant",
			"--target-family", "priv-escalation",
			"--rail", "donut",
			"--json",
		})
	})
	if err != nil {
		t.Fatalf("runImprove flags mode: %v", err)
	}
	var prop improveProposal
	if jerr := json.Unmarshal([]byte(out), &prop); jerr != nil {
		t.Fatalf("output not a valid proposal envelope: %v\noutput: %s", jerr, out)
	}
	if prop.SchemaVersion != ImproveSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", prop.SchemaVersion, ImproveSchemaVersion)
	}
	if !prop.InScope {
		t.Fatalf("flags-mode proposal must be in_scope: %+v", prop)
	}
	if prop.DetectorID != "self-owner-grant-off-hours" || prop.EventType != "github.permission.grant" {
		t.Fatalf("proposal fields wrong: %+v", prop)
	}
	if prop.TargetFamily != "priv-escalation" || prop.Rail != "donut" {
		t.Fatalf("proposal optional fields wrong: %+v", prop)
	}
}

// TestImproveFlagsMode_RequiresBothFields proves flags mode rejects a half-specified
// proposal (one of --detector-id/--event-type without the other).
func TestImproveFlagsMode_RequiresBothFields(t *testing.T) {
	if err := runImprove([]string{"--detector-id", "x"}); err == nil {
		t.Fatal("expected error when --event-type is missing in flags mode")
	}
	if err := runImprove([]string{"--event-type", "y"}); err == nil {
		t.Fatal("expected error when --detector-id is missing in flags mode")
	}
}

// TestImproveFreeText_ExtractsInScopeProposal proves free-text mode makes ONE
// inference call with the extraction prompt and emits the structured, in_scope
// proposal the model returned — end-to-end over a real HTTP round-trip.
func TestImproveFreeText_ExtractsInScopeProposal(t *testing.T) {
	reply := `{"in_scope": true, "kind": "detector", "detector_id": "self-owner-grant-off-hours", "event_type": "github.permission.grant", "target_family": "", "refusal_reason": ""}`
	srv := stubInferenceServer(t, reply)

	out, err := withStdout(t, func() error {
		return runImprove([]string{
			"--base-url", srv.URL,
			"--rail", "donut",
			"--json",
			"watch for admins granting themselves owner outside business hours",
		})
	})
	if err != nil {
		t.Fatalf("runImprove free-text: %v", err)
	}
	var prop improveProposal
	if jerr := json.Unmarshal([]byte(out), &prop); jerr != nil {
		t.Fatalf("output not a valid proposal envelope: %v\noutput: %s", jerr, out)
	}
	if !prop.InScope || prop.DetectorID != "self-owner-grant-off-hours" || prop.EventType != "github.permission.grant" {
		t.Fatalf("free-text proposal wrong: %+v", prop)
	}
	// --rail is a CLI-level field, forwarded onto the proposal even in free-text mode.
	if prop.Rail != "donut" {
		t.Fatalf("rail not forwarded onto free-text proposal: %+v", prop)
	}
}

// TestImproveFreeText_HonestRefusal proves an out-of-scope request is honestly
// refused (in_scope=false + guidance) — NEVER a fabricated detector_id/event_type,
// and NOT an error (a refusal is a legitimate outcome).
func TestImproveFreeText_HonestRefusal(t *testing.T) {
	reply := `{"in_scope": false, "kind": "", "detector_id": "", "event_type": "", "target_family": "", "refusal_reason": "That is a general question; mallcop can instead propose a new detector for a specific source and action."}`
	srv := stubInferenceServer(t, reply)

	out, err := withStdout(t, func() error {
		return runImprove([]string{"--base-url", srv.URL, "--json", "what is the meaning of life?"})
	})
	if err != nil {
		t.Fatalf("a refusal must not be an error: %v", err)
	}
	var prop improveProposal
	if jerr := json.Unmarshal([]byte(out), &prop); jerr != nil {
		t.Fatalf("output not a valid proposal envelope: %v\noutput: %s", jerr, out)
	}
	if prop.InScope {
		t.Fatalf("out-of-scope request must not be in_scope: %+v", prop)
	}
	if prop.DetectorID != "" || prop.EventType != "" {
		t.Fatalf("refusal must NOT fabricate proposal fields: %+v", prop)
	}
	if prop.RefusalReason == "" {
		t.Fatalf("refusal must carry a guidance reason: %+v", prop)
	}
}

// TestImproveFreeText_UnparseableReplyErrors proves a non-JSON model reply is a
// hard error — the command never fabricates a proposal from garbage.
func TestImproveFreeText_UnparseableReplyErrors(t *testing.T) {
	srv := stubInferenceServer(t, "sure! here is a detector for you, buddy")

	_, err := withStdout(t, func() error {
		return runImprove([]string{"--base-url", srv.URL, "watch for x"})
	})
	if err == nil {
		t.Fatal("expected an error for an unparseable model reply")
	}
	if isFindingsError(err) {
		t.Fatalf("unparseable reply must be a real error (exit 2), not the findings sentinel: %v", err)
	}
}

// TestImproveFreeText_RequiresEndpoint proves free-text mode fails loud when no
// inference endpoint is configured (there is no offline extraction, and we must
// never fabricate).
func TestImproveFreeText_RequiresEndpoint(t *testing.T) {
	t.Setenv(envInferenceURL, "")
	if err := runImprove([]string{"watch for repo transfers"}); err == nil {
		t.Fatal("expected an error when no inference endpoint is configured for free-text mode")
	}
}

// TestImprove_ModesAreExclusive proves mixing flags mode with a free-text request
// is rejected rather than silently preferring one.
func TestImprove_ModesAreExclusive(t *testing.T) {
	if err := runImprove([]string{"--detector-id", "x", "--event-type", "y", "some free text"}); err == nil {
		t.Fatal("expected an error when flags mode and free text are combined")
	}
}

// TestImprove_NoInputErrors proves a bare `mallcop improve` with neither flags nor
// free text is a usage error.
func TestImprove_NoInputErrors(t *testing.T) {
	if err := runImprove(nil); err == nil {
		t.Fatal("expected a usage error with no flags and no free text")
	}
}

// TestParseSelfextExtraction proves the strict parse: it tolerates a ```json fence,
// and rejects an in_scope=true reply missing detector_id/event_type (so a
// successful parse always means a complete, dispatchable proposal).
func TestParseSelfextExtraction(t *testing.T) {
	fenced := "```json\n{\"in_scope\":true,\"kind\":\"detector\",\"detector_id\":\"d\",\"event_type\":\"e\",\"target_family\":\"\",\"refusal_reason\":\"\"}\n```"
	got, err := parseSelfextExtraction(fenced)
	if err != nil {
		t.Fatalf("fenced strict JSON must parse: %v", err)
	}
	if !got.InScope || got.DetectorID != "d" || got.EventType != "e" {
		t.Fatalf("parsed extraction wrong: %+v", got)
	}

	incomplete := `{"in_scope":true,"detector_id":"","event_type":""}`
	if _, err := parseSelfextExtraction(incomplete); err == nil {
		t.Fatal("in_scope=true without detector_id/event_type must be rejected")
	}

	if _, err := parseSelfextExtraction("not json at all"); err == nil {
		t.Fatal("non-JSON must be rejected")
	}
}
