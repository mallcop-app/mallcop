package inference

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
)

// sampleRequest builds a MessagesRequest carrying a tool definition, mirroring
// what the agent loop will send: a user turn plus an advertised tool. The tool's
// input_schema is an arbitrary JSON object so we exercise the `any` field.
func sampleRequest() agent.MessagesRequest {
	return agent.MessagesRequest{
		Model:     "mallcop-default",
		MaxTokens: 256,
		System:    "You are a security triage analyst.",
		Messages: []agent.Message{
			{
				Role:    "user",
				Content: []agent.ContentBlock{{Type: "text", Text: "Triage finding fnd_001."}},
			},
		},
		Tools: []agent.Tool{
			{
				Name:        "resolve_finding",
				Description: "Record the resolution for a finding.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"action": map[string]any{"type": "string"},
						"reason": map[string]any{"type": "string"},
					},
					"required": []string{"action", "reason"},
				},
			},
		},
	}
}

// TestDirectClient_ToolUseTurn drives a DirectClient against a scripted
// Anthropic-compatible server that returns a tool_use block followed (on the
// second call) by a final text block — the canonical two-turn tool loop. We
// assert: (1) the request wire shape carried the tool definition through to the
// server, (2) the tool_use block round-trips into the typed response, and (3) the
// auth headers (both Bearer and x-api-key) are set from the single Key field.
func TestDirectClient_ToolUseTurn(t *testing.T) {
	var gotBodies []string
	var sawBearer, sawXAPIKey bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "Bearer test-key" {
			sawBearer = true
		}
		if r.Header.Get("x-api-key") == "test-key" {
			sawXAPIKey = true
		}
		buf, _ := io.ReadAll(r.Body)
		gotBodies = append(gotBodies, string(buf))

		w.Header().Set("Content-Type", "application/json")
		// First call: emit a tool_use block + stop_reason "tool_use".
		// Second call (after a tool_result is appended by the loop): final text.
		var resp map[string]any
		if len(gotBodies) == 1 {
			resp = map[string]any{
				"type":        "message",
				"role":        "assistant",
				"stop_reason": "tool_use",
				"content": []map[string]any{
					{
						"type":  "tool_use",
						"id":    "toolu_001",
						"name":  "resolve_finding",
						"input": map[string]any{"action": "escalate", "reason": "unknown actor"},
					},
				},
			}
		} else {
			resp = map[string]any{
				"type":        "message",
				"role":        "assistant",
				"stop_reason": "end_turn",
				"content": []map[string]any{
					{"type": "text", "text": "Finding escalated for human review."},
				},
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := &DirectClient{BaseURL: srv.URL, Key: "test-key", Model: "ignored-because-req-has-model"}

	// --- turn 1: expect tool_use ------------------------------------------------
	resp, err := c.Messages(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("turn 1 Messages: unexpected error: %v", err)
	}
	if resp.StopReason != "tool_use" {
		t.Fatalf("turn 1 stop_reason = %q, want %q", resp.StopReason, "tool_use")
	}
	if len(resp.Content) != 1 || resp.Content[0].Type != "tool_use" {
		t.Fatalf("turn 1 content = %+v, want a single tool_use block", resp.Content)
	}
	tu := resp.Content[0]
	if tu.ID != "toolu_001" || tu.Name != "resolve_finding" {
		t.Fatalf("turn 1 tool_use id/name = %q/%q, want toolu_001/resolve_finding", tu.ID, tu.Name)
	}
	input, ok := tu.Input.(map[string]any)
	if !ok {
		t.Fatalf("turn 1 tool_use input is %T, want map", tu.Input)
	}
	if input["action"] != "escalate" {
		t.Fatalf("turn 1 tool_use input action = %v, want escalate", input["action"])
	}

	// --- assert the request wire shape carried the tool definition --------------
	if len(gotBodies) != 1 {
		t.Fatalf("server saw %d bodies after turn 1, want 1", len(gotBodies))
	}
	if !strings.Contains(gotBodies[0], `"resolve_finding"`) {
		t.Fatalf("turn 1 request body did not carry the tool definition:\n%s", gotBodies[0])
	}
	if !strings.Contains(gotBodies[0], `"tools"`) {
		t.Fatalf("turn 1 request body missing tools field:\n%s", gotBodies[0])
	}
	if !strings.Contains(gotBodies[0], `"input_schema"`) {
		t.Fatalf("turn 1 request body missing input_schema:\n%s", gotBodies[0])
	}

	// --- both auth schemes set from the single Key field ------------------------
	if !sawBearer {
		t.Error("server never saw Authorization: Bearer <Key>")
	}
	if !sawXAPIKey {
		t.Error("server never saw x-api-key: <Key>")
	}

	// --- turn 2: terminal text turn (simulate the loop sending a tool_result) ---
	follow := sampleRequest()
	follow.Messages = append(follow.Messages,
		agent.Message{Role: "assistant", Content: []agent.ContentBlock{tu}},
		agent.Message{Role: "user", Content: []agent.ContentBlock{{
			Type:      "tool_result",
			ToolUseID: tu.ID,
			Content:   "ok",
		}}},
	)
	resp2, err := c.Messages(context.Background(), follow)
	if err != nil {
		t.Fatalf("turn 2 Messages: unexpected error: %v", err)
	}
	if resp2.StopReason != "end_turn" {
		t.Fatalf("turn 2 stop_reason = %q, want end_turn", resp2.StopReason)
	}
	if len(resp2.Content) != 1 || resp2.Content[0].Type != "text" {
		t.Fatalf("turn 2 content = %+v, want a single text block", resp2.Content)
	}
	if !strings.Contains(resp2.Content[0].Text, "escalated") {
		t.Fatalf("turn 2 text = %q, want it to mention escalation", resp2.Content[0].Text)
	}
}

// TestDirectClient_TextOnlyTerminalTurn round-trips against the SHARED
// cannedbackend (the repo's fake Anthropic-compatible /v1/messages server). Its
// /v1/messages handler emits a text-only block with stop_reason end_turn — the
// terminal turn — and records the request body, so we also confirm a request
// carrying tool definitions reaches the backend intact.
func TestDirectClient_TextOnlyTerminalTurn(t *testing.T) {
	be := &cannedbackend.CannedBackend{
		CannedResolutionFunc: func(int) string { return "benign — no action required" },
	}
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	defer be.Stop()

	c := &DirectClient{BaseURL: be.URL(), Key: "mallcop-sk-test", Model: "mallcop-default"}

	resp, err := c.Messages(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Messages against cannedbackend: %v", err)
	}
	if resp.StopReason != "end_turn" {
		t.Fatalf("stop_reason = %q, want end_turn", resp.StopReason)
	}
	if len(resp.Content) != 1 || resp.Content[0].Type != "text" {
		t.Fatalf("content = %+v, want single text block", resp.Content)
	}
	if !strings.Contains(resp.Content[0].Text, "benign") {
		t.Fatalf("text = %q, want it to contain the scripted text", resp.Content[0].Text)
	}

	// The cannedbackend records every request; the tool definition must have
	// traveled the wire onto the backend.
	reqs := be.Requests()
	if len(reqs) != 1 {
		t.Fatalf("cannedbackend saw %d requests, want 1", len(reqs))
	}
	if reqs[0].Path != "/v1/messages" {
		t.Fatalf("cannedbackend path = %q, want /v1/messages", reqs[0].Path)
	}
	if !strings.Contains(string(reqs[0].Body), `"resolve_finding"`) {
		t.Fatalf("cannedbackend request body did not carry the tool definition:\n%s", reqs[0].Body)
	}
}

// TestDirectClient_HTTPErrorSurfacedAsError asserts a non-2xx response becomes a
// Go error (never a panic) and that the error carries the status code and a body
// snippet for diagnostics. The returned response is the zero value.
func TestDirectClient_HTTPErrorSurfacedAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"rate_limit","message":"slow down"}}`))
	}))
	defer srv.Close()

	c := &DirectClient{BaseURL: srv.URL, Key: "k", Model: "m"}

	resp, err := c.Messages(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("expected an error for HTTP 429, got nil")
	}
	if resp.StopReason != "" || resp.Content != nil {
		t.Fatalf("expected zero-value response on error, got %+v", resp)
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error %q does not mention the 429 status", err.Error())
	}
	if !strings.Contains(err.Error(), "rate_limit") {
		t.Errorf("error %q does not carry a body snippet", err.Error())
	}
}

// TestDirectClient_MissingModelIsError proves a request with no model (and no
// client default) fails fast with an error rather than POSTing an invalid body.
func TestDirectClient_MissingModelIsError(t *testing.T) {
	c := &DirectClient{BaseURL: "http://127.0.0.1:1", Key: "k"} // no Model
	req := sampleRequest()
	req.Model = ""
	if _, err := c.Messages(context.Background(), req); err == nil {
		t.Fatal("expected an error when no model is set, got nil")
	}
}

// TestDirectClient_TransportErrorSurfacedAsError proves a connection failure
// (unroutable address) surfaces as a Go error, not a panic.
func TestDirectClient_TransportErrorSurfacedAsError(t *testing.T) {
	// 127.0.0.1:0 is not a connectable address for a client dial.
	c := &DirectClient{BaseURL: "http://127.0.0.1:0", Key: "k", Model: "m"}
	if _, err := c.Messages(context.Background(), sampleRequest()); err == nil {
		t.Fatal("expected a transport error, got nil")
	}
}
