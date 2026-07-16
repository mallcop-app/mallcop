package streamshim

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeUpstream stands in for Forge: it 501s any streaming request (exactly as
// real Forge does) and 400s max_tokens over the cap, otherwise returns a normal
// completion. It records the last request it saw.
type fakeUpstream struct {
	sawStream    bool
	sawMaxTokens float64
	sawAuth      string
	sawPath      string
}

func (f *fakeUpstream) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.sawPath = r.URL.Path
		f.sawAuth = r.Header.Get("Authorization")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if s, ok := body["stream"].(bool); ok && s {
			f.sawStream = true
			http.Error(w, `{"error":{"type":"not_implemented","message":"Streaming requires Premium plan."}}`, http.StatusNotImplemented)
			return
		}
		if mt, ok := body["max_tokens"].(float64); ok {
			f.sawMaxTokens = mt
			if mt > MaxTokensCap {
				http.Error(w, `{"error":{"type":"invalid_request_error","message":"max_tokens must not exceed 4096"}}`, http.StatusBadRequest)
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "chatcmpl-1",
			"model": "heal",
			"choices": []map[string]any{{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": "hello world"},
				"finish_reason": "stop",
			}},
		})
	}
}

func startShim(t *testing.T) (*Shim, *fakeUpstream) {
	t.Helper()
	up := &fakeUpstream{}
	upSrv := httptest.NewServer(up.handler())
	t.Cleanup(upSrv.Close)
	sh, err := Start(upSrv.URL+"/v1", MaxTokensCap, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sh.Close() })
	return sh, up
}

// TestBridgesStreamingRequestToNonStreamingUpstream is the core proof: a client
// that streams gets an SSE reply, while the UPSTREAM never sees stream=true (so
// it never 501s) — the exact failure that blocked the code lane.
func TestBridgesStreamingRequestToNonStreamingUpstream(t *testing.T) {
	sh, up := startShim(t)

	req := `{"model":"heal","stream":true,"max_tokens":32000,"messages":[{"role":"user","content":"hi"}]}`
	resp, err := http.Post(sh.BaseURL()+"/chat/completions", "application/json", strings.NewReader(req))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if up.sawStream {
		t.Error("upstream saw stream=true — the shim must force it false (else 501)")
	}
	if up.sawMaxTokens != MaxTokensCap {
		t.Errorf("upstream saw max_tokens=%v, want clamped to %d", up.sawMaxTokens, MaxTokensCap)
	}

	// The SSE body must carry the assistant content in a delta, then [DONE].
	var content string
	var sawDone bool
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimPrefix(sc.Text(), "data: ")
		if line == "[DONE]" {
			sawDone = true
			continue
		}
		if line == "" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(line), &chunk); err == nil && len(chunk.Choices) > 0 {
			content += chunk.Choices[0].Delta.Content
		}
	}
	if content != "hello world" {
		t.Errorf("reassembled content = %q, want %q", content, "hello world")
	}
	if !sawDone {
		t.Error("SSE stream missing terminal [DONE]")
	}
}

// TestForwardsAuthorizationUnchanged pins the credential-path contract: the
// caller's bearer token is forwarded verbatim; the shim adds/alters no auth.
func TestForwardsAuthorizationUnchanged(t *testing.T) {
	sh, up := startShim(t)
	req, _ := http.NewRequest(http.MethodPost, sh.BaseURL()+"/chat/completions",
		strings.NewReader(`{"model":"heal","stream":true,"messages":[]}`))
	req.Header.Set("Authorization", "Bearer mallcop-sk-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if up.sawAuth != "Bearer mallcop-sk-secret" {
		t.Errorf("upstream Authorization = %q, want forwarded unchanged", up.sawAuth)
	}
}

// TestNonStreamingClientPassthrough: a client that does NOT stream gets the raw
// JSON back (no SSE framing), and the upstream still never streams.
func TestNonStreamingClientPassthrough(t *testing.T) {
	sh, up := startShim(t)
	resp, err := http.Post(sh.BaseURL()+"/chat/completions", "application/json",
		strings.NewReader(`{"model":"heal","messages":[]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json passthrough", ct)
	}
	if up.sawStream {
		t.Error("upstream saw stream=true on a non-streaming client")
	}
}

// TestUpstreamErrorPassthrough: a non-2xx upstream is relayed with its status and
// body, not swallowed into an SSE 200.
func TestUpstreamErrorPassthrough(t *testing.T) {
	up := &fakeUpstream{}
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"type":"authentication_error","message":"Invalid API key"}}`, http.StatusUnauthorized)
	}))
	t.Cleanup(upSrv.Close)
	sh, err := Start(upSrv.URL+"/v1", MaxTokensCap, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sh.Close() })
	_ = up

	resp, err := http.Post(sh.BaseURL()+"/chat/completions", "application/json",
		strings.NewReader(`{"model":"heal","stream":true,"messages":[]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 relayed", resp.StatusCode)
	}
}

// TestRelaysToolCalls is the regression for the bug that made every authoring run
// write nothing: an agentic model returns content:null + tool_calls +
// finish_reason=tool_calls, and the SSE delta MUST carry the tool_calls through
// (opencode authors files via them).
func TestRelaysToolCalls(t *testing.T) {
	up := &fakeUpstream{}
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		up.sawStream, _ = body["stream"].(bool)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-tc","model":"heal","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"tc1","type":"function","function":{"name":"write_file","arguments":"{\"path\":\"foo.txt\"}"}}]},"finish_reason":"tool_calls"}]}`)
	}))
	t.Cleanup(upSrv.Close)
	sh, err := Start(upSrv.URL+"/v1", MaxTokensCap, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sh.Close() })

	resp, err := http.Post(sh.BaseURL()+"/chat/completions", "application/json",
		strings.NewReader(`{"model":"heal","stream":true,"messages":[]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	var sawToolCall, sawFinish bool
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimPrefix(sc.Text(), "data: ")
		if line == "" || line == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Function struct {
							Name string `json:"name"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(line), &chunk); err == nil && len(chunk.Choices) > 0 {
			if len(chunk.Choices[0].Delta.ToolCalls) > 0 && chunk.Choices[0].Delta.ToolCalls[0].Function.Name == "write_file" {
				sawToolCall = true
			}
			if chunk.Choices[0].FinishReason == "tool_calls" {
				sawFinish = true
			}
		}
	}
	if !sawToolCall {
		t.Error("SSE delta dropped tool_calls — the client would author nothing")
	}
	if !sawFinish {
		t.Error("SSE chunk lost finish_reason=tool_calls")
	}
}

// TestBindsLoopbackOnly ensures the shim never advertises a non-loopback address.
func TestBindsLoopbackOnly(t *testing.T) {
	sh, _ := startShim(t)
	if !strings.Contains(sh.BaseURL(), "127.0.0.1") {
		t.Errorf("BaseURL = %q, want 127.0.0.1 loopback", sh.BaseURL())
	}
}
