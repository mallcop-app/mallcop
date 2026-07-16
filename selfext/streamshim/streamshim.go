// Package streamshim bridges a streaming-only inference client (opencode, which
// always sends `stream: true`) to a NON-streaming upstream (an inference
// endpoint that hard-501s streaming: "Reject streaming — 501"). It listens on
// loopback, rewrites each request to be non-streaming (and caps max_tokens to
// the endpoint's ceiling), forwards it to the real endpoint verbatim otherwise,
// and replays the single JSON response back to the client as a minimal
// Server-Sent Events stream when the client asked to stream.
//
// It is a pure transport bridge on the credential path: the caller's own
// Authorization header is forwarded UNCHANGED and never logged. The shim adds no
// auth, holds no key, and rewrites only `stream` and `max_tokens`. It binds
// 127.0.0.1 only.
//
// This exists because every agentic coding tool streams unconditionally; the
// durable fix is the endpoint implementing SSE passthrough, after
// which the engine drops the shim and points opencode straight at the endpoint.
package streamshim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// MaxTokensCap is the inference endpoint's hard per-request output ceiling (it
// 400s above this). opencode requests far more, so the shim clamps down to it.
const MaxTokensCap = 4096

// Shim is a running loopback stream→non-stream bridge. Zero value is not usable;
// construct with Start.
type Shim struct {
	srv      *http.Server
	ln       net.Listener
	target   string // upstream base URL including the /v1 suffix, e.g. https://inference.example/v1
	clampMax int    // max_tokens ceiling to clamp to; <=0 disables the clamp
	client   *http.Client
	log      *slog.Logger
}

// Start binds a loopback listener and begins serving. targetBaseURL is the real
// upstream base URL WITH its /v1 suffix (the same string the adapter would
// otherwise give opencode). clampMaxTokens caps each request's max_tokens (use
// MaxTokensCap for the metered rail; pass <=0 to leave max_tokens untouched,
// e.g. for a BYOI endpoint with its own limits). The returned Shim serves until
// Close.
func Start(targetBaseURL string, clampMaxTokens int, logger *slog.Logger) (*Shim, error) {
	if strings.TrimSpace(targetBaseURL) == "" {
		return nil, errors.New("streamshim: target base URL is empty")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("streamshim: listen: %w", err)
	}
	s := &Shim{
		ln:       ln,
		target:   strings.TrimRight(targetBaseURL, "/"),
		clampMax: clampMaxTokens,
		client:   &http.Client{Timeout: 5 * time.Minute},
		log:      logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// BaseURL is the loopback base URL to hand the inference client, WITH the /v1
// suffix (so the adapter's own "append /v1" logic is bypassed — pass this
// through unchanged). Requests to <BaseURL>/chat/completions are bridged.
func (s *Shim) BaseURL() string {
	return fmt.Sprintf("http://%s/v1", s.ln.Addr().String())
}

// Close stops the server.
func (s *Shim) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func (s *Shim) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "streamshim: only POST is bridged", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		http.Error(w, "streamshim: read request", http.StatusBadRequest)
		return
	}

	// Was the client asking to stream? Decide the reply shape, then force the
	// upstream request to be non-streaming and clamp max_tokens.
	clientWantsStream, rewritten := rewriteRequest(body, s.clampMax)

	// Forward upstream. Path is preserved (chat/completions or messages); the
	// caller's Authorization and Content-Type are forwarded unchanged.
	upURL := s.target + normalizePath(r.URL.Path)
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upURL, bytes.NewReader(rewritten))
	if err != nil {
		http.Error(w, "streamshim: build upstream request", http.StatusInternalServerError)
		return
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		upReq.Header.Set("Authorization", auth)
	}
	upReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(upReq)
	if err != nil {
		s.log.Error("streamshim: upstream call failed", "err", err)
		http.Error(w, "streamshim: upstream call failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	// A non-2xx upstream (or a non-streaming client) is passed through verbatim.
	if resp.StatusCode/100 != 2 || !clientWantsStream {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	// Streaming client + successful non-streaming upstream body → replay as SSE.
	writeSSE(w, respBody)
}

// normalizePath keeps the sub-path opencode addressed (…/chat/completions or
// …/messages) after the shim's /v1 base. The client hits <BaseURL>/chat/...,
// i.e. /v1/chat/completions; the upstream target already ends in /v1, so strip
// the leading /v1 the client sent.
func normalizePath(p string) string {
	p = strings.TrimPrefix(p, "/v1")
	if p == "" {
		p = "/chat/completions"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// rewriteRequest returns whether the client requested streaming, and the body
// with stream forced false and (when clampMax>0) max_tokens clamped to it. On
// unparseable JSON it reports no-stream and returns the body unchanged (upstream
// will reject it authoritatively).
func rewriteRequest(body []byte, clampMax int) (clientWantsStream bool, out []byte) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return false, body
	}
	if v, ok := m["stream"].(bool); ok && v {
		clientWantsStream = true
	}
	m["stream"] = false
	if clampMax > 0 {
		if mt, ok := numeric(m["max_tokens"]); ok && mt > float64(clampMax) {
			m["max_tokens"] = clampMax
		}
	}
	rewritten, err := json.Marshal(m)
	if err != nil {
		return clientWantsStream, body
	}
	return clientWantsStream, rewritten
}

func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// writeSSE replays a single OpenAI-shape chat.completion JSON body as the SSE
// event sequence opencode's provider expects: one chunk carrying the full
// assistant message as a delta, then [DONE]. This is deliberately minimal —
// opencode reassembles deltas, so a single full-content delta is sufficient.
func writeSSE(w http.ResponseWriter, jsonBody []byte) {
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	chunk := toChunk(jsonBody)
	for _, line := range chunk {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", line)
		if flusher != nil {
			flusher.Flush()
		}
	}
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

// toChunk converts a completion body into the SSE data payload lines. It emits a
// single chunk mirroring the completion's id/model with the whole message as a
// delta and the upstream finish_reason. The delta carries BOTH content and
// tool_calls: agentic clients (opencode) author files via tool_calls with null
// content and finish_reason=tool_calls, so dropping tool_calls silently makes the
// client do nothing. If the body cannot be parsed it is forwarded as one raw data
// line so opencode still sees something rather than hanging.
func toChunk(jsonBody []byte) []string {
	var resp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role      string          `json:"role"`
				Content   *string         `json:"content"`
				ToolCalls json.RawMessage `json:"tool_calls,omitempty"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(jsonBody, &resp); err != nil || len(resp.Choices) == 0 {
		return []string{string(jsonBody)}
	}
	c := resp.Choices[0]
	finish := c.FinishReason
	if finish == "" {
		finish = "stop"
	}
	delta := map[string]any{"role": "assistant"}
	if c.Message.Content != nil {
		delta["content"] = *c.Message.Content
	}
	if len(c.Message.ToolCalls) > 0 && string(c.Message.ToolCalls) != "null" {
		delta["tool_calls"] = c.Message.ToolCalls
	}
	chunk := map[string]any{
		"id":     resp.ID,
		"object": "chat.completion.chunk",
		"model":  resp.Model,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         delta,
			"finish_reason": finish,
		}},
	}
	line, err := json.Marshal(chunk)
	if err != nil {
		return []string{string(jsonBody)}
	}
	return []string{string(line)}
}
