package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mallcop-app/mallcop/core/agent"
)

// DirectClient is a hand-rolled core/agent.Client that POSTs the Anthropic
// /v1/messages wire shape to BaseURL over plain net/http. It carries no SDK and
// no framework — the wire mapping IS the implementation.
//
// The {BaseURL, Key} pair is the OSS-BYOK ⇄ managed-Forge pivot (see doc.go):
// point BaseURL at the vendor for BYOK, or at Forge for the metered managed path.
// Model is the model id placed in the request body; Forge maps it onward.
//
// A zero HTTPClient uses http.DefaultClient. The zero value of DirectClient is
// not usable on its own (BaseURL and Model must be set), but it composes with
// struct literals: inference.DirectClient{BaseURL: url, Key: key, Model: model}.
type DirectClient struct {
	// BaseURL is the inference endpoint root, e.g. "https://forge.example/v1" or
	// "http://127.0.0.1:8080". The /v1/messages suffix is appended; a trailing
	// slash on BaseURL is tolerated.
	BaseURL string

	// Key is the bearer/api credential. For managed Forge this is a mallcop-sk-*
	// tenant key; for BYOK it is the vendor's own key. Sent as both
	// "Authorization: Bearer <Key>" and "x-api-key: <Key>" so an Anthropic-native
	// endpoint (x-api-key) and a Forge/OpenAI-style endpoint (Bearer) both
	// authenticate from the same field. Empty Key sends neither header.
	Key string

	// Model is the model identifier placed in the request body's "model" field if
	// the per-request Model is empty. A per-request MessagesRequest.Model always
	// wins when set.
	Model string

	// HTTPClient, if nil, defaults to http.DefaultClient. Injectable for tests and
	// for callers that need custom timeouts/transport.
	HTTPClient *http.Client
}

// compile-time proof DirectClient satisfies the agent seam.
var _ agent.Client = (*DirectClient)(nil)

// Messages performs one Anthropic-style /v1/messages exchange. It marshals req
// to the Anthropic wire JSON, POSTs it to {BaseURL}/v1/messages with the auth
// headers, and decodes the response body back into an agent.MessagesResponse.
//
// A non-2xx status is surfaced as a Go error carrying the status and a snippet of
// the response body — never a panic. Transport, marshal, and decode failures are
// likewise returned as errors. The zero-value MessagesResponse is returned
// alongside any error.
func (c *DirectClient) Messages(ctx context.Context, req agent.MessagesRequest) (agent.MessagesResponse, error) {
	var zero agent.MessagesResponse

	if c.BaseURL == "" {
		return zero, fmt.Errorf("inference: DirectClient.BaseURL is empty")
	}

	// A per-request Model wins; otherwise fall back to the client default. The
	// model field is required by the wire contract.
	if req.Model == "" {
		req.Model = c.Model
	}
	if req.Model == "" {
		return zero, fmt.Errorf("inference: no model set (neither request nor DirectClient.Model)")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return zero, fmt.Errorf("inference: marshal request: %w", err)
	}

	url := strings.TrimRight(c.BaseURL, "/") + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("inference: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.Key != "" {
		// Send both auth schemes so the same Key authenticates against an
		// Anthropic-native endpoint (x-api-key) and a Forge/OpenAI-style endpoint
		// (Bearer) without the caller knowing which is on the other end.
		httpReq.Header.Set("Authorization", "Bearer "+c.Key)
		httpReq.Header.Set("x-api-key", c.Key)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return zero, fmt.Errorf("inference: POST %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, fmt.Errorf("inference: read response body (status %d): %w", resp.StatusCode, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, fmt.Errorf("inference: %s returned HTTP %d: %s",
			url, resp.StatusCode, snippet(respBody))
	}

	var out agent.MessagesResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return zero, fmt.Errorf("inference: decode response (status %d, body %q): %w",
			resp.StatusCode, snippet(respBody), err)
	}
	return out, nil
}

// snippet bounds an error-embedded body so a large/HTML error page does not blow
// up the message. It is purely for diagnostics.
func snippet(b []byte) string {
	const max = 512
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}
