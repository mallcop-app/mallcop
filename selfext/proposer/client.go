package proposer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AnthropicClient is the real InferenceClient: it POSTs the Anthropic
// /v1/messages wire shape to {BaseURL}/v1/messages with the per-run key as
// BOTH Bearer and x-api-key, then decodes the response. It is a self-contained
// re-implementation of the Anthropic /v1/messages wire mapping — this engine
// does not depend on an external inference SDK, and the wire mapping IS the
// implementation (no SDK, no framework).
type AnthropicClient struct {
	// BaseURL is the inference endpoint base URL; "/v1/messages" is appended (a
	// trailing slash is tolerated). Required.
	BaseURL string
	// Key is the per-run key (a mallcop-sk-* run key or a BYOI provider key). Sent
	// as both "Authorization: Bearer" and "x-api-key" so an Anthropic-native and
	// an OpenAI-style endpoint both authenticate from the same field. Empty Key
	// sends neither header.
	Key string
	// HTTPClient, if nil, defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// compile-time proof AnthropicClient satisfies the proposer's seam.
var _ InferenceClient = (*AnthropicClient)(nil)

// Messages performs one Anthropic-style /v1/messages exchange. A non-2xx status,
// a transport failure, or a decode failure is returned as an error (never a
// panic); the zero MessagesResponse accompanies any error.
func (c *AnthropicClient) Messages(ctx context.Context, req MessagesRequest) (MessagesResponse, error) {
	var zero MessagesResponse

	if c.BaseURL == "" {
		return zero, fmt.Errorf("proposer: AnthropicClient.BaseURL is empty")
	}
	if req.Model == "" {
		return zero, fmt.Errorf("proposer: no model/lane set on the request")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return zero, fmt.Errorf("proposer: marshal request: %w", err)
	}

	url := strings.TrimRight(c.BaseURL, "/") + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("proposer: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.Key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Key)
		httpReq.Header.Set("x-api-key", c.Key)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return zero, fmt.Errorf("proposer: POST %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, fmt.Errorf("proposer: read response body (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, fmt.Errorf("proposer: %s returned HTTP %d: %s", url, resp.StatusCode, snippet(respBody))
	}

	var out MessagesResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return zero, fmt.Errorf("proposer: decode response (status %d, body %q): %w", resp.StatusCode, snippet(respBody), err)
	}
	return out, nil
}

// snippet bounds an error-embedded body so a large error page does not blow up
// the message.
func snippet(b []byte) string {
	const max = 512
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + " …(truncated)"
	}
	return s
}
