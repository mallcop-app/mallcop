// forge_usage.go — per-scenario Forge usage querying for mallcop-academy.
//
// Academy queries GET /v1/usage from the Forge inference proxy after each
// scenario reaches a terminal state. The query uses a time window
// [postedAt, terminalAt] to attribute usage events to the scenario.
//
// Auth: requires the same FORGE_API_KEY used to bootstrap the deployment
// (RoleTenant level — /v1/usage requires at minimum RoleTenant).
//
// Concurrency note: with max_concurrent > 1, time windows for simultaneous
// scenarios overlap. Attribution is approximate — events from one concurrent
// scenario may be counted in another. The run-level totals (sum across all
// scenarios) remain accurate to the actual Forge metering.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ScenarioUsage holds per-scenario Forge usage totals derived from metering data.
type ScenarioUsage struct {
	ForgeCalls int     `json:"forge_calls"`
	TokensIn   int64   `json:"tokens_in"`
	TokensOut  int64   `json:"tokens_out"`
	CostUSD    float64 `json:"cost_usd,omitempty"`
}

// usageFetcher fetches per-scenario Forge usage from the metering API.
// Implementations must be safe for concurrent use.
type usageFetcher interface {
	// fetch returns the usage totals for events that occurred between since and until.
	// Returns zero-value ScenarioUsage on error (non-fatal — academy continues without metrics).
	fetch(since, until time.Time) (ScenarioUsage, error)
}

// forgeUsageEvent is the JSON shape of one event in GET /v1/usage response.
type forgeUsageEvent struct {
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
	Status       string  `json:"status"`
}

// forgeUsageResponse is the JSON shape returned by GET /v1/usage.
type forgeUsageResponse struct {
	Object string            `json:"object"`
	Data   []forgeUsageEvent `json:"data"`
}

// httpUsageFetcher queries the Forge REST API for usage events.
type httpUsageFetcher struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// newHTTPUsageFetcher constructs a fetcher from env vars:
//   - FORGE_BASE_URL (default: https://forge.3dl.dev)
//   - FORGE_API_KEY
//
// Returns nil if FORGE_API_KEY is not set (caller should use noopUsageFetcher).
func newHTTPUsageFetcher() *httpUsageFetcher {
	apiKey := os.Getenv("FORGE_API_KEY")
	if apiKey == "" {
		return nil
	}
	baseURL := os.Getenv("FORGE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://forge.3dl.dev"
	}
	return &httpUsageFetcher{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// fetch queries GET /v1/usage?since=<since>&until=<until> and returns aggregated totals.
// Only events with status="ok" are counted.
func (f *httpUsageFetcher) fetch(since, until time.Time) (ScenarioUsage, error) {
	url := fmt.Sprintf("%s/v1/usage?since=%s&until=%s",
		f.baseURL,
		since.UTC().Format(time.RFC3339),
		until.UTC().Format(time.RFC3339),
	)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ScenarioUsage{}, fmt.Errorf("forge usage: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return ScenarioUsage{}, fmt.Errorf("forge usage: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ScenarioUsage{}, fmt.Errorf("forge usage: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return ScenarioUsage{}, fmt.Errorf("forge usage: server returned %d: %s", resp.StatusCode, body)
	}

	var usageResp forgeUsageResponse
	if err := json.Unmarshal(body, &usageResp); err != nil {
		return ScenarioUsage{}, fmt.Errorf("forge usage: parse response: %w", err)
	}

	var out ScenarioUsage
	for _, e := range usageResp.Data {
		if e.Status != "ok" {
			continue
		}
		out.ForgeCalls++
		out.TokensIn += int64(e.InputTokens)
		out.TokensOut += int64(e.OutputTokens)
		out.CostUSD += e.CostUSD
	}
	return out, nil
}

// noopUsageFetcher returns zero values and no error. Used when FORGE_API_KEY
// is absent (e.g., --no-judge runs in isolation without Forge credentials).
type noopUsageFetcher struct{}

func (n *noopUsageFetcher) fetch(_, _ time.Time) (ScenarioUsage, error) {
	return ScenarioUsage{}, nil
}
