package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
)

const (
	defaultMallcopAppURL = "https://mallcop.app"
	defaultServiceTokenEnv = "MALLCOP_SERVICE_TOKEN"
	defaultAppURLEnv       = "MALLCOP_APP_URL"
)

// balanceResponse matches the JSON returned by GET /v1/balance on mallcop.app.
type balanceResponse struct {
	Donuts map[string]int `json:"donuts"`
	Error  string         `json:"error,omitempty"`
}

func runBalance(args []string) error {
	fs := flag.NewFlagSet("balance", flag.ContinueOnError)
	appURL := fs.String("url", os.Getenv(defaultAppURLEnv), "mallcop.app base URL (default: $MALLCOP_APP_URL or https://mallcop.app)")
	apiKey := fs.String("key", os.Getenv(defaultServiceTokenEnv), "mallcop service token (default: $MALLCOP_SERVICE_TOKEN)")
	asJSON := fs.Bool("json", false, "Output as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *appURL == "" {
		*appURL = defaultMallcopAppURL
	}
	*appURL = strings.TrimRight(*appURL, "/")

	if *apiKey == "" {
		return fmt.Errorf("no service token: set %s or pass --key <token>", defaultServiceTokenEnv)
	}

	req, err := http.NewRequest(http.MethodGet, *appURL+"/v1/balance", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+*apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET /v1/balance: %w", err)
	}
	defer resp.Body.Close()

	var bal balanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&bal); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if resp.StatusCode >= 400 {
		if bal.Error != "" {
			return fmt.Errorf("balance: %s (HTTP %d)", bal.Error, resp.StatusCode)
		}
		return fmt.Errorf("balance: HTTP %d", resp.StatusCode)
	}

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(bal)
	}

	// Human-readable output.
	total, _ := bal.Donuts["total"]
	fmt.Printf("Donut balance: %d 🍩\n", total)

	// Print per-pool breakdown if there are pools beyond "total".
	var pools []string
	for k := range bal.Donuts {
		if k != "total" {
			pools = append(pools, k)
		}
	}
	if len(pools) > 0 {
		sort.Strings(pools)
		for _, pool := range pools {
			fmt.Printf("  %-16s %d\n", pool+":", bal.Donuts[pool])
		}
	}

	return nil
}
