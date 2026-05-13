package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/3dl-dev/mallcop-pro/testutil"
)

// captureStdout redirects os.Stdout to a buffer, runs f, and returns the output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

// TestBalance_MissingToken verifies that runBalance returns an error when no token is set.
// Uses real handleBalance: no Forge call made because the CLI rejects before sending.
func TestBalance_MissingToken(t *testing.T) {
	ff := testutil.FakeForge(t, nil, nil)
	app := testutil.NewServer(t, ff, 1000)
	err := runBalance([]string{"--url", app.URL})
	if err == nil {
		t.Fatal("expected error when no token provided")
	}
	if !strings.Contains(err.Error(), "MALLCOP_SERVICE_TOKEN") {
		t.Errorf("error should mention MALLCOP_SERVICE_TOKEN, got: %v", err)
	}
}

// TestBalance_Unauthorized verifies that runBalance returns an error when the key is unknown.
// Real handleBalance returns 502 (BadGateway) when Forge /v1/keys returns 401 for
// the unknown customer key — the CLI surfaces this as an error.
func TestBalance_Unauthorized(t *testing.T) {
	ff := testutil.FakeForge(t,
		map[string]string{"valid-key": "acct-valid"},
		map[string]string{"acct-valid": `{"account_id":"acct-valid","balance_micro":5000}`},
	)
	app := testutil.NewServer(t, ff, 1000)
	err := runBalance([]string{"--url", app.URL, "--key", "invalid-key"})
	if err == nil {
		t.Fatal("expected error when using unknown key")
	}
	// handleBalance returns 502 when AccountID resolution fails (Forge returned 401).
	// runBalance converts HTTP >= 400 to an error string containing the status code.
	if !strings.Contains(err.Error(), "502") &&
		!strings.Contains(err.Error(), "401") &&
		!strings.Contains(err.Error(), "unauthorized") &&
		!strings.Contains(err.Error(), "failed") {
		t.Errorf("expected auth-failure error, got: %v", err)
	}
}

// TestBalance_HumanReadable verifies human-readable output format with pools.
// Real handleBalance converts micro-USD to donuts via pricing.MicroToDonuts:
//
//	subscription=10000 / 1000 = 10 donuts
//	credits=3000 / 1000 = 3 donuts
//	total=13 donuts
func TestBalance_HumanReadable(t *testing.T) {
	ff := testutil.FakeForge(t,
		map[string]string{"mallcop-sk-test": "acct-test"},
		map[string]string{"acct-test": `{
			"account_id": "acct-test",
			"balance_micro": 13000,
			"pools": {"subscription": 10000, "credits": 3000}
		}`},
	)
	app := testutil.NewServer(t, ff, 1000 /* 1000 micro per donut */)

	out := captureStdout(t, func() {
		if err := runBalance([]string{"--url", app.URL, "--key", "mallcop-sk-test"}); err != nil {
			t.Errorf("runBalance: %v", err)
		}
	})

	if !strings.Contains(out, "13") {
		t.Errorf("expected total donuts (13) in output, got: %q", out)
	}
	if !strings.Contains(out, "subscription") {
		t.Errorf("expected 'subscription' pool in output, got: %q", out)
	}
	if !strings.Contains(out, "credits") {
		t.Errorf("expected 'credits' pool in output, got: %q", out)
	}
}

// TestBalance_JSONOutput verifies --json output format.
// Real handleBalance: subscription=5000 micro / 1000 = 5 donuts, total=5.
func TestBalance_JSONOutput(t *testing.T) {
	ff := testutil.FakeForge(t,
		map[string]string{"mallcop-sk-test": "acct-json"},
		map[string]string{"acct-json": `{
			"account_id": "acct-json",
			"balance_micro": 5000,
			"pools": {"subscription": 5000}
		}`},
	)
	app := testutil.NewServer(t, ff, 1000)

	out := captureStdout(t, func() {
		if err := runBalance([]string{"--url", app.URL, "--key", "mallcop-sk-test", "--json"}); err != nil {
			t.Errorf("runBalance --json: %v", err)
		}
	})

	var resp balanceResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decode JSON output: %v (%q)", err, out)
	}
	if resp.Donuts["total"] != 5 {
		t.Errorf("expected total=5, got %d", resp.Donuts["total"])
	}
	if resp.Donuts["subscription"] != 5 {
		t.Errorf("expected subscription=5, got %d", resp.Donuts["subscription"])
	}
}

// TestBalance_NoPools verifies output when no pool breakdown is present.
// Real handleBalance uses the no-pools path: balance_micro=7000 / 1000 = 7 donuts total.
func TestBalance_NoPools(t *testing.T) {
	ff := testutil.FakeForge(t,
		map[string]string{"mallcop-sk-simple": "acct-simple"},
		map[string]string{"acct-simple": `{"account_id":"acct-simple","balance_micro":7000}`},
	)
	app := testutil.NewServer(t, ff, 1000)

	out := captureStdout(t, func() {
		if err := runBalance([]string{"--url", app.URL, "--key", "mallcop-sk-simple"}); err != nil {
			t.Errorf("runBalance: %v", err)
		}
	})

	if !strings.Contains(out, "7") {
		t.Errorf("expected 7 donuts in output, got: %q", out)
	}
}

// TestBalance_EnvVars verifies MALLCOP_APP_URL and MALLCOP_SERVICE_TOKEN env vars.
// Real handleBalance: balance_micro=99000 / 1000 = 99 donuts.
func TestBalance_EnvVars(t *testing.T) {
	ff := testutil.FakeForge(t,
		map[string]string{"mallcop-sk-env-key": "acct-env"},
		map[string]string{"acct-env": `{"account_id":"acct-env","balance_micro":99000}`},
	)
	app := testutil.NewServer(t, ff, 1000)

	t.Setenv(defaultAppURLEnv, app.URL)
	t.Setenv(defaultServiceTokenEnv, "mallcop-sk-env-key")

	out := captureStdout(t, func() {
		if err := runBalance([]string{}); err != nil {
			t.Errorf("runBalance via env: %v", err)
		}
	})

	if !strings.Contains(out, "99") {
		t.Errorf("expected 99 donuts in output, got: %q", out)
	}
}

// TestBalance_LiveForge exercises the full round-trip: CLI → real mallcop-pro httptest
// server (via testutil.NewServerWithForgeURL) → real Forge (forge.3dl.dev).
// No handler logic is reimplemented here — the real server.handleBalance,
// forge.Client, and pricing.MicroToDonuts are all exercised.
//
// Requires FORGE_API_KEY and FORGE_BASE_URL. When set the test runs unconditionally.
// If Forge is unreachable when env is set the test fails — not skips. This is
// intentional: a set env with an unreachable service is a CI infrastructure problem,
// not a reason to silently pass.
//
// CI secret prereq: mallcoppro-718-ci-key (operator provisions low-limit key).
func TestBalance_LiveForge(t *testing.T) {
	apiKey := os.Getenv("FORGE_API_KEY")
	forgeBaseURL := os.Getenv("FORGE_BASE_URL")
	if apiKey == "" || forgeBaseURL == "" {
		t.Skip("skipping live Forge test: FORGE_API_KEY and FORGE_BASE_URL not set")
	}

	// Evidence per implementer spec §7 — inability claims must be proven with evidence.
	t.Logf("FORGE_API_KEY prefix: %s...", apiKey[:min(12, len(apiKey))])
	t.Logf("FORGE_BASE_URL: %s", forgeBaseURL)

	// Boot a real mallcop-pro httptest server pointing at forge.3dl.dev.
	// The costPerDonutMicro=1000 matches the integration test fixture.
	// If the configured rate changes, this test surfaces it correctly (unlike
	// the old hardcoded fakeMallcopApp whose shape was author-driven, not
	// derived from the real handleBalance output).
	app := testutil.NewServerWithForgeURL(t, apiKey, forgeBaseURL, 1000)

	out := captureStdout(t, func() {
		if err := runBalance([]string{"--url", app.URL, "--key", apiKey}); err != nil {
			t.Errorf("runBalance against live Forge: %v", err)
		}
	})

	t.Logf("Live Forge balance output: %s", strings.TrimSpace(out))

	if !strings.Contains(out, "Donut balance:") {
		t.Errorf("expected 'Donut balance:' in output, got: %q", out)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
