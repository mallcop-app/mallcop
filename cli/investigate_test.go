package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// TestRunInvestigate_FlagValidation proves runInvestigate rejects the invalid
// flag combinations loudly (a flag error, never a silent no-op or a fall
// through to an unconfigured investigate.Ask/Serve call).
func TestRunInvestigate_FlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"neither question nor serve", []string{"--store", t.TempDir()}},
		{"both question and serve", []string{"--question", "q", "--serve", "--store", t.TempDir()}},
		{"serve without inbox/outbox/session", []string{"--serve", "--store", t.TempDir()}},
		{"serve with both session and inbox/outbox", []string{"--serve", "--session", "s1", "--inbox", "i", "--outbox", "o", "--store", t.TempDir()}},
		{"missing store", []string{"--question", "q"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if err := runInvestigate(c.args); err == nil {
				t.Fatalf("runInvestigate(%v): want error, got nil", c.args)
			}
		})
	}
}

// TestRunInvestigate_QuestionEndToEnd drives the ACTUAL `mallcop investigate
// --question` CLI path: real flag parsing, real inference-endpoint resolution
// from $MALLCOP_INFERENCE_URL/$MALLCOP_API_KEY (mirroring `mallcop scan`),
// real core/store git-backed store (opened via the same openOrInitStore scan
// uses), and a real inference.DirectClient talking to a scripted HTTP server
// — the ONLY stub is that HTTP server (the LLM transport double), exactly as
// in core/investigate's own integration test. It proves the CLI wiring
// (flags -> investigate.Options -> investigate.Ask -> stdout) actually works
// end-to-end, not just the core loop in isolation.
func TestRunInvestigate_QuestionEndToEnd(t *testing.T) {
	storeDir := t.TempDir()
	st, err := openOrInitStore(storeDir)
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}
	ev := event.Event{
		ID:        "evt-cli-001",
		Source:    "github",
		Type:      "login",
		Actor:     "ghost",
		Timestamp: time.Date(2026, 6, 30, 3, 0, 0, 0, time.UTC),
		Payload:   json.RawMessage(`{"target":"prod-console","action":"login"}`),
	}
	if _, err := st.Append(store.KindEvents, ev); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":        "message",
				"role":        "assistant",
				"stop_reason": "tool_use",
				"content": []map[string]any{
					{"type": "tool_use", "id": "t1", "name": "search_events", "input": map[string]any{"actor": "ghost"}},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":        "message",
			"role":        "assistant",
			"stop_reason": "end_turn",
			"content": []map[string]any{
				{"type": "text", "text": "ghost logged into prod-console; see evt-cli-001."},
			},
		})
	}))
	defer srv.Close()

	t.Setenv(envInferenceURL, srv.URL)
	t.Setenv(envInferenceKey, "test-key")

	stdout := captureStdout(t, func() {
		if err := runInvestigate([]string{"--question", "what did ghost do?", "--store", storeDir}); err != nil {
			t.Fatalf("runInvestigate: %v", err)
		}
	})

	if calls != 2 {
		t.Fatalf("scripted server saw %d calls, want 2 (question turn + tool_result follow-up)", calls)
	}
	if !strings.Contains(stdout, "evt-cli-001") {
		t.Fatalf("stdout = %q, want it to contain the real seeded event id evt-cli-001", stdout)
	}
}
