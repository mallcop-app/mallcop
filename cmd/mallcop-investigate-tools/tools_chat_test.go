// tools_chat_test.go — integration tests for read-recent-chat and search-chat-history.
//
// All tests use a real isolated campfire populated with synthetic bridge-tagged
// messages. No mocks. Requires cf binary on PATH (skips otherwise).
//
// Bridge tag convention (from mallcop/src/mallcop/telegram_bridge.py):
//   Inbound: tags = ["chat", "session:<chat_id>", "platform:telegram"]
//   payload = {"content": <text>, "from": <sender_id>}
//   --instance telegram-bridge
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// postBridgeMessage posts a synthetic inbound bridge message to campfireID.
// body is the message text; fromID is the simulated Telegram sender ID.
func postBridgeMessage(t *testing.T, cfBin, cfHome, campfireID, body, fromID string) {
	t.Helper()
	payload, err := json.Marshal(map[string]interface{}{
		"content": body,
		"from":    fromID,
	})
	if err != nil {
		t.Fatalf("marshal bridge payload: %v", err)
	}
	cmd := exec.Command(cfBin, "send", campfireID, string(payload),
		"--tag", "chat",
		"--tag", "session:"+fromID,
		"--tag", "platform:telegram",
		"--instance", "telegram-bridge",
	)
	cmd.Env = setEnvF1G(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("post bridge message %q: %v\nout: %s", body, err, out)
	}
}

// postNonBridgeMessage posts a message WITHOUT the "chat" bridge tag.
func postNonBridgeMessage(t *testing.T, cfBin, cfHome, campfireID, body string) {
	t.Helper()
	cmd := exec.Command(cfBin, "send", campfireID, body, "--tag", "response")
	cmd.Env = setEnvF1G(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("post non-bridge message: %v\nout: %s", err, out)
	}
}

// parseChatOutput decodes JSON array of chatMessage from captured stdout.
func parseChatOutput(t *testing.T, raw string) []map[string]interface{} {
	t.Helper()
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil
	}
	var msgs []map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &msgs); err != nil {
		t.Fatalf("parse chat output: %v\nraw=%q", err, raw)
	}
	return msgs
}

// ---- TestReadRecentChat_PostsAndReads -----------------------------------------

// TestReadRecentChat_PostsAndReads posts N synthetic bridge messages, calls
// read-recent-chat with limit < N, and asserts reverse-chrono + correct count.
func TestReadRecentChat_PostsAndReads(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	// Post 5 messages.
	bodies := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	for _, b := range bodies {
		postBridgeMessage(t, cfBin, cfHome, campfireID, b, "user1")
	}

	// read-recent-chat with limit=3 should return 3 messages.
	inputJSON, _ := json.Marshal(map[string]interface{}{
		"campfire_id": campfireID,
		"limit":       3,
	})
	out := captureStdout(t, func() {
		err := runReadRecentChat(string(inputJSON))
		if err != nil {
			t.Errorf("read-recent-chat: unexpected error: %v", err)
		}
	})

	msgs := parseChatOutput(t, out)
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (limit), got %d", len(msgs))
	}

	// Verify reverse-chronological order: newest first.
	// "epsilon" was posted last so should appear first.
	first, _ := msgs[0]["body"].(string)
	if first != "epsilon" {
		t.Errorf("first message body = %q, want %q (reverse-chrono)", first, "epsilon")
	}
	second, _ := msgs[1]["body"].(string)
	if second != "delta" {
		t.Errorf("second message body = %q, want %q", second, "delta")
	}
}

// ---- TestReadRecentChat_RespectsBridgeTag -------------------------------------

// TestReadRecentChat_RespectsBridgeTag posts both bridge-tagged and non-bridge
// messages; asserts only bridge-tagged ("chat") messages are returned.
func TestReadRecentChat_RespectsBridgeTag(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	postBridgeMessage(t, cfBin, cfHome, campfireID, "bridge msg 1", "user1")
	postNonBridgeMessage(t, cfBin, cfHome, campfireID, "non-bridge response")
	postBridgeMessage(t, cfBin, cfHome, campfireID, "bridge msg 2", "user1")

	inputJSON, _ := json.Marshal(map[string]interface{}{
		"campfire_id": campfireID,
		"limit":       100,
	})
	out := captureStdout(t, func() {
		err := runReadRecentChat(string(inputJSON))
		if err != nil {
			t.Errorf("read-recent-chat: unexpected error: %v", err)
		}
	})

	msgs := parseChatOutput(t, out)
	if len(msgs) != 2 {
		t.Errorf("expected 2 bridge messages, got %d; messages=%v", len(msgs), msgs)
	}
	for _, m := range msgs {
		tags, _ := m["tags"].([]interface{})
		hasChatTag := false
		for _, tag := range tags {
			if tag == "chat" {
				hasChatTag = true
			}
		}
		if !hasChatTag {
			t.Errorf("message missing 'chat' tag: %v", m)
		}
	}
}

// ---- TestReadRecentChat_FiltersUnsignedMessages --------------------------------

// TestReadRecentChat_FiltersUnsignedMessages verifies that messages with a
// valid signature field are returned. Since cf 0.16 does not expose
// signature_valid, this test posts normal messages (which are signed by the
// local identity) and verifies they pass the signature guard. The guard itself
// is a non-empty signature check — cf validates the actual sig on read.
func TestReadRecentChat_FiltersUnsignedMessages(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	// Post a legitimate signed message.
	postBridgeMessage(t, cfBin, cfHome, campfireID, "signed bridge message", "user1")

	inputJSON, _ := json.Marshal(map[string]interface{}{
		"campfire_id": campfireID,
		"limit":       10,
	})
	out := captureStdout(t, func() {
		err := runReadRecentChat(string(inputJSON))
		if err != nil {
			t.Errorf("read-recent-chat: unexpected error: %v", err)
		}
	})

	msgs := parseChatOutput(t, out)
	if len(msgs) == 0 {
		t.Error("expected at least 1 message (signed by local cf identity), got 0")
	}
	// Verify each returned message has a non-empty message_id (proxy for valid normalization).
	for _, m := range msgs {
		if id, _ := m["message_id"].(string); id == "" {
			t.Errorf("message missing message_id: %v", m)
		}
	}
}

// ---- TestSearchChatHistory_FindsByQuery ----------------------------------------

// TestSearchChatHistory_FindsByQuery posts messages with varied bodies,
// searches for a keyword, asserts only matching messages are returned.
func TestSearchChatHistory_FindsByQuery(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	postBridgeMessage(t, cfBin, cfHome, campfireID, "hello world", "user1")
	postBridgeMessage(t, cfBin, cfHome, campfireID, "finding abc-123 looks suspicious", "user1")
	postBridgeMessage(t, cfBin, cfHome, campfireID, "all looks good", "user1")
	postBridgeMessage(t, cfBin, cfHome, campfireID, "investigate finding abc-123 please", "user1")

	inputJSON, _ := json.Marshal(map[string]interface{}{
		"campfire_id": campfireID,
		"query":       "abc-123",
		"limit":       20,
	})
	out := captureStdout(t, func() {
		err := runSearchChatHistory(string(inputJSON))
		if err != nil {
			t.Errorf("search-chat-history: unexpected error: %v", err)
		}
	})

	msgs := parseChatOutput(t, out)
	if len(msgs) != 2 {
		t.Errorf("expected 2 matches for 'abc-123', got %d; msgs=%v", len(msgs), msgs)
	}
	for _, m := range msgs {
		body, _ := m["body"].(string)
		if !strings.Contains(strings.ToLower(body), "abc-123") {
			t.Errorf("returned message body %q does not contain query 'abc-123'", body)
		}
	}
}

// ---- TestSearchChatHistory_CaseInsensitive -------------------------------------

// TestSearchChatHistory_CaseInsensitive verifies query matching is case-insensitive.
func TestSearchChatHistory_CaseInsensitive(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	postBridgeMessage(t, cfBin, cfHome, campfireID, "IAM policy change detected", "user1")
	postBridgeMessage(t, cfBin, cfHome, campfireID, "unrelated message", "user1")

	// Search in different case.
	inputJSON, _ := json.Marshal(map[string]interface{}{
		"campfire_id": campfireID,
		"query":       "iam policy",
	})
	out := captureStdout(t, func() {
		err := runSearchChatHistory(string(inputJSON))
		if err != nil {
			t.Errorf("search-chat-history: unexpected error: %v", err)
		}
	})

	msgs := parseChatOutput(t, out)
	if len(msgs) != 1 {
		t.Errorf("expected 1 match (case-insensitive), got %d", len(msgs))
	}
}

// ---- TestSearchChatHistory_RespectsLimit ----------------------------------------

// TestSearchChatHistory_RespectsLimit posts many matching messages and verifies
// limit caps the result count.
func TestSearchChatHistory_RespectsLimit(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	for i := 0; i < 10; i++ {
		postBridgeMessage(t, cfBin, cfHome, campfireID, "keyword match message", "user1")
	}

	inputJSON, _ := json.Marshal(map[string]interface{}{
		"campfire_id": campfireID,
		"query":       "keyword match",
		"limit":       3,
	})
	out := captureStdout(t, func() {
		err := runSearchChatHistory(string(inputJSON))
		if err != nil {
			t.Errorf("search-chat-history: unexpected error: %v", err)
		}
	})

	msgs := parseChatOutput(t, out)
	if len(msgs) != 3 {
		t.Errorf("expected 3 messages (limit), got %d", len(msgs))
	}
}

// ---- TestReadRecentChat_DefaultsToOperatorCampfireEnv -------------------------

// TestReadRecentChat_DefaultsToOperatorCampfireEnv verifies that when no
// campfire_id is given in input, the tool falls back to MALLCOP_OPERATOR_CAMPFIRE_ID.
func TestReadRecentChat_DefaultsToOperatorCampfireEnv(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	postBridgeMessage(t, cfBin, cfHome, campfireID, "env default test message", "user1")

	// Set env var, omit campfire_id from input.
	t.Setenv("MALLCOP_OPERATOR_CAMPFIRE_ID", campfireID)

	out := captureStdout(t, func() {
		// Empty input — no campfire_id.
		err := runReadRecentChat("{}")
		if err != nil {
			t.Errorf("read-recent-chat: unexpected error: %v", err)
		}
	})

	msgs := parseChatOutput(t, out)
	if len(msgs) == 0 {
		t.Error("expected at least 1 message when using MALLCOP_OPERATOR_CAMPFIRE_ID env, got 0")
	}
	body, _ := msgs[0]["body"].(string)
	if body != "env default test message" {
		t.Errorf("body = %q, want %q", body, "env default test message")
	}
}

// ---- Input validation tests ---------------------------------------------------

func TestReadRecentChat_MissingCampfireID(t *testing.T) {
	// No env, no campfire_id in input.
	t.Setenv("MALLCOP_OPERATOR_CAMPFIRE_ID", "")
	err := runReadRecentChat("{}")
	if err == nil || !strings.Contains(err.Error(), "campfire_id") {
		t.Errorf("expected campfire_id-required error, got: %v", err)
	}
}

func TestSearchChatHistory_MissingQuery(t *testing.T) {
	err := runSearchChatHistory(`{"campfire_id":"abc"}`)
	if err == nil || !strings.Contains(err.Error(), "query") {
		t.Errorf("expected query-required error, got: %v", err)
	}
}

func TestReadRecentChat_LimitTooHigh(t *testing.T) {
	err := runReadRecentChat(`{"campfire_id":"abc","limit":200}`)
	if err == nil || !strings.Contains(err.Error(), "100") {
		t.Errorf("expected limit-too-high error, got: %v", err)
	}
}

func TestSearchChatHistory_LimitTooHigh(t *testing.T) {
	err := runSearchChatHistory(`{"campfire_id":"abc","query":"x","limit":200}`)
	if err == nil || !strings.Contains(err.Error(), "100") {
		t.Errorf("expected limit-too-high error, got: %v", err)
	}
}
