// tools_chat.go — read-recent-chat and search-chat-history action tools.
//
// These tools read messages from the operator campfire that were posted by the
// Telegram bridge (telegram_bridge.py in the mallcop repo). The bridge posts
// inbound Telegram messages with tags: "chat", "session:<chat_id>",
// "platform:telegram". The payload is JSON {"content": text, "from": str(from_id)}.
//
// # Tag convention (source of truth: mallcop/src/mallcop/telegram_bridge.py)
//
//   Inbound (Telegram → campfire):
//     tags: ["chat", "session:<chat_id>", "platform:telegram"]
//     payload: {"content": <message text>, "from": <sender id>}
//     instance: "telegram-bridge"
//
//   Outbound (campfire → Telegram): tagged "response" — NOT read by these tools.
//
// # Bidirectional: YES. The bridge forwards:
//   - Telegram → campfire (inbound, tag: chat)
//   - campfire → Telegram (outbound, tag: response) — handled by the bridge, not here.
//
// # Sender model
//   The bridge posts under its own campfire member key (whichever identity
//   ran cf init in the bridge's CF_HOME). The --instance flag is "telegram-bridge".
//   There is no separate bot pubkey: the sender field is the bridge's campfire key.
//
// # Signature model (cf 0.16)
//   cf does not expose a signature_valid field in --json output. Signature
//   verification is performed by the cf binary on read — messages returned by
//   cf read are assumed signature-valid. We guard against messages that have an
//   empty signature field as a belt-and-suspenders check.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// bridgeInboundTag is the primary campfire tag used by the Telegram bridge for
// inbound messages. This is the source-of-truth tag from telegram_bridge.py.
const bridgeInboundTag = "chat"

// chatMessage is the normalized shape returned by read-recent-chat and
// search-chat-history.
type chatMessage struct {
	MessageID          string   `json:"message_id"`
	Sender             string   `json:"sender"`
	SenderDisplayName  string   `json:"sender_display_name,omitempty"`
	Body               string   `json:"body"`
	Timestamp          int64    `json:"timestamp"`
	Tags               []string `json:"tags"`
}

// readRecentChatInput is the input schema for read-recent-chat.
type readRecentChatInput struct {
	CampfireID string `json:"campfire_id"`
	Limit      int    `json:"limit"`
}

// searchChatHistoryInput is the input schema for search-chat-history.
type searchChatHistoryInput struct {
	CampfireID string `json:"campfire_id"`
	Query      string `json:"query"`
	Limit      int    `json:"limit"`
}

// cfReadChatMessages fetches bridge-inbound messages from campfireID via cf CLI.
// Returns raw cf JSON message objects.
func cfReadChatMessages(campfireID string) ([]map[string]interface{}, error) {
	cfBin, err := cfBinPath()
	if err != nil {
		return nil, err
	}

	args := []string{"read", campfireID, "--json", "--all", "--tag", bridgeInboundTag}
	cmd := exec.Command(cfBin, args...) // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("cf read: %w; stderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("cf read: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	var msgs []map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &msgs); err != nil {
		return nil, fmt.Errorf("cf read: parse JSON output: %w", err)
	}
	return msgs, nil
}

// extractChatBody parses the payload of a bridge-posted message and returns
// the message body text. The bridge posts JSON {"content": text, "from": id}.
// Falls back to raw payload if JSON parsing fails.
func extractChatBody(payload string) string {
	if payload == "" {
		return ""
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &parsed); err == nil {
		// Try content field first (bridge convention).
		for _, key := range []string{"content", "text", "message"} {
			if v, ok := parsed[key].(string); ok && v != "" {
				return v
			}
		}
	}
	return payload
}

// extractSenderDisplayName extracts the from field from a bridge payload as a
// display name. The bridge stores the Telegram user ID as a string.
func extractSenderDisplayName(payload string) string {
	if payload == "" {
		return ""
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		return ""
	}
	for _, key := range []string{"from", "from_id", "user_id"} {
		if v, ok := parsed[key]; ok {
			switch s := v.(type) {
			case string:
				return s
			case float64:
				return fmt.Sprintf("%.0f", s)
			}
		}
	}
	return ""
}

// normalizeChatMessage converts a raw cf message map to a chatMessage.
// Returns nil if the message lacks a signature (guard against unsigned messages).
func normalizeChatMessage(m map[string]interface{}) *chatMessage {
	// Signature guard: cf 0.16 does not expose signature_valid but does include
	// the signature field. A missing or empty signature means the message was not
	// signed and MUST be rejected.
	sig, _ := m["signature"].(string)
	if sig == "" {
		return nil
	}

	id, _ := m["id"].(string)
	sender, _ := m["sender"].(string)
	payload, _ := m["payload"].(string)

	// Timestamp: cf uses nanosecond int (int64 or float64 depending on JSON parse).
	var ts int64
	switch v := m["timestamp"].(type) {
	case float64:
		ts = int64(v)
	case int64:
		ts = v
	case json.Number:
		n, _ := v.Int64()
		ts = n
	}

	// Tags: cf returns as []interface{} of strings.
	var tags []string
	if tagsRaw, ok := m["tags"]; ok {
		switch t := tagsRaw.(type) {
		case []interface{}:
			for _, tag := range t {
				if s, ok := tag.(string); ok {
					tags = append(tags, s)
				}
			}
		case []string:
			tags = append(tags, t...)
		}
	}

	body := extractChatBody(payload)
	if body == "" {
		return nil
	}

	displayName := extractSenderDisplayName(payload)

	return &chatMessage{
		MessageID:         id,
		Sender:            sender,
		SenderDisplayName: displayName,
		Body:              body,
		Timestamp:         ts,
		Tags:              tags,
	}
}

// runReadRecentChat implements the read-recent-chat tool.
// Reads bridge-inbound messages from the operator campfire, returns last N
// in reverse-chronological order (newest first).
func runReadRecentChat(inputJSON string) error {
	var input readRecentChatInput
	if inputJSON != "" {
		if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
			return fmt.Errorf("read-recent-chat: parse input: %w", err)
		}
	}

	// Apply defaults.
	if input.Limit == 0 {
		input.Limit = 20
	}
	if input.Limit < 1 {
		return errors.New("read-recent-chat: limit must be >= 1")
	}
	if input.Limit > 100 {
		return errors.New("read-recent-chat: limit must be <= 100")
	}

	// Resolve campfire ID: input field > env var.
	campfireID := input.CampfireID
	if campfireID == "" {
		campfireID = os.Getenv("MALLCOP_OPERATOR_CAMPFIRE_ID")
	}
	if campfireID == "" {
		return errors.New("read-recent-chat: campfire_id required (or set MALLCOP_OPERATOR_CAMPFIRE_ID env)")
	}

	rawMsgs, err := cfReadChatMessages(campfireID)
	if err != nil {
		return fmt.Errorf("read-recent-chat: %w", err)
	}

	// Normalize and filter.
	var msgs []*chatMessage
	for _, m := range rawMsgs {
		if cm := normalizeChatMessage(m); cm != nil {
			msgs = append(msgs, cm)
		}
	}

	// Sort reverse-chronological (newest first by timestamp nanoseconds).
	sort.Slice(msgs, func(i, j int) bool {
		return msgs[i].Timestamp > msgs[j].Timestamp
	})

	// Apply limit.
	if len(msgs) > input.Limit {
		msgs = msgs[:input.Limit]
	}

	// Dereference for JSON output.
	out := make([]chatMessage, len(msgs))
	for i, m := range msgs {
		out[i] = *m
	}

	return emitJSON(out)
}

// runSearchChatHistory implements the search-chat-history tool.
// Fetches all bridge-inbound messages, filters by case-insensitive body
// substring match, returns up to limit results in reverse-chronological order.
func runSearchChatHistory(inputJSON string) error {
	var input searchChatHistoryInput
	if inputJSON != "" {
		if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
			return fmt.Errorf("search-chat-history: parse input: %w", err)
		}
	}

	if input.Query == "" {
		return errors.New("search-chat-history: query is required")
	}

	// Apply defaults.
	if input.Limit == 0 {
		input.Limit = 20
	}
	if input.Limit < 1 {
		return errors.New("search-chat-history: limit must be >= 1")
	}
	if input.Limit > 100 {
		return errors.New("search-chat-history: limit must be <= 100")
	}

	// Resolve campfire ID.
	campfireID := input.CampfireID
	if campfireID == "" {
		campfireID = os.Getenv("MALLCOP_OPERATOR_CAMPFIRE_ID")
	}
	if campfireID == "" {
		return errors.New("search-chat-history: campfire_id required (or set MALLCOP_OPERATOR_CAMPFIRE_ID env)")
	}

	rawMsgs, err := cfReadChatMessages(campfireID)
	if err != nil {
		return fmt.Errorf("search-chat-history: %w", err)
	}

	queryLower := strings.ToLower(input.Query)

	var msgs []*chatMessage
	for _, m := range rawMsgs {
		cm := normalizeChatMessage(m)
		if cm == nil {
			continue
		}
		if !strings.Contains(strings.ToLower(cm.Body), queryLower) {
			continue
		}
		msgs = append(msgs, cm)
	}

	// Sort reverse-chronological (newest first).
	sort.Slice(msgs, func(i, j int) bool {
		return msgs[i].Timestamp > msgs[j].Timestamp
	})

	// Apply limit.
	if len(msgs) > input.Limit {
		msgs = msgs[:input.Limit]
	}

	out := make([]chatMessage, len(msgs))
	for i, m := range msgs {
		out[i] = *m
	}

	return emitJSON(out)
}
