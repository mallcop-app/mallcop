package store

import (
	"encoding/json"
	"fmt"
)

// Directive is an operator-steering record on the directives stream. It is
// FIRST-CLASS: a directive appended by one process is loaded and obeyed by the
// next process that Opens the same repo. The scan pipeline calls LoadDirectives
// at startup and applies each directive (e.g. suppressing findings whose source
// or reason matches Pattern) before emitting results.
//
// Op is the verb the consumer dispatches on. The store does not interpret it —
// it only persists and replays — but the canonical vocabulary is:
//
//	suppress  — drop findings matching Pattern
//	focus     — prioritize findings matching Pattern
//	mute       — silence notifications for Pattern
//	unsuppress — cancel a prior suppress for Pattern
//
// Pattern is the target the op applies to (a finding type, source, actor glob,
// or substring — the consumer decides matching semantics). Reason is the
// human/agent rationale, preserved for audit. Meta carries op-specific extra
// fields without schema churn.
type Directive struct {
	Op      string          `json:"op"`
	Pattern string          `json:"pattern,omitempty"`
	Reason  string          `json:"reason,omitempty"`
	Actor   string          `json:"actor,omitempty"` // who issued it (operator/agent)
	Meta    json.RawMessage `json:"meta,omitempty"`
}

// Turn is one entry on the conversation stream — the durable agent-loop
// transcript. It is FIRST-CLASS alongside directives: the agent loop appends a
// Turn per exchange and replays the whole conversation on the next Open so a
// respawned session resumes with full context.
//
// Role is "user", "assistant", "system", or "tool". Content is the message
// text. ToolName/ToolInput/ToolResult are populated for tool turns. Meta is
// open for model/usage annotations.
type Turn struct {
	Role       string          `json:"role"`
	Content    string          `json:"content,omitempty"`
	ToolName   string          `json:"tool_name,omitempty"`
	ToolInput  json.RawMessage `json:"tool_input,omitempty"`
	ToolResult json.RawMessage `json:"tool_result,omitempty"`
	Meta       json.RawMessage `json:"meta,omitempty"`
}

// LoadDirectives replays the directives stream into typed Directive records,
// oldest first. This is the call the scan pipeline makes at startup to obey
// operator steering written in a prior process. A repo that has never had a
// directive appended returns an empty slice (not an error).
func (s *Store) LoadDirectives() ([]Directive, error) {
	raws, err := s.Load(KindDirectives)
	if err != nil {
		return nil, err
	}
	out := make([]Directive, 0, len(raws))
	for i, raw := range raws {
		var d Directive
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("store: decode directive %d: %w", i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// LoadConversation replays the conversation stream into typed Turn records,
// oldest first — the durable transcript the agent loop resumes from.
func (s *Store) LoadConversation() ([]Turn, error) {
	raws, err := s.Load(KindConversation)
	if err != nil {
		return nil, err
	}
	out := make([]Turn, 0, len(raws))
	for i, raw := range raws {
		var t Turn
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("store: decode turn %d: %w", i, err)
		}
		out = append(out, t)
	}
	return out, nil
}
