package proposer

// The Anthropic /v1/messages wire structs the proposer speaks. They are a
// mallcop-pro-LOCAL DUPLICATE of mallcop core/agent.MessagesRequest / Response /
// Message / ContentBlock / Tool (anthropic.go:45/93) — mallcop-pro must NOT
// import the mallcop module, and it only needs the minimal fields to advertise
// one add-only tool and read back one tool_use / text block.

// MessagesRequest is the minimal Anthropic-compatible request the proposer builds.
// Model carries the LANE (not a raw catalog id): Forge resolves the lane to a
// real Bedrock model, and a raw catalog id 404s (mallcop-pro commit 2cd40d3).
type MessagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
	Tools     []Tool    `json:"tools,omitempty"`
}

// Message is one turn in the conversation.
type Message struct {
	Role    string         `json:"role"` // "user" | "assistant"
	Content []ContentBlock `json:"content"`
}

// ContentBlock is one block within a message. Only the fields the proposer needs
// to advertise a tool and read back a tool_use / text block are modeled.
type ContentBlock struct {
	Type string `json:"type"` // "text" | "tool_use"
	Text string `json:"text,omitempty"`

	// tool_use
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Input any    `json:"input,omitempty"`
}

// Tool is a tool definition advertised to the model. InputSchema advertises the
// closed vocabulary as a JSON-schema enum — a HINT to the model; the server-side
// StrictParse is the actual gate.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	InputSchema any    `json:"input_schema,omitempty"`
}

// MessagesResponse is the minimal Anthropic-compatible response the proposer
// reads.
type MessagesResponse struct {
	StopReason string         `json:"stop_reason"`
	Content    []ContentBlock `json:"content"`
}
