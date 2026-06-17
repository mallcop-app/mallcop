// Package inference holds the network seam that satisfies core/agent.Client.
//
// It is the ONLY core/ package that performs HTTP I/O to reach the model, and it
// does so with the standard library alone — net/http + encoding/json — and no
// vendor LLM SDK, no agent-orchestration framework, and no transport. The
// repo-level import-lint (core/lint) enforces that: a real Anthropic/OpenAI/
// Bedrock SDK is a banned family across the whole core/ tree, so the wire shape
// here is hand-rolled against the Anthropic /v1/messages contract.
//
// DirectClient is the OSS-BYOK ⇄ managed-Forge pivot. The {BaseURL, Key} pair is
// the entire switch:
//
//   - BYOK: BaseURL points at the vendor's own endpoint and Key is the user's own
//     key — mallcop never sees inference dollars.
//   - Managed: BaseURL points at Forge (which meters, enforces limits, and routes
//     to Bedrock) and Key is a mallcop-sk-* tenant key.
//
// Nothing else in the request path changes between the two modes — same wire
// shape, same code. The agent loop (a later wave) consumes core/agent.Client and
// is handed a DirectClient by the caller; the loop cannot tell BYOK from managed,
// which is the point.
package inference
