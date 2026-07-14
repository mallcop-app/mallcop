package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/inference"
)

// ImproveSchemaVersion versions the self-extension PROPOSAL envelope `mallcop
// improve` emits — the linux-mode twin of mallcop-pro's POST /api/chat/propose
// response. Bump on any backwards-incompatible change to the improveProposal
// shape (same discipline as CollectSchemaVersion / selfgate.GateSchemaVersion).
const ImproveSchemaVersion = 1

// selfextExtractionSystemPrompt is the extraction system prompt, copied VERBATIM
// from mallcop-pro's internal/server/chat_propose.go
// (selfextExtractionSystemPrompt). `mallcop improve` is the linux-mode twin of
// that chat surface: the two must structure a free-text request into the SAME
// strict-JSON proposal shape, so the prompt is duplicated here byte-for-byte
// rather than reworded. mallcop (this module) cannot import mallcop-pro, so the
// only way to keep the two surfaces behaviorally identical is to copy the prompt.
// If you change one, change BOTH (TestImproveExtractionPromptMatchesChatPropose-
// intent: they must not drift).
const selfextExtractionSystemPrompt = `You turn ONE free-text request from a mallcop security customer into a ` +
	`structured self-extension proposal, or refuse it. mallcop can self-extend in exactly one way: authoring a ` +
	`NEW detector or connector mapping that watches a (source, event/action) pair and flags it as a finding — ` +
	`e.g. "watch for admins granting themselves owner outside business hours", "flag force-pushes to main by ` +
	`non-release accounts", "alert when a new OAuth app gets repo write access".

Reply with STRICT JSON ONLY (no markdown fences, no prose before or after) matching exactly this shape:
{"in_scope": true|false, "kind": "detector"|"connector", "detector_id": "kebab-case-id", "event_type": "dotted.event.type", "target_family": "", "refusal_reason": ""}

Rules:
- in_scope=true ONLY for a request that names a concrete source/actor/action mallcop could watch for and flag.
  detector_id and event_type are then BOTH REQUIRED, non-empty, and derived ONLY from what the user actually
  described — never invent specifics the request did not contain. detector_id is a short kebab-case slug
  (e.g. "self-owner-grant-off-hours"). event_type is a short dotted event name mallcop's connectors would emit
  for that action (e.g. "github.permission.grant", "iam.role.assume"). target_family is optional — leave it "".
- in_scope=false for anything else: general questions, requests to change existing detectors' thresholds,
  requests to merge/approve/auto-apply something, requests unrelated to security monitoring, or a request too
  vague to name a concrete source+action. Set refusal_reason to ONE short sentence telling the customer what
  mallcop can do instead (propose a NEW detector/connector for a specific source and action) — never leave it
  empty when in_scope is false.
- Never set in_scope=true without both detector_id and event_type populated.
- Output nothing but the JSON object.`

// selfextExtraction is the strict JSON shape selfextExtractionSystemPrompt asks
// the model to reply with. Field-identical to mallcop-pro's selfextExtraction.
type selfextExtraction struct {
	InScope       bool   `json:"in_scope"`
	Kind          string `json:"kind"`
	DetectorID    string `json:"detector_id"`
	EventType     string `json:"event_type"`
	TargetFamily  string `json:"target_family"`
	RefusalReason string `json:"refusal_reason"`
}

// improveProposal is the versioned envelope `mallcop improve` emits: the linux-mode
// equivalent of the chat propose response. It is a PROPOSE-ONLY artifact (R3): it
// carries the structured self-extension request a downstream gated dispatcher
// (mallcop-pro's /api/selfext, or a CI step) turns into a REVIEWED PR. `mallcop
// improve` itself never merges, applies, or opens a PR — it has no merge-capable
// code path, exactly like the chat propose surface it mirrors.
type improveProposal struct {
	SchemaVersion int  `json:"schema_version"`
	InScope       bool `json:"in_scope"`
	// Proposal fields, populated only when InScope is true.
	Kind         string `json:"kind,omitempty"`
	DetectorID   string `json:"detector_id,omitempty"`
	EventType    string `json:"event_type,omitempty"`
	TargetFamily string `json:"target_family,omitempty"`
	Rail         string `json:"rail,omitempty"`
	// RefusalReason is populated only when InScope is false — the honest guidance
	// message telling the operator what mallcop can do instead. Never a fabricated
	// proposal.
	RefusalReason string `json:"refusal_reason,omitempty"`
}

// runImprove implements `mallcop improve`: the linux-mode twin of the chat
// "Propose improvement" surface (mallcop-pro chat_propose.go, rd mallcoppro-44b).
// It turns an operator request into a structured, PROPOSE-ONLY self-extension
// proposal (R3 — the emitted proposal is fed to a gated dispatcher that opens a
// REVIEWED PR; this command never applies anything itself). Two modes:
//
//	mallcop improve --detector-id <id> --event-type <type> [--target-family <f>] [--rail <r>]
//	  FLAGS mode: no inference. The operator has already named the detector id and
//	  event type; emit the structured proposal directly.
//
//	mallcop improve "watch for admins granting themselves owner outside business hours"
//	  FREE-TEXT mode: ONE metered inference call with the SAME extraction prompt the
//	  chat surface uses (selfextExtractionSystemPrompt, copied verbatim), structuring
//	  the request into the same strict-JSON proposal. An out-of-scope or too-vague
//	  request honestly REFUSES (in_scope=false + guidance) — it never fabricates a
//	  detector_id/event_type. Flags must precede the free-text request.
//
// Inference auth mirrors `mallcop scan` / `mallcop investigate`: $MALLCOP_INFERENCE_URL
// + $MALLCOP_API_KEY (BYOK: vendor URL+key; Forge: forge URL + mallcop-sk-* key),
// or --base-url / a discovered mallcop.yaml. Free-text mode requires an endpoint
// (no useful offline extraction); flags mode needs none.
//
// Exit codes:
//
//	0  A proposal was emitted, OR a free-text request was honestly refused
//	   (in_scope=false is a legitimate outcome, not an error).
//	2  Failure (both modes' inputs missing/ambiguous, no inference endpoint in
//	   free-text mode, a transport error, or an unparseable model reply).
func runImprove(args []string) error {
	fs := flag.NewFlagSet("improve", flag.ContinueOnError)
	detectorID := fs.String("detector-id", "", "FLAGS mode: the detector id to propose (kebab-case). With --event-type, skips inference.")
	eventType := fs.String("event-type", "", "FLAGS mode: the dotted event type the detector gates on.")
	targetFamily := fs.String("target-family", "", "Optional detector family the proposal targets.")
	rail := fs.String("rail", "", "Optional self-extension rail to dispatch on (forwarded unchanged to the gated dispatcher).")
	baseURL := fs.String("base-url", "", "Free-text mode: inference endpoint base URL (overrides $"+envInferenceURL+")")
	configPath := fs.String("config", "", "Path to mallcop.yaml (overrides discovery/$"+config.EnvConfigPath+")")
	asJSON := fs.Bool("json", false, "Emit the versioned proposal envelope as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// The free-text request is whatever positional args remain after the flags.
	request := strings.TrimSpace(strings.Join(fs.Args(), " "))
	flagsMode := *detectorID != "" || *eventType != ""

	// The two modes are mutually exclusive: flags describe a fully-specified
	// proposal (no inference), free text asks the model to derive one. Mixing them
	// is ambiguous — reject rather than silently prefer one.
	if flagsMode && request != "" {
		return fmt.Errorf("improve: give EITHER --detector-id/--event-type (flags mode) OR a free-text request, not both")
	}

	if flagsMode {
		// FLAGS mode: both fields are required together — a detector proposal needs
		// an id AND the event type it gates on.
		if *detectorID == "" || *eventType == "" {
			return fmt.Errorf("improve: flags mode requires BOTH --detector-id and --event-type")
		}
		prop := improveProposal{
			SchemaVersion: ImproveSchemaVersion,
			InScope:       true,
			Kind:          "detector",
			DetectorID:    *detectorID,
			EventType:     *eventType,
			TargetFamily:  *targetFamily,
			Rail:          *rail,
		}
		return emitImproveProposal(prop, *asJSON)
	}

	if request == "" {
		return fmt.Errorf("improve: usage: mallcop improve \"<free-text request>\"  OR  mallcop improve --detector-id <id> --event-type <type>")
	}

	// FREE-TEXT mode: resolve the inference client exactly like `mallcop investigate`
	// (base-url flag > $MALLCOP_INFERENCE_URL > mallcop.yaml). A missing endpoint is
	// fatal — there is no useful offline extraction, and we must NEVER fabricate a
	// proposal from a request we could not actually structure.
	cfg, cfgPath, err := config.LoadEffective(*configPath)
	if err != nil {
		return fmt.Errorf("improve: %w", err)
	}
	haveConfig := cfgPath != ""

	url := config.Resolve(*baseURL, os.Getenv(envInferenceURL), cfgStr(haveConfig, cfg.Inference.Endpoint))
	if url == "" {
		return fmt.Errorf("improve: free-text mode needs an inference endpoint (set --base-url, $%s, or mallcop.yaml inference.endpoint) — or use --detector-id/--event-type for the no-inference flags mode", envInferenceURL)
	}
	key := os.Getenv(envInferenceKey)
	if key == "" && haveConfig && cfg.Inference.KeyEnv != "" {
		key = os.Getenv(cfg.Inference.KeyEnv)
	}
	model := config.Resolve(os.Getenv(envInferenceModel), cfgStr(haveConfig, cfg.Inference.Model), "triage")
	client := &inference.DirectClient{BaseURL: url, Key: key, Model: model}

	extraction, err := extractImproveProposal(context.Background(), client, request)
	if err != nil {
		return fmt.Errorf("improve: %w", err)
	}

	if !extraction.InScope {
		// Honest refusal — never a fabricated proposal.
		prop := improveProposal{
			SchemaVersion: ImproveSchemaVersion,
			InScope:       false,
			RefusalReason: extraction.RefusalReason,
		}
		return emitImproveProposal(prop, *asJSON)
	}

	prop := improveProposal{
		SchemaVersion: ImproveSchemaVersion,
		InScope:       true,
		Kind:          extraction.Kind,
		DetectorID:    extraction.DetectorID,
		EventType:     extraction.EventType,
		TargetFamily:  extraction.TargetFamily,
		Rail:          *rail,
	}
	return emitImproveProposal(prop, *asJSON)
}

// extractImproveProposal performs ONE inference call that structures nlRequest
// into a selfextExtraction, using selfextExtractionSystemPrompt (the SAME prompt
// as the chat surface). A transport failure, a reply with no text, or a reply
// that is not a complete strict-JSON extraction is returned as an error — this
// function NEVER fabricates a proposal from an unparseable or incomplete reply.
func extractImproveProposal(ctx context.Context, client agent.Client, nlRequest string) (selfextExtraction, error) {
	var zero selfextExtraction
	resp, err := client.Messages(ctx, agent.MessagesRequest{
		MaxTokens: 300,
		System:    selfextExtractionSystemPrompt,
		Messages: []agent.Message{{
			Role:    "user",
			Content: []agent.ContentBlock{{Type: "text", Text: nlRequest}},
		}},
	})
	if err != nil {
		return zero, fmt.Errorf("extraction inference call: %w", err)
	}
	var text string
	for _, block := range resp.Content {
		if block.Type == "text" && block.Text != "" {
			text = block.Text
			break
		}
	}
	if text == "" {
		return zero, fmt.Errorf("extraction reply carried no text content")
	}
	return parseSelfextExtraction(text)
}

// parseSelfextExtraction strict-decodes text as a selfextExtraction, tolerating a
// ```json ... ``` fence a model sometimes wraps strict-JSON output in despite
// being told not to (defensive only — no other leniency). An in_scope=true reply
// missing detector_id or event_type is rejected here, so a successful parse always
// means a complete, dispatchable proposal — copied from mallcop-pro chat_propose.go.
func parseSelfextExtraction(text string) (selfextExtraction, error) {
	var zero selfextExtraction
	trimmed := strings.TrimSpace(text)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)

	var out selfextExtraction
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return zero, fmt.Errorf("extraction reply was not valid JSON: %w", err)
	}
	if out.InScope && (out.DetectorID == "" || out.EventType == "") {
		return zero, fmt.Errorf("extraction reply set in_scope=true without both detector_id and event_type")
	}
	return out, nil
}

// emitImproveProposal renders the proposal, as the versioned JSON envelope with
// --json or as a human-readable summary otherwise.
func emitImproveProposal(p improveProposal, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(p); err != nil {
			return fmt.Errorf("improve: encode proposal: %w", err)
		}
		return nil
	}
	if !p.InScope {
		fmt.Printf("Not a self-extension proposal.\n")
		if p.RefusalReason != "" {
			fmt.Printf("  %s\n", p.RefusalReason)
		}
		fmt.Printf("mallcop improve proposes a NEW detector/connector for a specific source and action.\n")
		return nil
	}
	fmt.Printf("Self-extension proposal (propose-only — a gated, REVIEWED PR):\n")
	fmt.Printf("  Kind:          %s\n", p.Kind)
	fmt.Printf("  Detector id:   %s\n", p.DetectorID)
	fmt.Printf("  Event type:    %s\n", p.EventType)
	if p.TargetFamily != "" {
		fmt.Printf("  Target family: %s\n", p.TargetFamily)
	}
	if p.Rail != "" {
		fmt.Printf("  Rail:          %s\n", p.Rail)
	}
	fmt.Printf("Hand this proposal to the gated dispatcher (mallcop-pro /api/selfext or CI) to open the reviewed PR.\n")
	return nil
}
