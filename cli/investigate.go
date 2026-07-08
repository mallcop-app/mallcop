package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/investigate"
	"github.com/mallcop-app/mallcop/pkg/baseline"
)

// runInvestigate implements `mallcop investigate`: a REAL Anthropic-style
// tool-calling analyst over the local git-backed store (core/investigate).
// All agent logic, the inference credential, and the customer's data stay in
// this runner — see mallcop-pro docs/chat-investigate-protocol.md's boundary
// invariant. Two modes:
//
//	mallcop investigate --question "..." --store <dir> [--baseline <path>]
//	  Single-shot: ask one question, print the answer, exit.
//
//	mallcop investigate --serve --inbox <path> --outbox <path> --store <dir> [--baseline <path>]
//	  Long-running: read questions from --inbox, stream the trace + answers
//	  to --outbox, exit after --idle-timeout (default 90s) with no new
//	  question. The FILE LAYOUT --inbox/--outbox live under (a session dir on
//	  a git branch, GHA dispatch, etc.) is a transport concern owned by the
//	  caller (mallcop-pro / the sibling mallcoppro-067 item), not this flag.
//
// Inference auth mirrors `mallcop scan` exactly: $MALLCOP_INFERENCE_URL +
// $MALLCOP_API_KEY (BYOK: vendor URL+key; Forge: forge URL + mallcop-sk-*
// key), or --base-url / a discovered mallcop.yaml.
func runInvestigate(args []string) error {
	fs := flag.NewFlagSet("investigate", flag.ContinueOnError)
	question := fs.String("question", "", "Ask ONE question and print the answer (single-shot mode)")
	serve := fs.Bool("serve", false, "Run the long-lived serve loop: read questions from --inbox, stream trace+answers to --outbox")
	inboxPath := fs.String("inbox", "", "Questions+control JSONL to read from (required with --serve)")
	outboxPath := fs.String("outbox", "", "Trace JSONL to append to (required with --serve)")
	idleTimeout := fs.Duration("idle-timeout", investigate.DefaultIdleTimeout, "Serve mode: exit after this long with no new question")
	storePath := fs.String("store", "", "Path to the git-repo store to investigate (required)")
	baselinePath := fs.String("baseline", "", "Optional path to a baseline JSON file")
	repoRoot := fs.String("repo-root", "", "Optional repo root for lookup_rules' operator-decisions corpus (empty = self-resolve)")
	baseURL := fs.String("base-url", "", "Inference endpoint base URL (overrides $"+envInferenceURL+")")
	configPath := fs.String("config", "", "Path to mallcop.yaml (overrides discovery/$"+config.EnvConfigPath+")")
	asJSON := fs.Bool("json", false, "Single-shot mode: print the answer + citations as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *serve == (*question != "") {
		if *serve {
			return fmt.Errorf("investigate: --question and --serve are mutually exclusive")
		}
		return fmt.Errorf("investigate: exactly one of --question or --serve is required")
	}
	if *serve && (*inboxPath == "" || *outboxPath == "") {
		return fmt.Errorf("investigate: --serve requires both --inbox and --outbox")
	}
	if *storePath == "" {
		return fmt.Errorf("investigate: --store is required")
	}

	cfg, cfgPath, err := config.LoadEffective(*configPath)
	if err != nil {
		return fmt.Errorf("investigate: %w", err)
	}
	haveConfig := cfgPath != ""

	// Inference client: the same {BaseURL, Key} pivot `mallcop scan` uses.
	// Unlike scan (which tolerates a nil client and force-escalates), a nil
	// endpoint here is fatal — there is no useful degraded mode for an
	// analyst that never reaches a model.
	url := config.Resolve(*baseURL, os.Getenv(envInferenceURL), cfgStr(haveConfig, cfg.Inference.Endpoint))
	if url == "" {
		return fmt.Errorf("investigate: no inference endpoint configured (set --base-url, $%s, or mallcop.yaml inference.endpoint)", envInferenceURL)
	}
	key := os.Getenv(envInferenceKey)
	if key == "" && haveConfig && cfg.Inference.KeyEnv != "" {
		key = os.Getenv(cfg.Inference.KeyEnv)
	}
	model := config.Resolve(os.Getenv(envInferenceModel), cfgStr(haveConfig, cfg.Inference.Model), "mallcop-default")
	client := &inference.DirectClient{BaseURL: url, Key: key, Model: model}

	st, err := openOrInitStore(*storePath)
	if err != nil {
		return fmt.Errorf("investigate: %w", err)
	}

	var bl *baseline.Baseline
	resolvedBaseline := *baselinePath
	if resolvedBaseline == "" && haveConfig {
		resolvedBaseline = cfg.Store.Baseline
	}
	if resolvedBaseline != "" {
		bl, err = baseline.Load(resolvedBaseline)
		if err != nil {
			return fmt.Errorf("investigate: load baseline %s: %w", resolvedBaseline, err)
		}
	}

	opts := investigate.Options{
		Client:   client,
		Model:    model,
		Store:    st,
		Baseline: bl,
		RepoRoot: *repoRoot,
	}
	ctx := context.Background()

	if *serve {
		return investigate.Serve(ctx, investigate.ServeOptions{
			Options:     opts,
			InboxPath:   *inboxPath,
			OutboxPath:  *outboxPath,
			IdleTimeout: *idleTimeout,
		})
	}

	res, err := investigate.Ask(ctx, opts, *question)
	if err != nil {
		return fmt.Errorf("investigate: %w", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Answer    string                 `json:"answer"`
			Citations []investigate.Citation `json:"citations"`
		}{Answer: res.Answer, Citations: res.Citations})
	}
	fmt.Println(res.Answer)
	return nil
}
