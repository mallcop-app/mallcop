package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/investigate"
	"github.com/mallcop-app/mallcop/core/store"
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
//	  Long-running, plain-file mode: read questions from --inbox, stream the
//	  trace + answers to --outbox, exit after --idle-timeout (default 90s)
//	  with no new question. Local/laptop use.
//
//	mallcop investigate --serve --session <id> --chat-branch mallcop-chat --store <dir> [--repo <dir>]
//	  Long-running, git-mailbox mode (mallcoppro-067,
//	  core/investigate/gitmailbox.go): --inbox/--outbox are derived from
//	  sessions/<id>/{inbox,outbox}.jsonl on --chat-branch inside --repo (a
//	  git working tree, default "."), which is git-pulled/pushed exactly per
//	  docs/chat-investigate-protocol.md §1,2,4,6 -- this is what
//	  mallcop-investigate.yml's scaffolded GHA workflow runs. --inbox/--outbox
//	  are invalid together with --session.
//
// Inference auth mirrors `mallcop scan` exactly: $MALLCOP_INFERENCE_URL +
// $MALLCOP_API_KEY (BYOK: vendor URL+key; Forge: forge URL + mallcop-sk-*
// key), or --base-url / a discovered mallcop.yaml.
func runInvestigate(args []string) error {
	fs := flag.NewFlagSet("investigate", flag.ContinueOnError)
	question := fs.String("question", "", "Ask ONE question and print the answer (single-shot mode)")
	serve := fs.Bool("serve", false, "Run the long-lived serve loop: read questions from --inbox, stream trace+answers to --outbox")
	inboxPath := fs.String("inbox", "", "Questions+control JSONL to read from (plain-file mode; invalid with --session)")
	outboxPath := fs.String("outbox", "", "Trace JSONL to append to (plain-file mode; invalid with --session)")
	idleTimeout := fs.Duration("idle-timeout", investigate.DefaultIdleTimeout, "Serve mode: exit after this long with no new question")
	session := fs.String("session", "", "Session id: enables git-mailbox mode, deriving --inbox/--outbox from sessions/<id>/ on --chat-branch")
	chatBranch := fs.String("chat-branch", mallcopChatBranch, "Git-mailbox mode: the dedicated chat branch (separate from the findings branch)")
	chatRemote := fs.String("chat-remote", "origin", "Git-mailbox mode: the git remote to pull/push the chat branch against")
	repoDir := fs.String("repo", ".", "Git-mailbox mode: path to the git working tree the chat branch lives in")
	gcMaxAge := fs.Duration("gc-max-age", investigate.DefaultGCMaxAge, "Git-mailbox mode: prune sessions/* older than this at boot (<=0 disables)")
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
	if *serve && *session != "" && (*inboxPath != "" || *outboxPath != "") {
		return fmt.Errorf("investigate: --session (git-mailbox mode) and --inbox/--outbox (plain-file mode) are mutually exclusive")
	}
	if *serve && *session == "" && (*inboxPath == "" || *outboxPath == "") {
		return fmt.Errorf("investigate: --serve requires either --session or both --inbox and --outbox")
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
	model := config.Resolve(os.Getenv(envInferenceModel), cfgStr(haveConfig, cfg.Inference.Model), "triage")
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

	// When no explicit baseline is supplied, fall back to the baseline the SCAN
	// derived and persisted (KindBaseline). This hands check_baseline the SAME
	// actor/role/frequency context the scan gated on, so the analyst reasons over
	// what the scan actually saw instead of an empty baseline. An unscanned/eval
	// store has no persisted baseline → nil (check_baseline degrades to "unknown
	// entity", exactly as before this fallback existed).
	if bl == nil {
		bl, err = loadPersistedBaseline(st)
		if err != nil {
			return fmt.Errorf("investigate: %w", err)
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
		// A cancelled/timed-out GHA job delivers SIGINT/SIGTERM with a short
		// grace window before SIGKILL. A signal-aware ctx lets the serve loop
		// write its exit record — the browser's ONLY death signal — instead
		// of dying silently and leaving the chat page waiting forever
		// (mallcoppro-ebef).
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()

		serveOpts := investigate.ServeOptions{
			Options:     opts,
			InboxPath:   *inboxPath,
			OutboxPath:  *outboxPath,
			IdleTimeout: *idleTimeout,
		}
		if *session != "" {
			mb, err := investigate.OpenGitMailbox(investigate.GitMailboxOptions{
				RepoPath:  *repoDir,
				Branch:    *chatBranch,
				SessionID: *session,
				Remote:    *chatRemote,
				GCMaxAge:  *gcMaxAge,
			})
			if err != nil {
				return fmt.Errorf("investigate: %w", err)
			}
			serveOpts.InboxPath = mb.InboxPath()
			serveOpts.OutboxPath = mb.OutboxPath()
			serveOpts.Mailbox = mb
		}
		return investigate.Serve(ctx, serveOpts)
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

// loadPersistedBaseline returns the MOST RECENT baseline the scan pipeline
// persisted to the store's KindBaseline stream, or nil when the stream is empty
// (a store never scanned in derive mode — e.g. a fresh or eval store). KindBaseline
// is append-only history, so the LAST record is the current baseline. A nil result
// is not an error: check_baseline treats it as "no baseline data", exactly as an
// absent --baseline file did before this fallback existed.
func loadPersistedBaseline(st *store.Store) (*baseline.Baseline, error) {
	raws, err := st.Load(store.KindBaseline)
	if err != nil {
		return nil, fmt.Errorf("load persisted baseline: %w", err)
	}
	if len(raws) == 0 {
		return nil, nil
	}
	var b baseline.Baseline
	if err := json.Unmarshal(raws[len(raws)-1], &b); err != nil {
		return nil, fmt.Errorf("decode persisted baseline: %w", err)
	}
	return &b, nil
}
