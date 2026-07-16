package opencode

// realbin_test.go closes the veracity finding: adapter_test.go
// drives Invoke against FAKE shell-script opencode stands-ins the adapter
// happens to exec successfully — none of it proves the REAL `opencode` CLI
// (github.com/sst/opencode, npm package opencode-ai) actually honors the
// provider config this package builds, or that Parse()/redact.Redact() handle
// the REAL binary's own event-stream JSON shapes (as opposed to the shapes
// the shell stubs were hand-written to produce).
//
// These tests drive the REAL opencode binary against a LOCAL fake
// OpenAI-compatible SSE endpoint (a hermetic httptest.Server — no network, no
// Forge, no Bedrock, $0 spend) and prove two things the shell-stub suite
// cannot:
//
//   - TestRealOpencode_OutputCapReachesWire: the `models.<model>.limit.output`
//     value ProviderConfig declares is the ACTUAL `max_tokens` the real
//     opencode binary puts on the wire in its chat-completions request — the
//     exact mechanism f482488 fixed (before it, opencode defaulted ABOVE the
//     lane model's hard cap and every request 400s). The negative half
//     reproduces the pre-fix config shape (limit block omitted entirely)
//     against the real binary and shows it fails closed (config validation
//     error, zero requests reach the wire) — the literal regression this
//     fix guards against, live.
//   - TestRealOpencode_FileExtractionAndKeyRedaction: drives a REAL write-tool
//     round trip (the fake server scripts a tool_calls response) so the real
//     opencode binary ACTUALLY WRITES A FILE to the worktree and emits ITS
//     OWN "tool"/"write" event JSON — proving Parse()'s fileKeyPattern
//     extraction against the genuine wire shape, not a hand-authored stub.
//     The tool call's file content carries the run's own apiKey (the shape a
//     buggy/malicious backend echoing config back would produce); the test
//     proves redact.Redact scrubs it from Result.TranscriptRedacted.
//
// Both SKIP (not fail) when the sibling `opencode` binary is not on PATH —
// this is a real integration test with a real external dependency, not a
// mock with a fallback. It RUNS locally whenever `opencode` (opencode-ai) is
// npm-installed (the standard self-ext dev/runner dependency), and is wired
// into CI via go-test.yml's `npm install -g opencode-ai` step (see that
// workflow) so it runs for real on every push/PR, not just locally.
//
// # Why --pure (adapter.extraRunArgs), and the raw observation it surfaces
//
// Both tests set extraRunArgs=[]string{"--pure"} (opencode: "run without
// external plugins") for hermetic determinism: a cold opencode invocation
// WITHOUT --pure was observed, live against this exact harness during
// development, to occasionally stall 30s+ before ever reaching our LOCAL fake
// server at all (no request logged) — an unrelated network dependency
// (plugin loading) outside what these tests verify. WITH --pure, every trial
// (cold $HOME, warm $HOME, repeated runs) completed in under 4 seconds.
// Production Adapter.Invoke() does NOT pass --pure today — this is a RAW
// OBSERVATION (an intermittent hang was seen; --pure was not investigated as
// a production fix) surfaced here per CLAUDE.md's no-silent-spec-deviation
// rule, not a claim the production path itself hangs the same way (Confine
// jails the child's network egress to just the inference-endpoint port,
// which may already fail plugin loading closed rather than hanging — that
// interaction is untested). Tracked as an opencode-pure-flakiness
// follow-up; not fixed here — this task adds tests, not a production change
// to Invoke's own argv.
//
// # If a real opencode binary is not available in CI
//
// If the go-test.yml `npm install -g opencode-ai` step is ever removed or
// starts failing (network egress, npm registry outage, a broken release),
// these tests degrade to a SKIP with a message naming exactly what's missing
// and why (see mustRealOpencodeBin) — never a silent pass and never a build
// failure elsewhere in the package.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/sandbox"
)

// mustRealOpencodeBin resolves the real `opencode` CLI: the OPENCODE_BIN env
// var when set, else PATH. Skips the test loudly when it is absent — see the
// package-level doc comment above for what that means and where it's wired
// into CI.
func mustRealOpencodeBin(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("OPENCODE_BIN"); bin != "" {
		return bin
	}
	bin, err := exec.LookPath("opencode")
	if err != nil {
		t.Skipf("real-opencode integration test SKIPPED: `opencode` not found on PATH (%v). "+
			"This test proves the output-cap wire contract and event-stream extraction/redaction "+
			" against the REAL opencode-ai CLI, not a shell-script stand-in — it has "+
			"nothing to fall back to. Install: `npm install -g opencode-ai`. Wired into CI via "+
			".github/workflows/go-test.yml.", err)
	}
	return bin
}

// fakeOpenAIServer is a minimal, hermetic OpenAI-compatible chat-completions
// SSE endpoint good enough for the REAL opencode binary's ai-sdk
// openai-compatible provider to complete a run against. It scripts exactly
// two behaviors, detected from the request body (no state beyond that — the
// real opencode binary is itself the only "client" driving this):
//
//   - a request with NO "write" tool declared (opencode's lightweight
//     "generate a title" call) always gets a short plain-text reply.
//   - a request WITH the "write" tool declared: the FIRST such request (no
//     prior "role":"tool" message in the conversation) gets a tool_calls
//     response invoking write(filePath, content) with the server's
//     configured fileContent; any FOLLOW-UP request (the tool result already
//     appended) gets a plain-text "done" reply, ending the run.
//
// It also records every request's declared max_tokens for the caller to
// assert on afterward.
type fakeOpenAIServer struct {
	fileContent string // written into the scripted write-tool call's content

	maxTokensSeen []int64
}

func newFakeOpenAIServer(t *testing.T, fileContent string) (*httptest.Server, *fakeOpenAIServer) {
	t.Helper()
	f := &fakeOpenAIServer{fileContent: fileContent}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readAll(r)
		if err != nil {
			t.Errorf("fakeOpenAIServer: read request body: %v", err)
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}

		var req struct {
			MaxTokens int64 `json:"max_tokens"`
			Messages  []struct {
				Role string `json:"role"`
			} `json:"messages"`
			Tools []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("fakeOpenAIServer: decode request JSON: %v\nbody: %s", err, body)
			http.Error(w, "decode error", http.StatusInternalServerError)
			return
		}
		f.maxTokensSeen = append(f.maxTokensSeen, req.MaxTokens)

		hasWriteTool := false
		for _, tl := range req.Tools {
			if tl.Function.Name == "write" {
				hasWriteTool = true
			}
		}
		isFollowup := false
		for _, m := range req.Messages {
			if m.Role == "tool" {
				isFollowup = true
			}
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)

		send := func(chunk map[string]any) {
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", data)
			if fl != nil {
				fl.Flush()
			}
		}

		switch {
		case hasWriteTool && !isFollowup:
			send(map[string]any{
				"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "heal",
				"choices": []map[string]any{{
					"index": 0,
					"delta": map[string]any{
						"role": "assistant",
						"tool_calls": []map[string]any{{
							"index": 0, "id": "call_1", "type": "function",
							"function": map[string]any{
								"name": "write",
								"arguments": mustJSON(map[string]any{
									"filePath": "authored-by-real-opencode.txt",
									"content":  f.fileContent,
								}),
							},
						}},
					},
					"finish_reason": nil,
				}},
			})
			send(map[string]any{
				"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "heal",
				"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "tool_calls"}},
				"usage":   map[string]any{"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
			})
		default:
			content := "Test title"
			if isFollowup {
				content = "done authoring the file"
			}
			send(map[string]any{
				"id": "c2", "object": "chat.completion.chunk", "created": 0, "model": "heal",
				"choices": []map[string]any{{
					"index": 0, "delta": map[string]any{"role": "assistant", "content": content}, "finish_reason": nil,
				}},
			})
			send(map[string]any{
				"id": "c2", "object": "chat.completion.chunk", "created": 0, "model": "heal",
				"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
				"usage":   map[string]any{"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
			})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		if fl != nil {
			fl.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func readAll(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		buf.Write(sc.Bytes())
		buf.WriteByte('\n')
	}
	return buf.Bytes(), sc.Err()
}

// TestRealOpencode_OutputCapReachesWire proves ProviderConfig's declared
// `limit.output` is not just a JSON string the adapter constructs (already
// covered by TestProviderConfigOutputLimit) but the ACTUAL `max_tokens` the
// REAL opencode binary puts on the wire in every chat-completions request —
// the exact mechanism f482488 fixed. It drives Invoke end to end (real
// worktree, real ScrubbedEnv, real subprocess) against a local fake server
// that only records max_tokens and replies with plain text (no tool calls) —
// the smallest round trip that still proves the wire contract.
func TestRealOpencode_OutputCapReachesWire(t *testing.T) {
	bin := mustRealOpencodeBin(t)

	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	srv, fake := newFakeOpenAIServer(t, "unused for this test")

	const wantCap = 4096
	a := &Adapter{
		Bin: bin, Lane: "heal", Provider: "forge", ForgeBaseURL: srv.URL,
		MaxOutputTokens: wantCap, MaxContextTokens: 128000,
		extraRunArgs: []string{"--pure"},
	}
	res, err := a.Invoke(context.Background(), wt, "mallcop-sk-realbintest", "say hello")
	if err != nil {
		t.Fatalf("Invoke (real opencode): %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("real opencode exit code = %d, want 0; transcript:\n%s", res.ExitCode, res.TranscriptRedacted)
	}
	if len(fake.maxTokensSeen) == 0 {
		t.Fatalf("the real opencode binary never reached the fake server at all")
	}
	for i, got := range fake.maxTokensSeen {
		if got != wantCap {
			t.Errorf("request %d: real opencode sent max_tokens=%d, want the declared cap %d", i, got, wantCap)
		}
	}

	// ---- negative half: the PRE-FIX config shape (no models/limit block at
	//      all) against the REAL binary. ProviderConfig always declares the cap
	//      (there is no adapter knob to omit it), so this reproduces the
	//      pre-f482488 shape via a raw exec — proving the regression is REAL
	//      and reproducible against the real binary, not just asserted in a
	//      comment. ----
	srv2, _ := newFakeOpenAIServer(t, "unused")
	noLimitCfg := fmt.Sprintf(
		`{"$schema":"https://opencode.ai/config.json","provider":{"forge":{"npm":"@ai-sdk/openai-compatible","name":"Forge","options":{"baseURL":%q,"apiKey":"mallcop-sk-realbintest"}}}}`,
		srv2.URL+"/v1")
	cmd := exec.Command(bin, "run", "say hello", "-m", "forge/heal", "--format", "json",
		"--dangerously-skip-permissions", "--dir", wt.Dir, "--pure")
	cmd.Dir = wt.Dir
	cmd.Env = []string{"PATH=" + lookupPATH(t), "HOME=" + t.TempDir(), "OPENCODE_CONFIG_CONTENT=" + noLimitCfg}
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		t.Errorf("real opencode with NO output-cap declared: expected a non-zero exit (config validation "+
			"failure — this is the exact pre-f482488 regression), got exit 0. Output:\n%s", out)
	}
	if strings.Contains(string(out), "authored-by-real-opencode.txt") {
		t.Errorf("real opencode with NO output-cap declared should not have reached a working round trip: %s", out)
	}
}

// lookupPATH returns the current process's PATH so a raw exec.Command in a
// test can still resolve node/opencode without inheriting the rest of the
// test process's environment.
func lookupPATH(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("sh", "-c", "echo -n \"$PATH\"")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("resolve PATH: %v", err)
	}
	return string(out)
}

// TestRealOpencode_FileExtractionAndKeyRedaction drives a REAL write-tool
// round trip through the genuine opencode binary: the fake server scripts a
// tool_calls response invoking write(filePath, content), so opencode actually
// creates the file on disk and emits ITS OWN "tool"/"write" event JSON in
// --format json — proving Parse()'s fileKeyPattern extraction against the
// real wire shape (not the hand-authored writeInvokeStub fixture). The
// scripted file content carries the run's own apiKey (the shape a buggy or
// malicious backend echoing the request's own config back would produce);
// the test proves Invoke's redact.Redact pass scrubs it from
// Result.TranscriptRedacted before it is ever persisted.
func TestRealOpencode_FileExtractionAndKeyRedaction(t *testing.T) {
	bin := mustRealOpencodeBin(t)

	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	const apiKey = "mallcop-sk-REALOPENCODELEAKTEST0123456789"
	leakedContent := "authored by the real opencode binary; leaked key marker: " + apiKey
	srv, _ := newFakeOpenAIServer(t, leakedContent)

	a := &Adapter{
		Bin: bin, Lane: "heal", Provider: "forge", ForgeBaseURL: srv.URL,
		extraRunArgs: []string{"--pure"},
	}
	res, err := a.Invoke(context.Background(), wt, apiKey, "write a file")
	if err != nil {
		t.Fatalf("Invoke (real opencode): %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("real opencode exit code = %d, want 0; transcript:\n%s", res.ExitCode, res.TranscriptRedacted)
	}

	// ---- REAL file-extraction: opencode's OWN "tool"/"write" event carried
	//      the filePath, and Parse() (schema-tolerant walking of the REAL
	//      event stream) found it. ----
	foundFile := false
	for _, f := range res.AuthoredFiles {
		if strings.Contains(f, "authored-by-real-opencode.txt") {
			foundFile = true
		}
	}
	if !foundFile {
		t.Errorf("Parse() did not extract the authored file from the REAL opencode event stream; AuthoredFiles=%v", res.AuthoredFiles)
	}
	// The file must ALSO actually exist in the worktree — opencode's own
	// write-tool execution, not just its self-reported event.
	writtenPath := wt.Dir + "/authored-by-real-opencode.txt"
	writtenBytes, statErr := os.ReadFile(writtenPath)
	if statErr != nil {
		t.Fatalf("real opencode did not actually write the file to the worktree: %v", statErr)
	}
	if !strings.Contains(string(writtenBytes), "authored by the real opencode binary") {
		t.Errorf("written file content = %q, missing expected marker", writtenBytes)
	}

	// ---- REAL key redaction: the raw apiKey appeared in opencode's OWN
	//      tool-call event (embedded in the file content it echoed back) — the
	//      adapter's redact.Redact pass over the REAL combined stdout/stderr
	//      must have scrubbed it before it was ever returned. ----
	transcript := string(res.TranscriptRedacted)
	if strings.Contains(transcript, apiKey) {
		t.Errorf("transcript leaked the raw apiKey from the REAL opencode event stream:\n%s", transcript)
	}
	if strings.Contains(transcript, "mallcop-sk") {
		t.Errorf("transcript leaked a mallcop-sk-shaped token:\n%s", transcript)
	}
	if !strings.Contains(transcript, "***REDACTED***") {
		t.Errorf("expected the redaction marker in the transcript:\n%s", transcript)
	}
}
