package investigate

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/tools"
)

// TestToolDefs_IncludesGithubActor proves the investigate loop actually
// advertises github_actor to the model — the fifth tool this item adds
// alongside the four merged in #158. A model that is never told a tool
// exists can never call it, so this is the load-bearing half of "the loop
// can call it."
func TestToolDefs_IncludesGithubActor(t *testing.T) {
	defs := ToolDefs()
	var found *struct {
		hasLoginProp bool
		required     []string
	}
	for _, d := range defs {
		if d.Name != "github_actor" {
			continue
		}
		schema, ok := d.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("github_actor InputSchema is not a map[string]any: %T", d.InputSchema)
		}
		props, _ := schema["properties"].(map[string]any)
		_, hasLogin := props["login"]
		req, _ := schema["required"].([]string)
		found = &struct {
			hasLoginProp bool
			required     []string
		}{hasLoginProp: hasLogin, required: req}
	}
	if found == nil {
		t.Fatalf("ToolDefs() does not include github_actor; got tool names: %v", toolNames(defs))
	}
	if !found.hasLoginProp {
		t.Error("github_actor InputSchema.properties has no \"login\" field")
	}
	if len(found.required) != 1 || found.required[0] != "login" {
		t.Errorf("github_actor InputSchema.required = %v, want [\"login\"]", found.required)
	}
}

func toolNames(defs []agent.Tool) []string {
	names := make([]string, len(defs))
	for i, d := range defs {
		names[i] = d.Name
	}
	return names
}

// TestExecuteTool_DispatchesGithubActor proves ExecuteTool actually routes a
// "github_actor" tool_use to tools.GithubActor and gets back a real answer
// for the reserved `ghost` login — the exact tombstone case the current chat
// hallucinates about — via the SAME dispatch path the model-driven loop
// uses (runTools -> ExecuteTool). This hits the REAL api.github.com; if the
// sandbox has no network reachability, the test is skipped rather than
// mocked (a mocked dispatch test would prove routing but not the real
// tombstone signal).
func TestExecuteTool_DispatchesGithubActor(t *testing.T) {
	requireGithubNetworkForDispatch(t)

	out, err := ExecuteTool(Options{}, "github_actor", map[string]any{"login": "ghost"})
	if err != nil {
		t.Fatalf("ExecuteTool(github_actor) returned error: %v", err)
	}
	env, ok := out.(tools.GithubActorEnvelope)
	if !ok {
		t.Fatalf("ExecuteTool(github_actor) returned %T, want tools.GithubActorEnvelope", out)
	}
	if !env.Ghost {
		t.Errorf("ExecuteTool(github_actor, login=ghost).Ghost = false, want true")
	}
	if !env.Found {
		t.Errorf("ExecuteTool(github_actor, login=ghost).Found = false, want true")
	}
}

// requireGithubNetworkForDispatch skips this test file's network-dependent
// case when api.github.com is unreachable, per the item's
// dependency-escalation instruction (escalate, don't mock).
func requireGithubNetworkForDispatch(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/", nil)
	if err != nil {
		t.Fatalf("build network-probe request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("api.github.com unreachable from this sandbox (%v) — mallcoppro-5d08 requires a LIVE test; "+
			"escalate as a dependency rather than mocking the GitHub API", err)
	}
	_ = resp.Body.Close()
}
