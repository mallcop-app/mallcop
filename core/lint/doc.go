// Package lint hosts the repo-level import-lint guard for the core/ tree.
//
// The product runtime — everything under core/ that ships in the mallcop
// binary — must depend on NO agent-orchestration framework. The model is
// reached only through the hand-rolled anthropic.Client interface in
// core/agent, threaded in by the caller; the core packages themselves must not
// import a campfire transport, the legion automaton engine, a Claude Code /
// agent-orchestration framework, or a vendor LLM SDK.
//
// This package contains no production code — only imports_test.go, which walks
// every production .go file under core/ and fails the build if any of them
// imports a banned family. It exists as its own package so the test can reach
// the whole core/ subtree (located by walking up to go.mod) rather than a
// single package directory, the way the per-package imports_test.go files do.
package lint
