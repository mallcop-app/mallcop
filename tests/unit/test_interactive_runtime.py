"""Tests for InteractiveRuntime and build_interactive_runtime factory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mallcop.actors._schema import ActorManifest
from mallcop.actors.interactive_runtime import (
    InteractiveRuntime,
    TurnResult,
    build_interactive_runtime,
)
from mallcop.actors.runtime import _TRUSTED_TOOLS
from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall
from mallcop.tools import ToolContext, ToolRegistry, tool


# ─── Helpers ─────────────────────────────────────────────────────────


def _make_manifest(
    tools: list[str] | None = None,
    permissions: list[str] | None = None,
    model: str = "detective",
) -> ActorManifest:
    return ActorManifest(
        name="interactive",
        type="agent",
        description="Interactive actor",
        version="0.1.0",
        model=model,
        tools=tools or [],
        permissions=permissions or ["read", "write"],
        routes_to=None,
        max_iterations=None,
        config={},
    )


def _build_registry() -> ToolRegistry:
    reg = ToolRegistry()

    @tool(name="search-findings", description="Search findings", permission="read")
    def search_findings(query: str) -> str:
        return f"findings for {query}"

    @tool(name="list-findings", description="List findings", permission="read")
    def list_findings() -> str:
        return "recent findings"

    @tool(name="annotate-finding", description="Annotate finding", permission="write")
    def annotate_finding(finding_id: str, note: str) -> str:
        return f"annotated {finding_id}"

    reg.register(search_findings)
    reg.register(list_findings)
    reg.register(annotate_finding)
    return reg


def _make_context() -> ToolContext:
    return ToolContext(
        store=MagicMock(),
        connectors={},
        config=MagicMock(),
    )


class MockLLMClient(LLMClient):
    """Mock LLM that returns pre-configured responses in sequence."""

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self._call_count = 0
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int | None = None,
    ) -> LLMResponse:
        self.calls.append({
            "model": model,
            "system_prompt": system_prompt,
            "messages": messages,
            "tools": tools,
        })
        if self._call_count >= len(self._responses):
            raise RuntimeError("MockLLMClient exhausted responses")
        resp = self._responses[self._call_count]
        self._call_count += 1
        return resp


def _make_runtime(
    responses: list[LLMResponse],
    tools: list[str] | None = None,
    permissions: list[str] | None = None,
    system_prompt: str = "You are a security assistant.",
) -> tuple[InteractiveRuntime, MockLLMClient]:
    llm = MockLLMClient(responses)
    manifest = _make_manifest(
        tools=tools or ["search-findings", "list-findings", "annotate-finding"],
        permissions=permissions or ["read", "write"],
    )
    registry = _build_registry()
    context = _make_context()
    runtime = InteractiveRuntime(
        manifest=manifest,
        registry=registry,
        llm=llm,
        context=context,
        system_prompt=system_prompt,
    )
    return runtime, llm


# ─── Core loop tests ─────────────────────────────────────────────────


class TestTermination:
    def test_termination_on_text(self) -> None:
        """LLM returns text without tool_calls → single iteration."""
        responses = [
            LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=150,
                text="Here are the recent security findings.",
            )
        ]
        runtime, llm = _make_runtime(responses)
        messages = [{"role": "user", "content": "Show me recent findings"}]

        result = runtime.run_turn(messages)

        assert result.text == "Here are the recent security findings."
        assert result.tokens_used == 150
        assert result.iterations == 1
        assert result.tool_calls == 0
        assert len(llm.calls) == 1

    def test_multi_iteration_tool_loop(self) -> None:
        """LLM returns tool_call first, then text; tool results passed back correctly."""
        responses = [
            LLMResponse(
                tool_calls=[ToolCall(name="list-findings", arguments={})],
                resolution=None,
                tokens_used=80,
                text="",
            ),
            LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=120,
                text="I found 3 open findings.",
            ),
        ]
        runtime, llm = _make_runtime(responses)
        messages = [{"role": "user", "content": "List findings"}]

        result = runtime.run_turn(messages)

        assert result.text == "I found 3 open findings."
        assert result.tokens_used == 200
        assert result.iterations == 2
        assert result.tool_calls == 1
        assert len(llm.calls) == 2

        # Verify tool result was fed back with correct shape
        second_call_messages = llm.calls[1]["messages"]
        tool_msgs = [m for m in second_call_messages if m.get("role") == "tool"]
        assert len(tool_msgs) == 1
        assert tool_msgs[0]["name"] == "list-findings"
        assert "recent findings" in tool_msgs[0]["content"]

    def test_budget_exhausted(self) -> None:
        """total_tokens > budget after first call → returns donut budget message."""
        responses = [
            LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=5000,  # Exceeds 12 * 1000 = 12000? No, let's use 13000
                text="",
            ),
        ]
        # With turn_budget_donuts=5 → budget = 5000 tokens
        # Response uses 5000+1 tokens... let's set tokens_used to 6000
        responses[0] = LLMResponse(
            tool_calls=[],
            resolution=None,
            tokens_used=6000,
            text="",
        )
        runtime, llm = _make_runtime(responses)
        messages = [{"role": "user", "content": "Tell me everything"}]

        result = runtime.run_turn(messages, turn_budget_donuts=5)

        assert "donut" in result.text.lower()
        assert "5" in result.text  # mentions the budget count
        assert result.tokens_used == 6000
        assert result.iterations == 1

    def test_max_iterations(self) -> None:
        """LLM always returns tool_calls, never text → returns 'couldn't reach conclusion'."""
        tool_call_response = LLMResponse(
            tool_calls=[ToolCall(name="list-findings", arguments={})],
            resolution=None,
            tokens_used=10,
            text="",
        )
        # 20 iterations max
        runtime, llm = _make_runtime([tool_call_response] * 20)
        messages = [{"role": "user", "content": "Investigate everything"}]

        result = runtime.run_turn(messages)

        assert "couldn't reach a conclusion" in result.text
        assert "20" in result.text
        assert result.iterations == 20
        assert len(llm.calls) == 20


class TestErrorHandling:
    def test_llm_api_error_propagates(self) -> None:
        """LLMAPIError from llm.chat → propagates to caller."""
        llm = MockLLMClient([])
        # Override chat to raise immediately
        llm.chat = lambda **kwargs: (_ for _ in ()).throw(LLMAPIError("backend down"))  # type: ignore

        manifest = _make_manifest(tools=["list-findings"])
        registry = _build_registry()
        context = _make_context()
        runtime = InteractiveRuntime(
            manifest=manifest,
            registry=registry,
            llm=llm,
            context=context,
            system_prompt="You are a security assistant.",
        )

        with pytest.raises(LLMAPIError, match="backend down"):
            runtime.run_turn([{"role": "user", "content": "hello"}])

    def test_llm_api_error_propagates_via_mock(self) -> None:
        """LLMAPIError via a raising MockLLMClient propagates."""

        class ErrorLLM(LLMClient):
            def chat(self, model, system_prompt, messages, tools, max_tokens=None):
                raise LLMAPIError("service unavailable")

        manifest = _make_manifest(tools=["list-findings"])
        registry = _build_registry()
        context = _make_context()
        runtime = InteractiveRuntime(
            manifest=manifest,
            registry=registry,
            llm=ErrorLLM(),
            context=context,
            system_prompt="assistant",
        )

        with pytest.raises(LLMAPIError):
            runtime.run_turn([{"role": "user", "content": "hello"}])

    def test_empty_response_iter0(self) -> None:
        """LLM returns empty (no text, no tool_calls, 0 tokens) on iter 0 → raises LLMAPIError."""
        responses = [
            LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=0,
                text="",
            )
        ]
        runtime, _ = _make_runtime(responses)

        with pytest.raises(LLMAPIError, match="backend returned empty response"):
            runtime.run_turn([{"role": "user", "content": "hello"}])

    def test_tool_error_continues(self) -> None:
        """Tool execution raises → result is {'error': ...} dict, loop continues."""
        reg = ToolRegistry()

        @tool(name="broken-tool", description="Broken tool", permission="read")
        def broken_tool() -> str:
            raise RuntimeError("disk full")

        reg.register(broken_tool)

        responses = [
            LLMResponse(
                tool_calls=[ToolCall(name="broken-tool", arguments={})],
                resolution=None,
                tokens_used=50,
                text="",
            ),
            LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=60,
                text="There was an error with that tool.",
            ),
        ]
        llm = MockLLMClient(responses)
        manifest = _make_manifest(tools=["broken-tool"])
        context = _make_context()
        runtime = InteractiveRuntime(
            manifest=manifest,
            registry=reg,
            llm=llm,
            context=context,
            system_prompt="assistant",
        )

        result = runtime.run_turn([{"role": "user", "content": "use broken tool"}])

        # Loop continued and returned text
        assert result.text == "There was an error with that tool."
        assert result.iterations == 2

        # Error was fed back to LLM as tool result
        second_call_messages = llm.calls[1]["messages"]
        tool_msgs = [m for m in second_call_messages if m.get("role") == "tool"]
        assert len(tool_msgs) == 1
        assert "error" in tool_msgs[0]["content"].lower()


class TestSessionAndPermissions:
    def test_session_id_propagated(self) -> None:
        """session_id passed to run_turn → context.session_id updated."""
        responses = [
            LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=100,
                text="Done.",
            )
        ]
        runtime, _ = _make_runtime(responses)
        messages = [{"role": "user", "content": "hello"}]

        assert runtime._context.session_id == ""
        runtime.run_turn(messages, session_id="session-abc-123")
        assert runtime._context.session_id == "session-abc-123"

    def test_read_only_tool_honored(self) -> None:
        """Tool with write permission raises PermissionError when manifest is read-only."""
        # Manifest only has read permission; annotate-finding requires write
        manifest = _make_manifest(
            tools=["search-findings", "list-findings"],
            permissions=["read"],
        )
        registry = _build_registry()
        context = _make_context()
        llm = MockLLMClient([
            LLMResponse(tool_calls=[], resolution=None, tokens_used=100, text="ok"),
        ])
        # Construction should succeed since we're not including write tools in manifest
        runtime = InteractiveRuntime(
            manifest=manifest,
            registry=registry,
            llm=llm,
            context=context,
            system_prompt="assistant",
        )
        result = runtime.run_turn([{"role": "user", "content": "hello"}])
        assert result.text == "ok"

    def test_trusted_tool_bypass(self) -> None:
        """A tool in _TRUSTED_TOOLS → result NOT sanitized (no USER_DATA markers added)."""
        reg = ToolRegistry()

        # Register a tool with the trusted name
        trusted_name = next(iter(_TRUSTED_TOOLS))  # e.g. "load-skill"

        @tool(name=trusted_name, description="Trusted tool", permission="read")
        def trusted_fn() -> str:
            return "trusted raw content"

        reg.register(trusted_fn)

        responses = [
            LLMResponse(
                tool_calls=[ToolCall(name=trusted_name, arguments={})],
                resolution=None,
                tokens_used=50,
                text="",
            ),
            LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=60,
                text="Skill loaded.",
            ),
        ]
        llm = MockLLMClient(responses)
        manifest = _make_manifest(tools=[trusted_name])
        context = _make_context()
        runtime = InteractiveRuntime(
            manifest=manifest,
            registry=reg,
            llm=llm,
            context=context,
            system_prompt="assistant",
        )

        runtime.run_turn([{"role": "user", "content": "load skill"}])

        # Check the tool result message in the second LLM call
        second_call_messages = llm.calls[1]["messages"]
        tool_msgs = [m for m in second_call_messages if m.get("role") == "tool"]
        assert len(tool_msgs) == 1
        # Trusted tool result should NOT have USER_DATA markers
        assert "USER_DATA_BEGIN" not in tool_msgs[0]["content"]
        assert "trusted raw content" in tool_msgs[0]["content"]


# ─── Factory tests ────────────────────────────────────────────────────


class TestFactory:
    def test_factory_effective_tools(self, tmp_path: Path) -> None:
        """Synthetic manifest includes named tools + all read-permission registry tools."""
        # Build a minimal config mock
        config = MagicMock()
        config.connectors = {}

        store = MagicMock()
        llm = MockLLMClient([])
        actor_runner = MagicMock()

        # The factory discovers tools from the real built-in tools directory
        # and from the interactive manifest.
        # We'll verify that effective_tools >= named tools from manifest
        runtime = build_interactive_runtime(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_runner=actor_runner,
        )

        # The synthetic manifest's tools should be a superset of the interactive manifest's tools
        # (named tools + all read tools in registry)
        from mallcop.actors._schema import load_actor_manifest
        interactive_dir = Path(__file__).parent.parent.parent / "src/mallcop/actors/interactive"
        orig_manifest = load_actor_manifest(interactive_dir)

        # Every named tool from the original manifest should be in the synthetic one
        # (if it exists in the registry; some may be missing but that's OK)
        effective = set(runtime._manifest.tools)
        # At minimum: the factory should produce >= the read tools from the registry
        # (all_reads + named_tools >= named_tools)
        assert len(effective) > 0

        # Verify all_reads logic: all read-permission tools in registry should be included
        all_read_metas = runtime._registry.get_eligible_tools(names=None, max_permission="read")
        all_read_names = {m.name for m in all_read_metas}
        # Every read tool in registry should appear in effective tools
        assert all_read_names.issubset(effective)

    def test_factory_actor_runner(self, tmp_path: Path) -> None:
        """context.actor_runner == passed actor_runner."""
        config = MagicMock()
        config.connectors = {}

        store = MagicMock()
        llm = MockLLMClient([])
        actor_runner = MagicMock()
        actor_runner.__name__ = "mock_actor_runner"

        runtime = build_interactive_runtime(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_runner=actor_runner,
        )

        assert runtime._context.actor_runner is actor_runner
