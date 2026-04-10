"""End-to-end integration test: container-mode chat path.

Proves that the full chat path works with:
- A real InteractiveRuntime (not a mock) built from container-mode minimal config
- A scripted LLM that returns a canned response (no API calls)
- A real ConversationStore (JSONL on disk)
- A real campfire (filesystem transport) for CampfireDispatcher

This is the proof that the feature works before handing off to human validation.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

from mallcop.actors.interactive_runtime import (
    InteractiveRuntime,
    TurnResult,
    build_interactive_runtime,
)
from mallcop.actors.runtime import build_actor_runner
from mallcop.chat import TOKENS_PER_DONUT, chat_turn
from mallcop.config import BudgetConfig, DeliveryConfig, MallcopConfig
from mallcop.conversation import ConversationStore
from mallcop.llm_types import LLMResponse
from mallcop.store import JsonlStore


# ---------------------------------------------------------------------------
# Scripted LLM — returns pre-configured responses, no API calls
# ---------------------------------------------------------------------------

class ScriptedLLM:
    """LLM that returns pre-configured responses in sequence."""

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self._idx = 0
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
        if self._idx >= len(self._responses):
            return LLMResponse(
                text="(exhausted)", tool_calls=[], tokens_used=10, resolution=None,
            )
        resp = self._responses[self._idx]
        self._idx += 1
        return resp


# ---------------------------------------------------------------------------
# Minimal container config — no mallcop.yaml on disk
# ---------------------------------------------------------------------------

def _container_config(campfire_id: str = "fake-cf") -> MallcopConfig:
    return MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id=campfire_id),
    )


# ---------------------------------------------------------------------------
# Test 1: build_interactive_runtime succeeds with container config
# ---------------------------------------------------------------------------

def test_build_interactive_runtime_container_config(tmp_path: Path) -> None:
    """build_interactive_runtime produces a working InteractiveRuntime
    from a minimal container config (no mallcop.yaml, no connectors)."""
    config = _container_config()
    store = JsonlStore(tmp_path)
    llm = ScriptedLLM([LLMResponse(text="hello", tool_calls=[], tokens_used=50, resolution=None)])

    actor_runner = build_actor_runner(
        root=tmp_path, store=store, config=config, llm=llm,
        validate_paths=False,
    )

    runtime = build_interactive_runtime(
        root=tmp_path, store=store, config=config,
        llm=llm, actor_runner=actor_runner,
    )

    assert isinstance(runtime, InteractiveRuntime), (
        f"Expected InteractiveRuntime, got {type(runtime)}"
    )
    # Verify it has a system prompt loaded from POST.md
    assert runtime._system_prompt, "system_prompt is empty — POST.md not loaded"
    assert len(runtime._system_prompt) > 50, (
        f"system_prompt too short ({len(runtime._system_prompt)} chars) — POST.md not loaded correctly"
    )


# ---------------------------------------------------------------------------
# Test 2: InteractiveRuntime.run_turn produces a TurnResult with scripted LLM
# ---------------------------------------------------------------------------

def test_interactive_runtime_run_turn_scripted_llm(tmp_path: Path) -> None:
    """A real InteractiveRuntime (built from container config) executes run_turn
    with a scripted LLM and returns a TurnResult with the expected text."""
    config = _container_config()
    store = JsonlStore(tmp_path)
    llm = ScriptedLLM([
        LLMResponse(text="You have 3 open findings.", tool_calls=[], tokens_used=120, resolution=None),
    ])

    actor_runner = build_actor_runner(
        root=tmp_path, store=store, config=config, llm=llm,
        validate_paths=False,
    )
    runtime = build_interactive_runtime(
        root=tmp_path, store=store, config=config,
        llm=llm, actor_runner=actor_runner,
    )

    result = runtime.run_turn(
        messages=[{"role": "user", "content": "show me the findings"}],
        turn_budget_donuts=12,
        session_id="test-session-001",
    )

    assert isinstance(result, TurnResult)
    assert result.text == "You have 3 open findings."
    assert result.tokens_used == 120
    assert result.iterations == 1

    # Verify the LLM received the right inputs
    assert len(llm.calls) == 1
    call = llm.calls[0]
    assert call["messages"][-1]["content"] == "show me the findings"
    assert "security" in call["system_prompt"].lower(), (
        "system_prompt should contain security-related content from POST.md"
    )
    assert len(call["tools"]) > 0, "tool schemas should be non-empty"


# ---------------------------------------------------------------------------
# Test 3: Full chat_turn path — user question → store → runtime → response
# ---------------------------------------------------------------------------

def test_chat_turn_full_path_with_real_runtime(tmp_path: Path) -> None:
    """chat_turn with a REAL InteractiveRuntime (not mock):
    1. Appends user message to ConversationStore
    2. Loads recent history (5-msg window)
    3. Calls run_turn on the real InteractiveRuntime
    4. Appends assistant response to store
    5. Returns response dict with text, tokens, footer
    """
    config = _container_config()
    store_backend = JsonlStore(tmp_path)
    conv_store = ConversationStore(tmp_path / "conversations.jsonl")

    llm = ScriptedLLM([
        LLMResponse(
            text="Based on your scan, you have 2 critical and 1 medium finding.",
            tool_calls=[], tokens_used=200, resolution=None,
        ),
    ])

    actor_runner = build_actor_runner(
        root=tmp_path, store=store_backend, config=config, llm=llm,
        validate_paths=False,
    )
    runtime = build_interactive_runtime(
        root=tmp_path, store=store_backend, config=config,
        llm=llm, actor_runner=actor_runner,
    )

    session_id = f"e2e-test-{uuid.uuid4()}"

    result = asyncio.run(chat_turn(
        question="What are my findings?",
        session_id=session_id,
        interactive_runner=runtime,
        store=conv_store,
        root=tmp_path,
    ))

    # Verify response dict structure
    assert isinstance(result, dict)
    assert result["response"] == "Based on your scan, you have 2 critical and 1 medium finding."
    assert result["tokens_used"] == 200
    assert "footer" in result

    # Verify the ConversationStore has both messages
    history = conv_store.load_session(session_id)
    assert len(history) == 2, f"Expected 2 messages (user + assistant), got {len(history)}"
    assert history[0].role == "user"
    assert history[0].content == "What are my findings?"
    assert history[1].role == "assistant"
    assert history[1].content == "Based on your scan, you have 2 critical and 1 medium finding."

    # Verify LLM received the user message in the messages array
    assert len(llm.calls) == 1
    llm_messages = llm.calls[0]["messages"]
    assert llm_messages[-1]["role"] == "user"
    assert llm_messages[-1]["content"] == "What are my findings?"


# ---------------------------------------------------------------------------
# Test 4: Multi-turn conversation — 5-message window works
# ---------------------------------------------------------------------------

def test_chat_turn_multi_turn_5msg_window(tmp_path: Path) -> None:
    """Three chat turns: the third turn's LLM call receives at most 5 messages
    (the 5-message preload window), not the full history."""
    config = _container_config()
    store_backend = JsonlStore(tmp_path)
    conv_store = ConversationStore(tmp_path / "conversations.jsonl")
    session_id = f"e2e-multi-{uuid.uuid4()}"

    # We need 3 LLM responses (one per turn)
    llm = ScriptedLLM([
        LLMResponse(text="Response 1", tool_calls=[], tokens_used=100, resolution=None),
        LLMResponse(text="Response 2", tool_calls=[], tokens_used=100, resolution=None),
        LLMResponse(text="Response 3", tool_calls=[], tokens_used=100, resolution=None),
    ])

    actor_runner = build_actor_runner(
        root=tmp_path, store=store_backend, config=config, llm=llm,
        validate_paths=False,
    )
    runtime = build_interactive_runtime(
        root=tmp_path, store=store_backend, config=config,
        llm=llm, actor_runner=actor_runner,
    )

    # Turn 1
    asyncio.run(chat_turn(
        question="Question 1",
        session_id=session_id,
        interactive_runner=runtime,
        store=conv_store,
        root=tmp_path,
    ))

    # Turn 2
    asyncio.run(chat_turn(
        question="Question 2",
        session_id=session_id,
        interactive_runner=runtime,
        store=conv_store,
        root=tmp_path,
    ))

    # Turn 3
    result = asyncio.run(chat_turn(
        question="Question 3",
        session_id=session_id,
        interactive_runner=runtime,
        store=conv_store,
        root=tmp_path,
    ))

    assert result["response"] == "Response 3"

    # After 3 turns, store has 6 messages (3 user + 3 assistant)
    history = conv_store.load_session(session_id)
    assert len(history) == 6, f"Expected 6 messages, got {len(history)}"

    # The 3rd LLM call should have received at most 5 messages (the window)
    third_call = llm.calls[2]
    assert len(third_call["messages"]) == 5, (
        f"Expected 5-message window, got {len(third_call['messages'])} messages: "
        f"{[m['content'][:20] for m in third_call['messages']]}"
    )
    # The last message should be "Question 3"
    assert third_call["messages"][-1]["content"] == "Question 3"


# ---------------------------------------------------------------------------
# Test 5: interactive_runner=None returns platform error (not crash)
# ---------------------------------------------------------------------------

def test_chat_turn_none_runner_returns_platform_error(tmp_path: Path) -> None:
    """When interactive_runner is None, chat_turn returns a platform error
    and does NOT append any messages to the store."""
    conv_store = ConversationStore(tmp_path / "conversations.jsonl")
    session_id = f"e2e-none-{uuid.uuid4()}"

    result = asyncio.run(chat_turn(
        question="Hello?",
        session_id=session_id,
        interactive_runner=None,
        store=conv_store,
        root=tmp_path,
    ))

    assert "Pro subscription required" in result["response"]
    # The user message should NOT be in the store (early return before append)
    history = conv_store.load_session(session_id)
    # Only the platform error response is appended
    user_msgs = [m for m in history if m.role == "user"]
    assert len(user_msgs) == 0, "User message should NOT be appended when runner is None"


# ---------------------------------------------------------------------------
# Test 6: Full CampfireDispatcher round-trip with real InteractiveRuntime
# ---------------------------------------------------------------------------

def test_dispatcher_round_trip_real_runtime(tmp_path: Path) -> None:
    """CampfireDispatcher receives an inbound message, runs chat_turn with
    a REAL InteractiveRuntime (scripted LLM), and posts a response back
    to a real filesystem campfire."""
    import tempfile
    # Use a clean CF_HOME to avoid relay config from ~/.cf/config.toml
    cf_home = tempfile.mkdtemp(prefix="cf-e2e-")
    cf_env = {**__import__("os").environ, "CF_HOME": cf_home}
    subprocess.run(["cf", "init"], env=cf_env, capture_output=True)

    # Create a real campfire
    result = subprocess.run(
        ["cf", "create", "--description", "e2e-chat-test",
         "--transport", "filesystem", "--no-config", "--json"],
        capture_output=True, text=True, env=cf_env,
    )
    assert result.returncode == 0, f"cf create failed: {result.stderr}"
    campfire_id = json.loads(result.stdout)["campfire_id"]

    try:
        # Declare convention operations
        fixtures_dir = Path(__file__).parent / "fixtures" / "declarations"
        for decl_file in sorted(fixtures_dir.glob("*.json")):
            decl = subprocess.run(
                ["cf", "send", campfire_id, "--tag", "convention:operation",
                 decl_file.read_text()],
                capture_output=True, text=True, env=cf_env,
            )
            assert decl.returncode == 0, f"convention declare failed: {decl.stderr}"

        # Send an inbound message
        session_id = str(uuid.uuid4())
        inbound = subprocess.run(
            ["cf", campfire_id, "inbound-message",
             "--content", "What are my open findings?",
             "--from_id", session_id,
             "--platform", "telegram"],
            capture_output=True, text=True, env=cf_env,
        )
        assert inbound.returncode == 0, f"inbound-message failed: {inbound.stderr}"

        # Build a real InteractiveRuntime with scripted LLM
        config = _container_config(campfire_id=campfire_id)
        store_backend = JsonlStore(tmp_path)
        llm = ScriptedLLM([
            LLMResponse(
                text="You have 2 critical findings: MC-001 (S3 bucket public) and MC-002 (IAM overpermission).",
                tool_calls=[], tokens_used=150, resolution=None,
            ),
        ])
        actor_runner = build_actor_runner(
            root=tmp_path, store=store_backend, config=config, llm=llm,
            validate_paths=False,
        )
        runtime = build_interactive_runtime(
            root=tmp_path, store=store_backend, config=config,
            llm=llm, actor_runner=actor_runner,
        )

        # Create dispatcher with real runtime
        from mallcop.campfire_dispatch import CampfireDispatcher

        dispatcher = CampfireDispatcher(
            campfire_id=campfire_id,
            interactive_runner=runtime,
            root=tmp_path,
            poll_interval=0.1,
            cf_home=cf_home,
        )

        # Run one poll cycle
        async def run_one_poll():
            messages = await dispatcher._read_new_messages()
            assert len(messages) >= 1, f"Expected at least 1 inbound message, got {len(messages)}"
            for msg in messages:
                await dispatcher._dispatch_message(msg)

        asyncio.run(run_one_poll())

        # Read the campfire for the response
        read_result = subprocess.run(
            ["cf", "read", campfire_id, "--all", "--json"],
            capture_output=True, text=True, env=cf_env,
        )
        assert read_result.returncode == 0
        all_msgs = json.loads(read_result.stdout) or []

        # Find the response message
        response_msgs = [
            m for m in all_msgs
            if any("relay:response" in t for t in m.get("tags", []))
        ]
        assert len(response_msgs) >= 1, (
            f"Expected at least 1 relay:response on campfire. "
            f"All tags: {[m.get('tags') for m in all_msgs]}"
        )

        # Verify the response content
        resp_payload = json.loads(response_msgs[0]["payload"])
        assert "MC-001" in resp_payload.get("content", ""), (
            f"Response should contain 'MC-001'. Got: {resp_payload}"
        )
        assert "MC-002" in resp_payload.get("content", ""), (
            f"Response should contain 'MC-002'. Got: {resp_payload}"
        )

        # Verify session tag
        session_tag = f"relay:session_id:{session_id}"
        assert session_tag in response_msgs[0]["tags"], (
            f"Expected {session_tag} in tags: {response_msgs[0]['tags']}"
        )

    finally:
        subprocess.run(["cf", "disband", campfire_id], capture_output=True, env=cf_env)
