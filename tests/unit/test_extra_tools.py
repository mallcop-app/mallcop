"""Tests for build_actor_runner extra_tools parameter.

Bead: mallcop-bs32

Tests that extra_tools passed to build_actor_runner are registered in
the tool registry and available to the actor runtime during execution.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import (
    LLMClient,
    LLMResponse,
    RunResult,
    ToolCall,
    build_actor_runner,
)
from mallcop.config import load_config
from mallcop.schemas import Event, Finding, FindingStatus, Severity
from mallcop.store import JsonlStore
from mallcop.tools import tool


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_finding(id: str = "fnd_001") -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001"],
        title="Test finding",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_event(id: str = "evt_001") -> Event:
    return Event(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2026, 3, 6, 12, 0, 1, tzinfo=timezone.utc),
        source="azure",
        event_type="sign-in",
        actor="admin@example.com",
        action="login",
        target="subscription-1",
        severity=Severity.INFO,
        metadata={},
        raw={},
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


def _write_config(root: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {"warn": "triage", "critical": "triage", "info": None},
        "actor_chain": {"triage": {"routes_to": None}},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


def _create_actor_dir(
    parent: Path,
    name: str,
    *,
    tools: list[str] | None = None,
) -> Path:
    actor_dir = parent / name
    actor_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "type": "agent",
        "description": f"Test {name} actor",
        "version": "0.1.0",
        "model": "haiku",
        "tools": tools or ["read-events", "my-extra-tool"],
        "permissions": ["read"],
        "max_iterations": 5,
    }
    with open(actor_dir / "manifest.yaml", "w") as f:
        yaml.dump(manifest, f)
    return actor_dir


# ─── The extra tool ──────────────────────────────────────────────────


@tool(name="my-extra-tool", description="A test extra tool", permission="read")
def my_extra_tool(query: str) -> str:
    """Returns a canned response for testing."""
    return f"extra-tool-result: {query}"


# ─── Tests ────────────────────────────────────────────────────────────


class TestExtraTools:
    """build_actor_runner with extra_tools registers them in the tool registry."""

    def test_extra_tool_is_callable_by_actor(self, tmp_path: Path) -> None:
        """An extra tool passed to build_actor_runner can be called by the LLM."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        # LLM calls the extra tool, then resolves
        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[ToolCall(name="my-extra-tool", arguments={"query": "test"})],
                resolution=None,
                tokens_used=50,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_001",
                    action=ResolutionAction.RESOLVED,
                    reason="Done via extra tool",
                ),
                tokens_used=50,
            ),
        ])

        triage_dir = _create_actor_dir(tmp_path / "actors", "triage")

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir],
            extra_tools=[my_extra_tool],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED

    def test_extra_tools_none_is_default(self, tmp_path: Path) -> None:
        """build_actor_runner works without extra_tools (backward compat)."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_001",
                    action=ResolutionAction.RESOLVED,
                    reason="Done",
                ),
                tokens_used=50,
            ),
        ])

        triage_dir = _create_actor_dir(
            tmp_path / "actors", "triage", tools=["read-events"]
        )

        # No extra_tools param — should work exactly as before
        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")
        assert result.resolution is not None
