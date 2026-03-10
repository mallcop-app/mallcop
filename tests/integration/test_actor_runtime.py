"""Integration test: triage actor with mock LLM against synthetic findings.

Tests the full flow: manifest loading → POST.md → tool registry → LLM loop → resolution.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from mallcop.actors._schema import ActorResolution, ResolutionAction, load_actor_manifest
from mallcop.actors.runtime import (
    ActorRuntime,
    LLMClient,
    LLMResponse,
    ToolCall,
    load_post_md,
)
from mallcop.schemas import Annotation, Finding, FindingStatus, Severity
from mallcop.tools import ToolRegistry, tool


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
    title: str = "New actor detected: unknown@example.com",
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001", "evt_002"],
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": "unknown@example.com"},
    )


def _build_full_registry() -> ToolRegistry:
    """Build a registry with all tools the triage actor needs."""
    reg = ToolRegistry()

    @tool(name="read-events", description="Read events by finding ID", permission="read")
    def read_events(finding_id: str | None = None, **kwargs: Any) -> list[dict[str, Any]]:
        return [
            {
                "id": "evt_001",
                "actor": "unknown@example.com",
                "action": "login",
                "timestamp": "2026-03-06T12:00:00Z",
                "source": "azure",
            }
        ]

    @tool(name="check-baseline", description="Check baseline for actor/entity", permission="read")
    def check_baseline(actor: str | None = None, **kwargs: Any) -> dict[str, Any]:
        if actor == "unknown@example.com":
            return {"known": False, "first_seen": None}
        return {"known": True, "first_seen": "2026-01-01T00:00:00Z"}

    @tool(name="read-finding", description="Read finding details", permission="read")
    def read_finding(finding_id: str) -> dict[str, Any]:
        return _make_finding(id=finding_id).to_dict()

    @tool(name="search-events", description="Search events", permission="read")
    def search_events(query: str, **kwargs: Any) -> list[dict[str, Any]]:
        return []

    @tool(name="resolve-finding", description="Resolve or escalate a finding", permission="read")
    def resolve_finding(finding_id: str, action: str, reason: str) -> dict[str, Any]:
        return {"finding_id": finding_id, "action": action, "reason": reason}

    reg.register(read_events)
    reg.register(check_baseline)
    reg.register(read_finding)
    reg.register(search_events)
    reg.register(resolve_finding)
    return reg


class MockLLMClient(LLMClient):
    """Mock LLM that simulates triage behavior."""

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


# ─── Integration: triage actor full flow ──────────────────────────────


class TestTriageActorIntegration:
    @pytest.fixture
    def triage_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "triage"

    def test_triage_resolves_known_actor(self, triage_dir: Path) -> None:
        """Triage actor investigates finding, checks baseline, resolves as benign."""
        manifest = load_actor_manifest(triage_dir)
        registry = _build_full_registry()
        post_md = load_post_md(triage_dir)
        assert len(post_md) > 0, "POST.md must exist and be non-empty"

        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="Checked baseline: unknown@example.com not in baseline, but login during business hours from known IP. Resolving as expected onboarding activity.",
        )

        # Simulate: LLM calls check-baseline, then read-events, then resolves
        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[
                    ToolCall(name="check-baseline", arguments={"actor": "unknown@example.com"})
                ],
                resolution=None,
                tokens_used=200,
            ),
            LLMResponse(
                tool_calls=[
                    ToolCall(name="read-events", arguments={"finding_id": "fnd_001"})
                ],
                resolution=None,
                tokens_used=300,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=resolution,
                tokens_used=150,
            ),
        ])

        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm)
        result = runtime.run(finding=_make_finding(), system_prompt=post_md)

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert result.tokens_used == 650
        assert result.iterations == 3
        # Verify LLM received the correct model
        assert llm.calls[0]["model"] == "sonnet"
        # Verify system prompt was the POST.md content
        assert llm.calls[0]["system_prompt"] == post_md

    def test_triage_escalates_uncertain_finding(self, triage_dir: Path) -> None:
        """Triage actor investigates but can't determine, escalates."""
        manifest = load_actor_manifest(triage_dir)
        registry = _build_full_registry()
        post_md = load_post_md(triage_dir)

        escalation = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.ESCALATED,
            reason="Actor not in baseline, activity at unusual hour (3 AM). Cannot determine intent. Escalating for human review.",
        )

        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[
                    ToolCall(name="check-baseline", arguments={"actor": "unknown@example.com"})
                ],
                resolution=None,
                tokens_used=200,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=escalation,
                tokens_used=150,
            ),
        ])

        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm)
        result = runtime.run(finding=_make_finding(), system_prompt=post_md)

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.ESCALATED
        assert result.iterations == 2

    def test_triage_uses_correct_tools(self, triage_dir: Path) -> None:
        """Verify triage actor only has access to its declared tools."""
        manifest = load_actor_manifest(triage_dir)
        registry = _build_full_registry()

        # Add a write tool that triage should NOT have access to
        @tool(name="ack-finding", description="Ack finding", permission="write")
        def ack_finding(finding_id: str) -> str:
            return "acked"
        registry.register(ack_finding)

        llm = MockLLMClient([])
        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm)
        filtered = runtime.get_filtered_tools()

        tool_names = [t._tool_meta.name for t in filtered]
        assert "read-events" in tool_names
        assert "check-baseline" in tool_names
        assert "read-finding" in tool_names
        assert "search-events" in tool_names
        assert "resolve-finding" in tool_names
        assert "ack-finding" not in tool_names
        assert len(tool_names) == 5

    def test_triage_hits_max_iterations(self, triage_dir: Path) -> None:
        """Triage actor escalates when hitting iteration limit."""
        manifest = load_actor_manifest(triage_dir)
        registry = _build_full_registry()
        post_md = load_post_md(triage_dir)

        # LLM keeps calling tools without resolving
        tool_response = LLMResponse(
            tool_calls=[
                ToolCall(name="read-events", arguments={"finding_id": "fnd_001"})
            ],
            resolution=None,
            tokens_used=100,
        )
        llm = MockLLMClient([tool_response] * 5)

        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm)
        result = runtime.run(finding=_make_finding(), system_prompt=post_md)

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.ESCALATED
        assert result.iterations == manifest.max_iterations
        assert "iteration" in result.resolution.reason.lower()
