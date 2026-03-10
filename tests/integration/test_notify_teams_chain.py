"""Integration test: triage → notify-teams chain delivery.

Tests the full actor chain: triage escalates → chain walk invokes notify-teams
channel actor → HTTP POST to Teams webhook with correct payload format.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.actors._schema import (
    ActorManifest,
    ActorResolution,
    ResolutionAction,
    load_actor_manifest,
)
from mallcop.actors.notify_teams.channel import DeliveryResult, format_digest
from mallcop.actors.runtime import (
    LLMClient,
    LLMResponse,
    RunResult,
    ToolCall,
    build_actor_runner,
)
from mallcop.schemas import Annotation, Finding, FindingStatus, Severity
from mallcop.tools import ToolRegistry, tool


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
    title: str = "New actor detected: unknown@example.com",
    annotations: list[Annotation] | None = None,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001"],
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=annotations or [],
        metadata={"actor": "unknown@example.com"},
    )


def _build_registry() -> ToolRegistry:
    """Minimal registry with tools the triage actor needs."""
    reg = ToolRegistry()

    @tool(name="read-events", description="Read events", permission="read")
    def read_events(**kwargs: Any) -> list[dict[str, Any]]:
        return []

    @tool(name="check-baseline", description="Check baseline", permission="read")
    def check_baseline(**kwargs: Any) -> dict[str, Any]:
        return {"known": False}

    @tool(name="read-finding", description="Read finding", permission="read")
    def read_finding(**kwargs: Any) -> dict[str, Any]:
        return {}

    @tool(name="search-events", description="Search events", permission="read")
    def search_events(**kwargs: Any) -> list[dict[str, Any]]:
        return []

    reg.register(read_events)
    reg.register(check_baseline)
    reg.register(read_finding)
    reg.register(search_events)
    return reg


class MockLLMClient(LLMClient):
    """Mock LLM that escalates on first call (triggers chain to notify-teams)."""

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self._call_count = 0

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        if self._call_count >= len(self._responses):
            raise RuntimeError("MockLLMClient exhausted responses")
        resp = self._responses[self._call_count]
        self._call_count += 1
        return resp


# ─── Tests ────────────────────────────────────────────────────────────


class TestNotifyTeamsChainDelivery:
    """Test triage → notify-teams chain walk with mocked HTTP."""

    @pytest.fixture
    def actor_dirs(self) -> list[Path]:
        actors_dir = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors"
        return [actors_dir / "triage", actors_dir / "investigate", actors_dir / "notify_teams"]

    def test_chain_walks_to_channel_actor_on_escalation(
        self, tmp_path: Path, actor_dirs: list[Path]
    ) -> None:
        """When triage escalates, chain walks triage → investigate → notify-teams."""
        # Triage LLM escalates, then investigate LLM escalates
        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_001",
                    action=ResolutionAction.ESCALATED,
                    reason="Cannot determine — escalating",
                ),
                tokens_used=100,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_001",
                    action=ResolutionAction.ESCALATED,
                    reason="Still suspicious — escalating to channel",
                ),
                tokens_used=150,
            ),
        ])

        # Write minimal config with webhook_url
        config = MagicMock()
        config.connectors = {}
        config.actors = {"notify-teams": {"webhook_url": "https://teams.example.com/webhook"}}
        store = MagicMock()

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=actor_dirs,
        )
        assert runner is not None

        finding = _make_finding()

        # Mock DNS + HTTP POST to Teams webhook
        public_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("52.96.0.1", 0))]
        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=public_addrinfo), \
             patch("mallcop.actors.notify_base.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            result = runner(finding, actor_name="triage")

        # Chain should have delivered via notify-teams
        assert mock_post.called
        call_kwargs = mock_post.call_args
        posted_url = call_kwargs[0][0] if call_kwargs[0] else call_kwargs[1].get("url")
        assert posted_url == "https://teams.example.com/webhook"

        # Verify payload structure matches Teams message card format
        posted_json = call_kwargs[1].get("json") or call_kwargs[0][1]
        assert posted_json["type"] == "message"
        assert "Mallcop" in posted_json["summary"]
        assert isinstance(posted_json["sections"], list)

    def test_channel_delivery_payload_has_correct_severity_sections(self) -> None:
        """format_digest groups findings by severity into sections."""
        findings = [
            _make_finding(id="fnd_c", severity=Severity.CRITICAL, title="Critical issue"),
            _make_finding(id="fnd_w", severity=Severity.WARN, title="Warning issue"),
            _make_finding(id="fnd_i", severity=Severity.INFO, title="Info note"),
        ]

        payload = format_digest(findings)

        assert payload["type"] == "message"
        assert "3 findings" in payload["summary"]
        assert len(payload["sections"]) == 3
        # Sections ordered: CRITICAL, WARN, INFO
        assert payload["sections"][0]["activityTitle"] == "CRITICAL (1)"
        assert payload["sections"][1]["activityTitle"] == "WARN (1)"
        assert payload["sections"][2]["activityTitle"] == "INFO (1)"

    def test_channel_delivery_includes_annotations_in_facts(self) -> None:
        """When findings have annotations (from triage), they appear in facts."""
        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 6, 12, 5, 0, tzinfo=timezone.utc),
            content="Escalated: unknown actor at unusual hour",
            action="escalated",
            reason="Cannot determine intent",
        )
        finding = _make_finding(annotations=[ann])

        payload = format_digest([finding])

        fact = payload["sections"][0]["facts"][0]
        assert fact["name"] == "fnd_001"
        assert "triage" in fact["value"]
        assert "Escalated" in fact["value"]

    def test_channel_delivery_http_failure_returns_error(self) -> None:
        """deliver_digest returns DeliveryResult with error on HTTP failure."""
        from mallcop.actors.notify_teams.channel import deliver_digest

        finding = _make_finding()

        public_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("52.96.0.1", 0))]
        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=public_addrinfo), \
             patch("mallcop.actors.notify_base.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 403
            mock_response.text = "Forbidden"
            mock_post.return_value = mock_response

            result = deliver_digest([finding], "https://teams.example.com/webhook")

        assert result.success is False
        assert "403" in result.error
        assert "Forbidden" in result.error
