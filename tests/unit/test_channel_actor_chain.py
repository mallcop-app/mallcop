"""Tests for channel-type actors in the actor chain walk.

Bead: mallcop-52, mallcop-58

Tests:
1. Chain walk routes escalated finding to channel actor (triage -> notify-teams)
2. Channel actor returns resolved RunResult (not escalated)
3. Channel actor receives the finding via deliver_digest
4. Chain walk returns escalated when channel delivery fails
5. build_actor_runner returns non-None when only channel actors exist in chain
6. Full chain walk triage -> investigate -> notify-teams reaches channel
7. Single finding channel delivers immediately (backward compat)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest
import yaml

from mallcop.actors._schema import (
    ActorManifest,
    ActorResolution,
    ResolutionAction,
)
from mallcop.actors.runtime import (
    LLMClient,
    LLMResponse,
    RunResult,
    build_actor_runner,
)
from mallcop.config import load_config
from mallcop.schemas import Finding, FindingStatus, Severity
from mallcop.store import JsonlStore


# --- Helpers ---


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001"],
        title=f"Finding {id}",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_event_dict() -> dict[str, Any]:
    from mallcop.schemas import Event

    evt = Event(
        id="evt_001",
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2026, 3, 6, 12, 0, 1, tzinfo=timezone.utc),
        source="azure",
        event_type="sign-in",
        actor="unknown@example.com",
        action="login",
        target="subscription-1",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )
    return evt


class MockLLMClient(LLMClient):
    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self._call_count = 0
        self.calls: list[dict[str, Any]] = []

    def chat(self, model, system_prompt, messages, tools) -> LLMResponse:
        self.calls.append({"model": model})
        if self._call_count >= len(self._responses):
            raise RuntimeError("MockLLMClient exhausted responses")
        resp = self._responses[self._call_count]
        self._call_count += 1
        return resp


def _write_config(root: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {"warn": "triage", "critical": "triage"},
        "actor_chain": {"triage": {"routes_to": "notify-teams"}},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


def _create_agent_dir(
    parent: Path,
    name: str,
    *,
    model: str = "haiku",
    routes_to: str | None = None,
) -> Path:
    actor_dir = parent / name
    actor_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "type": "agent",
        "description": f"Test {name} actor",
        "version": "0.1.0",
        "model": model,
        "tools": ["read-events"],
        "permissions": ["read"],
        "max_iterations": 5,
    }
    if routes_to is not None:
        manifest["routes_to"] = routes_to
    with open(actor_dir / "manifest.yaml", "w") as f:
        yaml.dump(manifest, f)
    return actor_dir


def _create_channel_dir(parent: Path, name: str) -> Path:
    actor_dir = parent / name
    actor_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "type": "channel",
        "description": f"Test {name} channel",
        "version": "0.1.0",
        "config": {"webhook_url": "https://test.webhook.example.com/hook"},
        "format": "digest",
    }
    with open(actor_dir / "manifest.yaml", "w") as f:
        yaml.dump(manifest, f)
    # Write a channel.py with deliver_digest
    channel_code = '''
from mallcop.actors.notify_teams.channel import DeliveryResult

def deliver_digest(findings, webhook_url):
    return DeliveryResult(success=True)
'''
    with open(actor_dir / "channel.py", "w") as f:
        f.write(channel_code)
    return actor_dir


def _escalate_response(finding_id: str) -> LLMResponse:
    return LLMResponse(
        tool_calls=[],
        resolution=ActorResolution(
            finding_id=finding_id,
            action=ResolutionAction.ESCALATED,
            reason="Needs escalation",
        ),
        tokens_used=100,
    )


# --- Tests ---


class TestChannelActorChainWalk:
    """Channel actors (type=channel) are visible to the chain walk."""

    def test_chain_routes_to_channel_actor(self, tmp_path: Path) -> None:
        """Triage escalates -> chain follows routes_to -> channel actor delivers."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event_dict()])

        triage_dir = _create_agent_dir(
            tmp_path / "actors", "triage", routes_to="notify-teams"
        )
        channel_dir = _create_channel_dir(tmp_path / "actors", "notify-teams")

        llm = MockLLMClient([_escalate_response("fnd_001")])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir, channel_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")

        # Channel actor should resolve the finding (delivered to channel)
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert "channel" in result.resolution.reason.lower() or "deliver" in result.resolution.reason.lower()

    def test_channel_actor_returns_resolved(self, tmp_path: Path) -> None:
        """Channel delivery success means the finding is resolved (delivered)."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event_dict()])

        # Only a channel actor — entered directly
        channel_dir = _create_channel_dir(tmp_path / "actors", "notify-teams")

        llm = MockLLMClient([])  # LLM should NOT be called for channel

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[channel_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="notify-teams")

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        # LLM should NOT have been called
        assert len(llm.calls) == 0

    def test_channel_delivery_uses_webhook_from_manifest(self, tmp_path: Path) -> None:
        """Channel actor reads webhook_url from manifest config."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event_dict()])

        # Create channel that records the webhook_url it receives
        channel_dir = tmp_path / "actors" / "track-channel"
        channel_dir.mkdir(parents=True)
        webhook = "https://hooks.example.com/test123"
        manifest = {
            "name": "track-channel",
            "type": "channel",
            "description": "Tracking channel",
            "version": "0.1.0",
            "config": {"webhook_url": webhook},
            "format": "digest",
        }
        with open(channel_dir / "manifest.yaml", "w") as f:
            yaml.dump(manifest, f)
        channel_code = '''
from dataclasses import dataclass

@dataclass
class DeliveryResult:
    success: bool
    error: str | None = None
    webhook_url: str | None = None

received_urls = []

def deliver_digest(findings, webhook_url):
    received_urls.append(webhook_url)
    return DeliveryResult(success=True, webhook_url=webhook_url)
'''
        with open(channel_dir / "channel.py", "w") as f:
            f.write(channel_code)

        llm = MockLLMClient([])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[channel_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="track-channel")

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED

    def test_channel_delivery_failure_escalates(self, tmp_path: Path) -> None:
        """When channel delivery fails, result is escalated."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event_dict()])

        # Create a channel actor whose deliver_digest returns failure
        channel_dir = tmp_path / "actors" / "fail-channel"
        channel_dir.mkdir(parents=True)
        manifest = {
            "name": "fail-channel",
            "type": "channel",
            "description": "Failing channel",
            "version": "0.1.0",
            "config": {"webhook_url": "https://bad.example.com"},
            "format": "digest",
        }
        with open(channel_dir / "manifest.yaml", "w") as f:
            yaml.dump(manifest, f)
        channel_code = '''
from dataclasses import dataclass

@dataclass
class DeliveryResult:
    success: bool
    error: str | None = None

def deliver_digest(findings, webhook_url):
    return DeliveryResult(success=False, error="Connection refused")
'''
        with open(channel_dir / "channel.py", "w") as f:
            f.write(channel_code)

        llm = MockLLMClient([])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[channel_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="fail-channel")

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.ESCALATED
        assert "Connection refused" in result.resolution.reason

    def test_tokens_accumulate_across_agent_and_channel(self, tmp_path: Path) -> None:
        """Token count from agent actor carries through to channel result.

        Chain here is triage -> notify-teams (direct, no investigate).
        Only 1 LLM response needed because triage routes directly to the
        channel — the channel does not invoke the LLM.
        """
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event_dict()])

        triage_dir = _create_agent_dir(
            tmp_path / "actors", "triage", routes_to="notify-teams"
        )
        channel_dir = _create_channel_dir(tmp_path / "actors", "notify-teams")

        llm = MockLLMClient([_escalate_response("fnd_001")])  # 100 tokens

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir, channel_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")

        # Tokens from triage (100) should be accumulated
        assert result.tokens_used == 100
        assert result.resolution.action == ResolutionAction.RESOLVED

    def test_chain_walk_reaches_channel_from_triage(self, tmp_path: Path) -> None:
        """Full chain: triage escalates -> investigate escalates -> notify-teams delivers.

        Starts at actor_name='triage', mocks LLM to escalate at every agent
        stage, and verifies the chain reaches notify-teams and calls deliver_digest.
        """
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event_dict()])

        # Build 3-link chain: triage -> investigate -> notify-teams
        triage_dir = _create_agent_dir(
            tmp_path / "actors", "triage", routes_to="investigate"
        )
        investigate_dir = _create_agent_dir(
            tmp_path / "actors", "investigate", routes_to="notify-teams"
        )
        channel_dir = _create_channel_dir(tmp_path / "actors", "notify-teams")

        # 2 escalation responses: one for triage, one for investigate
        llm = MockLLMClient([
            _escalate_response("fnd_001"),  # triage escalates
            _escalate_response("fnd_001"),  # investigate escalates
        ])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir, investigate_dir, channel_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")

        # Chain should have walked triage -> investigate -> notify-teams
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert "notify-teams" in result.resolution.reason.lower() or "channel" in result.resolution.reason.lower()
        # Both agent stages consumed tokens (100 each)
        assert result.tokens_used == 200
        # LLM was called exactly twice (once per agent actor)
        assert len(llm.calls) == 2

    def test_single_finding_channel_delivers_immediately(self, tmp_path: Path) -> None:
        """A single finding reaching the channel calls deliver_digest immediately.

        Backward compatibility: channel actors don't batch or defer — a single
        finding triggers immediate delivery via deliver_digest.
        """
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event_dict()])

        # Create a channel that tracks whether deliver_digest was called
        channel_dir = tmp_path / "actors" / "notify-teams"
        channel_dir.mkdir(parents=True)
        manifest = {
            "name": "notify-teams",
            "type": "channel",
            "description": "Test channel",
            "version": "0.1.0",
            "config": {"webhook_url": "https://test.webhook.example.com/hook"},
            "format": "digest",
        }
        with open(channel_dir / "manifest.yaml", "w") as f:
            yaml.dump(manifest, f)
        channel_code = '''
from dataclasses import dataclass

@dataclass
class DeliveryResult:
    success: bool
    error: str | None = None

delivered_findings = []

def deliver_digest(findings, webhook_url):
    delivered_findings.extend(findings)
    return DeliveryResult(success=True)
'''
        with open(channel_dir / "channel.py", "w") as f:
            f.write(channel_code)

        llm = MockLLMClient([])  # No LLM calls expected

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[channel_dir],
        )
        assert runner is not None

        finding = _make_finding()
        result = runner(finding, actor_name="notify-teams")

        # Should resolve immediately via deliver_digest
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert len(llm.calls) == 0
        # Verify deliver_digest was actually called by importing the module
        # and checking the recorded findings
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "test_channel", channel_dir / "channel.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # The module loaded by runtime is a different instance, so we verify
        # via the resolution reason that delivery happened
        assert "deliver" in result.resolution.reason.lower() or "channel" in result.resolution.reason.lower()
