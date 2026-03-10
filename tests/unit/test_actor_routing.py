"""Tests for actor routing by name: select manifest matching routing config.

Bead: mallcop-17

Tests:
1. actor_runner(finding, actor_name="triage") selects triage manifest
2. actor_runner(finding, actor_name="investigate") selects investigate manifest
3. actor_runner(finding, actor_name="nonexistent") returns skip RunResult with annotation
4. escalate.py passes actor_name from config.routing[severity] to runner
5. routes_to chain: triage escalates -> follows routes_to to next actor
6. routes_to chain terminates when actor resolves
7. routes_to chain terminates when routes_to is None (end of chain)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from mallcop.actors._schema import (
    ActorManifest,
    ActorResolution,
    ResolutionAction,
)
from mallcop.actors.runtime import (
    ActorRuntime,
    LLMClient,
    LLMResponse,
    RunResult,
    ToolCall,
    build_actor_runner,
)
from mallcop.config import BudgetConfig, MallcopConfig, load_config
from mallcop.schemas import Annotation, Event, Finding, FindingStatus, Severity
from mallcop.store import JsonlStore
from mallcop.tools import ToolContext, ToolRegistry


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001"],
        title=f"Finding {id}",
        severity=severity,
        status=status,
        annotations=[],
        metadata={},
    )


def _make_event(
    id: str = "evt_001",
    actor: str = "unknown@example.com",
) -> Event:
    return Event(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2026, 3, 6, 12, 0, 1, tzinfo=timezone.utc),
        source="azure",
        event_type="sign-in",
        actor=actor,
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


def _write_config(
    root: Path,
    routing: dict[str, str | None] | None = None,
) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": routing or {"warn": "triage", "critical": "triage", "info": None},
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
    model: str = "haiku",
    actor_type: str = "agent",
    routes_to: str | None = None,
    tools: list[str] | None = None,
    permissions: list[str] | None = None,
) -> Path:
    """Create a minimal actor directory with manifest.yaml."""
    actor_dir = parent / name
    actor_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "type": actor_type,
        "description": f"Test {name} actor",
        "version": "0.1.0",
        "model": model,
        "tools": tools or ["read-events"],
        "permissions": permissions or ["read"],
        "max_iterations": 5,
    }
    if routes_to is not None:
        manifest["routes_to"] = routes_to
    with open(actor_dir / "manifest.yaml", "w") as f:
        yaml.dump(manifest, f)
    return actor_dir


def _resolve_response(finding_id: str, action: ResolutionAction = ResolutionAction.RESOLVED, reason: str = "Done") -> LLMResponse:
    return LLMResponse(
        tool_calls=[],
        resolution=ActorResolution(
            finding_id=finding_id,
            action=action,
            reason=reason,
        ),
        tokens_used=100,
    )


def _escalate_response(finding_id: str, reason: str = "Needs escalation") -> LLMResponse:
    return LLMResponse(
        tool_calls=[],
        resolution=ActorResolution(
            finding_id=finding_id,
            action=ResolutionAction.ESCALATED,
            reason=reason,
        ),
        tokens_used=100,
    )


# ─── Test 1: actor_runner selects manifest by name ────────────────────


class TestActorRunnerSelectsByName:
    """actor_runner(finding, actor_name=X) selects the manifest named X."""

    def test_selects_triage_manifest(self, tmp_path: Path) -> None:
        """actor_runner with actor_name='triage' uses triage manifest."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        llm = MockLLMClient([
            _resolve_response("fnd_001"),
        ])

        triage_dir = _create_actor_dir(tmp_path / "actors", "triage")
        investigate_dir = _create_actor_dir(
            tmp_path / "actors", "investigate", model="sonnet"
        )

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        # Verify the LLM was called with the triage model (haiku)
        assert llm.calls[0]["model"] == "haiku"

    def test_selects_investigate_manifest(self, tmp_path: Path) -> None:
        """actor_runner with actor_name='investigate' uses investigate manifest."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        llm = MockLLMClient([
            _resolve_response("fnd_001"),
        ])

        triage_dir = _create_actor_dir(tmp_path / "actors", "triage")
        investigate_dir = _create_actor_dir(
            tmp_path / "actors", "investigate", model="sonnet"
        )

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="investigate")
        assert result.resolution is not None
        # Verify the LLM was called with the investigate model (sonnet)
        assert llm.calls[0]["model"] == "sonnet"


# ─── Test 2: missing actor name graceful skip ──────────────────────────


class TestMissingActorGracefulSkip:
    """actor_runner(finding, actor_name='nonexistent') returns skip result."""

    def test_missing_actor_returns_skip(self, tmp_path: Path) -> None:
        """Missing actor name returns a RunResult with escalated + skip reason."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        llm = MockLLMClient([])  # Should not be called

        triage_dir = _create_actor_dir(tmp_path / "actors", "triage")

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="nonexistent")
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.ESCALATED
        assert "nonexistent" in result.resolution.reason.lower()
        assert result.tokens_used == 0
        assert result.iterations == 0
        # LLM should NOT have been called
        assert len(llm.calls) == 0

    def test_no_actor_name_falls_back_to_first(self, tmp_path: Path) -> None:
        """When actor_name is not provided, falls back to first manifest (backward compat)."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        llm = MockLLMClient([
            _resolve_response("fnd_001"),
        ])

        triage_dir = _create_actor_dir(tmp_path / "actors", "triage")

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir],
        )
        assert runner is not None

        # Call without actor_name — should work (backward compat)
        result = runner(_make_finding())
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED


# ─── Test 3: escalate.py passes actor_name ─────────────────────────────


class TestEscalatePassesActorName:
    """escalate.py passes config.routing[severity] as actor_name to runner."""

    def test_passes_actor_name_from_routing(self, tmp_path: Path) -> None:
        """run_escalate passes actor_name kwarg to actor_runner."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path, routing={
            "warn": "triage",
            "critical": "investigate",
            "info": None,
        })

        findings = [
            _make_finding(id="fnd_warn", severity=Severity.WARN),
            _make_finding(id="fnd_crit", severity=Severity.CRITICAL),
        ]
        store = JsonlStore(tmp_path)
        store.append_findings(findings)

        received_actor_names: list[tuple[str, str]] = []

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            received_actor_names.append((finding.id, kwargs.get("actor_name", "")))
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=100,
                iterations=1,
            )

        run_escalate(tmp_path, actor_runner=mock_runner)

        # CRITICAL processed first (severity ordering)
        names_dict = dict(received_actor_names)
        assert names_dict["fnd_crit"] == "investigate"
        assert names_dict["fnd_warn"] == "triage"


# ─── Test 4: routes_to chain traversal ─────────────────────────────────


class TestRoutesToChain:
    """When triage escalates, follow routes_to to the next actor."""

    def test_follows_routes_to_on_escalation(self, tmp_path: Path) -> None:
        """Triage escalates -> routes_to investigate -> investigate resolves."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        # triage routes_to investigate
        triage_dir = _create_actor_dir(
            tmp_path / "actors", "triage", routes_to="investigate"
        )
        investigate_dir = _create_actor_dir(
            tmp_path / "actors", "investigate", model="sonnet"
        )

        # LLM responses: triage escalates, then investigate resolves
        llm = MockLLMClient([
            _escalate_response("fnd_001", "Needs deeper investigation"),
            _resolve_response("fnd_001", reason="Resolved by investigate"),
        ])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")

        # Final resolution should be from investigate (resolved)
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert "investigate" in result.resolution.reason.lower()

        # LLM should have been called twice: once for triage, once for investigate
        assert len(llm.calls) == 2
        assert llm.calls[0]["model"] == "haiku"      # triage
        assert llm.calls[1]["model"] == "sonnet"      # investigate

    def test_chain_terminates_on_resolve(self, tmp_path: Path) -> None:
        """If triage resolves, routes_to is NOT followed."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        triage_dir = _create_actor_dir(
            tmp_path / "actors", "triage", routes_to="investigate"
        )
        investigate_dir = _create_actor_dir(
            tmp_path / "actors", "investigate", model="sonnet"
        )

        # LLM: triage resolves immediately
        llm = MockLLMClient([
            _resolve_response("fnd_001", reason="Resolved by triage"),
        ])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        # Only triage was called, not investigate
        assert len(llm.calls) == 1

    def test_chain_terminates_when_routes_to_is_none(self, tmp_path: Path) -> None:
        """If actor has no routes_to and escalates, escalation is the final result."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        # triage has no routes_to
        triage_dir = _create_actor_dir(tmp_path / "actors", "triage")

        llm = MockLLMClient([
            _escalate_response("fnd_001", "Uncertain"),
        ])

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
        assert result.resolution.action == ResolutionAction.ESCALATED
        assert len(llm.calls) == 1

    def test_chain_terminates_when_routes_to_actor_missing(self, tmp_path: Path) -> None:
        """If routes_to points to a nonexistent actor, escalation is the final result."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        # triage routes_to "investigate" but investigate doesn't exist
        triage_dir = _create_actor_dir(
            tmp_path / "actors", "triage", routes_to="investigate"
        )

        llm = MockLLMClient([
            _escalate_response("fnd_001", "Needs investigation"),
        ])

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
        assert result.resolution.action == ResolutionAction.ESCALATED
        assert len(llm.calls) == 1

    def test_token_budget_accumulates_across_chain(self, tmp_path: Path) -> None:
        """Tokens from all actors in the chain accumulate in the result."""
        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)
        store.append_events([_make_event()])

        triage_dir = _create_actor_dir(
            tmp_path / "actors", "triage", routes_to="investigate"
        )
        investigate_dir = _create_actor_dir(
            tmp_path / "actors", "investigate", model="sonnet"
        )

        llm = MockLLMClient([
            _escalate_response("fnd_001"),  # 100 tokens
            _resolve_response("fnd_001"),   # 100 tokens
        ])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        result = runner(_make_finding(), actor_name="triage")
        assert result.tokens_used == 200  # 100 + 100
