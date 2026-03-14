"""Integration tests for actor runtime wired into the escalate pipeline.

Tests the full path: CLI builds ActorRuntime with ToolContext + discovered tools,
passes as actor_runner to run_escalate. Actors execute and query real store data.

Bead: mallcop-8.2.3
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
    load_actor_manifest,
)
from mallcop.actors.runtime import (
    ActorRuntime,
    LLMClient,
    LLMResponse,
    RunResult,
    ToolCall,
    load_post_md,
)
from mallcop.config import MallcopConfig, BudgetConfig, load_config
from mallcop.schemas import Event, Finding, FindingStatus, Severity
from mallcop.store import JsonlStore
from mallcop.tools import ToolContext, ToolRegistry


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_event(
    id: str = "evt_001",
    actor: str = "unknown@example.com",
    action: str = "login",
    source: str = "azure",
) -> Event:
    return Event(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2026, 3, 6, 12, 0, 1, tzinfo=timezone.utc),
        source=source,
        event_type="sign-in",
        actor=actor,
        action=action,
        target="subscription-1",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
    event_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=event_ids or ["evt_001"],
        title=f"New actor detected: unknown@example.com",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": "unknown@example.com"},
    )


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
        "squelch": 0,  # disabled: integration tests are not testing squelch gating
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


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


# ─── Test 1: CLI passes actor_runner (not None) to run_escalate ──────


class TestCliPassesActorRunner:
    """Verify that build_actor_runner produces a callable, not None."""

    def test_build_actor_runner_returns_callable(self, tmp_path: Path) -> None:
        """build_actor_runner with a mock LLM returns a working callable."""
        from mallcop.actors.runtime import build_actor_runner

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)

        # Seed store with events so tools have data
        events = [_make_event()]
        store.append_events(events)

        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_001",
                    action=ResolutionAction.RESOLVED,
                    reason="Known actor",
                ),
                tokens_used=100,
            ),
        ])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
        )

        assert runner is not None
        assert callable(runner)

    def test_build_actor_runner_returns_none_without_agent_actors(self, tmp_path: Path) -> None:
        """If no agent-type actor manifests exist, runner is None."""
        from mallcop.actors.runtime import build_actor_runner

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)

        # No actor directories → no triage manifest
        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=MockLLMClient([]),
            actor_dirs=[],  # explicitly empty
        )

        assert runner is None


# ─── Test 2: runtime executes tools with ToolContext ─────────────────


class TestRuntimeExecutesWithContext:
    """ActorRuntime with real registry + ToolContext: tools get context injected."""

    def test_tool_receives_context_with_real_store_data(self, tmp_path: Path) -> None:
        """When LLM calls read-events, the tool receives ToolContext and returns real data."""
        store = JsonlStore(tmp_path)
        events = [_make_event(id="evt_001", actor="unknown@example.com")]
        store.append_events(events)

        finding = _make_finding(event_ids=["evt_001"])
        store.append_findings([finding])

        # Discover real tools
        tools_dir = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "tools"
        registry = ToolRegistry.discover_tools([tools_dir])

        context = ToolContext(
            store=store,
            connectors={},
            config=MallcopConfig(
                secrets_backend="env",
                connectors={},
                routing={},
                actor_chain={},
                budget=BudgetConfig(),
            ),
        )

        manifest = ActorManifest(
            name="triage",
            type="agent",
            description="Test",
            version="0.1.0",
            model="haiku",
            tools=["read-events"],
            permissions=["read"],
            routes_to=None,
            max_iterations=5,
            config={},
        )

        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="Known actor",
        )

        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[
                    ToolCall(name="read-events", arguments={"finding_id": "fnd_001"})
                ],
                resolution=None,
                tokens_used=80,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=resolution,
                tokens_used=120,
            ),
        ])

        runtime = ActorRuntime(
            manifest=manifest,
            registry=registry,
            llm=llm,
            context=context,
        )
        result = runtime.run(finding=finding, system_prompt="Triage agent")

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED

        # Verify the tool result fed to LLM contains actual event data
        second_call = llm.calls[1]
        messages = second_call["messages"]
        tool_msgs = [m for m in messages if m.get("role") == "tool"]
        # tool_msgs[0] is the synthetic finding context, tool_msgs[1] is read-events
        assert len(tool_msgs) >= 2
        tool_result_content = tool_msgs[1]["content"]
        # The real read-events tool should return data containing our event
        assert "evt_001" in tool_result_content


# ─── Test 3: runtime filters tools by manifest ──────────────────────


class TestRuntimeFiltersByManifest:
    """Manifest lists [read-events, check-baseline], registry has 8 tools → LLM sees 2."""

    def test_llm_only_sees_manifest_tools(self, tmp_path: Path) -> None:
        tools_dir = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "tools"
        registry = ToolRegistry.discover_tools([tools_dir])

        # Registry should have all 8 tools
        all_tools = registry.list_tools()
        assert len(all_tools) >= 6  # at least 6 tools from the tools dir

        manifest = ActorManifest(
            name="triage",
            type="agent",
            description="Test",
            version="0.1.0",
            model="haiku",
            tools=["read-events", "check-baseline"],
            permissions=["read"],
            routes_to=None,
            max_iterations=5,
            config={},
        )

        store = JsonlStore(tmp_path)
        context = ToolContext(
            store=store,
            connectors={},
            config=MallcopConfig(
                secrets_backend="env",
                connectors={},
                routing={},
                actor_chain={},
                budget=BudgetConfig(),
            ),
        )

        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="Done",
        )
        llm = MockLLMClient([
            LLMResponse(tool_calls=[], resolution=resolution, tokens_used=100),
        ])

        runtime = ActorRuntime(
            manifest=manifest,
            registry=registry,
            llm=llm,
            context=context,
        )

        # Verify filtered tools
        filtered = runtime.get_filtered_tools()
        tool_names = [t._tool_meta.name for t in filtered]
        assert sorted(tool_names) == ["check-baseline", "read-events"]

        # Run and check LLM only received 2 tool schemas
        runtime.run(finding=_make_finding(), system_prompt="Test")
        assert len(llm.calls[0]["tools"]) == 2


# ─── Test 4: escalate processes finding with real actor_runner ───────


class TestEscalateWithActorRunner:
    """Real store with open finding, actor_runner closure → finding resolved."""

    def test_finding_resolved_by_actor(self, tmp_path: Path) -> None:
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        events = [_make_event()]
        store.append_events(events)
        store.append_findings([_make_finding(severity=Severity.WARN)])

        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="Known actor, normal activity",
        )

        def actor_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=resolution,
                tokens_used=200,
                iterations=2,
            )

        result = run_escalate(tmp_path, actor_runner=actor_runner)
        assert result["findings_processed"] == 1

        # Re-read from disk to verify finding was updated
        fresh_store = JsonlStore(tmp_path)
        updated = fresh_store.query_findings()
        resolved = [f for f in updated if f.id == "fnd_001"]
        assert resolved[0].status == FindingStatus.RESOLVED

    def test_finding_escalated_stays_open(self, tmp_path: Path) -> None:
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        store.append_events([_make_event()])
        store.append_findings([_make_finding(severity=Severity.WARN)])

        def actor_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Uncertain",
                ),
                tokens_used=200,
                iterations=2,
            )

        result = run_escalate(tmp_path, actor_runner=actor_runner)
        assert result["findings_processed"] == 1

        fresh_store = JsonlStore(tmp_path)
        updated = fresh_store.query_findings()
        f = [f for f in updated if f.id == "fnd_001"][0]
        assert f.status == FindingStatus.OPEN
        assert len(f.annotations) > 0


# ─── Test 5: full pipeline integration ───────────────────────────────


class TestFullPipelineIntegration:
    """Store has events + findings, actor manifest + tools discovered,
    mock LLM calls read-events → LLM receives actual event data, resolves finding."""

    def test_end_to_end_actor_with_real_tools(self, tmp_path: Path) -> None:
        from mallcop.actors.runtime import build_actor_runner

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)

        # Seed real data
        events = [
            _make_event(id="evt_001", actor="unknown@example.com", action="login"),
            _make_event(id="evt_002", actor="unknown@example.com", action="read-blob"),
        ]
        store.append_events(events)

        finding = _make_finding(event_ids=["evt_001", "evt_002"])
        store.append_findings([finding])

        # Update baseline so check-baseline has data
        store.update_baseline(events)

        # Mock LLM: calls read-events, then check-baseline, then resolves
        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="Known actor after baseline check",
        )
        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[
                    ToolCall(name="read-events", arguments={"finding_id": "fnd_001"})
                ],
                resolution=None,
                tokens_used=100,
            ),
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        name="check-baseline",
                        arguments={"actor": "unknown@example.com"},
                    )
                ],
                resolution=None,
                tokens_used=100,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=resolution,
                tokens_used=50,
            ),
        ])

        # Use the real triage manifest
        triage_dir = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "triage"
        )

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir],
        )
        assert runner is not None

        # Execute the runner against the finding
        result = runner(finding, finding_token_budget=5000)

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert result.tokens_used == 250
        assert result.iterations == 3

        # Verify LLM received actual event data from the store
        # Second call (after read-events) should have tool result with real events
        second_call_msgs = llm.calls[1]["messages"]
        tool_results = [m for m in second_call_msgs if m.get("role") == "tool"]
        # tool_results[0] = finding context, tool_results[1] = read-events result
        read_events_result = tool_results[1]["content"]
        assert "evt_001" in read_events_result
        assert "unknown@example.com" in read_events_result

        # Third call should have check-baseline result
        third_call_msgs = llm.calls[2]["messages"]
        tool_results_3 = [m for m in third_call_msgs if m.get("role") == "tool"]
        baseline_result = tool_results_3[2]["content"]  # 3rd tool result
        assert "known" in baseline_result.lower()

    def test_full_escalate_pipeline_with_built_runner(self, tmp_path: Path) -> None:
        """run_escalate with a build_actor_runner-produced runner resolves findings."""
        from mallcop.actors.runtime import build_actor_runner
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)

        store.append_events([_make_event()])
        store.append_findings([_make_finding(severity=Severity.WARN)])

        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="Resolved by triage",
        )
        llm = MockLLMClient([
            LLMResponse(tool_calls=[], resolution=resolution, tokens_used=100),
        ])

        triage_dir = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "triage"
        )

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[triage_dir],
        )
        assert runner is not None

        result = run_escalate(tmp_path, actor_runner=runner)
        assert result["findings_processed"] == 1

        fresh_store = JsonlStore(tmp_path)
        updated = fresh_store.query_findings()
        f = [f for f in updated if f.id == "fnd_001"][0]
        assert f.status == FindingStatus.RESOLVED
