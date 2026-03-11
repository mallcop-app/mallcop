"""Integration test: investigate actor in the triage → investigate → notify-teams chain.

Tests:
1. Investigate actor loads manifest, uses sonnet model, has correct tools.
2. Triage escalates → investigate resolves (chain stops).
3. Triage escalates → investigate escalates → routes to notify-teams.
4. annotate-finding uses context.actor_name instead of hardcoded "agent".
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
    RunResult,
    ToolCall,
    load_post_md,
)
from mallcop.schemas import Annotation, Finding, FindingStatus, Severity
from mallcop.tools import ToolContext, ToolRegistry, tool


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
        annotations=[
            Annotation(
                actor="triage",
                timestamp=datetime(2026, 3, 6, 12, 5, 0, tzinfo=timezone.utc),
                content="Unknown actor, unusual hour. Escalating.",
                action="escalated",
                reason="Cannot determine intent",
            ),
        ],
        metadata={"actor": "unknown@example.com"},
    )


def _build_full_registry() -> ToolRegistry:
    """Build a registry with all tools the investigate actor needs."""
    reg = ToolRegistry()

    @tool(name="read-events", description="Read events by finding ID", permission="read")
    def read_events(finding_id: str | None = None, **kwargs: Any) -> list[dict[str, Any]]:
        return [{"id": "evt_001", "actor": "unknown@example.com", "action": "login"}]

    @tool(name="check-baseline", description="Check baseline for actor/entity", permission="read")
    def check_baseline(actor: str | None = None, **kwargs: Any) -> dict[str, Any]:
        return {"known": False, "first_seen": None}

    @tool(name="read-finding", description="Read finding details", permission="read")
    def read_finding(finding_id: str) -> dict[str, Any]:
        return _make_finding(id=finding_id).to_dict()

    @tool(name="search-events", description="Search events", permission="read")
    def search_events(query: str, **kwargs: Any) -> list[dict[str, Any]]:
        return []

    @tool(name="read-config", description="Read config", permission="read")
    def read_config(**kwargs: Any) -> dict[str, Any]:
        return {"connectors": {"azure": {}}, "routing": {"critical": "triage"}}

    @tool(name="annotate-finding", description="Add annotation to finding", permission="write")
    def annotate_finding(finding_id: str, text: str, **kwargs: Any) -> dict[str, Any]:
        return {"status": "ok", "finding_id": finding_id}

    @tool(name="resolve-finding", description="Resolve or escalate a finding", permission="read")
    def resolve_finding(finding_id: str, action: str, reason: str) -> dict[str, Any]:
        return {"finding_id": finding_id, "action": action, "reason": reason}

    @tool(name="baseline-stats", description="Get baseline statistics", permission="read")
    def baseline_stats(**kwargs: Any) -> dict[str, Any]:
        return {"total_frequency_entries": 0, "known_entities": {}}

    @tool(name="search-findings", description="Search findings", permission="read")
    def search_findings(**kwargs: Any) -> list[dict[str, Any]]:
        return []

    reg.register(read_events)
    reg.register(check_baseline)
    reg.register(read_finding)
    reg.register(search_events)
    reg.register(search_findings)
    reg.register(read_config)
    reg.register(annotate_finding)
    reg.register(resolve_finding)
    reg.register(baseline_stats)
    return reg


class MockLLMClient(LLMClient):
    """Mock LLM that returns pre-programmed responses."""

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


# ─── Tests ────────────────────────────────────────────────────────────


class TestInvestigateActorIntegration:
    @pytest.fixture
    def investigate_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "investigate"

    @pytest.fixture
    def triage_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "triage"

    def test_investigate_manifest_loads_correctly(self, investigate_dir: Path) -> None:
        """Investigate manifest has type=agent, model=sonnet, routes_to=notify-teams."""
        manifest = load_actor_manifest(investigate_dir)
        assert manifest.name == "investigate"
        assert manifest.type == "agent"
        assert manifest.model == "sonnet"
        assert manifest.routes_to == "notify-teams"
        assert "read-config" in manifest.tools
        assert "annotate-finding" in manifest.tools
        assert "write" in manifest.permissions

    def test_triage_routes_to_investigate(self, triage_dir: Path) -> None:
        """Triage manifest routes_to is now 'investigate', not 'notify-teams'."""
        manifest = load_actor_manifest(triage_dir)
        assert manifest.routes_to == "investigate"

    def test_investigate_resolves_finding(self, investigate_dir: Path) -> None:
        """Investigate actor gathers context and resolves finding — chain stops."""
        manifest = load_actor_manifest(investigate_dir)
        registry = _build_full_registry()
        post_md = load_post_md(investigate_dir)
        assert len(post_md) > 0

        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="After investigation: actor is a new contractor. Activity is benign.",
        )

        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[ToolCall(name="read-finding", arguments={"finding_id": "fnd_001"})],
                resolution=None,
                tokens_used=300,
            ),
            LLMResponse(
                tool_calls=[ToolCall(name="check-baseline", arguments={"actor": "unknown@example.com"})],
                resolution=None,
                tokens_used=400,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=resolution,
                tokens_used=200,
            ),
        ])

        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm)
        result = runtime.run(finding=_make_finding(), system_prompt=post_md)

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert result.tokens_used == 900
        assert result.iterations == 3
        # Investigate uses sonnet
        assert llm.calls[0]["model"] == "sonnet"

    def test_chain_triage_escalates_investigate_escalates(
        self, triage_dir: Path, investigate_dir: Path
    ) -> None:
        """Full chain: triage escalates → investigate escalates → would route to notify-teams.

        Uses build_actor_runner to exercise the real chain logic.
        """
        from mallcop.actors.runtime import build_actor_runner
        from mallcop.config import load_config
        from mallcop.store import JsonlStore

        import tempfile
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_data = {
                "secrets": {"backend": "env"},
                "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
                "routing": {"critical": "triage", "warn": "triage"},
                "actor_chain": {
                    "triage": {"routes_to": "investigate"},
                    "investigate": {"routes_to": "notify-teams"},
                },
                "budget": {
                    "max_findings_for_actors": 25,
                    "max_tokens_per_run": 50000,
                    "max_tokens_per_finding": 5000,
                },
            }
            with open(root / "mallcop.yaml", "w") as f:
                yaml.dump(config_data, f)

            config = load_config(root)
            store = JsonlStore(root)

            # Mock LLM: triage escalates (1 call), investigate escalates (1 call)
            triage_escalation = LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_001",
                    action=ResolutionAction.ESCALATED,
                    reason="Unusual hour, unknown actor. Escalating to investigation.",
                ),
                tokens_used=200,
            )
            investigate_escalation = LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_001",
                    action=ResolutionAction.ESCALATED,
                    reason="Cannot confirm intent. Needs human review.",
                ),
                tokens_used=500,
            )

            llm = MockLLMClient([triage_escalation, investigate_escalation])

            runner = build_actor_runner(
                root=root,
                store=store,
                config=config,
                llm=llm,
                actor_dirs=[triage_dir, investigate_dir],
            )

            assert runner is not None
            result = runner(_make_finding(), actor_name="triage")

            # Chain: triage (escalated) → investigate (escalated) → notify-teams (not found, chain ends)
            assert result.resolution is not None
            assert result.resolution.action == ResolutionAction.ESCALATED
            assert result.tokens_used == 700  # 200 + 500
            # triage used sonnet, investigate used sonnet
            assert llm.calls[0]["model"] == "sonnet"
            assert llm.calls[1]["model"] == "sonnet"


class TestAnnotateFindingActorName:
    """annotate-finding should use context.actor_name instead of hardcoded 'agent'."""

    def test_annotate_uses_context_actor_name(self, tmp_path: Path) -> None:
        """When context.actor_name is set, annotate-finding uses it as the annotation actor."""
        from mallcop.store import JsonlStore
        from mallcop.tools.findings import annotate_finding

        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        context = ToolContext(
            store=store,
            connectors={},
            config=None,
        )
        # Set actor_name on context
        context.actor_name = "investigate"  # type: ignore[attr-defined]

        result = annotate_finding(context, finding_id="fnd_001", text="Investigation complete.")

        # Verify the annotation was written with actor_name, not "agent"
        findings = store.query_findings()
        fnd = [f for f in findings if f.id == "fnd_001"][0]
        new_anns = [a for a in fnd.annotations if a.content == "Investigation complete."]
        assert len(new_anns) == 1
        assert new_anns[0].actor == "investigate"
