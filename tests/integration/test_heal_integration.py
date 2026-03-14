"""Integration tests for the heal actor.

Tests:
1. End-to-end: log_format_drift finding → heal actor → parser patch proposed
2. Chain integration: heal in actor chain processes drift findings
"""

from __future__ import annotations

import json
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
from mallcop.schemas import Finding, FindingStatus, Severity
from mallcop.tools import ToolContext, ToolRegistry, tool


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_drift_finding(id: str = "fnd_drift_001") -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc),
        detector="log-format-drift",
        event_ids=["evt_001"],
        title="myapp parser is stale, 45% of lines unrecognized.",
        severity=Severity.INFO,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={
            "app_name": "myapp",
            "unmatched_ratio": 0.45,
            "unmatched_lines": [
                '{"ts": "2026-03-14T10:00:00Z", "level": "INFO", "request_id": "abc", "msg": "hello"}'
            ],
            "current_patterns": [],
        },
    )


def _build_heal_registry() -> ToolRegistry:
    """Build a registry with tools the heal actor needs."""
    reg = ToolRegistry()

    @tool(name="read-finding", description="Read finding details", permission="read")
    def read_finding(finding_id: str) -> dict[str, Any]:
        return _make_drift_finding(id=finding_id).to_dict()

    @tool(name="annotate-finding", description="Add annotation to finding", permission="write")
    def annotate_finding(finding_id: str, text: str, **kwargs: Any) -> dict[str, Any]:
        return {"status": "ok", "finding_id": finding_id}

    @tool(name="resolve-finding", description="Resolve or escalate a finding", permission="read")
    def resolve_finding(finding_id: str, action: str, reason: str) -> dict[str, Any]:
        return {"finding_id": finding_id, "action": action, "reason": reason}

    reg.register(read_finding)
    reg.register(annotate_finding)
    reg.register(resolve_finding)
    return reg


class MockLLMClient(LLMClient):
    """Mock LLM returning pre-programmed responses."""

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
        self.calls.append({"model": model, "system_prompt": system_prompt})
        if self._call_count >= len(self._responses):
            raise RuntimeError("MockLLMClient exhausted responses")
        resp = self._responses[self._call_count]
        self._call_count += 1
        return resp


# ─── Tests ────────────────────────────────────────────────────────────


class TestHealActorIntegration:
    @pytest.fixture
    def heal_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "heal"

    def test_heal_manifest_loads_correctly(self, heal_dir: Path) -> None:
        """Heal manifest has type=agent, model=sonnet, correct tools."""
        manifest = load_actor_manifest(heal_dir)
        assert manifest.name == "heal"
        assert manifest.type == "agent"
        assert manifest.model == "sonnet"
        assert "annotate-finding" in manifest.tools
        assert "resolve-finding" in manifest.tools
        assert "write" in manifest.permissions

    def test_heal_post_md_loads(self, heal_dir: Path) -> None:
        """POST.md loads as non-empty string."""
        content = load_post_md(heal_dir)
        assert len(content) > 0
        assert "heal" in content.lower()

    def test_heal_actor_resolves_drift_finding(self, heal_dir: Path) -> None:
        """Heal actor calls annotate-finding then resolve-finding on drift."""
        manifest = load_actor_manifest(heal_dir)
        registry = _build_heal_registry()
        post_md = load_post_md(heal_dir)

        patch_json = json.dumps({
            "scenario": "new_field",
            "app_name": "myapp",
            "before": None,
            "after": {
                "name": "myapp_new",
                "pattern": r"^(?P<ts>\S+)\s+(?P<level>\S+)\s+(?P<msg>.+)$",
                "classification": "operational",
                "event_mapping": {
                    "event_type": "log_line",
                    "actor": "myapp",
                    "action": "log",
                    "target": "myapp",
                    "severity": "info",
                },
                "noise_filter": False,
            },
            "reason": "New JSON format detected in myapp logs.",
            "confidence": 0.65,
        })

        llm = MockLLMClient([
            # First call: LLM reads finding
            LLMResponse(
                tool_calls=[ToolCall(name="read-finding", arguments={"finding_id": "fnd_drift_001"})],
                resolution=None,
                tokens_used=200,
            ),
            # Second call: annotate with patch
            LLMResponse(
                tool_calls=[ToolCall(
                    name="annotate-finding",
                    arguments={"finding_id": "fnd_drift_001", "text": patch_json},
                )],
                resolution=None,
                tokens_used=300,
            ),
            # Third call: resolve
            LLMResponse(
                tool_calls=[ToolCall(
                    name="resolve-finding",
                    arguments={
                        "finding_id": "fnd_drift_001",
                        "action": "resolved",
                        "reason": "Proposed new template for new_field scenario in myapp parser.",
                    },
                )],
                resolution=None,
                tokens_used=150,
            ),
        ])

        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm)
        result = runtime.run(finding=_make_drift_finding(), system_prompt=post_md)

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert result.tokens_used == 650
        assert result.iterations == 3
        # Heal uses sonnet
        assert llm.calls[0]["model"] == "sonnet"

    def test_heal_actor_escalates_on_failure(self, heal_dir: Path) -> None:
        """If LLM returns no tool calls, runtime escalates."""
        manifest = load_actor_manifest(heal_dir)
        registry = _build_heal_registry()
        post_md = load_post_md(heal_dir)

        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_drift_001",
                    action=ResolutionAction.ESCALATED,
                    reason="Cannot determine drift pattern.",
                ),
                tokens_used=100,
            ),
        ])

        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm)
        result = runtime.run(finding=_make_drift_finding(), system_prompt=post_md)

        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.ESCALATED

    def test_heal_in_actor_chain(self, heal_dir: Path) -> None:
        """Heal processes a drift finding when invoked directly in the chain."""
        import tempfile

        import yaml

        from mallcop.actors.runtime import build_actor_runner
        from mallcop.config import load_config
        from mallcop.store import JsonlStore

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_data = {
                "secrets": {"backend": "env"},
                "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
                "routing": {"info": "heal"},
                "actor_chain": {},
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

            heal_resolution = LLMResponse(
                tool_calls=[ToolCall(
                    name="resolve-finding",
                    arguments={
                        "finding_id": "fnd_drift_001",
                        "action": "resolved",
                        "reason": "Proposed parser patch stored as annotation.",
                    },
                )],
                resolution=None,
                tokens_used=250,
            )

            llm = MockLLMClient([heal_resolution])

            runner = build_actor_runner(
                root=root,
                store=store,
                config=config,
                llm=llm,
                actor_dirs=[heal_dir],
            )

            assert runner is not None
            result = runner(_make_drift_finding(), actor_name="heal")

            # heal resolved the drift finding
            assert result.resolution is not None
            assert result.resolution.action == ResolutionAction.RESOLVED
            assert result.tokens_used == 250
            assert llm.calls[0]["model"] == "sonnet"


class TestHealHealActorDirectInvocation:
    """Tests for HealActor.handle() directly (no LLM)."""

    def test_drift_finding_gets_patch_annotation(self) -> None:
        from mallcop.actors.heal import HealActor

        finding = _make_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])

        assert len(results) == 1
        heal_anns = [a for a in results[0].annotations if a.actor == "heal"]
        assert len(heal_anns) == 1
        data = json.loads(heal_anns[0].content)
        assert data["app_name"] == "myapp"
        assert data["scenario"] in ("new_field", "renamed_field", "format_change")

    def test_chain_integration_heal_handles_drift_in_batch(self) -> None:
        """Multiple findings: only drift ones get heal annotations."""
        from mallcop.actors.heal import HealActor
        from mallcop.schemas import FindingStatus

        non_drift = Finding(
            id="fnd_other",
            timestamp=datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc),
            detector="priv-escalation",
            event_ids=["evt_99"],
            title="Privilege escalation detected",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )

        actor = HealActor()
        results = actor.handle([_make_drift_finding(), non_drift])

        drift_result = [r for r in results if r.id == "fnd_drift_001"][0]
        other_result = [r for r in results if r.id == "fnd_other"][0]

        assert any(a.actor == "heal" for a in drift_result.annotations)
        assert not any(a.actor == "heal" for a in other_result.annotations)
