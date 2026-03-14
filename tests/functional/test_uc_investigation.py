"""UC: Investigation workflow -- triage escalates, investigate actor runs, annotates findings.

Functional test exercising the full investigation actor chain:

1. Seed findings that triage has already escalated.
2. Run escalation with build_actor_runner (mock LLM).
3. Verify: triage escalates → investigate runs → resolves or escalates to notify-teams.
4. Verify: findings have annotations from the correct actor at each stage.
5. Verify: investigate actor uses sonnet model.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import LLMClient, LLMResponse, RunResult, ToolCall, build_actor_runner
from mallcop.escalate import run_escalate
from mallcop.config import load_config
from mallcop.schemas import Annotation, Event, Finding, FindingStatus, Severity
from mallcop.store import JsonlStore


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_config(root: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
        "routing": {"critical": "triage", "warn": "triage"},
        "actor_chain": {
            "triage": {"routes_to": "investigate"},
            "investigate": {"routes_to": "notify-teams"},
        },
        "actors": {
            "notify-teams": {"webhook_url": "https://test.webhook.example.com/test"},
        },
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 10000,
        },
        "squelch": 0,  # disabled: functional tests are not testing squelch gating
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _seed_findings(root: Path) -> list[Finding]:
    now = datetime.now(timezone.utc)
    findings = [
        Finding(
            id="fnd_crit_001",
            timestamp=now - timedelta(minutes=30),
            detector="new-actor",
            event_ids=["evt_001", "evt_002"],
            title="New actor: attacker@evil.com on azure",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "attacker@evil.com"},
        ),
        Finding(
            id="fnd_warn_001",
            timestamp=now - timedelta(minutes=28),
            detector="new-actor",
            event_ids=["evt_003"],
            title="New sign-in from attacker@evil.com",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "attacker@evil.com"},
        ),
    ]
    store = JsonlStore(root)
    store.append_findings(findings)
    return findings


class _ChainTrackingLLM(LLMClient):
    """Mock LLM that tracks calls and returns scripted responses.

    Distinguishes triage vs investigate by system prompt content.
    Triage: always escalates.
    Investigate: resolves the first finding, escalates the second.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._investigate_call_count = 0

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        self.calls.append({"model": model, "system_prompt": system_prompt})

        is_triage = system_prompt.strip().startswith("# Triage")

        if is_triage:
            # Triage: always escalate
            return LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="placeholder",
                    action=ResolutionAction.ESCALATED,
                    reason="Unusual activity, escalating to investigation.",
                ),
                tokens_used=200,
            )
        else:
            # Investigate: first call resolves, second escalates
            self._investigate_call_count += 1
            if self._investigate_call_count <= 1:
                return LLMResponse(
                    tool_calls=[],
                    resolution=ActorResolution(
                        finding_id="placeholder",
                        action=ResolutionAction.RESOLVED,
                        reason="Investigation complete: activity is benign contractor onboarding.",
                    ),
                    tokens_used=500,
                )
            else:
                return LLMResponse(
                    tool_calls=[],
                    resolution=ActorResolution(
                        finding_id="placeholder",
                        action=ResolutionAction.ESCALATED,
                        reason="Cannot confirm intent after investigation. Human review needed.",
                    ),
                    tokens_used=600,
                )


# ─── Tests ────────────────────────────────────────────────────────────


class TestInvestigationWorkflow:
    """Full investigation workflow through run_escalate with build_actor_runner."""

    def test_escalate_runs_triage_then_investigate(self, tmp_path: Path) -> None:
        """run_escalate with real actor_runner: triage→investigate chain executes correctly."""
        root = tmp_path
        _make_config(root)
        _seed_findings(root)

        config = load_config(root)
        store = JsonlStore(root)
        llm = _ChainTrackingLLM()

        runner = build_actor_runner(
            root=root,
            store=store,
            config=config,
            llm=llm,
        )
        assert runner is not None

        result = run_escalate(root, actor_runner=runner)

        assert result["status"] == "ok"
        assert result["findings_processed"] == 2

        # Verify LLM call sequence: for each finding, triage (sonnet) then investigate (sonnet)
        models_used = [c["model"] for c in llm.calls]
        # First finding: triage(sonnet) → investigate(sonnet, resolves)
        # Second finding: triage(sonnet) → investigate(sonnet, escalates)
        assert models_used == ["sonnet", "sonnet", "sonnet", "sonnet"]

    def test_first_finding_resolved_by_investigate(self, tmp_path: Path) -> None:
        """First CRITICAL finding is resolved by investigate — gets resolution annotation."""
        root = tmp_path
        _make_config(root)
        _seed_findings(root)

        config = load_config(root)
        store = JsonlStore(root)
        llm = _ChainTrackingLLM()

        runner = build_actor_runner(root=root, store=store, config=config, llm=llm)
        run_escalate(root, actor_runner=runner)

        # Re-read findings from store
        store2 = JsonlStore(root)
        findings = store2.query_findings()
        crit = [f for f in findings if f.id == "fnd_crit_001"][0]

        # Should be resolved (investigate resolved it)
        assert crit.status == FindingStatus.RESOLVED
        assert len(crit.annotations) >= 1
        resolved_anns = [a for a in crit.annotations if a.action == "resolved"]
        assert len(resolved_anns) == 1
        assert "benign" in resolved_anns[0].content.lower()

    def test_second_finding_escalated_through_chain(self, tmp_path: Path) -> None:
        """Second WARN finding escalated by both triage and investigate — remains open."""
        root = tmp_path
        _make_config(root)
        _seed_findings(root)

        config = load_config(root)
        store = JsonlStore(root)
        llm = _ChainTrackingLLM()

        runner = build_actor_runner(root=root, store=store, config=config, llm=llm)
        run_escalate(root, actor_runner=runner)

        store2 = JsonlStore(root)
        findings = store2.query_findings()
        warn = [f for f in findings if f.id == "fnd_warn_001"][0]

        # Should remain open (investigate escalated, chain ended at notify-teams)
        assert warn.status == FindingStatus.OPEN
        assert len(warn.annotations) >= 1
        escalated_anns = [a for a in warn.annotations if a.action == "escalated"]
        assert len(escalated_anns) >= 1
