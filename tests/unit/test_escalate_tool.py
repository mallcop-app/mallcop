"""Unit tests for escalate-to-investigator tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.chat import TOKENS_PER_DONUT
from mallcop.schemas import Finding, FindingStatus, Severity
from mallcop.tools import ToolContext
from mallcop.tools.escalate import escalate_to_investigator


# ─── Helpers ────────────────────────────────────────────────────────


def _make_finding(finding_id: str = "fnd_001") -> Finding:
    return Finding(
        id=finding_id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="test-detector",
        event_ids=[],
        title="Test finding",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_resolution(
    finding_id: str = "fnd_001",
    action: ResolutionAction = ResolutionAction.RESOLVED,
    reason: str = "Benign activity",
    confidence: float = 4.0,
) -> ActorResolution:
    return ActorResolution(
        finding_id=finding_id,
        action=action,
        reason=reason,
        confidence=confidence,
    )


def _make_run_result(
    finding_id: str = "fnd_001",
    action: ResolutionAction = ResolutionAction.RESOLVED,
    reason: str = "Benign activity",
    confidence: float = 4.0,
    tokens_used: int = 5000,
    iterations: int = 3,
) -> RunResult:
    return RunResult(
        resolution=_make_resolution(finding_id, action, reason, confidence),
        tokens_used=tokens_used,
        iterations=iterations,
    )


def _make_context(
    findings: list[Finding] | None = None,
    actor_runner: Any = None,
) -> ToolContext:
    store = MagicMock()
    store.query_findings.return_value = findings or []
    ctx = ToolContext(
        store=store,
        connectors={},
        config=MagicMock(),
        actor_runner=actor_runner,
    )
    return ctx


# ─── Tests ────────────────────────────────────────────────────────────


def test_happy_path():
    """actor_runner returns RunResult with resolved action; tool returns all 7 fields."""
    finding = _make_finding("fnd_001")
    run_result = _make_run_result(
        finding_id="fnd_001",
        tokens_used=3000,
        iterations=2,
        confidence=4.5,
    )

    actor_runner = MagicMock(return_value=run_result)
    ctx = _make_context(findings=[finding], actor_runner=actor_runner)

    result = escalate_to_investigator(ctx, finding_id="fnd_001", budget_donuts=20)

    assert "error" not in result
    assert result["finding_id"] == "fnd_001"
    assert result["action"] == "resolved"
    assert result["reason"] == "Benign activity"
    assert result["confidence"] == 4.5
    assert result["iterations"] == 2
    assert result["tokens_used"] == 3000
    assert result["donuts_used"] == 3000 / TOKENS_PER_DONUT


def test_finding_not_found():
    """Returns error dict when finding ID not found; does NOT call actor_runner."""
    actor_runner = MagicMock()
    ctx = _make_context(findings=[], actor_runner=actor_runner)

    result = escalate_to_investigator(ctx, finding_id="fnd_missing")

    assert result == {"error": "finding 'fnd_missing' not found"}
    actor_runner.assert_not_called()


def test_actor_runner_none():
    """Returns error when actor_runner is None (investigator chain not available)."""
    finding = _make_finding("fnd_001")
    ctx = _make_context(findings=[finding], actor_runner=None)

    result = escalate_to_investigator(ctx, finding_id="fnd_001")

    assert result == {"error": "investigator chain not available in this context"}


def test_actor_runner_raises():
    """Exception from actor_runner is caught; returns error dict, does NOT propagate."""
    finding = _make_finding("fnd_001")

    def bad_runner(*args, **kwargs):
        raise RuntimeError("something went wrong")

    ctx = _make_context(findings=[finding], actor_runner=bad_runner)

    result = escalate_to_investigator(ctx, finding_id="fnd_001")

    assert "error" in result
    assert "investigator failed" in result["error"]
    assert "RuntimeError" in result["error"]
    assert "something went wrong" in result["error"]


def test_budget_capping():
    """budget_donuts=50 is capped to 30; finding_token_budget == 30 * TOKENS_PER_DONUT."""
    finding = _make_finding("fnd_001")
    run_result = _make_run_result(tokens_used=1000)

    actor_runner = MagicMock(return_value=run_result)
    ctx = _make_context(findings=[finding], actor_runner=actor_runner)

    escalate_to_investigator(ctx, finding_id="fnd_001", budget_donuts=50)

    actor_runner.assert_called_once()
    call_kwargs = actor_runner.call_args[1]
    assert call_kwargs["finding_token_budget"] == 30 * TOKENS_PER_DONUT


def test_budget_floor():
    """budget_donuts=0 is floored to 1; finding_token_budget == 1 * TOKENS_PER_DONUT."""
    finding = _make_finding("fnd_001")
    run_result = _make_run_result(tokens_used=500)

    actor_runner = MagicMock(return_value=run_result)
    ctx = _make_context(findings=[finding], actor_runner=actor_runner)

    escalate_to_investigator(ctx, finding_id="fnd_001", budget_donuts=0)

    actor_runner.assert_called_once()
    call_kwargs = actor_runner.call_args[1]
    assert call_kwargs["finding_token_budget"] == 1 * TOKENS_PER_DONUT


def test_escalated_action_returned_as_is():
    """action='escalated' in result is returned as-is in the action field."""
    finding = _make_finding("fnd_001")
    run_result = _make_run_result(
        action=ResolutionAction.ESCALATED,
        reason="Too complex",
        tokens_used=2000,
        iterations=5,
    )

    actor_runner = MagicMock(return_value=run_result)
    ctx = _make_context(findings=[finding], actor_runner=actor_runner)

    result = escalate_to_investigator(ctx, finding_id="fnd_001")

    assert result["action"] == "escalated"
    assert result["reason"] == "Too complex"
    assert result["tokens_used"] == 2000
    assert result["iterations"] == 5
