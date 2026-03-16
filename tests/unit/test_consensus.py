"""Tests for consensus resolution logic."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.consensus import needs_consensus, run_consensus
from mallcop.schemas import Finding, FindingStatus, Severity

from datetime import datetime, timezone


def _make_finding(finding_id: str = "fnd_001") -> Finding:
    return Finding(
        id=finding_id,
        timestamp=datetime.now(timezone.utc),
        detector="test-detector",
        event_ids=["evt_001"],
        title="Test finding",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_result(
    action: ResolutionAction = ResolutionAction.RESOLVED,
    tokens: int = 100,
    reason: str = "test reason",
) -> RunResult:
    return RunResult(
        resolution=ActorResolution(
            finding_id="fnd_001",
            action=action,
            reason=reason,
            confidence=0.9,
        ),
        tokens_used=tokens,
        iterations=1,
    )


class TestNeedsConsensus:
    def test_true_when_resolved(self) -> None:
        result = _make_result(action=ResolutionAction.RESOLVED)
        assert needs_consensus(result) is True

    def test_false_when_escalated(self) -> None:
        result = _make_result(action=ResolutionAction.ESCALATED)
        assert needs_consensus(result) is False

    def test_false_when_no_resolution(self) -> None:
        result = RunResult(resolution=None, tokens_used=50, iterations=1)
        assert needs_consensus(result) is False


class TestRunConsensus:
    def test_unanimous_resolve_returns_original_with_summed_tokens(self) -> None:
        finding = _make_finding()
        first = _make_result(tokens=100)
        runner = MagicMock(return_value=_make_result(tokens=50))

        result = run_consensus(finding, runner, first, n_runs=2)

        assert result.resolution.action == ResolutionAction.RESOLVED
        assert result.tokens_used == 200  # 100 + 50 + 50
        assert runner.call_count == 2

    def test_one_dissent_overrides_to_escalated(self) -> None:
        finding = _make_finding()
        first = _make_result(tokens=100)
        resolve_result = _make_result(tokens=50)
        escalate_result = _make_result(
            action=ResolutionAction.ESCALATED, tokens=50
        )
        runner = MagicMock(side_effect=[resolve_result, escalate_result])

        result = run_consensus(finding, runner, first, n_runs=2)

        assert result.resolution.action == ResolutionAction.ESCALATED
        assert "Consensus escalation" in result.resolution.reason

    def test_all_dissent_returns_escalated(self) -> None:
        finding = _make_finding()
        first = _make_result(tokens=100)
        escalate_result = _make_result(
            action=ResolutionAction.ESCALATED, tokens=50
        )
        runner = MagicMock(return_value=escalate_result)

        result = run_consensus(finding, runner, first, n_runs=3)

        assert result.resolution.action == ResolutionAction.ESCALATED

    def test_runner_exception_counts_as_escalated(self) -> None:
        finding = _make_finding()
        first = _make_result(tokens=100)
        runner = MagicMock(side_effect=RuntimeError("LLM timeout"))

        result = run_consensus(finding, runner, first, n_runs=1)

        assert result.resolution.action == ResolutionAction.ESCALATED

    def test_no_resolution_counts_as_escalated(self) -> None:
        finding = _make_finding()
        first = _make_result(tokens=100)
        no_res = RunResult(resolution=None, tokens_used=50, iterations=1)
        runner = MagicMock(return_value=no_res)

        result = run_consensus(finding, runner, first, n_runs=1)

        assert result.resolution.action == ResolutionAction.ESCALATED

    def test_tokens_summed_across_all_runs(self) -> None:
        finding = _make_finding()
        first = _make_result(tokens=100)
        runner = MagicMock(return_value=_make_result(tokens=75))

        result = run_consensus(finding, runner, first, n_runs=3)

        assert result.tokens_used == 100 + 75 * 3

    def test_escalation_preserves_original_reason(self) -> None:
        finding = _make_finding()
        first = _make_result(tokens=100, reason="looks benign")
        runner = MagicMock(
            return_value=_make_result(action=ResolutionAction.ESCALATED, tokens=50)
        )

        result = run_consensus(finding, runner, first, n_runs=1)

        assert "looks benign" in result.resolution.reason
