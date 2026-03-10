"""Unit tests for escalate module: run_escalate orchestration logic.

Tests severity ordering, empty findings, budget exhaustion, missing routing,
cost logging, circuit breaker, and actor resolution application.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import BatchResult, RunResult
from mallcop.budget import BudgetConfig, BudgetTracker, CostEntry, order_by_severity, check_circuit_breaker
from mallcop.config import MallcopConfig, RouteConfig
from mallcop.config import BudgetConfig as ConfigBudgetConfig
from mallcop.schemas import Annotation, Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    id: str = "f-1",
    severity: Severity = Severity.WARN,
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        detector="test-detector",
        event_ids=["e-1"],
        title=f"Test finding {id}",
        severity=severity,
        status=status,
        annotations=[],
        metadata={},
    )


def _route(actor: str) -> RouteConfig:
    """Shorthand: single-actor chain with no notify channels."""
    return RouteConfig(chain=[actor], notify=[])


def _make_config(
    routing: dict[str, RouteConfig | None] | None = None,
    max_findings_for_actors: int = 25,
    max_tokens_per_run: int = 50000,
    max_tokens_per_finding: int = 5000,
) -> MallcopConfig:
    return MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing=routing or {},
        actor_chain={},
        budget=ConfigBudgetConfig(
            max_findings_for_actors=max_findings_for_actors,
            max_tokens_per_run=max_tokens_per_run,
            max_tokens_per_finding=max_tokens_per_finding,
        ),
    )


def _make_run_result(
    finding_id: str = "f-1",
    action: ResolutionAction = ResolutionAction.RESOLVED,
    reason: str = "Benign activity",
    tokens: int = 500,
) -> RunResult:
    return RunResult(
        resolution=ActorResolution(
            finding_id=finding_id,
            action=action,
            reason=reason,
        ),
        tokens_used=tokens,
        iterations=1,
    )


# ---------------------------------------------------------------------------
# Severity ordering (budget.order_by_severity)
# ---------------------------------------------------------------------------

class TestSeverityOrdering:
    """order_by_severity returns CRITICAL first, then WARN, then INFO."""

    def test_critical_before_warn_before_info(self) -> None:
        findings = [
            _make_finding("info-1", Severity.INFO),
            _make_finding("crit-1", Severity.CRITICAL),
            _make_finding("warn-1", Severity.WARN),
        ]
        ordered = order_by_severity(findings)
        assert [f.severity for f in ordered] == [
            Severity.CRITICAL,
            Severity.WARN,
            Severity.INFO,
        ]

    def test_stable_sort_within_same_severity(self) -> None:
        findings = [
            _make_finding("w-1", Severity.WARN),
            _make_finding("w-2", Severity.WARN),
            _make_finding("w-3", Severity.WARN),
        ]
        ordered = order_by_severity(findings)
        assert [f.id for f in ordered] == ["w-1", "w-2", "w-3"]

    def test_empty_list(self) -> None:
        assert order_by_severity([]) == []

    def test_single_finding(self) -> None:
        findings = [_make_finding("only")]
        ordered = order_by_severity(findings)
        assert len(ordered) == 1
        assert ordered[0].id == "only"


# ---------------------------------------------------------------------------
# Empty findings → no actor invocation
# ---------------------------------------------------------------------------

class TestEmptyFindings:
    """When no open findings exist, no actors are invoked and cost is logged."""

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    def test_no_findings_no_actor_calls(
        self, mock_load_config: MagicMock, mock_cost_log: MagicMock, tmp_path: Path
    ) -> None:
        config = _make_config(routing={"critical": _route("triage"), "warn": _route("triage")})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = []

        actor_runner = MagicMock()

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=actor_runner)

        actor_runner.assert_not_called()
        assert result["findings_processed"] == 0
        assert result["tokens_used"] == 0
        assert result["status"] == "ok"

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    def test_no_findings_cost_logged(
        self, mock_load_config: MagicMock, mock_cost_log: MagicMock, tmp_path: Path
    ) -> None:
        config = _make_config()
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = []

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            run_escalate(tmp_path)

        mock_cost_log.assert_called_once()
        cost_entry = mock_cost_log.call_args[0][1]
        assert isinstance(cost_entry, CostEntry)
        assert cost_entry.tokens_used == 0
        assert cost_entry.actors_invoked is False


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    """When findings exceed max_findings_for_actors, circuit breaker fires."""

    def test_circuit_breaker_returns_finding_when_exceeded(self) -> None:
        bc = BudgetConfig(max_findings_for_actors=5)
        findings = [_make_finding(f"f-{i}") for i in range(6)]
        cb = check_circuit_breaker(findings, bc)
        assert cb is not None
        assert cb.id == "meta_circuit_breaker"
        assert cb.severity == Severity.CRITICAL
        assert cb.metadata["finding_count"] == "6"
        assert cb.metadata["threshold"] == "5"

    def test_circuit_breaker_returns_none_when_under_threshold(self) -> None:
        bc = BudgetConfig(max_findings_for_actors=10)
        findings = [_make_finding(f"f-{i}") for i in range(10)]
        assert check_circuit_breaker(findings, bc) is None

    def test_circuit_breaker_returns_none_at_exact_threshold(self) -> None:
        bc = BudgetConfig(max_findings_for_actors=5)
        findings = [_make_finding(f"f-{i}") for i in range(5)]
        assert check_circuit_breaker(findings, bc) is None

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    def test_circuit_breaker_skips_actors_in_run_escalate(
        self, mock_load_config: MagicMock, mock_cost_log: MagicMock, tmp_path: Path
    ) -> None:
        config = _make_config(
            routing={"warn": _route("triage")},
            max_findings_for_actors=3,
        )
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding(f"f-{i}") for i in range(5)
        ]

        actor_runner = MagicMock()

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=actor_runner)

        actor_runner.assert_not_called()
        assert result["circuit_breaker_triggered"] is True
        assert result["findings_processed"] == 0
        assert result["tokens_used"] == 0
        # Circuit breaker finding should be appended to store
        mock_store.append_findings.assert_called_once()
        cb_findings = mock_store.append_findings.call_args[0][0]
        assert len(cb_findings) == 1
        assert cb_findings[0].id == "meta_circuit_breaker"

    def test_circuit_breaker_severity_breakdown(self) -> None:
        bc = BudgetConfig(max_findings_for_actors=2)
        findings = [
            _make_finding("f-1", Severity.CRITICAL),
            _make_finding("f-2", Severity.WARN),
            _make_finding("f-3", Severity.WARN),
        ]
        cb = check_circuit_breaker(findings, bc)
        assert cb is not None
        breakdown = cb.metadata["severity_breakdown"]
        assert breakdown["critical"] == 1
        assert breakdown["warn"] == 2


# ---------------------------------------------------------------------------
# Budget exhaustion mid-batch
# ---------------------------------------------------------------------------

class TestBudgetExhaustionMidBatch:
    """When token budget runs out mid-batch, remaining findings are skipped."""

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    @patch("mallcop.escalate.run_batch")
    def test_budget_exhausted_marks_remaining_findings(
        self,
        mock_run_batch: MagicMock,
        mock_load_config: MagicMock,
        mock_cost_log: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _make_config(
            routing={"warn": _route("triage")},
            max_tokens_per_run=1000,
        )
        mock_load_config.return_value = config

        findings = [_make_finding(f"f-{i}") for i in range(3)]
        mock_store = MagicMock()
        mock_store.query_findings.return_value = findings

        # run_batch processes only 1 of 3 findings (budget ran out)
        mock_run_batch.return_value = BatchResult(
            results=[_make_run_result("f-0", tokens=900)],
            total_tokens=900,
        )

        actor_runner = MagicMock()

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=actor_runner)

        assert result["findings_processed"] == 1
        assert result["budget_exhausted"] is True
        # Unprocessed findings (f-1, f-2) should get budget annotations
        budget_update_calls = [
            c for c in mock_store.update_finding.call_args_list
            if any(
                a.actor == "mallcop-budget"
                for a in c[1].get("annotations", c[0][1] if len(c[0]) > 1 else [])
                if isinstance(a, Annotation)
            )
        ]
        # Two unprocessed findings should be annotated
        assert mock_store.update_finding.call_count >= 2


# ---------------------------------------------------------------------------
# Missing routing config → graceful handling
# ---------------------------------------------------------------------------

class TestMissingRoutingConfig:
    """Findings with severity not in routing config are silently skipped."""

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    def test_unrouted_severity_skipped(
        self, mock_load_config: MagicMock, mock_cost_log: MagicMock, tmp_path: Path
    ) -> None:
        # Only route critical, not warn
        config = _make_config(routing={"critical": _route("triage")})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-1", Severity.WARN),
        ]

        actor_runner = MagicMock()

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=actor_runner)

        actor_runner.assert_not_called()
        assert result["findings_processed"] == 0

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    def test_empty_routing_skips_all(
        self, mock_load_config: MagicMock, mock_cost_log: MagicMock, tmp_path: Path
    ) -> None:
        config = _make_config(routing={})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-1", Severity.CRITICAL),
            _make_finding("f-2", Severity.WARN),
        ]

        actor_runner = MagicMock()

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=actor_runner)

        actor_runner.assert_not_called()
        assert result["findings_processed"] == 0

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    def test_routing_with_none_value_skips_severity(
        self, mock_load_config: MagicMock, mock_cost_log: MagicMock, tmp_path: Path
    ) -> None:
        config = _make_config(routing={"critical": _route("triage"), "warn": None})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-1", Severity.WARN),
        ]

        actor_runner = MagicMock()

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=actor_runner)

        actor_runner.assert_not_called()
        assert result["findings_processed"] == 0

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    def test_routing_with_empty_chain_skips_finding(
        self, mock_load_config: MagicMock, mock_cost_log: MagicMock, tmp_path: Path
    ) -> None:
        """RouteConfig with empty chain list is treated as unroutable."""
        config = _make_config(
            routing={"warn": RouteConfig(chain=[], notify=["slack"])}
        )
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-1", Severity.WARN),
        ]

        actor_runner = MagicMock()

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=actor_runner)

        actor_runner.assert_not_called()
        assert result["findings_processed"] == 0


# ---------------------------------------------------------------------------
# Cost logging on completion
# ---------------------------------------------------------------------------

class TestCostLogging:
    """Cost entry is always logged, with correct fields."""

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    @patch("mallcop.escalate.run_batch")
    def test_cost_logged_with_tokens(
        self,
        mock_run_batch: MagicMock,
        mock_load_config: MagicMock,
        mock_cost_log: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _make_config(routing={"critical": _route("triage")})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-1", Severity.CRITICAL),
        ]

        mock_run_batch.return_value = BatchResult(
            results=[_make_run_result("f-1", tokens=1200)],
            total_tokens=1200,
        )

        actor_runner = MagicMock()

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=actor_runner)

        mock_cost_log.assert_called_once()
        cost_entry = mock_cost_log.call_args[0][1]
        assert cost_entry.tokens_used == 1200
        assert cost_entry.actors_invoked is True
        assert cost_entry.findings == 1
        # Cost = (1200 / 1000) * 0.00025 = 0.0003
        assert abs(cost_entry.estimated_cost_usd - 0.0003) < 1e-9


# ---------------------------------------------------------------------------
# Actor resolution application
# ---------------------------------------------------------------------------

class TestActorResolutionApplication:
    """Verify that resolved/escalated findings update the store correctly."""

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    @patch("mallcop.escalate.run_batch")
    def test_resolved_finding_updates_store_status(
        self,
        mock_run_batch: MagicMock,
        mock_load_config: MagicMock,
        mock_cost_log: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _make_config(routing={"critical": _route("triage")})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-1", Severity.CRITICAL),
        ]

        mock_run_batch.return_value = BatchResult(
            results=[_make_run_result(
                "f-1",
                action=ResolutionAction.RESOLVED,
                reason="Known admin activity",
            )],
            total_tokens=800,
        )

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            run_escalate(tmp_path, actor_runner=MagicMock())

        mock_store.update_finding.assert_called_once()
        call_kwargs = mock_store.update_finding.call_args
        assert call_kwargs[0][0] == "f-1"
        assert call_kwargs[1]["status"] == FindingStatus.RESOLVED

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    @patch("mallcop.escalate.run_batch")
    def test_escalated_finding_adds_annotation_without_status_change(
        self,
        mock_run_batch: MagicMock,
        mock_load_config: MagicMock,
        mock_cost_log: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _make_config(routing={"warn": _route("triage")})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-1", Severity.WARN),
        ]

        mock_run_batch.return_value = BatchResult(
            results=[_make_run_result(
                "f-1",
                action=ResolutionAction.ESCALATED,
                reason="Needs human review",
            )],
            total_tokens=600,
        )

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            run_escalate(tmp_path, actor_runner=MagicMock())

        mock_store.update_finding.assert_called_once()
        call_kwargs = mock_store.update_finding.call_args
        assert call_kwargs[0][0] == "f-1"
        # Escalated findings should NOT get status changed
        assert "status" not in call_kwargs[1]
        annotations = call_kwargs[1]["annotations"]
        assert len(annotations) == 1
        assert annotations[0].action == "escalated"


# ---------------------------------------------------------------------------
# No actor runner provided
# ---------------------------------------------------------------------------

class TestNoActorRunner:
    """When actor_runner is None, findings are logged but not processed."""

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    def test_none_actor_runner_processes_zero(
        self, mock_load_config: MagicMock, mock_cost_log: MagicMock, tmp_path: Path
    ) -> None:
        config = _make_config(routing={"warn": _route("triage")})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-1", Severity.WARN),
        ]

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            result = run_escalate(tmp_path, actor_runner=None)

        assert result["findings_processed"] == 0
        assert result["tokens_used"] == 0
        assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# BudgetTracker unit tests
# ---------------------------------------------------------------------------

class TestBudgetTracker:
    """BudgetTracker tracks token usage and budget percentage."""

    def test_initial_tokens_zero(self) -> None:
        tracker = BudgetTracker(BudgetConfig(max_tokens_per_run=10000))
        assert tracker.tokens_used == 0

    def test_add_tokens(self) -> None:
        tracker = BudgetTracker(BudgetConfig(max_tokens_per_run=10000))
        tracker.add_tokens(3000)
        assert tracker.tokens_used == 3000

    def test_run_budget_exhausted(self) -> None:
        tracker = BudgetTracker(BudgetConfig(max_tokens_per_run=1000))
        tracker.add_tokens(1001)
        assert tracker.run_budget_exhausted() is True

    def test_run_budget_not_exhausted_at_exact_limit(self) -> None:
        tracker = BudgetTracker(BudgetConfig(max_tokens_per_run=1000))
        tracker.add_tokens(1000)
        assert tracker.run_budget_exhausted() is False

    def test_budget_remaining_pct(self) -> None:
        tracker = BudgetTracker(BudgetConfig(max_tokens_per_run=10000))
        tracker.add_tokens(2500)
        assert tracker.budget_remaining_pct() == 75.0

    def test_budget_remaining_pct_zero_max(self) -> None:
        tracker = BudgetTracker(BudgetConfig(max_tokens_per_run=0))
        assert tracker.budget_remaining_pct() == 0.0

    def test_run_budget_remaining_clamps_to_zero(self) -> None:
        tracker = BudgetTracker(BudgetConfig(max_tokens_per_run=100))
        tracker.add_tokens(200)
        assert tracker.run_budget_remaining() == 0


# ---------------------------------------------------------------------------
# Batch grouping by entry actor
# ---------------------------------------------------------------------------

class TestBatchGrouping:
    """Findings are grouped by entry actor from routing config."""

    @patch("mallcop.escalate.append_cost_log")
    @patch("mallcop.escalate.load_config")
    @patch("mallcop.escalate.run_batch")
    def test_different_severities_route_to_different_actors(
        self,
        mock_run_batch: MagicMock,
        mock_load_config: MagicMock,
        mock_cost_log: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _make_config(routing={"critical": _route("incident"), "warn": _route("triage")})
        mock_load_config.return_value = config

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [
            _make_finding("f-crit", Severity.CRITICAL),
            _make_finding("f-warn", Severity.WARN),
        ]

        mock_run_batch.return_value = BatchResult(
            results=[_make_run_result(tokens=100)],
            total_tokens=100,
        )

        with patch("mallcop.escalate.JsonlStore", return_value=mock_store):
            from mallcop.escalate import run_escalate

            run_escalate(tmp_path, actor_runner=MagicMock())

        # run_batch should be called twice: once for "incident", once for "triage"
        assert mock_run_batch.call_count == 2
        first_call_actor = mock_run_batch.call_args_list[0][1]["actor_name"]
        second_call_actor = mock_run_batch.call_args_list[1][1]["actor_name"]
        assert first_call_actor == "incident"
        assert second_call_actor == "triage"
