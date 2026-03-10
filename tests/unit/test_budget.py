"""Tests for budget controls: circuit breaker, token tracking, severity ordering, cost logging."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from mallcop.schemas import Finding, Severity, FindingStatus
from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.budget import (
    BudgetConfig,
    BudgetTracker,
    check_circuit_breaker,
    order_by_severity,
    CostEntry,
    append_cost_log,
)


# ─── Helpers ────────────────────────────────────────────────────────


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


# ─── Circuit breaker ───────────────────────────────────────────────


class TestCircuitBreaker:
    def test_below_threshold_passes(self) -> None:
        findings = [_make_finding(id=f"fnd_{i}") for i in range(5)]
        config = BudgetConfig(max_findings_for_actors=25)
        result = check_circuit_breaker(findings, config)
        assert result is None

    def test_at_threshold_passes(self) -> None:
        findings = [_make_finding(id=f"fnd_{i}") for i in range(25)]
        config = BudgetConfig(max_findings_for_actors=25)
        result = check_circuit_breaker(findings, config)
        assert result is None

    def test_above_threshold_fires(self) -> None:
        findings = [_make_finding(id=f"fnd_{i}") for i in range(26)]
        config = BudgetConfig(max_findings_for_actors=25)
        result = check_circuit_breaker(findings, config)
        assert result is not None
        assert result.severity == Severity.CRITICAL
        assert "circuit breaker" in result.title.lower()
        assert "26" in result.metadata.get("finding_count", "")
        assert "25" in result.metadata.get("threshold", "")

    def test_large_volume_fires(self) -> None:
        findings = [_make_finding(id=f"fnd_{i}") for i in range(247)]
        config = BudgetConfig(max_findings_for_actors=25)
        result = check_circuit_breaker(findings, config)
        assert result is not None
        # Should contain severity breakdown
        assert "severity_breakdown" in result.metadata


# ─── Per-run token budget ───────────────────────────────────────────


class TestBudgetTracker:
    def test_within_budget(self) -> None:
        config = BudgetConfig(max_tokens_per_run=50000, max_tokens_per_finding=5000)
        tracker = BudgetTracker(config)
        tracker.add_tokens(1000)
        assert not tracker.run_budget_exhausted()
        assert tracker.tokens_used == 1000

    def test_run_budget_exhaustion(self) -> None:
        config = BudgetConfig(max_tokens_per_run=1000, max_tokens_per_finding=5000)
        tracker = BudgetTracker(config)
        tracker.add_tokens(500)
        assert not tracker.run_budget_exhausted()
        tracker.add_tokens(501)
        assert tracker.run_budget_exhausted()

    def test_per_finding_budget_exhaustion(self) -> None:
        config = BudgetConfig(max_tokens_per_run=50000, max_tokens_per_finding=500)
        tracker = BudgetTracker(config)
        assert not tracker.finding_budget_exhausted(400)
        assert tracker.finding_budget_exhausted(501)

    def test_remaining_budget(self) -> None:
        config = BudgetConfig(max_tokens_per_run=10000, max_tokens_per_finding=5000)
        tracker = BudgetTracker(config)
        tracker.add_tokens(3000)
        assert tracker.run_budget_remaining() == 7000
        assert tracker.budget_remaining_pct() == 70.0

    def test_zero_budget_immediately_exhausted(self) -> None:
        config = BudgetConfig(max_tokens_per_run=0, max_tokens_per_finding=0)
        tracker = BudgetTracker(config)
        tracker.add_tokens(1)
        assert tracker.run_budget_exhausted()
        assert tracker.finding_budget_exhausted(1)


# ─── Severity-priority ordering ────────────────────────────────────


class TestSeverityOrdering:
    def test_critical_before_warn(self) -> None:
        findings = [
            _make_finding(id="fnd_w1", severity=Severity.WARN),
            _make_finding(id="fnd_c1", severity=Severity.CRITICAL),
            _make_finding(id="fnd_w2", severity=Severity.WARN),
        ]
        ordered = order_by_severity(findings)
        assert ordered[0].id == "fnd_c1"
        assert ordered[1].severity == Severity.WARN

    def test_critical_before_warn_before_info(self) -> None:
        findings = [
            _make_finding(id="fnd_i1", severity=Severity.INFO),
            _make_finding(id="fnd_w1", severity=Severity.WARN),
            _make_finding(id="fnd_c1", severity=Severity.CRITICAL),
        ]
        ordered = order_by_severity(findings)
        assert [f.severity for f in ordered] == [
            Severity.CRITICAL,
            Severity.WARN,
            Severity.INFO,
        ]

    def test_preserves_order_within_severity(self) -> None:
        findings = [
            _make_finding(id="fnd_c2", severity=Severity.CRITICAL),
            _make_finding(id="fnd_c1", severity=Severity.CRITICAL),
        ]
        ordered = order_by_severity(findings)
        assert ordered[0].id == "fnd_c2"
        assert ordered[1].id == "fnd_c1"

    def test_empty_list(self) -> None:
        assert order_by_severity([]) == []


# ─── Cost logging ──────────────────────────────────────────────────


class TestCostLogging:
    def test_cost_entry_to_dict(self) -> None:
        entry = CostEntry(
            timestamp=datetime(2026, 3, 6, 18, 0, 0, tzinfo=timezone.utc),
            events=127,
            findings=4,
            actors_invoked=True,
            tokens_used=18432,
            estimated_cost_usd=0.0014,
            budget_remaining_pct=63.0,
        )
        d = entry.to_dict()
        assert d["events"] == 127
        assert d["tokens_used"] == 18432
        assert d["actors_invoked"] is True

    def test_cost_entry_roundtrip(self) -> None:
        entry = CostEntry(
            timestamp=datetime(2026, 3, 6, 18, 0, 0, tzinfo=timezone.utc),
            events=50,
            findings=3,
            actors_invoked=True,
            tokens_used=5000,
            estimated_cost_usd=0.001,
            budget_remaining_pct=90.0,
        )
        d = entry.to_dict()
        entry2 = CostEntry.from_dict(d)
        assert entry2.events == entry.events
        assert entry2.tokens_used == entry.tokens_used

    def test_append_cost_log(self, tmp_path: Path) -> None:
        costs_file = tmp_path / "costs.jsonl"
        entry = CostEntry(
            timestamp=datetime(2026, 3, 6, 18, 0, 0, tzinfo=timezone.utc),
            events=100,
            findings=5,
            actors_invoked=True,
            tokens_used=10000,
            estimated_cost_usd=0.002,
            budget_remaining_pct=80.0,
        )
        append_cost_log(costs_file, entry)
        assert costs_file.exists()

        lines = costs_file.read_text().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["events"] == 100
        assert data["tokens_used"] == 10000

    def test_append_multiple_entries(self, tmp_path: Path) -> None:
        costs_file = tmp_path / "costs.jsonl"
        for i in range(3):
            entry = CostEntry(
                timestamp=datetime(2026, 3, 6, 18, i, 0, tzinfo=timezone.utc),
                events=100 + i,
                findings=i,
                actors_invoked=True,
                tokens_used=1000 * (i + 1),
                estimated_cost_usd=0.001 * (i + 1),
                budget_remaining_pct=90.0 - i * 10,
            )
            append_cost_log(costs_file, entry)

        lines = costs_file.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_circuit_breaker_not_invoked(self) -> None:
        entry = CostEntry(
            timestamp=datetime(2026, 3, 6, 18, 0, 0, tzinfo=timezone.utc),
            events=100,
            findings=5,
            actors_invoked=False,
            tokens_used=0,
            estimated_cost_usd=0.0,
            budget_remaining_pct=100.0,
        )
        assert entry.actors_invoked is False
        assert entry.tokens_used == 0
