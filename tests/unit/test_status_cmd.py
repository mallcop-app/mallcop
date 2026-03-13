"""Tests for mallcop status command."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from mallcop.schemas import Event, Finding, Severity, FindingStatus
from mallcop.budget import CostEntry, append_cost_log
from mallcop.store import JsonlStore


# ─── Helpers ────────────────────────────────────────────────────────


def _write_config(root: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {}},
        "routing": {},
        "actor_chain": {},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


def _make_event(id: str = "evt_001", source: str = "azure") -> Event:
    return Event(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2026, 3, 6, 12, 0, 1, tzinfo=timezone.utc),
        source=source,
        event_type="role_assignment",
        actor="admin@example.com",
        action="create",
        target="/subscriptions/123",
        severity=Severity.WARN,
        metadata={},
        raw={},
    )


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


# ─── Status: summary output ─────────────────────────────────────


class TestStatusSummary:
    def test_outputs_event_counts_by_source(self, tmp_path: Path) -> None:
        """status shows event counts grouped by source."""
        from mallcop.status import run_status

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        store.append_events([
            _make_event(id="evt_1", source="azure"),
            _make_event(id="evt_2", source="azure"),
            _make_event(id="evt_3", source="github"),
        ])

        result = run_status(tmp_path, costs=False)

        assert result["events_by_source"]["azure"] == 2
        assert result["events_by_source"]["github"] == 1

    def test_outputs_finding_counts_by_status(self, tmp_path: Path) -> None:
        """status shows finding counts grouped by status."""
        from mallcop.status import run_status

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        store.append_findings([
            _make_finding(id="fnd_1", status=FindingStatus.OPEN),
            _make_finding(id="fnd_2", status=FindingStatus.OPEN),
            _make_finding(id="fnd_3", status=FindingStatus.RESOLVED),
        ])

        result = run_status(tmp_path, costs=False)

        assert result["findings_by_status"]["open"] == 2
        assert result["findings_by_status"]["resolved"] == 1

    def test_outputs_finding_counts_by_severity(self, tmp_path: Path) -> None:
        """status shows finding counts grouped by severity."""
        from mallcop.status import run_status

        _write_config(tmp_path)
        store = JsonlStore(tmp_path)
        store.append_findings([
            _make_finding(id="fnd_1", severity=Severity.CRITICAL),
            _make_finding(id="fnd_2", severity=Severity.WARN),
            _make_finding(id="fnd_3", severity=Severity.WARN),
        ])

        result = run_status(tmp_path, costs=False)

        assert result["findings_by_severity"]["critical"] == 1
        assert result["findings_by_severity"]["warn"] == 2

    def test_empty_deployment_shows_zeroes(self, tmp_path: Path) -> None:
        """status on empty deployment shows zero counts."""
        from mallcop.status import run_status

        _write_config(tmp_path)

        result = run_status(tmp_path, costs=False)

        assert result["total_events"] == 0
        assert result["total_findings"] == 0

    def test_correct_summary_structure(self, tmp_path: Path) -> None:
        """status output has expected top-level keys."""
        from mallcop.status import run_status

        _write_config(tmp_path)

        result = run_status(tmp_path, costs=False)

        assert "status" in result
        assert "total_events" in result
        assert "total_findings" in result
        assert "events_by_source" in result
        assert "findings_by_status" in result
        assert "findings_by_severity" in result


# ─── Status: --costs ─────────────────────────────────────────────


class TestStatusCosts:
    def test_costs_includes_budget_info(self, tmp_path: Path) -> None:
        """status --costs includes budget utilization information."""
        from mallcop.status import run_status

        _write_config(tmp_path)
        (tmp_path / ".mallcop").mkdir(parents=True, exist_ok=True)
        costs_file = tmp_path / ".mallcop" / "costs.jsonl"
        for i in range(3):
            entry = CostEntry(
                timestamp=datetime(2026, 3, 6, 18, i, 0, tzinfo=timezone.utc),
                events=100 + i * 10,
                findings=3 + i,
                actors_invoked=True,
                tokens_used=10000 + i * 1000,
                estimated_cost_usd=0.002 + i * 0.001,
                budget_remaining_pct=80.0 - i * 5,
            )
            append_cost_log(costs_file, entry)

        result = run_status(tmp_path, costs=True)

        assert "costs" in result
        costs = result["costs"]
        assert "total_runs" in costs
        assert costs["total_runs"] == 3
        assert "avg_tokens_per_run" in costs
        assert "total_tokens" in costs
        assert "estimated_total_usd" in costs

    def test_costs_without_cost_file(self, tmp_path: Path) -> None:
        """status --costs with no costs.jsonl returns empty cost data."""
        from mallcop.status import run_status

        _write_config(tmp_path)

        result = run_status(tmp_path, costs=True)

        assert "costs" in result
        assert result["costs"]["total_runs"] == 0

    def test_costs_shows_circuit_breaker_count(self, tmp_path: Path) -> None:
        """status --costs shows how many times circuit breaker triggered."""
        from mallcop.status import run_status

        _write_config(tmp_path)
        (tmp_path / ".mallcop").mkdir(parents=True, exist_ok=True)
        costs_file = tmp_path / ".mallcop" / "costs.jsonl"
        # 2 runs with actors, 1 without (circuit breaker)
        entries = [
            CostEntry(
                timestamp=datetime(2026, 3, 6, 6, 0, 0, tzinfo=timezone.utc),
                events=50, findings=3, actors_invoked=True,
                tokens_used=5000, estimated_cost_usd=0.001,
                budget_remaining_pct=90.0,
            ),
            CostEntry(
                timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
                events=500, findings=100, actors_invoked=False,
                tokens_used=0, estimated_cost_usd=0.0,
                budget_remaining_pct=100.0,
            ),
            CostEntry(
                timestamp=datetime(2026, 3, 6, 18, 0, 0, tzinfo=timezone.utc),
                events=60, findings=4, actors_invoked=True,
                tokens_used=8000, estimated_cost_usd=0.002,
                budget_remaining_pct=84.0,
            ),
        ]
        for e in entries:
            append_cost_log(costs_file, e)

        result = run_status(tmp_path, costs=True)

        costs = result["costs"]
        assert costs["circuit_breaker_triggered"] == 1

    def test_no_costs_key_without_flag(self, tmp_path: Path) -> None:
        """status without --costs does not include cost data."""
        from mallcop.status import run_status

        _write_config(tmp_path)

        result = run_status(tmp_path, costs=False)

        assert "costs" not in result
