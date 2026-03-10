"""Tests for mallcop escalate command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from mallcop.schemas import Finding, Severity, FindingStatus, Annotation
from mallcop.actors._schema import ActorManifest, ActorResolution, ResolutionAction
from mallcop.actors.runtime import LLMClient, LLMResponse, ToolCall, RunResult
from mallcop.budget import BudgetConfig, CostEntry
from mallcop.store import JsonlStore


# ─── Helpers ────────────────────────────────────────────────────────


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


def _write_config(
    root: Path,
    routing: dict[str, str | None] | None = None,
    budget: dict[str, int] | None = None,
) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": routing or {"warn": "triage", "critical": "triage", "info": None},
        "actor_chain": {"triage": {"routes_to": None}},
        "budget": budget or {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


def _seed_findings(root: Path, findings: list[Finding]) -> None:
    store = JsonlStore(root)
    store.append_findings(findings)


# ─── Escalate: routing by severity ───────────────────────────────


class TestEscalateRouting:
    def test_loads_open_findings(self, tmp_path: Path) -> None:
        """escalate loads open findings from findings.jsonl."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        findings = [
            _make_finding(id="fnd_1", severity=Severity.WARN),
            _make_finding(id="fnd_2", severity=Severity.CRITICAL),
        ]
        _seed_findings(tmp_path, findings)

        result = run_escalate(tmp_path, actor_runner=lambda *a, **kw: RunResult(
            resolution=ActorResolution(
                finding_id=a[0].id,
                action=ResolutionAction.RESOLVED,
                reason="Test",
            ),
            tokens_used=100,
            iterations=1,
        ))

        assert result["findings_processed"] == 2

    def test_routes_by_severity(self, tmp_path: Path) -> None:
        """escalate routes findings to actors based on severity routing config."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path, routing={
            "warn": "triage",
            "critical": "triage",
            "info": None,
        })
        findings = [
            _make_finding(id="fnd_info", severity=Severity.INFO),
            _make_finding(id="fnd_warn", severity=Severity.WARN),
        ]
        _seed_findings(tmp_path, findings)

        routed_ids: list[str] = []

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            routed_ids.append(finding.id)
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

        # INFO has null routing → should not be routed
        assert "fnd_info" not in routed_ids
        # WARN has triage routing → should be routed
        assert "fnd_warn" in routed_ids

    def test_processes_severity_order_critical_first(self, tmp_path: Path) -> None:
        """escalate processes CRITICAL findings before WARN."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        findings = [
            _make_finding(id="fnd_w1", severity=Severity.WARN),
            _make_finding(id="fnd_c1", severity=Severity.CRITICAL),
            _make_finding(id="fnd_w2", severity=Severity.WARN),
        ]
        _seed_findings(tmp_path, findings)

        order: list[str] = []

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            order.append(finding.id)
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

        # CRITICAL should come first
        assert order[0] == "fnd_c1"

    def test_skips_resolved_findings(self, tmp_path: Path) -> None:
        """escalate only processes open findings."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        findings = [
            _make_finding(id="fnd_open", status=FindingStatus.OPEN),
            _make_finding(id="fnd_resolved", status=FindingStatus.RESOLVED),
        ]
        _seed_findings(tmp_path, findings)

        processed: list[str] = []

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            processed.append(finding.id)
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

        assert "fnd_open" in processed
        assert "fnd_resolved" not in processed


# ─── Escalate: circuit breaker ───────────────────────────────────


class TestEscalateCircuitBreaker:
    def test_circuit_breaker_skips_actors(self, tmp_path: Path) -> None:
        """When findings exceed threshold, circuit breaker fires and actors are not invoked."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path, budget={
            "max_findings_for_actors": 3,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        })
        findings = [_make_finding(id=f"fnd_{i}") for i in range(5)]
        _seed_findings(tmp_path, findings)

        actor_called = False

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            nonlocal actor_called
            actor_called = True
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=100,
                iterations=1,
            )

        result = run_escalate(tmp_path, actor_runner=mock_runner)

        assert not actor_called
        assert result["circuit_breaker_triggered"] is True


# ─── Escalate: per-run token ceiling ────────────────────────────


class TestEscalateTokenBudget:
    def test_enforces_per_run_ceiling(self, tmp_path: Path) -> None:
        """When per-run token ceiling is reached, remaining findings are skipped."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path, budget={
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 250,
            "max_tokens_per_finding": 5000,
        })
        findings = [_make_finding(id=f"fnd_{i}") for i in range(5)]
        _seed_findings(tmp_path, findings)

        call_count = 0

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            nonlocal call_count
            call_count += 1
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=100,
                iterations=1,
            )

        result = run_escalate(tmp_path, actor_runner=mock_runner)

        # Should stop after budget is exceeded (100 * 3 > 250)
        assert call_count < 5
        assert result["budget_exhausted"] is True

    def test_writes_cost_records(self, tmp_path: Path) -> None:
        """escalate appends cost entry to costs.jsonl."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        findings = [_make_finding(id="fnd_1")]
        _seed_findings(tmp_path, findings)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=500,
                iterations=1,
            )

        run_escalate(tmp_path, actor_runner=mock_runner)

        costs_file = tmp_path / "costs.jsonl"
        assert costs_file.exists()
        lines = costs_file.read_text().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["tokens_used"] == 500
        assert data["actors_invoked"] is True

    def test_writes_resolution_back_to_findings(self, tmp_path: Path) -> None:
        """escalate updates finding status after actor resolves."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        findings = [_make_finding(id="fnd_1")]
        _seed_findings(tmp_path, findings)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Known actor",
                ),
                tokens_used=500,
                iterations=1,
            )

        run_escalate(tmp_path, actor_runner=mock_runner)

        # Re-read store to verify finding was updated
        store = JsonlStore(tmp_path)
        updated = store.query_findings()
        resolved = [f for f in updated if f.id == "fnd_1"]
        assert len(resolved) == 1
        assert resolved[0].status == FindingStatus.RESOLVED

    def test_escalated_findings_stay_open(self, tmp_path: Path) -> None:
        """When actor escalates a finding, it stays open with annotation."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        findings = [_make_finding(id="fnd_1")]
        _seed_findings(tmp_path, findings)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Uncertain, needs human review",
                ),
                tokens_used=500,
                iterations=1,
            )

        run_escalate(tmp_path, actor_runner=mock_runner)

        store = JsonlStore(tmp_path)
        updated = store.query_findings()
        f = [f for f in updated if f.id == "fnd_1"][0]
        assert f.status == FindingStatus.OPEN
        assert len(f.annotations) > 0


# ─── Batch escalation ─────────────────────────────────────────


class TestEscalateBatch:
    def test_batch_result_aggregates_tokens(self, tmp_path: Path) -> None:
        """run_batch returns BatchResult with total_tokens summed across all findings."""
        from mallcop.actors.runtime import BatchResult, run_batch

        call_count = 0

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            nonlocal call_count
            call_count += 1
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=100,
                iterations=1,
            )

        findings = [_make_finding(id=f"fnd_{i}") for i in range(3)]
        batch_result = run_batch(mock_runner, findings, actor_name="triage")

        assert isinstance(batch_result, BatchResult)
        assert batch_result.total_tokens == 300
        assert len(batch_result.results) == 3
        assert call_count == 3

    def test_batch_respects_token_budget(self, tmp_path: Path) -> None:
        """run_batch stops processing when token budget is exhausted."""
        from mallcop.actors.runtime import BatchResult, run_batch

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=200,
                iterations=1,
            )

        findings = [_make_finding(id=f"fnd_{i}") for i in range(5)]
        batch_result = run_batch(
            mock_runner, findings, actor_name="triage", max_tokens=500,
        )

        # Budget is 500. After 2 findings: 400 (< 500, continue).
        # After 3 findings: 600 (>= 500, stop). So 3 processed, not all 5.
        assert len(batch_result.results) == 3
        assert len(batch_result.results) < 5  # didn't process all

    def test_escalate_uses_batch_processing(self, tmp_path: Path) -> None:
        """run_escalate groups findings and processes them via batch."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path)
        findings = [
            _make_finding(id="fnd_1", severity=Severity.WARN),
            _make_finding(id="fnd_2", severity=Severity.CRITICAL),
            _make_finding(id="fnd_3", severity=Severity.WARN),
        ]
        _seed_findings(tmp_path, findings)

        processed_ids: list[str] = []

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            processed_ids.append(finding.id)
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=100,
                iterations=1,
            )

        result = run_escalate(tmp_path, actor_runner=mock_runner)

        # All 3 findings should be processed
        assert result["findings_processed"] == 3
        assert len(processed_ids) == 3
        # Total tokens should reflect batch sum
        assert result["tokens_used"] == 300

    def test_escalate_batch_budget_limits_findings(self, tmp_path: Path) -> None:
        """run_escalate enforces per-run token budget across the batch."""
        from mallcop.escalate import run_escalate

        _write_config(tmp_path, budget={
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 250,
            "max_tokens_per_finding": 5000,
        })
        findings = [_make_finding(id=f"fnd_{i}") for i in range(5)]
        _seed_findings(tmp_path, findings)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=100,
                iterations=1,
            )

        result = run_escalate(tmp_path, actor_runner=mock_runner)

        assert result["budget_exhausted"] is True
        assert result["findings_processed"] < 5
