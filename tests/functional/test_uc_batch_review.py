"""UC: Batch review — escalate processes findings in batches through triage actor.

Functional test proving the batch model works end-to-end:

- Multiple findings with mixed severities → escalate → batch processing → resolutions
- Mock LLM client returns controlled responses per finding
- Verifies: all findings processed, correct token aggregation, budget limits respected

We mock:
  - Actor runner (no LLM calls) — deterministic resolve/escalate per severity

We verify:
  - Batch with known+unknown findings → correct resolve/escalate split
  - Batch budget tracking → costs.jsonl shows batch-level token usage
  - Batch with 0 findings → no actor invocation
  - Batch with 1 finding → works (degenerate case)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.schemas import (
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# --- Helpers ---


def _make_config_yaml(root: Path, budget_overrides: dict[str, Any] | None = None) -> None:
    """Write mallcop.yaml configured for batch review scenario."""
    budget = {
        "max_findings_for_actors": 25,
        "max_tokens_per_run": 50000,
        "max_tokens_per_finding": 5000,
    }
    if budget_overrides:
        budget.update(budget_overrides)

    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
        "routing": {
            "critical": "triage",
            "warn": "triage",
            "info": None,
        },
        "actor_chain": {"triage": {"routes_to": "notify-teams"}},
        "budget": budget,
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _make_findings(count: int, severity: Severity = Severity.WARN) -> list[Finding]:
    """Create N findings with given severity."""
    now = datetime.now(timezone.utc)
    findings = []
    for i in range(count):
        findings.append(Finding(
            id=f"fnd_batch_{severity.value}_{i:03d}",
            timestamp=now - timedelta(minutes=30 - i),
            detector="new-actor",
            event_ids=[f"evt_batch_{i:03d}"],
            title=f"Batch finding {i} ({severity.value})",
            severity=severity,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": f"actor_{i}@example.com"},
        ))
    return findings


def _make_mixed_findings() -> list[Finding]:
    """Create 5 findings: 2 CRITICAL (unknown actors), 2 WARN, 1 INFO (unroutable)."""
    now = datetime.now(timezone.utc)
    return [
        Finding(
            id="fnd_crit_001",
            timestamp=now - timedelta(minutes=30),
            detector="new-actor",
            event_ids=["evt_crit_001"],
            title="New actor: attacker@evil.com on azure",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "attacker@evil.com"},
        ),
        Finding(
            id="fnd_crit_002",
            timestamp=now - timedelta(minutes=28),
            detector="new-actor",
            event_ids=["evt_crit_002"],
            title="New actor: intruder@bad.com on azure",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "intruder@bad.com"},
        ),
        Finding(
            id="fnd_warn_001",
            timestamp=now - timedelta(minutes=25),
            detector="volume-anomaly",
            event_ids=["evt_warn_001"],
            title="Volume anomaly: deploy@example.com",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "deploy@example.com"},
        ),
        Finding(
            id="fnd_warn_002",
            timestamp=now - timedelta(minutes=20),
            detector="unusual-timing",
            event_ids=["evt_warn_002"],
            title="Unusual timing: admin@example.com",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "admin@example.com"},
        ),
        Finding(
            id="fnd_info_001",
            timestamp=now - timedelta(minutes=15),
            detector="new-actor",
            event_ids=["evt_info_001"],
            title="Info: routine sign-in",
            severity=Severity.INFO,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "service@example.com"},
        ),
    ]


# --- Tests ---


class TestBatchReviewMixed:
    """Batch with known+unknown findings produces correct resolve/escalate split."""

    def test_mixed_batch_correct_triage(self, tmp_path: Path) -> None:
        """5 mixed findings: CRITICAL escalated, WARN resolved, INFO skipped (no route)."""
        root = tmp_path
        _make_config_yaml(root)
        store = JsonlStore(root)

        findings = _make_mixed_findings()
        store.append_findings(findings)

        # Mock runner: escalate CRITICALs, resolve WARNs
        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            if finding.severity == Severity.CRITICAL:
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.ESCALATED,
                        reason=f"Unknown actor, escalating: {finding.title}",
                    ),
                    tokens_used=500,
                    iterations=2,
                )
            else:
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.RESOLVED,
                        reason=f"Known actor, benign: {finding.title}",
                    ),
                    tokens_used=300,
                    iterations=1,
                )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert result["status"] == "ok"
        # 4 routable findings (2 CRITICAL + 2 WARN), INFO has no route
        assert result["findings_processed"] == 4
        assert result["circuit_breaker_triggered"] is False

        # Verify finding states in store (fresh instance to read updated JSONL)
        fresh_store = JsonlStore(root)
        all_findings = fresh_store.query_findings()
        by_id = {f.id: f for f in all_findings}

        # CRITICALs: escalated -> still OPEN with annotation
        assert by_id["fnd_crit_001"].status == FindingStatus.OPEN
        assert len(by_id["fnd_crit_001"].annotations) >= 1
        assert by_id["fnd_crit_001"].annotations[0].action == "escalated"

        assert by_id["fnd_crit_002"].status == FindingStatus.OPEN
        assert by_id["fnd_crit_002"].annotations[0].action == "escalated"

        # WARNs: resolved
        assert by_id["fnd_warn_001"].status == FindingStatus.RESOLVED
        assert by_id["fnd_warn_001"].annotations[0].action == "resolved"

        assert by_id["fnd_warn_002"].status == FindingStatus.RESOLVED
        assert by_id["fnd_warn_002"].annotations[0].action == "resolved"

        # INFO: unroutable, no annotations added
        assert by_id["fnd_info_001"].status == FindingStatus.OPEN
        assert len(by_id["fnd_info_001"].annotations) == 0


class TestBatchBudgetTracking:
    """costs.jsonl shows batch-level token usage after escalation."""

    def test_batch_budget_tracking_costs_jsonl(self, tmp_path: Path) -> None:
        """Token usage from all findings aggregated in costs.jsonl."""
        root = tmp_path
        _make_config_yaml(root)
        store = JsonlStore(root)

        findings = _make_mixed_findings()
        store.append_findings(findings)

        call_count = 0

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            nonlocal call_count
            call_count += 1
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Escalating",
                ),
                tokens_used=750,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        # 4 routable findings x 750 tokens = 3000 total
        assert result["tokens_used"] == 3000
        assert call_count == 4  # INFO not routed

        costs_path = root / ".mallcop" / "costs.jsonl"
        assert costs_path.exists()
        cost_data = json.loads(costs_path.read_text().strip().split("\n")[-1])
        assert cost_data["tokens_used"] == 3000
        assert cost_data["actors_invoked"] is True
        assert cost_data["findings"] == 4  # 4 routable findings processed


class TestBatchZeroFindings:
    """Batch with 0 findings triggers no actor invocation."""

    def test_zero_findings_no_invocation(self, tmp_path: Path) -> None:
        """No open findings -> no actors invoked, costs show zero tokens."""
        root = tmp_path
        _make_config_yaml(root)

        runner_called = False

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            nonlocal runner_called
            runner_called = True
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Should not be called",
                ),
                tokens_used=100,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert result["status"] == "ok"
        assert result["findings_processed"] == 0
        assert result["tokens_used"] == 0
        assert runner_called is False

        # costs.jsonl written but with zero tokens
        costs_path = root / ".mallcop" / "costs.jsonl"
        assert costs_path.exists()
        cost_data = json.loads(costs_path.read_text().strip().split("\n")[-1])
        assert cost_data["tokens_used"] == 0
        assert cost_data["actors_invoked"] is False


class TestBatchSingleFinding:
    """Batch with 1 finding works correctly (degenerate case)."""

    def test_single_finding_batch(self, tmp_path: Path) -> None:
        """Single CRITICAL finding -> processed, annotated, costs tracked."""
        root = tmp_path
        _make_config_yaml(root)
        store = JsonlStore(root)

        findings = _make_findings(1, severity=Severity.CRITICAL)
        store.append_findings(findings)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Single finding escalated",
                ),
                tokens_used=1200,
                iterations=3,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert result["status"] == "ok"
        assert result["findings_processed"] == 1
        assert result["tokens_used"] == 1200

        # Verify annotation applied (fresh store to read updated JSONL)
        fresh_store = JsonlStore(root)
        all_findings = fresh_store.query_findings()
        assert len(all_findings) == 1
        assert len(all_findings[0].annotations) == 1
        assert all_findings[0].annotations[0].action == "escalated"
        assert all_findings[0].annotations[0].content == "Single finding escalated"

        # Costs tracked
        costs_path = root / ".mallcop" / "costs.jsonl"
        cost_data = json.loads(costs_path.read_text().strip().split("\n")[-1])
        assert cost_data["tokens_used"] == 1200
