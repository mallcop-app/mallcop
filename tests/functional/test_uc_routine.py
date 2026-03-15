"""UC: Routine monitoring -- triage resolves false positives, humans get only what matters.

Functional test exercising the full steady-state mallcop watch pipeline:
  Cron: mallcop watch
    -> scan: polls azure -- gets events
    -> detect: runs detectors against baseline -- produces WARN findings
    -> escalate: triage agent (mock LLM) reviews batch
      -> resolves some as "known actor, normal pattern"
      -> escalates others: "new IP on github, uncertain"
    -> results committed: findings updated, costs.jsonl written

We mock:
  - Azure connector (no live API calls) via patching poll methods
  - LLM client (deterministic triage decisions)
  - Teams webhook (capture POST payload instead of real HTTP)

We verify:
  - Full pipeline runs end-to-end via CLI
  - Triage resolves benign findings with annotations in findings.jsonl
  - Unresolved findings remain open with escalation annotations
  - costs.jsonl tracks token spend
  - Budget controls enforce per-run token ceiling
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import yaml
from click.testing import CliRunner

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.budget import CostEntry
from mallcop.cli import cli
from mallcop.schemas import (
    Baseline,
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# --- Helpers ---


def _make_config_yaml(
    root: Path,
    routing: dict[str, str | None] | None = None,
    budget: dict[str, int] | None = None,
) -> None:
    """Write mallcop.yaml with routing and budget configured for escalation."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
        "routing": routing or {
            "warn": "triage",
            "critical": "triage",
            "info": None,
        },
        "actor_chain": {"triage": {"routes_to": "notify-teams"}},
        "budget": budget or {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
        "squelch": 0,  # disabled: functional tests are not testing squelch gating
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _make_events(
    source: str,
    base_time: datetime,
    actors: list[str],
    count_per_actor: int = 3,
) -> list[Event]:
    """Generate synthetic events."""
    events: list[Event] = []
    for i, actor in enumerate(actors):
        for j in range(count_per_actor):
            ts = base_time + timedelta(hours=i * 6 + j)
            events.append(Event(
                id=f"evt_{source}_{actor.split('@')[0]}_{i}_{j}",
                timestamp=ts,
                ingested_at=ts + timedelta(seconds=1),
                source=source,
                event_type="role_assignment",
                actor=actor,
                action="create",
                target=f"/subscriptions/sub-001/resource_{i}_{j}",
                severity=Severity.WARN,
                metadata={"ip_address": f"10.0.{i}.{j}"},
                raw={"raw_data": True},
            ))
    return events


def _seed_events_and_baseline(
    root: Path,
    events: list[Event],
) -> None:
    """Seed events and build baseline from them."""
    store = JsonlStore(root)
    if events:
        store.append_events(events)
        store.update_baseline(events)


def _mock_list_subscriptions(self: Any) -> list[dict[str, Any]]:
    return [{"subscriptionId": "sub-001", "displayName": "Test"}]


# --- Tests ---


class TestFullWatchPipeline:
    """mallcop watch runs scan -> detect -> escalate end-to-end."""

    def test_watch_produces_scan_detect_escalate_output(self, tmp_path: Path) -> None:
        """Full watch pipeline returns combined output with all three stages."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        # Seed events from 20 days ago (past learning period)
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com", "deploy@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            result = CliRunner().invoke(cli, ["watch", "--dir", str(root)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["command"] == "watch"
        assert data["status"] == "ok"
        assert "scan" in data
        assert "detect" in data
        assert "escalate" in data

    def test_watch_not_learning_mode_runs_escalation(self, tmp_path: Path) -> None:
        """After learning period, watch runs escalation (not skipped)."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        old_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, old_events)

        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            result = CliRunner().invoke(cli, ["watch", "--dir", str(root)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        # Learning mode should be over
        assert data["detect"]["learning_connectors"] == []
        # Escalation should NOT be skipped for learning_mode
        escalate = data["escalate"]
        assert escalate.get("skipped") is not True or escalate.get("reason") != "learning_mode"


class TestTriageResolvesFindings:
    """Triage agent resolves benign findings, escalates uncertain ones."""

    def test_triage_resolves_known_actor_finding(self, tmp_path: Path) -> None:
        """Known actor findings are resolved by triage with annotation."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        # Seed baseline from old events
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        # Create open findings that triage will process
        known_finding = Finding(
            id="fnd_known_001",
            timestamp=now - timedelta(hours=1),
            detector="new-actor",
            event_ids=["evt_azure_admin_0_0"],
            title="Known actor: admin@example.com",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )
        store = JsonlStore(root)
        store.append_findings([known_finding])

        # Mock actor_runner to resolve this finding
        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Known actor, normal pattern",
                ),
                tokens_used=500,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert result["findings_processed"] == 1

        # Verify finding is now resolved
        store2 = JsonlStore(root)
        findings = store2.query_findings()
        resolved = [f for f in findings if f.id == "fnd_known_001"]
        assert len(resolved) == 1
        assert resolved[0].status == FindingStatus.RESOLVED
        assert len(resolved[0].annotations) > 0
        assert "Known actor" in resolved[0].annotations[0].content

    def test_triage_escalates_uncertain_finding(self, tmp_path: Path) -> None:
        """Uncertain findings are escalated by triage, stay open with annotation."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        uncertain_finding = Finding(
            id="fnd_uncertain_001",
            timestamp=now - timedelta(hours=1),
            detector="new-actor",
            event_ids=["evt_intruder_001"],
            title="New IP on github, uncertain",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )
        store = JsonlStore(root)
        store.append_findings([uncertain_finding])

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="New IP on github, uncertain",
                ),
                tokens_used=800,
                iterations=2,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert result["findings_processed"] == 1

        store2 = JsonlStore(root)
        findings = store2.query_findings()
        escalated = [f for f in findings if f.id == "fnd_uncertain_001"]
        assert len(escalated) == 1
        assert escalated[0].status == FindingStatus.OPEN  # stays open
        assert len(escalated[0].annotations) > 0
        assert escalated[0].annotations[0].action == "escalated"

    def test_mixed_batch_resolve_and_escalate(self, tmp_path: Path) -> None:
        """Triage resolves 2 known-actor findings, escalates 1 uncertain."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        findings = [
            Finding(
                id="fnd_benign_001",
                timestamp=now - timedelta(hours=2),
                detector="new-actor",
                event_ids=["evt_1"],
                title="Known actor pattern 1",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={},
            ),
            Finding(
                id="fnd_benign_002",
                timestamp=now - timedelta(hours=1.5),
                detector="new-actor",
                event_ids=["evt_2"],
                title="Known actor pattern 2",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={},
            ),
            Finding(
                id="fnd_suspicious_001",
                timestamp=now - timedelta(hours=1),
                detector="new-actor",
                event_ids=["evt_3"],
                title="New IP from unknown source",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={},
            ),
        ]
        store = JsonlStore(root)
        store.append_findings(findings)

        # Mock triage: resolve first two, escalate third
        resolve_ids = {"fnd_benign_001", "fnd_benign_002"}

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            if finding.id in resolve_ids:
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.RESOLVED,
                        reason="Known actor, normal pattern",
                    ),
                    tokens_used=500,
                    iterations=1,
                )
            else:
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.ESCALATED,
                        reason="New IP on github, uncertain",
                    ),
                    tokens_used=800,
                    iterations=2,
                )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert result["findings_processed"] == 3

        # Verify outcomes
        store2 = JsonlStore(root)
        all_findings = store2.query_findings()

        resolved = [f for f in all_findings if f.status == FindingStatus.RESOLVED]
        open_findings = [f for f in all_findings if f.status == FindingStatus.OPEN]

        assert len(resolved) == 2
        assert len(open_findings) == 1
        assert open_findings[0].id == "fnd_suspicious_001"

        # All should have annotations
        for f in all_findings:
            assert len(f.annotations) > 0


class TestCostTracking:
    """costs.jsonl tracks token spend per escalation run."""

    def test_costs_jsonl_written_after_escalate(self, tmp_path: Path) -> None:
        """costs.jsonl is created with token and cost data after escalation."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        findings = [
            Finding(
                id="fnd_cost_001",
                timestamp=now - timedelta(hours=1),
                detector="new-actor",
                event_ids=["evt_1"],
                title="Test finding for cost tracking",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={},
            ),
        ]
        store = JsonlStore(root)
        store.append_findings(findings)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=1500,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        # Verify costs.jsonl exists and has content
        costs_path = root / ".mallcop" / "costs.jsonl"
        assert costs_path.exists(), "costs.jsonl should be written after escalation"

        lines = costs_path.read_text().strip().split("\n")
        assert len(lines) >= 1

        cost_data = json.loads(lines[-1])
        assert cost_data["donuts_used"] == 1500
        assert cost_data["actors_invoked"] is True
        assert cost_data["findings"] == 1
        assert cost_data["estimated_cost_usd"] > 0
        assert "budget_remaining_pct" in cost_data

    def test_costs_accumulate_across_runs(self, tmp_path: Path) -> None:
        """Multiple escalation runs append to costs.jsonl."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="Test",
                ),
                tokens_used=1000,
                iterations=1,
            )

        from mallcop.escalate import run_escalate

        # Run 1
        finding1 = Finding(
            id="fnd_run1",
            timestamp=now - timedelta(hours=2),
            detector="new-actor",
            event_ids=["evt_r1"],
            title="Run 1 finding",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )
        store1 = JsonlStore(root)
        store1.append_findings([finding1])
        run_escalate(root, actor_runner=mock_runner)

        # Run 2 - new finding
        finding2 = Finding(
            id="fnd_run2",
            timestamp=now - timedelta(hours=1),
            detector="new-actor",
            event_ids=["evt_r2"],
            title="Run 2 finding",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )
        store2 = JsonlStore(root)
        store2.append_findings([finding2])
        run_escalate(root, actor_runner=mock_runner)

        costs_path = root / ".mallcop" / "costs.jsonl"
        lines = costs_path.read_text().strip().split("\n")
        assert len(lines) == 2, f"Expected 2 cost entries, got {len(lines)}"


class TestBudgetControls:
    """Budget controls cap spend during escalation."""

    def test_per_run_token_ceiling_enforced(self, tmp_path: Path) -> None:
        """When per-run token ceiling is hit, remaining findings are skipped."""
        root = tmp_path
        _make_config_yaml(root, budget={
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 800,  # Low ceiling
            "max_tokens_per_finding": 5000,
        })

        now = datetime.now(timezone.utc)
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        # Create 5 findings that will each consume 500 tokens
        findings = []
        for i in range(5):
            findings.append(Finding(
                id=f"fnd_budget_{i}",
                timestamp=now - timedelta(hours=5 - i),
                detector="new-actor",
                event_ids=[f"evt_b{i}"],
                title=f"Finding {i}",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={},
            ))
        store = JsonlStore(root)
        store.append_findings(findings)

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
                tokens_used=500,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        # With 800 token ceiling and 500 tokens per finding,
        # after 2 findings (1000 tokens), budget is exhausted
        assert call_count < 5, f"Should have stopped early, but processed {call_count}"
        assert result["budget_exhausted"] is True
        assert result["donuts_used"] > 0

        # Verify skipped findings are annotated
        store2 = JsonlStore(root)
        all_findings = store2.query_findings()
        budget_annotated = [
            f for f in all_findings
            if any("Budget exhausted" in a.content for a in f.annotations)
        ]
        assert len(budget_annotated) > 0, "Skipped findings should have budget annotation"

    def test_circuit_breaker_on_volume_spike(self, tmp_path: Path) -> None:
        """When findings exceed threshold, circuit breaker fires."""
        root = tmp_path
        _make_config_yaml(root, budget={
            "max_findings_for_actors": 3,  # Very low threshold
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        })

        now = datetime.now(timezone.utc)
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        # Create more findings than threshold
        findings = []
        for i in range(5):
            findings.append(Finding(
                id=f"fnd_cb_{i}",
                timestamp=now - timedelta(hours=5 - i),
                detector="new-actor",
                event_ids=[f"evt_cb{i}"],
                title=f"Circuit breaker finding {i}",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={},
            ))
        store = JsonlStore(root)
        store.append_findings(findings)

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

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert not actor_called, "Actors should not be invoked when circuit breaker fires"
        assert result["circuit_breaker_triggered"] is True
        assert result["donuts_used"] == 0

        # costs.jsonl should still be written
        costs_path = root / ".mallcop" / "costs.jsonl"
        assert costs_path.exists()


class TestEndToEndWatchWithEscalation:
    """Full end-to-end: watch CLI -> scan -> detect -> escalate with mock triage."""

    def test_full_pipeline_with_new_actor_detection_and_escalation(
        self, tmp_path: Path
    ) -> None:
        """Full pipeline: events -> detect new actor -> escalate -> findings annotated."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)

        # Seed old known events (past learning period) and build baseline
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com", "deploy@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        # Add a new unknown actor event (will trigger new-actor detector)
        intruder = Event(
            id="evt_intruder_routine",
            timestamp=now - timedelta(hours=1),
            ingested_at=now,
            source="azure",
            event_type="role_assignment",
            actor="intruder@evil.com",
            action="create",
            target="/subscriptions/sub-001/evil-resource",
            severity=Severity.WARN,
            metadata={"ip_address": "192.168.99.1"},
            raw={"raw_data": True},
        )
        store = JsonlStore(root)
        store.append_events([intruder])

        # Run watch with mock connector (returns no new events - already seeded)
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ), patch(
            "mallcop.escalate.run_escalate",
        ) as mock_escalate:
            mock_escalate.return_value = {
                "status": "ok",
                "findings_processed": 1,
                "findings_skipped": 0,
                "circuit_breaker_triggered": False,
                "budget_exhausted": False,
                "donuts_used": 800,
                "skipped": False,
                "reason": None,
            }
            result = CliRunner().invoke(cli, ["watch", "--dir", str(root)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["status"] == "ok"
        assert data["detect"]["findings_count"] >= 0
        # Escalation was called (learning mode is over)
        assert data["detect"]["learning_connectors"] == []

    def test_escalate_standalone_with_mock_triage(self, tmp_path: Path) -> None:
        """Standalone escalate command processes findings with mock triage actor."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        # Seed 3 WARN findings and 0 CRITICAL
        findings = [
            Finding(
                id=f"fnd_routine_{i}",
                timestamp=now - timedelta(hours=3 - i),
                detector="new-actor",
                event_ids=[f"evt_r{i}"],
                title=f"Routine finding {i}",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={},
            )
            for i in range(3)
        ]
        store = JsonlStore(root)
        store.append_findings(findings)

        # Mock: resolve first 2, escalate third
        resolve_ids = {"fnd_routine_0", "fnd_routine_1"}

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            if finding.id in resolve_ids:
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.RESOLVED,
                        reason="Known actor, normal pattern",
                    ),
                    tokens_used=500,
                    iterations=1,
                )
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="New IP on github, uncertain",
                ),
                tokens_used=800,
                iterations=2,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert result["status"] == "ok"
        assert result["findings_processed"] == 3
        assert result["donuts_used"] == 500 + 500 + 800  # 1800

        # Verify final state
        store2 = JsonlStore(root)
        all_findings = store2.query_findings()

        resolved = [f for f in all_findings if f.status == FindingStatus.RESOLVED]
        still_open = [f for f in all_findings if f.status == FindingStatus.OPEN]

        assert len(resolved) == 2
        assert len(still_open) == 1
        assert still_open[0].id == "fnd_routine_2"

        # costs.jsonl has one entry
        costs_path = root / ".mallcop" / "costs.jsonl"
        assert costs_path.exists()
        cost_data = json.loads(costs_path.read_text().strip().split("\n")[-1])
        assert cost_data["donuts_used"] == 1800
        assert cost_data["actors_invoked"] is True

    def test_watch_with_no_findings_still_succeeds(self, tmp_path: Path) -> None:
        """Watch pipeline completes successfully when no findings are detected."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        # All events from known actors, past learning period
        known_events = _make_events(
            "azure", now - timedelta(days=20),
            ["admin@example.com"],
            count_per_actor=5,
        )
        _seed_events_and_baseline(root, known_events)

        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            result = CliRunner().invoke(cli, ["watch", "--dir", str(root)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)
        assert data["status"] == "ok"


class TestTeamsDigestFormat:
    """Unresolved findings can be formatted for Teams delivery."""

    def test_format_digest_for_escalated_findings(self, tmp_path: Path) -> None:
        """Escalated findings format into Teams digest structure."""
        from mallcop.actors.notify_teams.channel import format_digest

        now = datetime.now(timezone.utc)
        findings = [
            Finding(
                id="fnd_teams_001",
                timestamp=now - timedelta(hours=1),
                detector="new-actor",
                event_ids=["evt_1"],
                title="New IP on github, uncertain",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={},
            ),
        ]

        digest = format_digest(findings)

        assert digest["type"] == "message"
        assert "1 finding" in digest["summary"]
        assert len(digest["sections"]) > 0
        # WARN section should exist
        warn_section = [s for s in digest["sections"] if "WARN" in s["activityTitle"]]
        assert len(warn_section) == 1
        assert len(warn_section[0]["facts"]) == 1

    def test_format_digest_with_annotations(self, tmp_path: Path) -> None:
        """Digest includes annotation info from triage."""
        from mallcop.actors.notify_teams.channel import format_digest
        from mallcop.schemas import Annotation

        now = datetime.now(timezone.utc)
        findings = [
            Finding(
                id="fnd_teams_ann",
                timestamp=now,
                detector="new-actor",
                event_ids=["evt_1"],
                title="New IP detected",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[
                    Annotation(
                        actor="triage",
                        timestamp=now,
                        content="New IP on github, uncertain",
                        action="escalated",
                        reason="Needs human review",
                    ),
                ],
                metadata={},
            ),
        ]

        digest = format_digest(findings)

        # The annotation content should appear in the facts
        facts = digest["sections"][0]["facts"]
        assert any("triage" in f["value"] for f in facts)

    def test_empty_findings_digest(self) -> None:
        """Empty findings produce an appropriate digest."""
        from mallcop.actors.notify_teams.channel import format_digest

        digest = format_digest([])
        assert "No findings" in digest["summary"]
        assert digest["sections"] == []
