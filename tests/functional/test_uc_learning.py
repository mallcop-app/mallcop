"""UC: Learning period -- events accumulate, baseline builds, no false alerts.

Functional test exercising the 14-day learning mode suppression:
  Days 1-14: mallcop watch runs, events accumulate, detectors fire but
             findings are INFO (no actor invocation, no escalation).
  Day 15:    detection runs with full severity.
  Baseline:  frequency tables and known entities build from accumulated events.
  Per-connector: adding a new connector later gets its own 14-day window.

We simulate time progression by injecting events with synthetic timestamps
and patching datetime.now() in the baseline module.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml
from click.testing import CliRunner

from mallcop.baseline import LEARNING_PERIOD_DAYS
from mallcop.cli import cli
from mallcop.schemas import (
    Baseline,
    Checkpoint,
    Event,
    PollResult,
    Severity,
)
from mallcop.store import JsonlStore


# --- Helpers ---


def _make_config_yaml(root: Path, connectors: dict[str, Any] | None = None) -> None:
    """Write a minimal mallcop.yaml into root."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": connectors or {"azure": {"subscription_ids": ["sub-001"]}},
        "routing": {},
        "actor_chain": {},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _make_events(
    source: str,
    base_time: datetime,
    actors: list[str],
    count_per_actor: int = 3,
) -> list[Event]:
    """Generate synthetic events for a connector."""
    events: list[Event] = []
    for i, actor in enumerate(actors):
        for j in range(count_per_actor):
            ts = base_time + timedelta(hours=i * 6 + j)
            events.append(Event(
                id=f"evt_{source}_{actor.split('@')[0]}_{j}",
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


def _make_poll_result(events: list[Event], connector: str) -> PollResult:
    """Create a PollResult from events."""
    return PollResult(
        events=events,
        checkpoint=Checkpoint(
            connector=connector,
            value=events[-1].timestamp.isoformat() if events else "none",
            updated_at=datetime.now(timezone.utc),
        ),
    )


def _seed_events(root: Path, events: list[Event]) -> None:
    """Write events directly into the store (bypassing connectors)."""
    store = JsonlStore(root)
    if events:
        store.append_events(events)


# --- Mock connector poll ---

# These are set by each test to control what events the mock connector returns
_MOCK_POLL_EVENTS: list[Event] = []


def _mock_list_subscriptions(self: Any) -> list[dict[str, Any]]:
    return [{"subscriptionId": "sub-001", "displayName": "Test"}]


def _mock_fetch_activity_log(
    self: Any,
    subscription_id: str,
    checkpoint: Checkpoint | None,
) -> list[dict[str, Any]]:
    # Return raw events that will be normalized by the connector
    return []


# --- Tests ---


class TestLearningModeDuringWindow:
    """During the first 14 days, all findings are INFO severity."""

    def test_watch_during_learning_findings_are_info(self, tmp_path: Path) -> None:
        """mallcop watch during learning period produces INFO-severity findings only."""
        root = tmp_path
        _make_config_yaml(root)

        # Seed events from 5 days ago (within learning window)
        now = datetime.now(timezone.utc)
        base_time = now - timedelta(days=5)
        events = _make_events("azure", base_time, ["admin@example.com"])
        _seed_events(root, events)

        # Run detect (not full watch, since we pre-seeded events)
        result = CliRunner().invoke(cli, ["detect", "--dir", str(root)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        # Azure is in learning mode
        assert "azure" in data["learning_connectors"]

        # All findings should be INFO severity (suppressed)
        if data["findings_count"] > 0:
            for det, sevs in data["summary"].items():
                for sev in sevs:
                    assert sev == "info", f"Expected INFO severity during learning, got {sev}"

    def test_watch_learning_mode_escalation_proceeds(self, tmp_path: Path) -> None:
        """During learning mode, watch still runs escalation.

        Learning mode suppression is per-finding (findings from learning connectors
        are forced to INFO severity in detect). The watch command must not skip
        escalation entirely when some connectors are in learning mode — that would
        block findings from mature connectors too (bead mallcop-ak1n.2.28).
        """
        root = tmp_path
        _make_config_yaml(root)

        # Seed events from 3 days ago (within learning window)
        now = datetime.now(timezone.utc)
        base_time = now - timedelta(days=3)
        events = _make_events("azure", base_time, ["new_user@evil.com"])
        _seed_events(root, events)

        # We need to patch the connector to avoid real API calls
        # Since events are already seeded, we mock the connector to return nothing new
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

        # Azure should be listed as learning
        assert "azure" in data["detect"]["learning_connectors"]

        # Escalation must NOT be skipped due to learning mode — it runs for all connectors.
        # Learning mode suppresses individual findings (forces INFO severity in detect),
        # not the escalation pipeline as a whole.
        assert "escalate" in data
        assert data["escalate"].get("skipped") is not True, (
            "Escalation must not be skipped when only some connectors are in learning mode. "
            "Learning mode suppression is per-finding."
        )


class TestLearningModeExpiry:
    """After 14 days, findings use full severity."""

    def test_detect_after_learning_period_uses_real_severity(self, tmp_path: Path) -> None:
        """After 14 days, new-actor findings are WARN, not forced to INFO."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)

        # Seed old events from 20 days ago (beyond learning window)
        old_time = now - timedelta(days=20)
        old_events = _make_events("azure", old_time, ["admin@example.com"])
        _seed_events(root, old_events)

        # Update baseline so admin is known
        store = JsonlStore(root)
        store.update_baseline(store.query_events())

        # Now seed a new unknown actor event (recent)
        new_event = Event(
            id="evt_intruder_001",
            timestamp=now - timedelta(hours=1),
            ingested_at=now,
            source="azure",
            event_type="role_assignment",
            actor="intruder@evil.com",
            action="create",
            target="/subscriptions/sub-001/evil-resource",
            severity=Severity.WARN,
            metadata={},
            raw={},
        )
        store2 = JsonlStore(root)
        store2.append_events([new_event])

        # Run detect
        result = CliRunner().invoke(cli, ["detect", "--dir", str(root)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        # Azure is NOT in learning mode (first event was 20 days ago)
        assert "azure" not in data["learning_connectors"]

        # Findings for the intruder should have WARN severity (not suppressed)
        assert data["findings_count"] > 0
        found_warn = False
        for det, sevs in data["summary"].items():
            if "warn" in sevs:
                found_warn = True
        assert found_warn, f"Expected WARN findings after learning period, got {data['summary']}"

    def test_watch_after_learning_escalation_not_skipped_for_learning(self, tmp_path: Path) -> None:
        """After learning period, escalation is not skipped for learning_mode reason."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)

        # Seed events from 20 days ago
        old_time = now - timedelta(days=20)
        old_events = _make_events("azure", old_time, ["admin@example.com"])
        _seed_events(root, old_events)

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

        # Learning connectors should be empty
        assert data["detect"]["learning_connectors"] == []

        # Escalation should not be skipped for learning_mode
        assert data["escalate"]["reason"] != "learning_mode"


class TestBaselineBuilds:
    """Baseline accumulates frequency tables and known entities from events."""

    def test_baseline_builds_known_entities(self, tmp_path: Path) -> None:
        """After watch, baseline contains known actors from accumulated events."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        base_time = now - timedelta(days=5)
        actors = ["admin@example.com", "deploy@example.com", "readonly@example.com"]
        events = _make_events("azure", base_time, actors)
        _seed_events(root, events)

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

        # Baseline should have known actors
        assert data["baseline"]["known_actor_count"] >= len(actors)
        assert "azure" in data["baseline"]["known_sources"]

    def test_baseline_builds_frequency_tables(self, tmp_path: Path) -> None:
        """After watch, baseline contains frequency table entries."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        base_time = now - timedelta(days=5)
        events = _make_events("azure", base_time, ["admin@example.com"], count_per_actor=5)
        _seed_events(root, events)

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

        # Baseline should have frequency table entries
        assert data["baseline"]["frequency_table_entries"] > 0

    def test_baseline_persisted_to_disk(self, tmp_path: Path) -> None:
        """After watch, baseline.json is written to disk."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        base_time = now - timedelta(days=5)
        events = _make_events("azure", base_time, ["admin@example.com"])
        _seed_events(root, events)

        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            result = CliRunner().invoke(cli, ["watch", "--dir", str(root)])

        assert result.exit_code == 0

        baseline_path = root / ".mallcop" / "baseline.json"
        assert baseline_path.exists(), "baseline.json not written to disk"

        baseline_data = json.loads(baseline_path.read_text())
        assert "frequency_tables" in baseline_data
        assert "known_entities" in baseline_data
        assert "relationships" in baseline_data

        # Known entities should include the actor (sanitized with markers)
        actors = baseline_data["known_entities"].get("actors", [])
        assert any("admin@example.com" in a for a in actors), \
            f"Expected actor 'admin@example.com' in sanitized actors: {actors}"

    def test_baseline_accumulates_across_runs(self, tmp_path: Path) -> None:
        """Multiple watch runs accumulate baseline data."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)

        # First run: seed events with actor A
        events1 = _make_events("azure", now - timedelta(days=10), ["alice@example.com"])
        _seed_events(root, events1)

        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            result1 = CliRunner().invoke(cli, ["watch", "--dir", str(root)])
        assert result1.exit_code == 0

        # Second run: add actor B events
        events2 = _make_events("azure", now - timedelta(days=9), ["bob@example.com"])
        # Write directly to the store
        store = JsonlStore(root)
        store.append_events(events2)

        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            result2 = CliRunner().invoke(cli, ["watch", "--dir", str(root)])
        assert result2.exit_code == 0

        data2 = json.loads(result2.output)
        # Both actors should be in the baseline now
        assert data2["baseline"]["known_actor_count"] >= 2


class TestPerConnectorLearning:
    """Learning mode is per-connector: new connector gets own 14-day window."""

    def test_old_connector_live_new_connector_learning(self, tmp_path: Path) -> None:
        """An established connector is live while a new one is still learning."""
        root = tmp_path
        _make_config_yaml(root, connectors={
            "azure": {"subscription_ids": ["sub-001"]},
        })

        now = datetime.now(timezone.utc)

        # Seed old azure events (20 days ago -- past learning)
        azure_events = _make_events("azure", now - timedelta(days=20), ["admin@example.com"])
        _seed_events(root, azure_events)

        # Seed new github events (3 days ago -- in learning)
        github_events = _make_events("github", now - timedelta(days=3), ["dev@example.com"])
        store = JsonlStore(root)
        store.append_events(github_events)

        # Update baseline from old events
        store2 = JsonlStore(root)
        store2.update_baseline(store2.query_events())

        # Add an unknown actor event from azure (should get WARN)
        intruder_azure = Event(
            id="evt_intruder_azure",
            timestamp=now - timedelta(hours=1),
            ingested_at=now,
            source="azure",
            event_type="role_assignment",
            actor="intruder@evil.com",
            action="create",
            target="/subscriptions/sub-001/evil",
            severity=Severity.WARN,
            metadata={},
            raw={},
        )
        # Add an unknown actor event from github (should get INFO - learning)
        intruder_github = Event(
            id="evt_intruder_github",
            timestamp=now - timedelta(hours=1),
            ingested_at=now,
            source="github",
            event_type="push",
            actor="intruder2@evil.com",
            action="push",
            target="repo/main",
            severity=Severity.WARN,
            metadata={},
            raw={},
        )
        store3 = JsonlStore(root)
        store3.append_events([intruder_azure, intruder_github])

        # Run detect
        result = CliRunner().invoke(cli, ["detect", "--dir", str(root)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        # github should be learning, azure should not
        assert "github" in data["learning_connectors"]
        assert "azure" not in data["learning_connectors"]

        # Check findings stored on disk
        store4 = JsonlStore(root)
        findings = store4.query_findings()

        # Find the azure intruder finding -- should be WARN
        azure_findings = [
            f for f in findings
            if "intruder@evil.com" in f.title
        ]
        assert len(azure_findings) > 0
        for f in azure_findings:
            assert f.severity == Severity.WARN, (
                f"Azure finding should be WARN (past learning), got {f.severity}"
            )

        # Find the github intruder finding -- should be INFO (learning)
        github_findings = [
            f for f in findings
            if "intruder2@evil.com" in f.title
        ]
        assert len(github_findings) > 0
        for f in github_findings:
            assert f.severity == Severity.INFO, (
                f"GitHub finding should be INFO (in learning), got {f.severity}"
            )


class TestWatchDryRun:
    """watch --dry-run runs scan and detect but skips escalation."""

    def test_dry_run_skips_escalation(self, tmp_path: Path) -> None:
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        events = _make_events("azure", now - timedelta(days=20), ["admin@example.com"])
        _seed_events(root, events)

        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            result = CliRunner().invoke(cli, ["watch", "--dry-run", "--dir", str(root)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["escalate"]["skipped"] is True
        assert data["escalate"]["reason"] == "dry_run"


class TestWatchEventsAccumulate:
    """Events accumulate in events/*.jsonl across watch runs."""

    def test_events_written_to_disk(self, tmp_path: Path) -> None:
        """After watch, events are persisted to events/ directory."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        events = _make_events("azure", now - timedelta(days=5), ["admin@example.com"])
        _seed_events(root, events)

        events_dir = root / ".mallcop" / "events"
        assert events_dir.exists(), "events/ directory should exist after seeding"
        event_files = list(events_dir.glob("*.jsonl"))
        assert len(event_files) > 0, "At least one event JSONL file should exist"

        # Read back and verify
        store = JsonlStore(root)
        stored_events = store.query_events()
        assert len(stored_events) == len(events)

    def test_findings_persisted_during_learning(self, tmp_path: Path) -> None:
        """Findings are logged (as INFO) even during learning period."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        # New unknown actor, within learning window
        events = _make_events("azure", now - timedelta(days=3), ["unknown@suspicious.com"])
        _seed_events(root, events)

        result = CliRunner().invoke(cli, ["detect", "--dir", str(root)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        # Should have findings (suppressed to INFO)
        assert data["findings_count"] > 0

        # Findings should be persisted
        findings_path = root / ".mallcop" / "findings.jsonl"
        assert findings_path.exists(), "findings.jsonl should be written"

        store = JsonlStore(root)
        findings = store.query_findings()
        assert len(findings) > 0
        for f in findings:
            assert f.severity == Severity.INFO, (
                f"Learning mode finding should be INFO, got {f.severity}"
            )


class TestFullLearningPeriodScenario:
    """End-to-end scenario: 14 days of learning, then live detection."""

    def test_full_14_day_learning_then_live(self, tmp_path: Path) -> None:
        """Simulates the full learning period lifecycle.

        1. Seed events from day 1 (14 days ago)
        2. Run watch -- learning mode active, findings are INFO
        3. Seed events from day 15+ (beyond learning)
        4. Run detect again -- learning mode over, findings are WARN
        5. Baseline contains all accumulated data
        """
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)

        # === Phase 1: Within learning window (day 1-14) ===

        # Seed events starting 10 days ago
        learning_events = _make_events(
            "azure",
            now - timedelta(days=10),
            ["admin@example.com", "deploy-sp@example.com"],
            count_per_actor=5,
        )
        _seed_events(root, learning_events)

        # Run watch during learning
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            result1 = CliRunner().invoke(cli, ["watch", "--dir", str(root)])

        assert result1.exit_code == 0, f"Phase 1 exit {result1.exit_code}: {result1.output}"
        data1 = json.loads(result1.output)

        # Learning mode is active
        assert "azure" in data1["detect"]["learning_connectors"]
        # Baseline starts building
        assert data1["baseline"]["known_actor_count"] >= 2
        assert data1["baseline"]["frequency_table_entries"] > 0

        # Any findings should be INFO
        if data1["detect"]["findings_count"] > 0:
            for det, sevs in data1["detect"]["summary"].items():
                for sev in sevs:
                    assert sev == "info"

        # === Phase 2: After learning window (day 15+) ===

        # Seed an old event to push earliest beyond 14 days
        old_anchor = Event(
            id="evt_anchor_old",
            timestamp=now - timedelta(days=15),
            ingested_at=now - timedelta(days=15),
            source="azure",
            event_type="role_assignment",
            actor="admin@example.com",
            action="create",
            target="/subscriptions/sub-001/anchor",
            severity=Severity.WARN,
            metadata={},
            raw={},
        )
        store = JsonlStore(root)
        store.append_events([old_anchor])

        # Add a new unknown actor event
        intruder_event = Event(
            id="evt_intruder_day15",
            timestamp=now - timedelta(hours=1),
            ingested_at=now,
            source="azure",
            event_type="role_assignment",
            actor="intruder@evil.com",
            action="create",
            target="/subscriptions/sub-001/evil-resource",
            severity=Severity.WARN,
            metadata={},
            raw={},
        )
        store.append_events([intruder_event])

        # Run detect
        result2 = CliRunner().invoke(cli, ["detect", "--dir", str(root)])
        assert result2.exit_code == 0, f"Phase 2 exit {result2.exit_code}: {result2.output}"
        data2 = json.loads(result2.output)

        # Learning mode should be over for azure
        assert "azure" not in data2["learning_connectors"]

        # The intruder finding should be WARN (real severity, not suppressed)
        assert data2["findings_count"] > 0
        found_warn = False
        for det, sevs in data2["summary"].items():
            if "warn" in sevs:
                found_warn = True
        assert found_warn, f"Expected WARN findings post-learning, got {data2['summary']}"

        # === Verify baseline accumulated properly ===
        result3 = CliRunner().invoke(cli, ["baseline", "--dir", str(root)])
        assert result3.exit_code == 0
        baseline_data = json.loads(result3.output)

        # Baseline has events from the learning period
        assert baseline_data["event_count"] > len(learning_events)
        assert baseline_data["known_actor_count"] >= 2
        assert "azure" in baseline_data["known_sources"]
