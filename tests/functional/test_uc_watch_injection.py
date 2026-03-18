"""UC: Watch mode event injection -- watch ingests injected events and writes findings.

Functional test verifying the watch pipeline handles events injected via a mock
connector (ConnectorEventInjector pattern). The test:

- Starts a watch run with GitHub connector mock returning 3 collaborator_added events
- Verifies findings.jsonl has 3+ entries after the run (one per new actor)
- Verifies watch exits 0 and returns ok status

We mock:
  - GitHub connector poll (returns 3 synthetic collaborator_added events)
  - LLM actor builder (mock that escalates all findings)

We verify:
  - watch exits 0
  - findings.jsonl has entries for each injected collaborator_added event
  - JSON output contains scan/detect/escalate sub-results
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.cli import cli
from mallcop.schemas import (
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    PollResult,
    Severity,
)
from mallcop.store import JsonlStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_github_watch_config(root: Path) -> None:
    """Write mallcop.yaml for watch injection test."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"github": {"org": "acme-corp"}},
        "routing": {
            "critical": "triage",
            "warn": "triage",
            "info": None,
        },
        "actor_chain": {"triage": {"routes_to": "notify-teams"}},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
        "squelch": 0,
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _seed_watch_baseline(root: Path) -> datetime:
    """Seed known actors from 20 days ago so learning mode is off."""
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(days=20)

    known_events: list[Event] = []
    for i, actor in enumerate(["admin-user", "devops-bot"]):
        for j in range(5):
            ts = base_time + timedelta(hours=i * 6 + j)
            known_events.append(Event(
                id=f"evt_watch_baseline_{actor.replace('-', '_')}_{j}",
                timestamp=ts,
                ingested_at=ts + timedelta(seconds=1),
                source="github",
                event_type="push",
                actor=actor,
                action="git.push",
                target="acme-corp/web-app",
                severity=Severity.INFO,
                metadata={"org": "acme-corp"},
                raw={"raw_data": True},
            ))

    store = JsonlStore(root)
    store.append_events(known_events)
    store.update_baseline(known_events)
    return now


def _make_collaborator_added_events(now: datetime, count: int = 3) -> list[Event]:
    """Produce N synthetic collaborator_added events from unknown actors.

    Each event is from a distinct new actor so new-actor detector produces
    one finding per actor.
    """
    events: list[Event] = []
    for i in range(count):
        actor = f"new-contractor-{i:02d}"
        events.append(Event(
            id=f"evt_inject_collab_{i:02d}",
            timestamp=now - timedelta(hours=count - i),
            ingested_at=now - timedelta(hours=count - i - 1),
            source="github",
            event_type="collaborator_added",
            actor="admin-user",
            action="repo.add_member",
            target=f"acme-corp/repo-{i}",
            severity=Severity.WARN,
            metadata={
                "org": "acme-corp",
                "action_detail": "repo.add_member",
                "added_user": actor,
            },
            raw={"user": actor, "action": "repo.add_member"},
        ))
        # Also add an event from the new actor themselves so new-actor fires
        events.append(Event(
            id=f"evt_inject_actor_push_{i:02d}",
            timestamp=now - timedelta(minutes=30 + i * 5),
            ingested_at=now,
            source="github",
            event_type="push",
            actor=actor,
            action="git.push",
            target=f"acme-corp/repo-{i}",
            severity=Severity.INFO,
            metadata={"org": "acme-corp"},
            raw={"raw_data": True},
        ))
    return events


def _escalating_actor(finding: Finding, **kwargs: Any) -> RunResult:
    """Mock actor runner: escalates all findings."""
    return RunResult(
        resolution=ActorResolution(
            finding_id=finding.id,
            action=ResolutionAction.ESCALATED,
            reason="Watch injection test: unknown collaborator. Escalating.",
        ),
        tokens_used=200,
        iterations=1,
    )


# ---------------------------------------------------------------------------
# ConnectorEventInjector: inject events into the store before watch runs scan
# ---------------------------------------------------------------------------


class ConnectorEventInjector:
    """Test helper that injects a fixed list of events into the store.

    Used in place of a real connector -- the injected events appear in the
    store as if scan had polled a live API. The watch command's scan step
    is mocked to write these events and return a summary.
    """

    def __init__(self, root: Path, events: list[Event]) -> None:
        self._root = root
        self._events = events

    def inject(self) -> dict[str, Any]:
        """Write events to the store and return the scan-step summary dict."""
        store = JsonlStore(self._root)
        store.append_events(self._events)
        now = datetime.now(timezone.utc)
        store.set_checkpoint(Checkpoint(
            connector="github",
            value=f"cursor-inject-{len(self._events)}",
            updated_at=now,
        ))
        return {
            "status": "ok",
            "total_events_ingested": len(self._events),
            "connectors": {
                "github": {
                    "status": "ok",
                    "events_ingested": len(self._events),
                    "checkpoint": f"cursor-inject-{len(self._events)}",
                }
            },
        }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.functional
class TestWatchInjection:
    """Watch pipeline processes injected events and writes findings."""

    def test_watch_injects_events_and_writes_findings(
        self, tmp_path: Path
    ) -> None:
        """Inject 3 collaborator_added events via ConnectorEventInjector mock,
        watch produces >= 3 finding entries in findings.jsonl, exits 0."""
        root = tmp_path
        cli_runner = CliRunner()

        # Setup: config + baseline (learning mode off)
        _make_github_watch_config(root)
        now = _seed_watch_baseline(root)

        # Build 3 collaborator_added events (one per new contractor)
        injected_events = _make_collaborator_added_events(now, count=3)
        injector = ConnectorEventInjector(root, injected_events)

        # Patch scan pipeline to use injector (writes events to store, returns summary)
        scan_summary = injector.inject()

        def _mock_scan_pipeline(root_arg: Path, store: Any = None) -> dict[str, Any]:
            # Events already injected; just return the summary
            return scan_summary

        # Patch actor runner builder to return a deterministic escalating actor
        with patch("mallcop.cli._run_scan_pipeline", side_effect=_mock_scan_pipeline), \
             patch("mallcop.cli._build_actor_runner", return_value=_escalating_actor):
            watch_result = cli_runner.invoke(cli, ["watch", "--dir", str(root)])

        assert watch_result.exit_code == 0, (
            f"watch exit {watch_result.exit_code}: {watch_result.output}"
        )

        watch_data = json.loads(watch_result.output)
        assert watch_data["command"] == "watch"
        assert watch_data["status"] == "ok"
        assert "scan" in watch_data
        assert "detect" in watch_data
        assert "escalate" in watch_data

        # Scan step should reflect injected events
        assert watch_data["scan"]["status"] == "ok"
        assert watch_data["scan"]["total_events_ingested"] == len(injected_events)

        # Detect step should have found findings for the new actors
        assert watch_data["detect"]["status"] == "ok"
        assert watch_data["detect"]["findings_count"] >= 3, (
            f"Expected >= 3 findings (one per new actor), "
            f"got {watch_data['detect']['findings_count']}"
        )

        # findings.jsonl must exist with >= 3 entries
        findings_path = root / ".mallcop" / "findings.jsonl"
        assert findings_path.exists(), "findings.jsonl must exist after watch"

        raw_lines = [
            ln for ln in findings_path.read_text().strip().splitlines()
            if ln.strip()
        ]
        assert len(raw_lines) >= 3, (
            f"Expected >= 3 findings in findings.jsonl, got {len(raw_lines)}"
        )

        # Each finding line should be valid JSON with expected shape
        for line in raw_lines:
            fnd = json.loads(line)
            assert "id" in fnd
            assert "status" in fnd
            assert "severity" in fnd
            assert "detector" in fnd

        # Escalate step should have processed findings
        escalate = watch_data["escalate"]
        assert escalate.get("status") == "ok"
        assert escalate.get("findings_processed", 0) >= 3, (
            f"Expected escalate to process >= 3 findings, "
            f"got {escalate.get('findings_processed', 0)}"
        )

    def test_watch_exits_zero_with_only_info_events(self, tmp_path: Path) -> None:
        """Watch exits 0 and scan/detect/escalate all appear in output even with low-severity events."""
        root = tmp_path
        cli_runner = CliRunner()

        _make_github_watch_config(root)
        now = _seed_watch_baseline(root)

        # Inject a single push event (lowest severity)
        push_event = Event(
            id="evt_watch_info_push_001",
            timestamp=now - timedelta(hours=1),
            ingested_at=now,
            source="github",
            event_type="push",
            actor="admin-user",
            action="git.push",
            target="acme-corp/web-app",
            severity=Severity.INFO,
            metadata={"org": "acme-corp"},
            raw={"raw_data": True},
        )
        injector = ConnectorEventInjector(root, [push_event])
        scan_summary = injector.inject()

        def _mock_scan(root_arg: Path, store: Any = None) -> dict[str, Any]:
            return scan_summary

        with patch("mallcop.cli._run_scan_pipeline", side_effect=_mock_scan), \
             patch("mallcop.cli._build_actor_runner", return_value=_escalating_actor):
            watch_result = cli_runner.invoke(cli, ["watch", "--dir", str(root)])

        assert watch_result.exit_code == 0, (
            f"watch exit {watch_result.exit_code}: {watch_result.output}"
        )
        watch_data = json.loads(watch_result.output)
        assert watch_data["status"] == "ok"
        # All three stages must be present regardless of findings count
        assert "scan" in watch_data
        assert "detect" in watch_data
        assert "escalate" in watch_data
        assert watch_data["scan"]["status"] == "ok"
        assert watch_data["detect"]["status"] == "ok"

    def test_watch_scan_detect_escalate_all_present_in_output(
        self, tmp_path: Path
    ) -> None:
        """Watch output JSON contains scan, detect, and escalate sub-results."""
        root = tmp_path
        cli_runner = CliRunner()

        _make_github_watch_config(root)
        now = _seed_watch_baseline(root)

        injected = _make_collaborator_added_events(now, count=1)
        injector = ConnectorEventInjector(root, injected)
        scan_summary = injector.inject()

        def _mock_scan(root_arg: Path, store: Any = None) -> dict[str, Any]:
            return scan_summary

        with patch("mallcop.cli._run_scan_pipeline", side_effect=_mock_scan), \
             patch("mallcop.cli._build_actor_runner", return_value=_escalating_actor):
            result = cli_runner.invoke(cli, ["watch", "--dir", str(root)])

        assert result.exit_code == 0
        data = json.loads(result.output)

        # All three pipeline stages must be represented in the output
        assert "scan" in data, "watch output missing 'scan' key"
        assert "detect" in data, "watch output missing 'detect' key"
        assert "escalate" in data, "watch output missing 'escalate' key"

        # Sub-result shapes
        assert data["scan"]["status"] == "ok"
        assert data["detect"]["status"] == "ok"
        assert "findings_count" in data["detect"]
        assert data["escalate"]["status"] == "ok"
        assert "findings_processed" in data["escalate"]
