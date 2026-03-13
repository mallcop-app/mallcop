"""Integration test: app discovery framework wired into scan + detect pipelines."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from mallcop.schemas import (
    Baseline,
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    PollResult,
    Severity,
)


# -- Fixtures -----------------------------------------------------------------


_PARSER_YAML = {
    "app": "opensign",
    "version": 1,
    "generated_at": "2026-03-07T12:00:00Z",
    "generated_by": "test",
    "templates": [
        {
            "name": "http_request",
            "pattern": r'"(?P<method>\w+) (?P<path>[^ ]+) HTTP/[\d.]+" (?P<status>\d+)',
            "classification": "routine",
            "event_mapping": {
                "event_type": "http_request",
                "actor": "",
                "action": "{method}",
                "target": "{path}",
                "severity": "info",
            },
            "noise_filter": True,
        },
        {
            "name": "auth_failure",
            "pattern": r"AUTH FAILED: user=(?P<user>[^ ]+) ip=(?P<ip>[^ ]+)",
            "classification": "security",
            "event_mapping": {
                "event_type": "auth_failure",
                "actor": "{user}",
                "action": "login_failed",
                "target": "opensign",
                "severity": "warn",
                "metadata": {"ip_address": "{ip}"},
            },
            "noise_filter": False,
        },
    ],
    "noise_summary": True,
    "unmatched_threshold": 0.3,
}


_DETECTORS_YAML = {
    "app": "opensign",
    "detectors": [
        {
            "name": "opensign-auth-brute-force",
            "description": "Burst of auth failures from same IP",
            "event_type": "auth_failure",
            "condition": {
                "type": "count_threshold",
                "group_by": ["metadata.ip_address"],
                "window_minutes": 5,
                "threshold": 3,
            },
            "severity": "critical",
        },
    ],
}


_MALLCOP_YAML = {
    "secrets": {"backend": "env"},
    "connectors": {
        "container-logs": {
            "subscription_id": "sub-1",
            "resource_group": "rg-1",
            "apps": [
                {"name": "opensign", "container": "opensign"},
            ],
        },
    },
    "routing": {},
    "actor_chain": {},
    "budget": {},
}


def _setup_deployment_repo(tmp_path: Path) -> Path:
    """Set up a deployment repo with mallcop.yaml, apps/opensign/parser.yaml + detectors.yaml."""
    # mallcop.yaml
    with open(tmp_path / "mallcop.yaml", "w") as f:
        yaml.dump(_MALLCOP_YAML, f)

    # apps/opensign/
    app_dir = tmp_path / "apps" / "opensign"
    app_dir.mkdir(parents=True)
    with open(app_dir / "parser.yaml", "w") as f:
        yaml.dump(_PARSER_YAML, f)
    with open(app_dir / "detectors.yaml", "w") as f:
        yaml.dump(_DETECTORS_YAML, f)

    # Store directories
    (tmp_path / ".mallcop" / "events").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".mallcop" / "findings").mkdir(parents=True, exist_ok=True)

    return tmp_path


def _make_poll_result_with_log_lines(lines: list[str]) -> PollResult:
    """Build a PollResult with log_line events from raw lines."""
    now = datetime.now(timezone.utc)
    events = []
    for i, line in enumerate(lines):
        events.append(Event(
            id=f"evt_{i}",
            timestamp=now,
            ingested_at=now,
            source="container-logs",
            event_type="log_line",
            actor="opensign",
            action="log",
            target="opensign",
            severity=Severity.INFO,
            metadata={"app": "opensign", "line_number": i + 1},
            raw={"line": line},
        ))
    return PollResult(
        events=events,
        checkpoint=Checkpoint(
            connector="container-logs",
            value=now.isoformat(),
            updated_at=now,
        ),
    )


# -- Tests --------------------------------------------------------------------


class TestScanPipelineWithParsers:
    """Verify scan pipeline applies parser transforms to container-logs events."""

    def test_scan_transforms_log_lines_through_parser(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        root = _setup_deployment_repo(tmp_path)

        # Simulate log lines
        log_lines = [
            '"GET /api/doc HTTP/1.1" 200',
            '"POST /api/sign HTTP/1.1" 201',
            'AUTH FAILED: user=alice ip=10.0.0.1',
        ]
        poll_result = _make_poll_result_with_log_lines(log_lines)

        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=root) as td:
            # Copy config and apps into isolated fs
            _setup_deployment_repo(Path(td))

            with patch(
                "mallcop.cli.instantiate_connector"
            ) as mock_connector_fn:
                mock_connector = MagicMock()
                mock_connector.poll.return_value = poll_result
                mock_connector_fn.return_value = mock_connector

                result = runner.invoke(cli, ["scan"])

            assert result.exit_code == 0, f"scan failed: {result.output}"
            output = json.loads(result.output)
            assert output["status"] == "ok"

            # The parser should have produced:
            # - 2 noise-filtered http_request lines (counted, not stored)
            # - 1 auth_failure event (stored)
            # - 1 noise_summary event (stored)
            # - 1 parser_summary event (stored, for drift detection)
            # Total stored = 3 events
            assert output["total_events_ingested"] == 3
            conn_summary = output["connectors"]["container-logs"]
            assert conn_summary["status"] == "ok"
            assert conn_summary["events_ingested"] == 3

    def test_scan_without_parser_passes_raw_events(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        # No apps/ directory — events pass through unmodified
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(_MALLCOP_YAML, f)

        log_lines = ['"GET /api/doc HTTP/1.1" 200']
        poll_result = _make_poll_result_with_log_lines(log_lines)

        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            with open(Path(td) / "mallcop.yaml", "w") as f:
                yaml.dump(_MALLCOP_YAML, f)

            with patch(
                "mallcop.cli.instantiate_connector"
            ) as mock_connector_fn:
                mock_connector = MagicMock()
                mock_connector.poll.return_value = poll_result
                mock_connector_fn.return_value = mock_connector

                result = runner.invoke(cli, ["scan"])

            assert result.exit_code == 0, f"scan failed: {result.output}"
            output = json.loads(result.output)
            # Without parser, raw event passes through
            assert output["total_events_ingested"] == 1


class TestDetectPipelineWithDeclarativeDetectors:
    """Verify detect pipeline loads and runs declarative detectors from apps/."""

    def test_detect_runs_declarative_detectors(self, tmp_path: Path) -> None:
        from mallcop.detect import run_detect

        root = _setup_deployment_repo(tmp_path)

        # Create events that should trigger the auth brute force detector
        now = datetime.now(timezone.utc)
        events = []
        for i in range(5):
            events.append(Event(
                id=f"evt_auth_{i}",
                timestamp=now + timedelta(seconds=i),
                ingested_at=now,
                source="container-logs",
                event_type="auth_failure",
                actor="alice",
                action="login_failed",
                target="opensign",
                severity=Severity.WARN,
                metadata={"app": "opensign", "ip_address": "10.0.0.1"},
                raw={},
            ))

        baseline = Baseline(
            known_entities={"actors": [], "targets": []},
            frequency_tables={},
            relationships={},
        )

        findings = run_detect(
            events, baseline, learning_connectors=set(),
            root=root, config_connectors=_MALLCOP_YAML["connectors"],
        )

        # The declarative detector should find 5 auth failures from same IP
        brute_force_findings = [
            f for f in findings if "auth-brute-force" in f.detector
        ]
        assert len(brute_force_findings) >= 1
        assert brute_force_findings[0].severity == Severity.CRITICAL

    def test_detect_without_app_detectors_uses_only_plugins(self, tmp_path: Path) -> None:
        from mallcop.detect import run_detect

        # No apps/ directory
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(_MALLCOP_YAML, f)

        now = datetime.now(timezone.utc)
        events = [Event(
            id="evt_1",
            timestamp=now,
            ingested_at=now,
            source="container-logs",
            event_type="auth_failure",
            actor="alice",
            action="login_failed",
            target="opensign",
            severity=Severity.WARN,
            metadata={"app": "opensign", "ip_address": "10.0.0.1"},
            raw={},
        )]

        baseline = Baseline(
            known_entities={"actors": [], "targets": []},
            frequency_tables={},
            relationships={},
        )

        # Should not crash, just uses built-in detectors
        findings = run_detect(
            events, baseline, learning_connectors=set(),
            root=tmp_path, config_connectors=_MALLCOP_YAML["connectors"],
        )

        # No app detectors loaded, so no brute-force findings
        brute_force_findings = [
            f for f in findings if "auth-brute-force" in f.detector
        ]
        assert len(brute_force_findings) == 0

    def test_detect_backward_compatible_without_root(self) -> None:
        """run_detect still works when called without root/config_connectors (old API)."""
        from mallcop.detect import run_detect

        baseline = Baseline(
            known_entities={"actors": [], "targets": []},
            frequency_tables={},
            relationships={},
        )

        # Old-style call without root/config_connectors
        findings = run_detect([], baseline, learning_connectors=set())
        assert findings == []
