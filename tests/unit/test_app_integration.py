"""Tests for app_integration: wiring parsers and declarative detectors into pipelines."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from mallcop.app_integration import (
    apply_parsers,
    find_apps_dir,
    get_configured_app_names,
    load_app_detectors,
)
from mallcop.schemas import Baseline, Event, Severity


# -- Helpers ------------------------------------------------------------------


def _make_log_event(
    app_name: str, line: str, event_id: str = "evt_test",
) -> Event:
    now = datetime.now(timezone.utc)
    return Event(
        id=event_id,
        timestamp=now,
        ingested_at=now,
        source="container-logs",
        event_type="log_line",
        actor=app_name,
        action="log",
        target=app_name,
        severity=Severity.INFO,
        metadata={"app": app_name, "line_number": 1},
        raw={"line": line},
    )


def _make_azure_event(event_id: str = "evt_azure") -> Event:
    now = datetime.now(timezone.utc)
    return Event(
        id=event_id,
        timestamp=now,
        ingested_at=now,
        source="azure",
        event_type="activity_log",
        actor="admin@example.com",
        action="create",
        target="vm-1",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


_PARSER_YAML = {
    "app": "testapp",
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
                "target": "testapp",
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
    "app": "testapp",
    "detectors": [
        {
            "name": "testapp-auth-brute-force",
            "description": "Burst of auth failures",
            "event_type": "auth_failure",
            "condition": {
                "type": "count_threshold",
                "group_by": ["metadata.ip_address"],
                "window_minutes": 5,
                "threshold": 3,
            },
            "severity": "critical",
        },
        {
            "name": "testapp-unusual-endpoint",
            "description": "Request to unknown path",
            "event_type": "http_request",
            "condition": {
                "type": "new_value",
                "field": "target",
            },
            "severity": "warn",
        },
    ],
}


# -- get_configured_app_names -------------------------------------------------


class TestGetConfiguredAppNames:
    def test_no_container_logs(self) -> None:
        connectors = {"azure": {"subscription_ids": ["sub-1"]}}
        assert get_configured_app_names(connectors) == []

    def test_empty_apps(self) -> None:
        connectors = {"container-logs": {"apps": []}}
        assert get_configured_app_names(connectors) == []

    def test_extracts_names(self) -> None:
        connectors = {
            "container-logs": {
                "apps": [
                    {"name": "opensign", "container": "opensign"},
                    {"name": "webapp", "container": "webapp"},
                ],
            },
        }
        assert get_configured_app_names(connectors) == ["opensign", "webapp"]

    def test_skips_empty_names(self) -> None:
        connectors = {
            "container-logs": {
                "apps": [{"name": ""}, {"name": "valid"}],
            },
        }
        assert get_configured_app_names(connectors) == ["valid"]

    def test_no_apps_key(self) -> None:
        connectors = {"container-logs": {"subscription_id": "sub-1"}}
        assert get_configured_app_names(connectors) == []


# -- find_apps_dir ------------------------------------------------------------


class TestFindAppsDir:
    def test_returns_apps_subdir(self, tmp_path: Path) -> None:
        assert find_apps_dir(tmp_path) == tmp_path / "apps"


# -- apply_parsers ------------------------------------------------------------


class TestApplyParsers:
    def test_no_apps_dir_passes_through(self, tmp_path: Path) -> None:
        events = [_make_log_event("myapp", "some log line")]
        result = apply_parsers(events, tmp_path, ["myapp"])
        assert len(result) == 1
        assert result[0].event_type == "log_line"

    def test_no_parser_yaml_passes_through(self, tmp_path: Path) -> None:
        apps_dir = tmp_path / "apps" / "myapp"
        apps_dir.mkdir(parents=True)
        events = [_make_log_event("myapp", "some log line")]
        result = apply_parsers(events, tmp_path, ["myapp"])
        assert len(result) == 1
        assert result[0].event_type == "log_line"

    def test_parser_transforms_matching_lines(self, tmp_path: Path) -> None:
        apps_dir = tmp_path / "apps" / "testapp"
        apps_dir.mkdir(parents=True)
        with open(apps_dir / "parser.yaml", "w") as f:
            yaml.dump(_PARSER_YAML, f)

        events = [
            _make_log_event(
                "testapp",
                'AUTH FAILED: user=alice ip=10.0.0.1',
                event_id="evt_1",
            ),
        ]
        result = apply_parsers(events, tmp_path, ["testapp"])

        # Should have the auth_failure event + noise summary
        auth_events = [e for e in result if e.event_type == "auth_failure"]
        assert len(auth_events) == 1
        assert auth_events[0].actor == "alice"
        assert auth_events[0].action == "login_failed"
        assert auth_events[0].severity == Severity.WARN
        assert auth_events[0].metadata["ip_address"] == "10.0.0.1"

    def test_noise_filter_suppresses_events(self, tmp_path: Path) -> None:
        apps_dir = tmp_path / "apps" / "testapp"
        apps_dir.mkdir(parents=True)
        with open(apps_dir / "parser.yaml", "w") as f:
            yaml.dump(_PARSER_YAML, f)

        events = [
            _make_log_event(
                "testapp",
                '"GET /index HTTP/1.1" 200',
                event_id="evt_1",
            ),
        ]
        result = apply_parsers(events, tmp_path, ["testapp"])

        # HTTP request was noise-filtered, should only have summary
        http_events = [e for e in result if e.event_type == "http_request"]
        assert len(http_events) == 0
        summary_events = [e for e in result if e.event_type == "noise_summary"]
        assert len(summary_events) == 1
        assert summary_events[0].metadata["template_counts"]["http_request"] == 1

    def test_non_container_logs_events_pass_through(self, tmp_path: Path) -> None:
        apps_dir = tmp_path / "apps" / "testapp"
        apps_dir.mkdir(parents=True)
        with open(apps_dir / "parser.yaml", "w") as f:
            yaml.dump(_PARSER_YAML, f)

        azure_evt = _make_azure_event()
        log_evt = _make_log_event(
            "testapp",
            'AUTH FAILED: user=bob ip=10.0.0.2',
            event_id="evt_2",
        )
        result = apply_parsers([azure_evt, log_evt], tmp_path, ["testapp"])

        # Azure event passes through unchanged
        azure_result = [e for e in result if e.source == "azure"]
        assert len(azure_result) == 1
        assert azure_result[0].id == "evt_azure"

    def test_events_from_unconfigured_app_pass_through(self, tmp_path: Path) -> None:
        apps_dir = tmp_path / "apps" / "testapp"
        apps_dir.mkdir(parents=True)
        with open(apps_dir / "parser.yaml", "w") as f:
            yaml.dump(_PARSER_YAML, f)

        # Event from "otherapp" which has no parser
        evt = _make_log_event("otherapp", "some log", event_id="evt_other")
        result = apply_parsers([evt], tmp_path, ["testapp"])
        assert len(result) == 1
        assert result[0].event_type == "log_line"

    def test_empty_events_no_crash(self, tmp_path: Path) -> None:
        apps_dir = tmp_path / "apps" / "testapp"
        apps_dir.mkdir(parents=True)
        with open(apps_dir / "parser.yaml", "w") as f:
            yaml.dump(_PARSER_YAML, f)

        result = apply_parsers([], tmp_path, ["testapp"])
        assert result == []

    def test_mixed_apps_parser_and_no_parser(self, tmp_path: Path) -> None:
        # testapp has parser, otherapp does not
        apps_dir = tmp_path / "apps" / "testapp"
        apps_dir.mkdir(parents=True)
        with open(apps_dir / "parser.yaml", "w") as f:
            yaml.dump(_PARSER_YAML, f)

        evt1 = _make_log_event(
            "testapp",
            'AUTH FAILED: user=alice ip=10.0.0.1',
            event_id="evt_1",
        )
        evt2 = _make_log_event("otherapp", "plain log", event_id="evt_2")

        result = apply_parsers([evt1, evt2], tmp_path, ["testapp", "otherapp"])

        # otherapp event passes through unchanged
        other_events = [e for e in result if e.metadata.get("app") == "otherapp"]
        assert len(other_events) == 1
        assert other_events[0].event_type == "log_line"

        # testapp event is parsed
        auth_events = [e for e in result if e.event_type == "auth_failure"]
        assert len(auth_events) == 1


# -- load_app_detectors -------------------------------------------------------


class TestLoadAppDetectors:
    def test_no_apps_dir_returns_empty(self, tmp_path: Path) -> None:
        result = load_app_detectors(tmp_path, ["testapp"])
        assert result == []

    def test_no_detectors_yaml_returns_empty(self, tmp_path: Path) -> None:
        apps_dir = tmp_path / "apps" / "testapp"
        apps_dir.mkdir(parents=True)
        result = load_app_detectors(tmp_path, ["testapp"])
        assert result == []

    def test_loads_detectors_from_yaml(self, tmp_path: Path) -> None:
        apps_dir = tmp_path / "apps" / "testapp"
        apps_dir.mkdir(parents=True)
        with open(apps_dir / "detectors.yaml", "w") as f:
            yaml.dump(_DETECTORS_YAML, f)

        result = load_app_detectors(tmp_path, ["testapp"])
        assert len(result) == 2
        names = {d._name for d in result}
        assert "testapp-auth-brute-force" in names
        assert "testapp-unusual-endpoint" in names

    def test_loads_from_multiple_apps(self, tmp_path: Path) -> None:
        for app_name in ["app1", "app2"]:
            apps_dir = tmp_path / "apps" / app_name
            apps_dir.mkdir(parents=True)
            detectors_data = {
                "app": app_name,
                "detectors": [
                    {
                        "name": f"{app_name}-detector",
                        "event_type": "test_event",
                        "condition": {"type": "new_value", "field": "target"},
                        "severity": "warn",
                    },
                ],
            }
            with open(apps_dir / "detectors.yaml", "w") as f:
                yaml.dump(detectors_data, f)

        result = load_app_detectors(tmp_path, ["app1", "app2"])
        assert len(result) == 2
        names = {d._name for d in result}
        assert "app1-detector" in names
        assert "app2-detector" in names

    def test_skips_unconfigured_apps(self, tmp_path: Path) -> None:
        # detectors.yaml exists for app1 but only app2 is configured
        apps_dir = tmp_path / "apps" / "app1"
        apps_dir.mkdir(parents=True)
        with open(apps_dir / "detectors.yaml", "w") as f:
            yaml.dump(_DETECTORS_YAML, f)

        result = load_app_detectors(tmp_path, ["app2"])
        assert result == []
