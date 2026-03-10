"""Tests for discover-app CLI command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from mallcop.connectors.container_logs.connector import ContainerLogsConnector


SAMPLE_LOGS = (
    "2026-03-05T14:30:00.000Z opensign started on port 3000\n"
    "2026-03-05T15:00:00.000Z GET /api/health 200 12ms\n"
    "2026-03-05T15:01:00.000Z POST /api/documents/sign 201 340ms\n"
    "2026-03-05T15:02:00.000Z GET /api/health 200 11ms\n"
    "2026-03-05T16:00:00.000Z ERROR: database connection timeout\n"
)


def _write_config(tmp_path: Path, apps: list[dict[str, str]] | None = None) -> None:
    if apps is None:
        apps = [{"name": "opensign", "container": "opensign"}]
    config = {
        "secrets": {"backend": "env"},
        "connectors": {
            "container-logs": {
                "subscription_id": "sub-001",
                "resource_group": "acme-rg",
                "apps": apps,
            }
        },
        "routing": {},
        "actor_chain": {},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(tmp_path / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)


class TestDiscoverAppOutput:
    """Test the discover_app logic produces correct structured output."""

    def test_returns_sample_lines(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic

        _write_config(tmp_path)
        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = discover_app_logic("opensign", tmp_path, lines=100)

        assert result["app_name"] == "opensign"
        assert len(result["sample_lines"]) == 5
        assert result["sample_lines"][0] == "2026-03-05T14:30:00.000Z opensign started on port 3000"

    def test_returns_log_stats(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic

        _write_config(tmp_path)
        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = discover_app_logic("opensign", tmp_path, lines=100)

        stats = result["log_stats"]
        assert stats["total_lines"] == 5
        assert stats["lines_with_timestamp"] == 5
        assert stats["lines_without_timestamp"] == 0
        assert stats["earliest_timestamp"] is not None
        assert stats["latest_timestamp"] is not None

    def test_returns_suggested_output_paths(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic

        _write_config(tmp_path)
        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = discover_app_logic("opensign", tmp_path, lines=100)

        paths = result["suggested_output_paths"]
        assert "apps/opensign/parser.yaml" in paths
        assert "apps/opensign/detectors.yaml" in paths
        assert "apps/opensign/discovery.yaml" in paths

    def test_limits_sample_lines(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic

        _write_config(tmp_path)
        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = discover_app_logic("opensign", tmp_path, lines=3)

        # Should return last 3 lines (most recent)
        assert len(result["sample_lines"]) == 3

    def test_unknown_app_raises_error(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic, DiscoverAppError

        _write_config(tmp_path)
        with pytest.raises(DiscoverAppError, match="not found"):
            discover_app_logic("nonexistent", tmp_path, lines=100)

    def test_no_container_logs_connector_raises_error(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic, DiscoverAppError

        # Config without container-logs connector
        config = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "budget": {
                "max_findings_for_actors": 25,
                "max_tokens_per_run": 50000,
                "max_tokens_per_finding": 5000,
            },
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        with pytest.raises(DiscoverAppError, match="container-logs"):
            discover_app_logic("opensign", tmp_path, lines=100)

    def test_empty_logs_returns_empty_sample(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic

        _write_config(tmp_path)
        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=""
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = discover_app_logic("opensign", tmp_path, lines=100)

        assert result["sample_lines"] == []
        assert result["log_stats"]["total_lines"] == 0

    def test_lines_without_timestamps_counted(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic

        logs = "plain log line\nanother plain line\n2026-03-05T14:30:00.000Z timestamped\n"
        _write_config(tmp_path)
        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=logs
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = discover_app_logic("opensign", tmp_path, lines=100)

        assert result["log_stats"]["total_lines"] == 3
        assert result["log_stats"]["lines_with_timestamp"] == 1
        assert result["log_stats"]["lines_without_timestamp"] == 2

    def test_refresh_flag_works_same_as_normal(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic

        _write_config(tmp_path)
        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = discover_app_logic("opensign", tmp_path, lines=100, refresh=True)

        assert result["app_name"] == "opensign"
        assert result["refresh"] is True

    def test_non_refresh_flag_in_output(self, tmp_path: Path) -> None:
        from mallcop.discover_app import discover_app_logic

        _write_config(tmp_path)
        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = discover_app_logic("opensign", tmp_path, lines=100, refresh=False)

        assert result["refresh"] is False
