"""Functional tests for discover-app CLI command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import yaml
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.connectors.container_logs.connector import ContainerLogsConnector


SAMPLE_LOGS = (
    "2026-03-05T14:30:00.000Z opensign started on port 3000\n"
    "2026-03-05T15:00:00.000Z GET /api/health 200 12ms\n"
    "2026-03-05T15:01:00.000Z POST /api/documents/sign 201 340ms\n"
    "2026-03-05T15:02:00.000Z GET /api/health 200 11ms\n"
    "2026-03-05T16:00:00.000Z ERROR: database connection timeout\n"
)


def _write_config(tmp_path: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {
            "container-logs": {
                "subscription_id": "sub-001",
                "resource_group": "acme-rg",
                "apps": [{"name": "opensign", "container": "opensign"}],
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


class TestDiscoverAppCLI:
    def test_outputs_json_with_sample_lines(self, tmp_path: Path) -> None:
        _write_config(tmp_path)
        runner = CliRunner()

        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = runner.invoke(
                cli, ["discover-app", "opensign", "--dir", str(tmp_path)]
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["app_name"] == "opensign"
        assert len(output["sample_lines"]) == 5
        assert output["log_stats"]["total_lines"] == 5
        assert len(output["suggested_output_paths"]) == 3

    def test_refresh_flag(self, tmp_path: Path) -> None:
        _write_config(tmp_path)
        runner = CliRunner()

        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = runner.invoke(
                cli, ["discover-app", "opensign", "--refresh", "--dir", str(tmp_path)]
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["refresh"] is True

    def test_lines_flag(self, tmp_path: Path) -> None:
        _write_config(tmp_path)
        runner = CliRunner()

        with patch.object(
            ContainerLogsConnector, "_fetch_logs_for_app", return_value=SAMPLE_LOGS
        ), patch.object(
            ContainerLogsConnector, "authenticate"
        ):
            result = runner.invoke(
                cli, ["discover-app", "opensign", "--lines", "2", "--dir", str(tmp_path)]
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert len(output["sample_lines"]) == 2

    def test_unknown_app_returns_error(self, tmp_path: Path) -> None:
        _write_config(tmp_path)
        runner = CliRunner()

        result = runner.invoke(
            cli, ["discover-app", "nonexistent", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 1
        output = json.loads(result.output)
        assert output["status"] == "error"
        assert "not found" in output["error"]

    def test_no_config_returns_error(self, tmp_path: Path) -> None:
        runner = CliRunner()

        result = runner.invoke(
            cli, ["discover-app", "opensign", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 1
        output = json.loads(result.output)
        assert output["status"] == "error"
