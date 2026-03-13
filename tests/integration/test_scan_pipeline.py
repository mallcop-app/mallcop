"""Integration test: mallcop init + mallcop scan end-to-end pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity
from mallcop.connectors.azure.connector import AzureConnector


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "azure"


def _load_fixture(name: str) -> dict[str, Any]:
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


class TestInitCommand:
    """mallcop init discovers connectors, writes config, estimates costs."""

    def test_init_discovers_azure_and_writes_config(self, tmp_path: Path) -> None:
        """init discovers Azure connector with fixtures, writes mallcop.yaml."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        fixture = _load_fixture("discovery_subscriptions.json")
        activity_fixture = _load_fixture("activity_log_events.json")

        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            with patch.object(
                AzureConnector, "_list_subscriptions", return_value=fixture["value"]
            ), patch.object(
                AzureConnector, "_fetch_activity_log", return_value=activity_fixture["value"]
            ):
                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0, f"init failed: {result.output}"
            output = json.loads(result.output)

            # Config file was written
            config_path = Path(td) / "mallcop.yaml"
            assert config_path.exists(), "mallcop.yaml not created"

            config = yaml.safe_load(config_path.read_text())
            assert "connectors" in config
            assert "azure" in config["connectors"]
            assert "budget" in config

            # Output includes discovery results
            assert output["status"] == "ok"
            assert "connectors" in output
            assert any(c["name"] == "azure" for c in output["connectors"])

    def test_init_includes_cost_estimate(self, tmp_path: Path) -> None:
        """init output includes cost estimation data."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        fixture = _load_fixture("discovery_subscriptions.json")
        activity_fixture = _load_fixture("activity_log_events.json")

        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch.object(
                AzureConnector, "_list_subscriptions", return_value=fixture["value"]
            ), patch.object(
                AzureConnector, "_fetch_activity_log", return_value=activity_fixture["value"]
            ):
                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0
            output = json.loads(result.output)
            assert "cost_estimate" in output

    def test_init_reports_missing_credentials(self, tmp_path: Path) -> None:
        """init reports connectors that are unavailable due to missing creds."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch.object(
                AzureConnector,
                "_list_subscriptions",
                side_effect=Exception("Auth failed"),
            ), patch.object(
                AzureConnector, "_fetch_activity_log", return_value=[]
            ):
                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0
            output = json.loads(result.output)
            # Should still write config (even if no connectors available)
            assert output["status"] == "ok"


class TestScanCommand:
    """mallcop scan polls connectors, stores events, manages checkpoints."""

    def _write_config(self, directory: Path, sub_ids: list[str] | None = None) -> None:
        """Write a minimal mallcop.yaml for testing."""
        if sub_ids is None:
            sub_ids = ["00000000-0000-0000-0000-000000000001"]
        config = {
            "secrets": {"backend": "env"},
            "connectors": {
                "azure": {
                    "tenant_id": "${AZURE_TENANT_ID}",
                    "client_id": "${AZURE_CLIENT_ID}",
                    "client_secret": "${AZURE_CLIENT_SECRET}",
                    "subscription_ids": sub_ids,
                },
            },
            "routing": {},
            "actor_chain": {},
            "budget": {
                "max_findings_for_actors": 25,
                "max_tokens_per_run": 50000,
                "max_tokens_per_finding": 5000,
            },
        }
        with open(directory / "mallcop.yaml", "w") as f:
            yaml.dump(config, f)

    def test_scan_polls_and_writes_events(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """scan polls Azure, writes events to JSONL files."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        activity_fixture = _load_fixture("activity_log_events.json")
        self._write_config(tmp_path)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000099")
        monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000088")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "super-secret")

        runner = CliRunner()
        with patch.object(
            AzureConnector, "_get_token", return_value="fake-token"
        ), patch.object(
            AzureConnector, "_fetch_activity_log", return_value=activity_fixture["value"]
        ):
            result = runner.invoke(cli, ["scan"], catch_exceptions=False)

        assert result.exit_code == 0, f"scan failed: {result.output}"
        output = json.loads(result.output)

        assert output["status"] == "ok"
        assert output["connectors"]["azure"]["events_ingested"] == 3

        # Verify events JSONL files created
        events_dir = tmp_path / ".mallcop" / "events"
        assert events_dir.exists()
        event_files = list(events_dir.glob("*.jsonl"))
        assert len(event_files) > 0

        # Verify event content
        all_events = []
        for ef in event_files:
            for line in ef.read_text().strip().split("\n"):
                if line:
                    all_events.append(json.loads(line))
        assert len(all_events) == 3
        assert all_events[0]["source"] == "azure"

    def test_scan_creates_checkpoint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """scan creates checkpoint file after polling."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        activity_fixture = _load_fixture("activity_log_events.json")
        self._write_config(tmp_path)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000099")
        monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000088")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "super-secret")

        runner = CliRunner()
        with patch.object(
            AzureConnector, "_get_token", return_value="fake-token"
        ), patch.object(
            AzureConnector, "_fetch_activity_log", return_value=activity_fixture["value"]
        ):
            result = runner.invoke(cli, ["scan"], catch_exceptions=False)

        assert result.exit_code == 0

        # Verify checkpoint written
        checkpoints_path = tmp_path / ".mallcop" / "checkpoints.yaml"
        assert checkpoints_path.exists()
        checkpoints = yaml.safe_load(checkpoints_path.read_text())
        assert "azure" in checkpoints
        assert "value" in checkpoints["azure"]

    def test_scan_checkpoint_prevents_duplicates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Running scan twice with same data should not duplicate events."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        activity_fixture = _load_fixture("activity_log_events.json")
        self._write_config(tmp_path)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000099")
        monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000088")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "super-secret")

        runner = CliRunner()

        # First scan
        with patch.object(
            AzureConnector, "_get_token", return_value="fake-token"
        ), patch.object(
            AzureConnector, "_fetch_activity_log", return_value=activity_fixture["value"]
        ):
            result1 = runner.invoke(cli, ["scan"], catch_exceptions=False)
        assert result1.exit_code == 0
        output1 = json.loads(result1.output)
        assert output1["connectors"]["azure"]["events_ingested"] == 3

        # Second scan with same data — checkpoint should filter everything
        with patch.object(
            AzureConnector, "_get_token", return_value="fake-token"
        ), patch.object(
            AzureConnector, "_fetch_activity_log", return_value=activity_fixture["value"]
        ):
            result2 = runner.invoke(cli, ["scan"], catch_exceptions=False)
        assert result2.exit_code == 0
        output2 = json.loads(result2.output)
        assert output2["connectors"]["azure"]["events_ingested"] == 0

        # Verify total events on disk is still 3 (no duplicates)
        events_dir = tmp_path / ".mallcop" / "events"
        all_events = []
        for ef in events_dir.glob("*.jsonl"):
            for line in ef.read_text().strip().split("\n"):
                if line:
                    all_events.append(json.loads(line))
        assert len(all_events) == 3

    def test_scan_output_is_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """scan output is valid JSON (for AI consumption)."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        activity_fixture = _load_fixture("activity_log_events.json")
        self._write_config(tmp_path)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000099")
        monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000088")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "super-secret")

        runner = CliRunner()
        with patch.object(
            AzureConnector, "_fetch_activity_log", return_value=activity_fixture["value"]
        ):
            result = runner.invoke(cli, ["scan"], catch_exceptions=False)

        # Must be valid JSON
        data = json.loads(result.output)
        assert isinstance(data, dict)
