"""Tests for mallcop patrol CLI commands."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli


# ─── Helpers ────────────────────────────────────────────────────────


def _write_config(root: Path, extra: dict[str, Any] | None = None) -> None:
    config: dict[str, Any] = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {},
        "actor_chain": {},
        "budget": {
            "max_findings_for_actors": 25,
            "max_donuts_per_run": 500,
            "max_donuts_per_finding": 5000,
        },
    }
    if extra:
        config.update(extra)
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _read_config(root: Path) -> dict[str, Any]:
    with open(root / "mallcop.yaml") as f:
        return yaml.safe_load(f)


def _mock_crontab_backend() -> MagicMock:
    """Return a mock CrontabBackend with sensible defaults."""
    m = MagicMock()
    m.read_entries.return_value = []
    m.entry_exists.return_value = False
    m.remove_entry.return_value = True
    return m


# ─── patrol create ──────────────────────────────────────────────────


class TestPatrolCreate:
    def test_create_writes_crontab_entry(self, tmp_path: Path) -> None:
        """patrol create writes a crontab entry via CrontabBackend."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "create", "sweep", "--every", "6h"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["status"] == "ok"
        assert output["name"] == "sweep"
        mock_backend.write_entry.assert_called_once()
        call_kwargs = mock_backend.write_entry.call_args
        assert call_kwargs[1].get("name") == "sweep" or call_kwargs[0][0] == "sweep"

    def test_create_updates_mallcop_yaml_patrols_section(self, tmp_path: Path) -> None:
        """patrol create writes the patrol to mallcop.yaml."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "create", "sweep", "--every", "6h"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        config = _read_config(tmp_path)
        assert "patrols" in config
        assert "sweep" in config["patrols"]
        assert config["patrols"]["sweep"]["every"] == "6h"

    def test_create_with_budget_option(self, tmp_path: Path) -> None:
        """patrol create --budget stores budget in config."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "create", "sweep", "--every", "1d", "--budget", "100"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        config = _read_config(tmp_path)
        assert config["patrols"]["sweep"]["budget"] == 100

    def test_create_budget_exceeds_max_donuts_per_run_errors(self, tmp_path: Path) -> None:
        """patrol create --budget > max_donuts_per_run exits with error."""
        _write_config(tmp_path)  # max_donuts_per_run=500
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "create", "sweep", "--every", "1d", "--budget", "1000"],
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code != 0 or "error" in result.output.lower()
        output = json.loads(result.output)
        assert output["status"] == "error"
        assert "budget" in output["error"].lower() or "max_donuts" in output["error"].lower()

    def test_create_with_research_flag(self, tmp_path: Path) -> None:
        """patrol create --research sets research: true in config."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "create", "deep", "--every", "1d", "--research"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        config = _read_config(tmp_path)
        assert config["patrols"]["deep"]["research"] is True

    def test_create_with_no_git_flag(self, tmp_path: Path) -> None:
        """patrol create --no-git sets with_git: false in config."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "create", "sweep", "--every", "6h", "--no-git"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        config = _read_config(tmp_path)
        assert config["patrols"]["sweep"]["with_git"] is False

    def test_create_with_chain_and_notify(self, tmp_path: Path) -> None:
        """patrol create --chain/--notify stores actor routing."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                [
                    "patrol", "create", "sweep", "--every", "1h",
                    "--chain", "triage,investigate",
                    "--notify", "slack,email",
                ],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        config = _read_config(tmp_path)
        assert config["patrols"]["sweep"]["chain"] == ["triage", "investigate"]
        assert config["patrols"]["sweep"]["notify"] == ["slack", "email"]

    def test_create_duplicate_name_errors(self, tmp_path: Path) -> None:
        """patrol create with duplicate name exits with error."""
        _write_config(tmp_path, extra={"patrols": {"sweep": {"every": "1h"}}})
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()
        mock_backend.entry_exists.return_value = True

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "create", "sweep", "--every", "6h"],
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        output = json.loads(result.output)
        assert output["status"] == "error"
        assert "already exists" in output["error"].lower() or "exists" in output["error"].lower()


# ─── patrol list ────────────────────────────────────────────────────


class TestPatrolList:
    def test_list_shows_all_patrols(self, tmp_path: Path) -> None:
        """patrol list shows all configured patrols."""
        _write_config(
            tmp_path,
            extra={
                "patrols": {
                    "sweep": {"every": "6h"},
                    "daily": {"every": "1d"},
                }
            },
        )
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()
        from mallcop.crontab import PatrolEntry
        mock_backend.read_entries.return_value = [
            PatrolEntry(name="sweep", schedule="0 */6 * * *", command="watch"),
            PatrolEntry(name="daily", schedule="0 0 * * *", command="watch"),
        ]

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "list"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["status"] == "ok"
        assert len(output["patrols"]) == 2
        names = {p["name"] for p in output["patrols"]}
        assert "sweep" in names
        assert "daily" in names

    def test_list_shows_schedule_and_enabled_status(self, tmp_path: Path) -> None:
        """patrol list includes schedule and enabled field."""
        _write_config(
            tmp_path,
            extra={
                "patrols": {
                    "sweep": {"every": "1h", "enabled": False},
                }
            },
        )
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()
        mock_backend.read_entries.return_value = []  # no crontab entry = disabled

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "list"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        patrol = output["patrols"][0]
        assert "schedule" in patrol
        assert "enabled" in patrol

    def test_list_empty_when_no_patrols(self, tmp_path: Path) -> None:
        """patrol list returns empty list when no patrols configured."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "list"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["patrols"] == []


# ─── patrol update ──────────────────────────────────────────────────


class TestPatrolUpdate:
    def test_update_changes_schedule(self, tmp_path: Path) -> None:
        """patrol update --every replaces the crontab entry and config."""
        _write_config(tmp_path, extra={"patrols": {"sweep": {"every": "6h"}}})
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()
        mock_backend.entry_exists.return_value = True

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "update", "sweep", "--every", "1d"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["status"] == "ok"
        config = _read_config(tmp_path)
        assert config["patrols"]["sweep"]["every"] == "1d"
        mock_backend.write_entry.assert_called_once()

    def test_update_nonexistent_patrol_errors(self, tmp_path: Path) -> None:
        """patrol update on unknown patrol exits with error."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "update", "nonexistent", "--every", "1d"],
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        output = json.loads(result.output)
        assert output["status"] == "error"


# ─── patrol disable ─────────────────────────────────────────────────


class TestPatrolDisable:
    def test_disable_removes_crontab_entry(self, tmp_path: Path) -> None:
        """patrol disable removes the crontab entry but keeps config."""
        _write_config(tmp_path, extra={"patrols": {"sweep": {"every": "6h"}}})
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()
        mock_backend.entry_exists.return_value = True

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "disable", "sweep"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["status"] == "ok"
        mock_backend.remove_entry.assert_called_once_with("sweep")

        # Config still has patrol, but marked disabled
        config = _read_config(tmp_path)
        assert "sweep" in config["patrols"]
        assert config["patrols"]["sweep"].get("enabled") is False

    def test_disable_nonexistent_patrol_errors(self, tmp_path: Path) -> None:
        """patrol disable on unknown patrol exits with error."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "disable", "nonexistent"],
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        output = json.loads(result.output)
        assert output["status"] == "error"


# ─── patrol enable ──────────────────────────────────────────────────


class TestPatrolEnable:
    def test_enable_recreates_crontab_entry(self, tmp_path: Path) -> None:
        """patrol enable re-creates the crontab entry from config."""
        _write_config(
            tmp_path,
            extra={"patrols": {"sweep": {"every": "6h", "enabled": False}}},
        )
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()
        mock_backend.entry_exists.return_value = False

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "enable", "sweep"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["status"] == "ok"
        mock_backend.write_entry.assert_called_once()

        # Config should be marked enabled
        config = _read_config(tmp_path)
        assert config["patrols"]["sweep"].get("enabled") is not False

    def test_enable_nonexistent_patrol_errors(self, tmp_path: Path) -> None:
        """patrol enable on unknown patrol exits with error."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "enable", "nonexistent"],
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        output = json.loads(result.output)
        assert output["status"] == "error"


# ─── patrol remove ──────────────────────────────────────────────────


class TestPatrolRemove:
    def test_remove_removes_crontab_and_config(self, tmp_path: Path) -> None:
        """patrol remove cleans up both crontab entry and config."""
        _write_config(tmp_path, extra={"patrols": {"sweep": {"every": "6h"}}})
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()
        mock_backend.entry_exists.return_value = True

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "remove", "sweep"],
                catch_exceptions=False,
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["status"] == "ok"
        mock_backend.remove_entry.assert_called_once_with("sweep")

        config = _read_config(tmp_path)
        patrols = config.get("patrols", {})
        assert "sweep" not in patrols

    def test_remove_nonexistent_patrol_errors(self, tmp_path: Path) -> None:
        """patrol remove on unknown patrol exits with error."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "remove", "nonexistent"],
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        output = json.loads(result.output)
        assert output["status"] == "error"


# ─── patrol run ─────────────────────────────────────────────────────


class TestPatrolRun:
    def test_run_executes_watch_by_default(self, tmp_path: Path) -> None:
        """patrol run calls mallcop watch for a non-research patrol."""
        _write_config(tmp_path, extra={"patrols": {"sweep": {"every": "6h"}}})
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            with patch("mallcop.patrol_cli.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
                result = runner.invoke(
                    cli,
                    ["patrol", "run", "sweep"],
                    catch_exceptions=False,
                    env={"MALLCOP_REPO": str(tmp_path)},
                )

        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        assert output["status"] == "ok"
        # Should have called subprocess with mallcop watch
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert any("watch" in str(arg) for arg in call_args)

    def test_run_research_patrol_calls_research(self, tmp_path: Path) -> None:
        """patrol run calls mallcop research for a research patrol."""
        _write_config(
            tmp_path,
            extra={"patrols": {"deep": {"every": "1d", "research": True}}},
        )
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            with patch("mallcop.patrol_cli.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
                result = runner.invoke(
                    cli,
                    ["patrol", "run", "deep"],
                    catch_exceptions=False,
                    env={"MALLCOP_REPO": str(tmp_path)},
                )

        assert result.exit_code == 0, result.output
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert any("research" in str(arg) for arg in call_args)

    def test_run_nonexistent_patrol_errors(self, tmp_path: Path) -> None:
        """patrol run on unknown patrol exits with error."""
        _write_config(tmp_path)
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            result = runner.invoke(
                cli,
                ["patrol", "run", "nonexistent"],
                env={"MALLCOP_REPO": str(tmp_path)},
            )

        output = json.loads(result.output)
        assert output["status"] == "error"

    def test_run_reports_subprocess_failure(self, tmp_path: Path) -> None:
        """patrol run reports error when subprocess exits nonzero."""
        _write_config(tmp_path, extra={"patrols": {"sweep": {"every": "6h"}}})
        runner = CliRunner()
        mock_backend = _mock_crontab_backend()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=mock_backend):
            with patch("mallcop.patrol_cli.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stdout=b"", stderr=b"something failed"
                )
                result = runner.invoke(
                    cli,
                    ["patrol", "run", "sweep"],
                    env={"MALLCOP_REPO": str(tmp_path)},
                )

        output = json.loads(result.output)
        assert output["status"] == "error"
