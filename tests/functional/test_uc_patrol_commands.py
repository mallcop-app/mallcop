"""UC: Patrol lifecycle and validation — create, list, update, disable, enable, remove, run.

Functional tests exercising patrol CLI commands end-to-end with a FakeCrontabBackend
that writes to a tmp file instead of the system crontab.

We mock:
  - CrontabBackend (no system crontab writes) via FakeCrontabBackend
  - subprocess.run for patrol run (no actual mallcop subprocess)

We verify:
  - Full lifecycle: create -> list -> update -> disable -> enable -> remove
  - Validation errors: invalid period, duplicate name, budget over max, update nonexistent
  - patrol run invokes the correct subprocess command
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli


# ---------------------------------------------------------------------------
# FakeCrontabBackend
# ---------------------------------------------------------------------------


class FakeCrontabBackend:
    """CrontabBackend replacement that writes to a tmp file, never the system crontab."""

    def __init__(self, crontab_file: Path, repo_path: Path | None = None) -> None:
        self._file = crontab_file
        self.repo_path = repo_path or Path.cwd()
        # Ensure file exists
        if not self._file.exists():
            self._file.write_text("")

    # Replicate the real backend's public API

    def write_entry(self, name: str, schedule: str, command: str, with_git: bool = True) -> None:
        lines = self._read_lines()
        lines = self._remove_patrol_lines(lines, name)
        marker = f"# mallcop:patrol:{name}"
        cron_line = f"{schedule} /opt/mallcop/venv/bin/mallcop {command}"
        if lines and lines[-1] != "":
            lines.append("")
        lines.append(marker)
        lines.append(cron_line)
        self._write_lines(lines)

    def read_entries(self):
        from mallcop.crontab import PatrolEntry
        lines = self._read_lines()
        entries = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("# mallcop:patrol:"):
                name = line[len("# mallcop:patrol:"):]
                j = i + 1
                while j < len(lines) and lines[j].strip() == "":
                    j += 1
                if j < len(lines) and not lines[j].startswith("#"):
                    cron_line = lines[j]
                    parts = cron_line.split(None, 5)
                    if len(parts) >= 6:
                        schedule = " ".join(parts[:5])
                        command = parts[5]
                        entries.append(PatrolEntry(name=name, schedule=schedule, command=command))
                    i = j + 1
                    continue
            i += 1
        return entries

    def remove_entry(self, name: str) -> bool:
        lines = self._read_lines()
        original = list(lines)
        lines = self._remove_patrol_lines(lines, name)
        if lines == original:
            return False
        self._write_lines(lines)
        return True

    def entry_exists(self, name: str) -> bool:
        return any(e.name == name for e in self.read_entries())

    def _read_lines(self) -> list[str]:
        text = self._file.read_text()
        lines = text.splitlines()
        while lines and lines[-1].strip() == "":
            lines.pop()
        return lines

    def _write_lines(self, lines: list[str]) -> None:
        content = "\n".join(lines)
        if content and not content.endswith("\n"):
            content += "\n"
        self._file.write_text(content)

    @staticmethod
    def _remove_patrol_lines(lines: list[str], name: str) -> list[str]:
        marker = f"# mallcop:patrol:{name}"
        result: list[str] = []
        i = 0
        while i < len(lines):
            if lines[i] == marker:
                j = i + 1
                while j < len(lines) and lines[j].strip() == "":
                    j += 1
                if j < len(lines) and not lines[j].startswith("#"):
                    i = j + 1
                else:
                    i += 1
                continue
            result.append(lines[i])
            i += 1
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(root: Path, max_donuts: int = 50000) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
        "budget": {"max_donuts_per_run": max_donuts},
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


def _make_patrol_backend(tmp_path: Path, repo_path: Path) -> FakeCrontabBackend:
    crontab_file = tmp_path / "crontab"
    crontab_file.touch()
    return FakeCrontabBackend(crontab_file, repo_path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.functional
class TestPatrolLifecycle:
    """Full patrol lifecycle: create -> list -> update -> disable -> enable -> remove."""

    def test_patrol_full_lifecycle(self, tmp_path: Path) -> None:
        """Complete lifecycle exercised sequentially against a tmp deployment repo."""
        root = tmp_path
        _make_config(root)

        crontab_file = tmp_path / "crontab.txt"
        crontab_file.touch()
        backend = FakeCrontabBackend(crontab_file, root)

        runner = CliRunner()

        with patch("mallcop.patrol_cli.CrontabBackend", return_value=backend), \
             patch.dict("os.environ", {"MALLCOP_REPO": str(root)}):

            # --- create ---
            r = runner.invoke(cli, ["patrol", "create", "nightly", "--every", "1d"])
            assert r.exit_code == 0, f"create failed: {r.output}"
            data = json.loads(r.output)
            assert data["status"] == "ok"
            assert data["name"] == "nightly"
            assert data["every"] == "1d"
            assert "0 0 * * *" in data["schedule"]

            # --- list (shows the created entry) ---
            r = runner.invoke(cli, ["patrol", "list"])
            assert r.exit_code == 0, f"list failed: {r.output}"
            data = json.loads(r.output)
            assert data["status"] == "ok"
            patrol_names = [p["name"] for p in data["patrols"]]
            assert "nightly" in patrol_names

            nightly = next(p for p in data["patrols"] if p["name"] == "nightly")
            assert nightly["every"] == "1d"
            assert nightly["enabled"] is True

            # --- update (change period) ---
            r = runner.invoke(cli, ["patrol", "update", "nightly", "--every", "6h"])
            assert r.exit_code == 0, f"update failed: {r.output}"
            data = json.loads(r.output)
            assert data["status"] == "ok"
            assert data["name"] == "nightly"
            assert "0 */6 * * *" in data["schedule"]

            # Verify list shows updated period
            r = runner.invoke(cli, ["patrol", "list"])
            assert r.exit_code == 0
            data = json.loads(r.output)
            nightly = next(p for p in data["patrols"] if p["name"] == "nightly")
            assert nightly["every"] == "6h"

            # --- disable (removes crontab entry, marks disabled) ---
            r = runner.invoke(cli, ["patrol", "disable", "nightly"])
            assert r.exit_code == 0, f"disable failed: {r.output}"
            data = json.loads(r.output)
            assert data["status"] == "ok"
            assert data["enabled"] is False

            # list should show disabled
            r = runner.invoke(cli, ["patrol", "list"])
            assert r.exit_code == 0
            data = json.loads(r.output)
            nightly = next(p for p in data["patrols"] if p["name"] == "nightly")
            assert nightly["enabled"] is False

            # --- enable (re-creates crontab entry) ---
            r = runner.invoke(cli, ["patrol", "enable", "nightly"])
            assert r.exit_code == 0, f"enable failed: {r.output}"
            data = json.loads(r.output)
            assert data["status"] == "ok"
            assert data["enabled"] is True

            # list should show enabled
            r = runner.invoke(cli, ["patrol", "list"])
            assert r.exit_code == 0
            data = json.loads(r.output)
            nightly = next(p for p in data["patrols"] if p["name"] == "nightly")
            assert nightly["enabled"] is True

            # --- remove (removes from crontab + config) ---
            r = runner.invoke(cli, ["patrol", "remove", "nightly"])
            assert r.exit_code == 0, f"remove failed: {r.output}"
            data = json.loads(r.output)
            assert data["status"] == "ok"
            assert data["removed"] is True

            # list should not show it anymore
            r = runner.invoke(cli, ["patrol", "list"])
            assert r.exit_code == 0
            data = json.loads(r.output)
            patrol_names = [p["name"] for p in data["patrols"]]
            assert "nightly" not in patrol_names


@pytest.mark.functional
class TestPatrolValidationErrors:
    """Error conditions for patrol commands."""

    def test_invalid_cron_period(self, tmp_path: Path) -> None:
        """Invalid period string returns error JSON and exits 1."""
        root = tmp_path
        _make_config(root)

        crontab_file = tmp_path / "crontab.txt"
        crontab_file.touch()
        backend = FakeCrontabBackend(crontab_file, root)

        runner = CliRunner()
        with patch("mallcop.patrol_cli.CrontabBackend", return_value=backend), \
             patch.dict("os.environ", {"MALLCOP_REPO": str(root)}):
            r = runner.invoke(cli, ["patrol", "create", "bad-patrol", "--every", "notaperiod"])
        assert r.exit_code == 1
        data = json.loads(r.output)
        assert data["status"] == "error"
        assert "error" in data
        assert "notaperiod" in data["error"] or "Invalid" in data["error"] or "period" in data["error"].lower()

    def test_duplicate_patrol_name(self, tmp_path: Path) -> None:
        """Creating a patrol with an already-used name returns error JSON and exits 1."""
        root = tmp_path
        _make_config(root)

        crontab_file = tmp_path / "crontab.txt"
        crontab_file.touch()
        backend = FakeCrontabBackend(crontab_file, root)

        runner = CliRunner()
        with patch("mallcop.patrol_cli.CrontabBackend", return_value=backend), \
             patch.dict("os.environ", {"MALLCOP_REPO": str(root)}):
            # First create succeeds
            r = runner.invoke(cli, ["patrol", "create", "daily", "--every", "1d"])
            assert r.exit_code == 0

            # Second create with same name fails
            r = runner.invoke(cli, ["patrol", "create", "daily", "--every", "1h"])
        assert r.exit_code == 1
        data = json.loads(r.output)
        assert data["status"] == "error"
        assert "already exists" in data["error"] or "daily" in data["error"]

    def test_budget_over_max(self, tmp_path: Path) -> None:
        """Patrol budget exceeding max_donuts_per_run returns error JSON and exits 1."""
        root = tmp_path
        _make_config(root, max_donuts=50000)

        crontab_file = tmp_path / "crontab.txt"
        crontab_file.touch()
        backend = FakeCrontabBackend(crontab_file, root)

        runner = CliRunner()
        with patch("mallcop.patrol_cli.CrontabBackend", return_value=backend), \
             patch.dict("os.environ", {"MALLCOP_REPO": str(root)}):
            r = runner.invoke(cli, ["patrol", "create", "overbudget", "--every", "1d", "--budget", "999999"])
        assert r.exit_code == 1
        data = json.loads(r.output)
        assert data["status"] == "error"
        assert "budget" in data["error"].lower() or "999999" in data["error"] or "50000" in data["error"]

    def test_update_nonexistent_patrol(self, tmp_path: Path) -> None:
        """Updating a patrol that doesn't exist returns error JSON and exits 1."""
        root = tmp_path
        _make_config(root)

        crontab_file = tmp_path / "crontab.txt"
        crontab_file.touch()
        backend = FakeCrontabBackend(crontab_file, root)

        runner = CliRunner()
        with patch("mallcop.patrol_cli.CrontabBackend", return_value=backend), \
             patch.dict("os.environ", {"MALLCOP_REPO": str(root)}):
            r = runner.invoke(cli, ["patrol", "update", "ghost-patrol", "--every", "1h"])
        assert r.exit_code == 1
        data = json.loads(r.output)
        assert data["status"] == "error"
        assert "not found" in data["error"] or "ghost-patrol" in data["error"]


@pytest.mark.functional
class TestPatrolRun:
    """patrol run invokes a watch subprocess with correct arguments."""

    def test_patrol_run_invokes_watch(self, tmp_path: Path) -> None:
        """After creating a patrol, patrol run executes mallcop watch --dir <root>."""
        root = tmp_path
        _make_config(root)

        crontab_file = tmp_path / "crontab.txt"
        crontab_file.touch()
        backend = FakeCrontabBackend(crontab_file, root)

        runner = CliRunner()
        with patch("mallcop.patrol_cli.CrontabBackend", return_value=backend), \
             patch.dict("os.environ", {"MALLCOP_REPO": str(root)}):
            # Create the patrol first
            r = runner.invoke(cli, ["patrol", "create", "nightly", "--every", "1d"])
            assert r.exit_code == 0

            # Run patrol run with mocked subprocess
            with patch("mallcop.patrol_cli.subprocess.run") as mock_sub:
                mock_sub.return_value = MagicMock(returncode=0, stderr=b"")
                r = runner.invoke(cli, ["patrol", "run", "nightly"])

        assert r.exit_code == 0, f"patrol run failed: {r.output}"
        data = json.loads(r.output)
        assert data["status"] == "ok"
        assert data["name"] == "nightly"

        # Verify subprocess.run was called with a watch command
        assert mock_sub.called
        called_cmd = mock_sub.call_args[0][0]
        assert "watch" in called_cmd

    def test_patrol_run_research_patrol(self, tmp_path: Path) -> None:
        """Research patrol invokes mallcop research subprocess."""
        root = tmp_path
        _make_config(root)

        crontab_file = tmp_path / "crontab.txt"
        crontab_file.touch()
        backend = FakeCrontabBackend(crontab_file, root)

        runner = CliRunner()
        with patch("mallcop.patrol_cli.CrontabBackend", return_value=backend), \
             patch.dict("os.environ", {"MALLCOP_REPO": str(root)}):
            # Create a research patrol
            r = runner.invoke(cli, ["patrol", "create", "research-nightly", "--every", "1d", "--research"])
            assert r.exit_code == 0
            create_data = json.loads(r.output)
            assert create_data["command"] == "research"

            with patch("mallcop.patrol_cli.subprocess.run") as mock_sub:
                mock_sub.return_value = MagicMock(returncode=0, stderr=b"")
                r = runner.invoke(cli, ["patrol", "run", "research-nightly"])

        assert r.exit_code == 0, f"patrol run failed: {r.output}"
        data = json.loads(r.output)
        assert data["command"] == "research"

        called_cmd = mock_sub.call_args[0][0]
        assert "research" in called_cmd

    def test_patrol_run_results_in_ok(self, tmp_path: Path) -> None:
        """patrol run with exit_code=0 subprocess returns ok status."""
        root = tmp_path
        _make_config(root)

        crontab_file = tmp_path / "crontab.txt"
        crontab_file.touch()
        backend = FakeCrontabBackend(crontab_file, root)

        runner = CliRunner()
        with patch("mallcop.patrol_cli.CrontabBackend", return_value=backend), \
             patch.dict("os.environ", {"MALLCOP_REPO": str(root)}):
            r = runner.invoke(cli, ["patrol", "create", "p1", "--every", "15m"])
            assert r.exit_code == 0

            with patch("mallcop.patrol_cli.subprocess.run") as mock_sub:
                mock_sub.return_value = MagicMock(returncode=0, stderr=b"")
                r = runner.invoke(cli, ["patrol", "run", "p1"])

        assert r.exit_code == 0
        data = json.loads(r.output)
        assert data["status"] == "ok"
        assert data["exit_code"] == 0
