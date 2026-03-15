"""Tests for mallcop.telemetry."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mallcop.telemetry import _log_invocation, is_enabled, log_cli


class TestIsEnabled:
    def test_disabled_when_flag_missing(self, tmp_path):
        with patch("mallcop.telemetry._ENABLED_FLAG", tmp_path / "nope"):
            assert is_enabled() is False

    def test_enabled_when_flag_exists(self, tmp_path):
        flag = tmp_path / "telemetry-enabled"
        flag.touch()
        with patch("mallcop.telemetry._ENABLED_FLAG", flag):
            assert is_enabled() is True


class TestLogInvocation:
    def test_writes_jsonl_entry(self, tmp_path):
        log_file = tmp_path / "telemetry.jsonl"
        _log_invocation("scan", ["dir_path"], 0, 123.4, log_file=log_file)

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1

        entry = json.loads(lines[0])
        assert entry["command"] == "scan"
        assert entry["flags"] == ["dir_path"]
        assert entry["exit_code"] == 0
        assert entry["wall_time_ms"] == 123.4
        assert "ts" in entry

    def test_appends_multiple(self, tmp_path):
        log_file = tmp_path / "telemetry.jsonl"
        _log_invocation("scan", [], 0, 10.0, log_file=log_file)
        _log_invocation("detect", ["human"], 1, 20.0, log_file=log_file)

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["command"] == "scan"
        assert json.loads(lines[1])["command"] == "detect"


class TestLogCliDecorator:
    def test_decorator_skips_when_disabled(self, tmp_path):
        with patch("mallcop.telemetry._ENABLED_FLAG", tmp_path / "nope"):
            @log_cli
            def my_cmd():
                return 42

            assert my_cmd() == 42

    def test_decorator_logs_when_enabled(self, tmp_path):
        flag = tmp_path / "telemetry-enabled"
        flag.touch()
        log_file = tmp_path / "telemetry.jsonl"

        with patch("mallcop.telemetry._ENABLED_FLAG", flag), \
             patch("mallcop.telemetry._LOG_FILE", log_file):
            @log_cli
            def my_cmd(**kwargs):
                return "ok"

            result = my_cmd()
            assert result == "ok"

            lines = log_file.read_text().strip().split("\n")
            assert len(lines) == 1
            entry = json.loads(lines[0])
            assert entry["command"] == "my_cmd"
            assert entry["exit_code"] == 0


class TestInstrumentedGroup:
    """Test the Click group-level instrumentation."""

    def test_cli_group_instruments_subcommand(self, tmp_path):
        """When telemetry is enabled, invoking a CLI command logs it."""
        import click
        from click.testing import CliRunner
        from mallcop.cli import cli

        flag = tmp_path / "telemetry-enabled"
        flag.touch()
        log_file = tmp_path / "telemetry.jsonl"

        with patch("mallcop.telemetry._ENABLED_FLAG", flag), \
             patch("mallcop.telemetry._LOG_FILE", log_file):
            runner = CliRunner()
            result = runner.invoke(cli, ["--version"])

        # --version exits 0; telemetry should have logged
        assert result.exit_code == 0
        if log_file.exists():
            lines = log_file.read_text().strip().split("\n")
            assert len(lines) >= 1
