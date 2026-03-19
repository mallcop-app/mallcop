"""Tests for crontab.py error handling and path quoting."""

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from mallcop.crontab import CrontabBackend


class TestReadRawLinesErrorHandling:

    def test_no_crontab_returns_empty(self):
        """'no crontab for user' stderr should return empty list, not raise."""
        backend = CrontabBackend()
        result = MagicMock()
        result.returncode = 1
        result.stderr = b"no crontab for baron"
        with patch("mallcop.crontab.subprocess.run", return_value=result):
            lines = backend._read_raw_lines()
        assert lines == []

    def test_permission_error_raises(self):
        """Non-'no crontab' errors should raise RuntimeError."""
        backend = CrontabBackend()
        result = MagicMock()
        result.returncode = 1
        result.stderr = b"Permission denied"
        with patch("mallcop.crontab.subprocess.run", return_value=result):
            with pytest.raises(RuntimeError, match="crontab -l failed"):
                backend._read_raw_lines()

    def test_success_returns_lines(self):
        backend = CrontabBackend()
        result = MagicMock()
        result.returncode = 0
        result.stdout = b"# mallcop:patrol:test\n*/5 * * * * /opt/mallcop\n"
        with patch("mallcop.crontab.subprocess.run", return_value=result):
            lines = backend._read_raw_lines()
        assert len(lines) == 2


class TestWriteRawLinesErrorHandling:

    def test_write_failure_raises(self):
        """Failed crontab write should raise RuntimeError."""
        backend = CrontabBackend()
        result = MagicMock()
        result.returncode = 1
        result.stderr = b"crontab: installing new crontab failed"
        with patch("mallcop.crontab.subprocess.run", return_value=result):
            with pytest.raises(RuntimeError, match="crontab write failed"):
                backend._write_raw_lines(["# test line"])

    def test_write_success_does_not_raise(self):
        backend = CrontabBackend()
        result = MagicMock()
        result.returncode = 0
        result.stderr = b""
        with patch("mallcop.crontab.subprocess.run", return_value=result):
            backend._write_raw_lines(["# test line"])


class TestBuildCommandPathQuoting:

    def test_path_with_spaces_is_quoted(self):
        backend = CrontabBackend(repo_path=Path("/home/baron/my projects/deploy"))
        cmd = backend._build_command("watch --once", with_git=False)
        assert "'/home/baron/my projects/deploy'" in cmd

    def test_normal_path_is_quoted(self):
        backend = CrontabBackend(repo_path=Path("/home/baron/projects/mallcop"))
        cmd = backend._build_command("watch --once", with_git=False)
        assert "/home/baron/projects/mallcop" in cmd


# ─── 5.8: crontab edge cases ──────────────────────────────────────────────────


class TestReadEntriesEdgeCases:
    """mallcop-ak1n.5.8: read_entries and write_entry edge cases."""

    def _mock_read(self, lines: list[str]):
        """Return a mock subprocess result for crontab -l."""
        result = MagicMock()
        result.returncode = 0
        result.stdout = "\n".join(lines).encode() + b"\n"
        return result

    def _mock_write(self):
        result = MagicMock()
        result.returncode = 0
        result.stderr = b""
        return result

    def test_read_entries_short_cron_line_skipped(self):
        """Cron entries with fewer than 6 fields are silently skipped."""
        lines = [
            "# mallcop:patrol:short",
            "* * * * cmd_only_five_parts",
        ]
        backend = CrontabBackend()
        read_result = self._mock_read(lines)
        with patch("mallcop.crontab.subprocess.run", return_value=read_result):
            entries = backend.read_entries()
        # Entry with only 5 fields (no repo path as 6th) should be skipped
        assert len(entries) == 0

    def test_read_entries_valid_six_field_line_is_parsed(self):
        """Standard 6-field cron line (5 schedule fields + command) is parsed correctly."""
        lines = [
            "# mallcop:patrol:hourly",
            "0 * * * * /opt/mallcop/venv/bin/mallcop watch --dir /repo",
        ]
        backend = CrontabBackend()
        read_result = self._mock_read(lines)
        with patch("mallcop.crontab.subprocess.run", return_value=read_result):
            entries = backend.read_entries()
        assert len(entries) == 1
        assert entries[0].name == "hourly"
        assert entries[0].schedule == "0 * * * *"

    def test_write_entry_idempotent_no_duplicate(self):
        """Calling write_entry twice for the same name produces exactly one marker+line."""
        existing_lines = [
            "# mallcop:patrol:sweep",
            "*/30 * * * * /opt/mallcop/venv/bin/mallcop watch --dir /repo",
        ]
        backend = CrontabBackend(repo_path=Path("/repo"))
        read_result = MagicMock()
        read_result.returncode = 0
        read_result.stdout = "\n".join(existing_lines).encode() + b"\n"

        written_contents: list[bytes] = []

        def fake_run(cmd, **kwargs):
            if cmd[0] == "crontab" and cmd[1] == "-l":
                return read_result
            if cmd[0] == "crontab" and cmd[1] == "-":
                written_contents.append(kwargs.get("input", b""))
                r = MagicMock()
                r.returncode = 0
                r.stderr = b""
                return r
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("mallcop.crontab.subprocess.run", side_effect=fake_run):
            backend.write_entry(name="sweep", schedule="0 * * * *", command="watch", with_git=False)

        assert len(written_contents) == 1
        written_text = written_contents[0].decode()
        # Only one marker for 'sweep'
        assert written_text.count("# mallcop:patrol:sweep") == 1

    def test_patrol_name_with_space_in_marker(self):
        """Patrol names with spaces are stored in the marker comment as-is."""
        backend = CrontabBackend(repo_path=Path("/repo"))
        read_lines: list[list[str]] = [[]]

        def fake_run(cmd, **kwargs):
            if cmd[0] == "crontab" and cmd[1] == "-l":
                r = MagicMock()
                r.returncode = 1
                r.stderr = b"no crontab for user"
                return r
            if cmd[0] == "crontab" and cmd[1] == "-":
                content = kwargs.get("input", b"").decode()
                read_lines[0] = content.splitlines()
                r = MagicMock()
                r.returncode = 0
                r.stderr = b""
                return r

        with patch("mallcop.crontab.subprocess.run", side_effect=fake_run):
            backend.write_entry(name="my patrol", schedule="0 * * * *", command="watch", with_git=False)

        # The marker should contain the name as-is
        assert any("# mallcop:patrol:my patrol" in line for line in read_lines[0])
