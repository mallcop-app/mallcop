"""Unit tests for CrontabBackend: read/write/remove crontab entries for patrol scheduling."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from mallcop.crontab import CrontabBackend, PatrolEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MARKER_PREFIX = "# mallcop:patrol:"

SAMPLE_CRONTAB = """\
# existing user job
0 5 * * * /usr/bin/backup
# mallcop:patrol:sweep
*/30 * * * * cd /patrol && /opt/mallcop/venv/bin/mallcop watch && git add -A && git diff --cached --quiet || git commit -m "mallcop watch $(date -u +%Y-%m-%dT%H:%M:%SZ)" && git push
# mallcop:patrol:deep
0 2 * * * cd /patrol && /opt/mallcop/venv/bin/mallcop watch && git add -A && git diff --cached --quiet || git commit -m "mallcop watch $(date -u +%Y-%m-%dT%H:%M:%SZ)" && git push
"""

SAMPLE_CRONTAB_NO_MALLCOP = """\
# existing user job
0 5 * * * /usr/bin/backup
30 23 * * * /usr/bin/nightly
"""

EMPTY_CRONTAB = ""


def _make_backend(repo_path: str = "/patrol") -> CrontabBackend:
    return CrontabBackend(repo_path=Path(repo_path))


def _mock_crontab_list(content: str) -> MagicMock:
    """Return a mock for subprocess.run that returns crontab -l output."""
    mock = MagicMock()
    mock.returncode = 0
    mock.stdout = content.encode()
    mock.stderr = b""
    return mock


def _mock_crontab_list_empty() -> MagicMock:
    """Simulate 'no crontab for user' (returncode 1, empty stdout)."""
    mock = MagicMock()
    mock.returncode = 1
    mock.stdout = b""
    mock.stderr = b"no crontab for user\n"
    return mock


# ---------------------------------------------------------------------------
# read_entries
# ---------------------------------------------------------------------------


class TestReadEntries:
    def test_returns_all_mallcop_entries(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(SAMPLE_CRONTAB)):
            entries = backend.read_entries()
        assert len(entries) == 2
        names = [e.name for e in entries]
        assert "sweep" in names
        assert "deep" in names

    def test_ignores_non_mallcop_lines(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(SAMPLE_CRONTAB_NO_MALLCOP)):
            entries = backend.read_entries()
        assert entries == []

    def test_empty_crontab_returns_empty_list(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(EMPTY_CRONTAB)):
            entries = backend.read_entries()
        assert entries == []

    def test_no_crontab_for_user_returns_empty_list(self):
        """crontab -l exits 1 with 'no crontab for user' — should not raise."""
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list_empty()):
            entries = backend.read_entries()
        assert entries == []

    def test_entry_has_schedule(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(SAMPLE_CRONTAB)):
            entries = backend.read_entries()
        sweep = next(e for e in entries if e.name == "sweep")
        assert sweep.schedule == "*/30 * * * *"

    def test_entry_has_command(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(SAMPLE_CRONTAB)):
            entries = backend.read_entries()
        sweep = next(e for e in entries if e.name == "sweep")
        assert "mallcop watch" in sweep.command

    def test_malformed_crontab_line_skipped_gracefully(self):
        """A marker comment with no following crontab line should not crash."""
        malformed = "# mallcop:patrol:orphan\n"  # marker with no schedule line after
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(malformed)):
            entries = backend.read_entries()
        # Orphan marker with no schedule line: skipped or returned with empty schedule
        assert len(entries) <= 1  # may be 0 or 1 depending on impl, but must not crash


# ---------------------------------------------------------------------------
# entry_exists
# ---------------------------------------------------------------------------


class TestEntryExists:
    def test_returns_true_for_existing_entry(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(SAMPLE_CRONTAB)):
            assert backend.entry_exists("sweep") is True

    def test_returns_false_for_missing_entry(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(SAMPLE_CRONTAB)):
            assert backend.entry_exists("nonexistent") is False

    def test_returns_false_when_no_crontab(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list_empty()):
            assert backend.entry_exists("sweep") is False


# ---------------------------------------------------------------------------
# write_entry — git wrapper included by default
# ---------------------------------------------------------------------------


class TestWriteEntry:
    def test_writes_marker_comment_before_entry(self):
        backend = _make_backend(repo_path="/myrepo")
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(EMPTY_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.write_entry("sweep", "*/30 * * * *", "mallcop watch")

        assert any(line == "# mallcop:patrol:sweep" for line in written_lines)

    def test_git_wrapper_included_by_default(self):
        backend = _make_backend(repo_path="/myrepo")
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(EMPTY_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.write_entry("sweep", "*/30 * * * *", "mallcop watch", with_git=True)

        cron_line = next(l for l in written_lines if "mallcop" in l and not l.startswith("#"))
        assert "git add -A" in cron_line
        assert "git commit" in cron_line
        assert "git push" in cron_line

    def test_no_git_omits_git_wrapper(self):
        backend = _make_backend(repo_path="/myrepo")
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(EMPTY_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.write_entry("sweep", "*/30 * * * *", "mallcop watch", with_git=False)

        cron_line = next(l for l in written_lines if "mallcop" in l and not l.startswith("#"))
        assert "git" not in cron_line

    def test_entry_includes_cd_to_repo(self):
        backend = _make_backend(repo_path="/myrepo")
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(EMPTY_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.write_entry("sweep", "*/30 * * * *", "mallcop watch")

        cron_line = next(l for l in written_lines if "mallcop" in l and not l.startswith("#"))
        assert "cd /myrepo" in cron_line

    def test_existing_entry_replaced(self):
        """Writing a patrol that already exists replaces it (idempotent)."""
        backend = _make_backend(repo_path="/patrol")
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(SAMPLE_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.write_entry("sweep", "0 * * * *", "mallcop watch")  # new schedule

        # Only one sweep marker should appear
        markers = [l for l in written_lines if l == "# mallcop:patrol:sweep"]
        assert len(markers) == 1

        # New schedule in cron line
        cron_line = next(
            (l for l in written_lines if "mallcop" in l and not l.startswith("#") and "sweep" not in l.split()[0]),
            None,
        )
        # Find the sweep cron line (line after the sweep marker)
        marker_idx = written_lines.index("# mallcop:patrol:sweep")
        new_cron_line = written_lines[marker_idx + 1]
        assert new_cron_line.startswith("0 * * * *")

    def test_research_command_used_for_research_patrol(self):
        """When command is 'mallcop research', entry uses mallcop research."""
        backend = _make_backend(repo_path="/myrepo")
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(EMPTY_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.write_entry("research", "0 3 * * 0", "mallcop research")

        cron_line = next(l for l in written_lines if "mallcop" in l and not l.startswith("#"))
        assert "mallcop research" in cron_line

    def test_preserves_non_mallcop_lines(self):
        """Existing non-mallcop crontab entries are preserved."""
        backend = _make_backend(repo_path="/myrepo")
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(SAMPLE_CRONTAB_NO_MALLCOP)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.write_entry("sweep", "*/30 * * * *", "mallcop watch")

        assert any("/usr/bin/backup" in l for l in written_lines)
        assert any("/usr/bin/nightly" in l for l in written_lines)


# ---------------------------------------------------------------------------
# remove_entry
# ---------------------------------------------------------------------------


class TestRemoveEntry:
    def test_removes_existing_entry_returns_true(self):
        backend = _make_backend()
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(SAMPLE_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            result = backend.remove_entry("sweep")

        assert result is True
        assert not any("mallcop:patrol:sweep" in l for l in written_lines)

    def test_missing_entry_returns_false(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list(SAMPLE_CRONTAB)):
            result = backend.remove_entry("nonexistent")
        assert result is False

    def test_remove_preserves_other_mallcop_entries(self):
        backend = _make_backend()
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(SAMPLE_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.remove_entry("sweep")

        # deep entry still present
        assert any("mallcop:patrol:deep" in l for l in written_lines)

    def test_remove_preserves_non_mallcop_lines(self):
        backend = _make_backend()
        written_lines: list[str] = []

        def fake_run(args, **kwargs):
            if args == ["crontab", "-l"]:
                return _mock_crontab_list(SAMPLE_CRONTAB)
            if args[0] == "crontab" and args[1] == "-":
                written_lines.extend(kwargs.get("input", b"").decode().splitlines())
                mock = MagicMock()
                mock.returncode = 0
                return mock
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run):
            backend.remove_entry("sweep")

        assert any("/usr/bin/backup" in l for l in written_lines)

    def test_remove_when_no_crontab_returns_false(self):
        backend = _make_backend()
        with patch("subprocess.run", return_value=_mock_crontab_list_empty()):
            result = backend.remove_entry("sweep")
        assert result is False
