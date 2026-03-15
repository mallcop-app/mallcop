"""Crontab backend: read/write/remove crontab entries for patrol scheduling.

Each patrol is represented by a pair of lines in the crontab:
    # mallcop:patrol:<name>
    <schedule> <command>

The marker comment makes mallcop entries identifiable and manageable without
touching other crontab content.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CrontabBackend",
    "PatrolEntry",
]

MARKER_PREFIX = "# mallcop:patrol:"
MALLCOP_BIN = "/opt/mallcop/venv/bin/mallcop"

GIT_WRAPPER = (
    "git add -A && git diff --cached --quiet || "
    'git commit -m "mallcop watch $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" && git push'
)


@dataclass
class PatrolEntry:
    """A single patrol crontab entry."""

    name: str
    schedule: str
    command: str


class CrontabBackend:
    """Manages mallcop patrol entries in the user's crontab.

    All operations are atomic: read current crontab → modify in memory → write
    back. Non-mallcop lines are always preserved unchanged.
    """

    def __init__(self, repo_path: Path | None = None) -> None:
        self.repo_path = repo_path or Path.cwd()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write_entry(
        self,
        name: str,
        schedule: str,
        command: str,
        with_git: bool = True,
    ) -> None:
        """Write (or replace) a crontab entry for a patrol.

        Args:
            name: Patrol name — used in the marker comment and as identifier.
            schedule: Cron schedule expression, e.g. ``*/30 * * * *``.
            command: The mallcop subcommand to run (``mallcop watch`` or
                ``mallcop research``).  Do not include ``cd`` — it is added
                automatically using ``self.repo_path``.
            with_git: When True (default), append the git lifecycle wrapper
                (``git add -A && git commit && git push``) after the mallcop
                command.
        """
        lines = self._read_raw_lines()

        # Remove any existing entry for this name
        lines = self._remove_patrol_lines(lines, name)

        # Build the full shell command
        full_cmd = self._build_command(command, with_git)
        cron_line = f"{schedule} {full_cmd}"

        # Append new entry (marker + cron line)
        if lines and lines[-1] != "":
            lines.append("")
        lines.append(f"{MARKER_PREFIX}{name}")
        lines.append(cron_line)

        self._write_raw_lines(lines)

    def read_entries(self) -> list[PatrolEntry]:
        """Read all mallcop patrol entries from the crontab.

        Returns an empty list if there is no crontab or no mallcop entries.
        Malformed entries (marker with no following cron line) are skipped.
        """
        lines = self._read_raw_lines()
        entries: list[PatrolEntry] = []

        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith(MARKER_PREFIX):
                name = line[len(MARKER_PREFIX):]
                # Next non-empty line should be the cron entry
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
                # Orphan marker — skip
            i += 1

        return entries

    def remove_entry(self, name: str) -> bool:
        """Remove a patrol entry by name.

        Returns:
            True if the entry was found and removed, False if it was not present.
        """
        lines = self._read_raw_lines()
        original = list(lines)
        lines = self._remove_patrol_lines(lines, name)

        if lines == original:
            return False

        self._write_raw_lines(lines)
        return True

    def entry_exists(self, name: str) -> bool:
        """Return True if a patrol entry with the given name exists."""
        return any(e.name == name for e in self.read_entries())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_command(self, command: str, with_git: bool) -> str:
        """Build the full shell command for a crontab line."""
        repo = str(self.repo_path)
        mallcop_cmd = f"{MALLCOP_BIN} {command.removeprefix('mallcop ').strip()}"
        base = f"cd {repo} && {mallcop_cmd}"
        if with_git:
            return f"{base} && {GIT_WRAPPER}"
        return base

    def _read_raw_lines(self) -> list[str]:
        """Read current crontab contents as a list of lines (no trailing newlines).

        Returns an empty list if there is no crontab for the current user.
        """
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
        )
        # rc=1 with "no crontab for user" is the normal empty state
        if result.returncode != 0:
            return []

        text = result.stdout.decode(errors="replace")
        # splitlines handles \r\n, \n, etc.
        lines = text.splitlines()
        # Strip trailing empty lines to keep the file tidy
        while lines and lines[-1].strip() == "":
            lines.pop()
        return lines

    def _write_raw_lines(self, lines: list[str]) -> None:
        """Write lines back to the crontab via ``crontab -``."""
        content = "\n".join(lines)
        if content and not content.endswith("\n"):
            content += "\n"
        subprocess.run(
            ["crontab", "-"],
            input=content.encode(),
            capture_output=True,
        )

    @staticmethod
    def _remove_patrol_lines(lines: list[str], name: str) -> list[str]:
        """Return a copy of lines with the named patrol's marker + cron line removed."""
        marker = f"{MARKER_PREFIX}{name}"
        result: list[str] = []
        i = 0
        while i < len(lines):
            if lines[i] == marker:
                # Skip the marker and the following cron line (if any)
                j = i + 1
                while j < len(lines) and lines[j].strip() == "":
                    j += 1
                if j < len(lines) and not lines[j].startswith("#"):
                    i = j + 1  # skip marker + cron line
                else:
                    i += 1  # skip only the orphan marker
                continue
            result.append(lines[i])
            i += 1
        return result
