"""Git-oops detector: scans git repos for leaked credentials and security antipatterns.

Unlike cloud-event detectors, git-oops scans file contents directly.
Patterns are YAML-driven (patterns.yaml) and extensible.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

# Binary file extensions to skip
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".db", ".sqlite", ".sqlite3",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
})

# Max file size to scan (1 MB)
_MAX_FILE_SIZE = 1_048_576


def _load_patterns(patterns_path: Path | None = None) -> list[dict[str, Any]]:
    """Load pattern rules from patterns.yaml."""
    if patterns_path is None:
        patterns_path = Path(__file__).parent / "patterns.yaml"
    with open(patterns_path) as f:
        data = yaml.safe_load(f)
    return data.get("patterns", [])


def _git_tracked_files(repo_path: Path) -> list[str] | None:
    """Get list of tracked files via git ls-files. Returns None if not a git repo."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        return [line for line in result.stdout.splitlines() if line]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _walk_files(repo_path: Path) -> list[str]:
    """Walk directory tree, returning relative file paths. Fallback when git unavailable."""
    files = []
    for path in repo_path.rglob("*"):
        if path.is_file() and ".git" not in path.parts:
            files.append(str(path.relative_to(repo_path)))
    return files


def _expand_braces(pattern: str) -> list[str]:
    """Expand brace alternatives: **/*.{py,js} -> [**/*.py, **/*.js]."""
    brace_match = re.search(r"\{([^}]+)\}", pattern)
    if not brace_match:
        return [pattern]
    alternatives = brace_match.group(1).split(",")
    prefix = pattern[: brace_match.start()]
    suffix = pattern[brace_match.end() :]
    return [prefix + alt.strip() + suffix for alt in alternatives]


def _match_file_glob(filepath: str, file_glob: str) -> bool:
    """Check if filepath matches the pattern's file_glob.

    Supports ** for recursive matching and {a,b} brace expansion.
    PurePath.match('**/*.py') doesn't match root-level 'app.py',
    so we also try the pattern without the **/ prefix.
    """
    from pathlib import PurePath

    path = PurePath(filepath)
    for pattern in _expand_braces(file_glob):
        if path.match(pattern):
            return True
        # PurePath.match('**/*.py') misses root-level files — try without **/
        if pattern.startswith("**/"):
            if path.match(pattern[3:]):
                return True
    return False


def _is_binary(filepath: Path) -> bool:
    """Quick check if file is likely binary."""
    return filepath.suffix.lower() in _BINARY_EXTENSIONS


def scan_repo(
    repo_path: Path,
    patterns: list[dict[str, Any]] | None = None,
    patterns_path: Path | None = None,
) -> list[Finding]:
    """Scan a repo for credential leaks and antipatterns.

    Args:
        repo_path: Path to the git repository root.
        patterns: Pre-loaded pattern rules (overrides patterns_path).
        patterns_path: Path to patterns.yaml (defaults to bundled file).

    Returns:
        List of findings for each pattern match.
    """
    if patterns is None:
        patterns = _load_patterns(patterns_path)

    # Get file list — prefer git-tracked, fall back to walk
    tracked = _git_tracked_files(repo_path)
    file_list = tracked if tracked is not None else _walk_files(repo_path)

    # Compile regexes once
    compiled: list[tuple[dict[str, Any], re.Pattern[str]]] = []
    for pat in patterns:
        try:
            compiled.append((pat, re.compile(pat["regex"])))
        except re.error:
            continue  # Skip invalid patterns

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()  # (pattern_id, filepath) dedup

    for rel_path in file_list:
        full_path = repo_path / rel_path

        # Skip binary files
        if _is_binary(full_path):
            continue

        # Skip files larger than limit
        try:
            if full_path.stat().st_size > _MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        for pat, regex in compiled:
            if not _match_file_glob(rel_path, pat["file_glob"]):
                continue

            # Read and scan
            try:
                content = full_path.read_text(errors="replace")
            except OSError:
                continue

            matches = list(regex.finditer(content))
            if not matches:
                continue

            dedup_key = (pat["id"], rel_path)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Find line numbers for first few matches
            match_lines = []
            for m in matches[:5]:
                line_no = content[: m.start()].count("\n") + 1
                match_lines.append(line_no)

            severity_str = pat.get("severity", "warn")
            severity = Severity(severity_str)

            findings.append(
                Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    detector="git-oops",
                    event_ids=[],
                    title=f"git-oops: {pat['description']} in {rel_path}",
                    severity=severity,
                    status=FindingStatus.OPEN,
                    annotations=[],
                    metadata={
                        "pattern_id": pat["id"],
                        "file": rel_path,
                        "match_count": len(matches),
                        "line_numbers": match_lines,
                        "description": pat["description"],
                    },
                )
            )

    return findings


class GitOopsDetector(DetectorBase):
    """Scans git repos for leaked credentials and security antipatterns.

    Unlike other detectors, git-oops scans file contents directly rather
    than processing cloud events. Pass repo_paths to scan specific repos,
    or it will scan the current working directory.
    """

    def __init__(
        self,
        repo_paths: list[Path] | None = None,
        patterns_path: Path | None = None,
    ) -> None:
        self._repo_paths = repo_paths
        self._patterns_path = patterns_path

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        """Scan configured repos for credential leaks.

        Only scans when repo_paths were explicitly provided. When instantiated
        by the detect pipeline with no args, returns no findings — use scan_repo()
        directly or pass repo_paths to opt in.
        """
        if self._repo_paths is None:
            return []
        all_findings: list[Finding] = []
        for repo_path in self._repo_paths:
            if repo_path.is_dir():
                all_findings.extend(
                    scan_repo(repo_path, patterns_path=self._patterns_path)
                )
        return all_findings

    def relevant_sources(self) -> list[str] | None:
        # git-oops doesn't process cloud events — return empty list
        # so the detect pipeline passes no events (saves filtering time)
        return []

    def relevant_event_types(self) -> list[str] | None:
        return []
