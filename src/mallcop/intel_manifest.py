"""Intel manifest: track which OSINT advisories have been processed.

This module provides a JSONL-based manifest to prevent redundant research of advisories.
When an advisory is researched (whether or not a detector is generated), it's recorded
in intel-manifest.jsonl with metadata about the research and any resulting detector.

Format (intel-manifest.jsonl):
    {"id":"CVE-2026-1234","source":"nvd","researched_at":"2026-03-15T14:00:00Z","detector":"cve-2026-1234-detection","reason":null}
    {"id":"GHSA-xxxx-yyyy","source":"github-advisory","researched_at":"2026-03-15T14:00:00Z","detector":null,"reason":"not relevant to configured connectors"}

Design note: This prevents the OSINT research agent from re-researching the same
advisory multiple times in the same patrol run or across runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class IntelEntry:
    """A single worked intel entry in the manifest.

    Fields:
        id: Advisory identifier (e.g. "CVE-2026-1234", "GHSA-xxxx-yyyy").
        source: Where the advisory came from ("nvd", "github-advisory", "vendor-bulletin").
        researched_at: When the advisory was researched (ISO 8601 datetime).
        detector: Name of detector generated from this advisory, or None if not relevant.
        reason: Why no detector was generated (if detector is None).
    """

    id: str
    source: str
    researched_at: datetime
    detector: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "source": self.source,
            "researched_at": self.researched_at.isoformat(),
            "detector": self.detector,
            "reason": self.reason,
        }

    def to_json(self) -> str:
        """Convert to JSON string for JSONL persistence."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IntelEntry:
        """Create from dictionary (e.g. after JSON parsing)."""
        return cls(
            id=data["id"],
            source=data["source"],
            researched_at=datetime.fromisoformat(data["researched_at"]),
            detector=data.get("detector"),
            reason=data.get("reason"),
        )

    @classmethod
    def from_json(cls, line: str) -> IntelEntry:
        """Create from JSONL line."""
        return cls.from_dict(json.loads(line))


def load_manifest(path: Path) -> list[IntelEntry]:
    """Load all entries from intel-manifest.jsonl.

    Returns an empty list if the file doesn't exist or is empty.

    Args:
        path: Path to intel-manifest.jsonl file.

    Returns:
        List of IntelEntry objects, in the order they appear in the manifest.
    """
    if not path.exists():
        return []

    entries: list[IntelEntry] = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:  # Skip empty lines
                entries.append(IntelEntry.from_json(line))

    return entries


def save_entry(path: Path, entry: IntelEntry) -> None:
    """Append one entry to intel-manifest.jsonl.

    Creates the file if it doesn't exist. Always appends (never overwrites).

    Args:
        path: Path to intel-manifest.jsonl file.
        entry: IntelEntry to append.
    """
    with open(path, "a") as f:
        f.write(entry.to_json() + "\n")


def already_worked(path: Path, intel_id: str) -> bool:
    """Check if an advisory ID has already been processed.

    Args:
        path: Path to intel-manifest.jsonl file.
        intel_id: Advisory ID to check (e.g. "CVE-2026-1234").

    Returns:
        True if the ID exists in the manifest, False otherwise.
    """
    entries = load_manifest(path)
    return any(entry.id == intel_id for entry in entries)


def filter_new(path: Path, candidates: list[str]) -> list[str]:
    """Filter a list of advisory IDs to only those not yet processed.

    This is the core deduplication function: given a list of candidate advisory IDs,
    returns only those that don't exist in the manifest. Maintains order of candidates.

    Args:
        path: Path to intel-manifest.jsonl file.
        candidates: List of advisory IDs to filter.

    Returns:
        Subset of candidates not in the manifest, in original order.
    """
    entries = load_manifest(path)
    worked_ids = {entry.id for entry in entries}
    return [candidate for candidate in candidates if candidate not in worked_ids]
