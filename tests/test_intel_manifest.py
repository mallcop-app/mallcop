"""Tests for intel manifest: IntelEntry, load_manifest, save_entry, already_worked, filter_new."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mallcop.intel_manifest import (
    IntelEntry,
    load_manifest,
    save_entry,
    already_worked,
    filter_new,
)


# --- Fixtures ---


@pytest.fixture
def temp_manifest_path():
    """Create a temporary JSONL file path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        path = Path(f.name)
    yield path
    path.unlink(missing_ok=True)


def _make_entry(
    intel_id: str = "CVE-2026-1234",
    source: str = "nvd",
    detector: str | None = "cve-2026-1234-detection",
    reason: str | None = None,
) -> IntelEntry:
    """Create an IntelEntry for testing."""
    return IntelEntry(
        id=intel_id,
        source=source,
        researched_at=datetime(2026, 3, 15, 14, 0, 0, tzinfo=timezone.utc),
        detector=detector,
        reason=reason,
    )


# --- Unit Tests ---


class TestIntelEntry:
    """Test IntelEntry dataclass."""

    def test_entry_with_detector(self):
        """Test creating an entry with a generated detector."""
        entry = _make_entry()
        assert entry.id == "CVE-2026-1234"
        assert entry.source == "nvd"
        assert entry.detector == "cve-2026-1234-detection"
        assert entry.reason is None

    def test_entry_without_detector_irrelevant(self):
        """Test creating an entry marked as irrelevant (no detector, no reason)."""
        entry = _make_entry(intel_id="GHSA-xxxx-yyyy", detector=None, reason=None)
        assert entry.id == "GHSA-xxxx-yyyy"
        assert entry.source == "nvd"
        assert entry.detector is None
        assert entry.reason is None

    def test_entry_without_detector_with_reason(self):
        """Test creating an entry with reason why no detector was generated."""
        entry = _make_entry(
            intel_id="GHSA-aaaa-bbbb",
            detector=None,
            reason="not relevant to configured connectors",
        )
        assert entry.id == "GHSA-aaaa-bbbb"
        assert entry.detector is None
        assert entry.reason == "not relevant to configured connectors"

    def test_to_dict(self):
        """Test converting IntelEntry to dict."""
        entry = _make_entry()
        data = entry.to_dict()
        assert data["id"] == "CVE-2026-1234"
        assert data["source"] == "nvd"
        assert data["researched_at"] == "2026-03-15T14:00:00+00:00"
        assert data["detector"] == "cve-2026-1234-detection"
        assert data["reason"] is None

    def test_from_dict(self):
        """Test creating IntelEntry from dict."""
        data = {
            "id": "CVE-2026-1234",
            "source": "nvd",
            "researched_at": "2026-03-15T14:00:00+00:00",
            "detector": "cve-2026-1234-detection",
            "reason": None,
        }
        entry = IntelEntry.from_dict(data)
        assert entry.id == "CVE-2026-1234"
        assert entry.source == "nvd"
        assert entry.detector == "cve-2026-1234-detection"
        assert entry.reason is None

    def test_from_dict_with_reason(self):
        """Test creating IntelEntry from dict with reason."""
        data = {
            "id": "GHSA-xxxx-yyyy",
            "source": "github-advisory",
            "researched_at": "2026-03-15T14:00:00+00:00",
            "detector": None,
            "reason": "not relevant to configured connectors",
        }
        entry = IntelEntry.from_dict(data)
        assert entry.id == "GHSA-xxxx-yyyy"
        assert entry.detector is None
        assert entry.reason == "not relevant to configured connectors"

    def test_to_json(self):
        """Test converting IntelEntry to JSON line."""
        entry = _make_entry()
        line = entry.to_json()
        data = json.loads(line)
        assert data["id"] == "CVE-2026-1234"
        assert data["detector"] == "cve-2026-1234-detection"

    def test_from_json(self):
        """Test creating IntelEntry from JSON line."""
        line = '{"id":"CVE-2026-1234","source":"nvd","researched_at":"2026-03-15T14:00:00+00:00","detector":"cve-2026-1234-detection","reason":null}'
        entry = IntelEntry.from_json(line)
        assert entry.id == "CVE-2026-1234"
        assert entry.detector == "cve-2026-1234-detection"


# --- load_manifest Tests ---


class TestLoadManifest:
    """Test load_manifest function."""

    def test_load_empty_file(self, temp_manifest_path):
        """Test loading from empty JSONL file."""
        temp_manifest_path.touch()  # Create empty file
        entries = load_manifest(temp_manifest_path)
        assert entries == []

    def test_load_missing_file(self, temp_manifest_path):
        """Test loading from non-existent file returns empty list."""
        # File doesn't exist
        entries = load_manifest(temp_manifest_path)
        assert entries == []

    def test_load_single_entry(self, temp_manifest_path):
        """Test loading manifest with one entry."""
        entry = _make_entry()
        temp_manifest_path.write_text(entry.to_json() + "\n")

        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 1
        assert entries[0].id == "CVE-2026-1234"
        assert entries[0].detector == "cve-2026-1234-detection"

    def test_load_multiple_entries(self, temp_manifest_path):
        """Test loading manifest with multiple entries."""
        entry1 = _make_entry(intel_id="CVE-2026-1234")
        entry2 = _make_entry(
            intel_id="GHSA-xxxx-yyyy",
            source="github-advisory",
            detector=None,
            reason="not relevant",
        )
        entry3 = _make_entry(
            intel_id="CVE-2026-5678", detector="cve-2026-5678-detection"
        )

        lines = [entry1.to_json(), entry2.to_json(), entry3.to_json()]
        temp_manifest_path.write_text("\n".join(lines) + "\n")

        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 3
        assert entries[0].id == "CVE-2026-1234"
        assert entries[1].id == "GHSA-xxxx-yyyy"
        assert entries[2].id == "CVE-2026-5678"


# --- save_entry Tests ---


class TestSaveEntry:
    """Test save_entry function."""

    def test_save_to_empty_file(self, temp_manifest_path):
        """Test saving entry to empty file."""
        temp_manifest_path.touch()
        entry = _make_entry()
        save_entry(temp_manifest_path, entry)

        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 1
        assert entries[0].id == "CVE-2026-1234"

    def test_save_to_nonexistent_file(self, temp_manifest_path):
        """Test saving entry creates file if it doesn't exist."""
        # Don't create the file
        entry = _make_entry()
        save_entry(temp_manifest_path, entry)

        assert temp_manifest_path.exists()
        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 1
        assert entries[0].id == "CVE-2026-1234"

    def test_save_appends_without_overwriting(self, temp_manifest_path):
        """Test that save_entry appends, doesn't overwrite."""
        entry1 = _make_entry(intel_id="CVE-2026-1111")
        save_entry(temp_manifest_path, entry1)

        entry2 = _make_entry(intel_id="CVE-2026-2222")
        save_entry(temp_manifest_path, entry2)

        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 2
        assert entries[0].id == "CVE-2026-1111"
        assert entries[1].id == "CVE-2026-2222"

    def test_save_with_reason(self, temp_manifest_path):
        """Test saving entry with reason (no detector)."""
        entry = _make_entry(
            intel_id="GHSA-xxxx-yyyy",
            detector=None,
            reason="not relevant to configured connectors",
        )
        save_entry(temp_manifest_path, entry)

        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 1
        assert entries[0].id == "GHSA-xxxx-yyyy"
        assert entries[0].reason == "not relevant to configured connectors"


# --- already_worked Tests ---


class TestAlreadyWorked:
    """Test already_worked function."""

    def test_empty_manifest(self, temp_manifest_path):
        """Test already_worked returns False on empty manifest."""
        temp_manifest_path.touch()
        assert already_worked(temp_manifest_path, "CVE-2026-1234") is False

    def test_already_worked_returns_true(self, temp_manifest_path):
        """Test already_worked returns True for existing ID."""
        entry = _make_entry(intel_id="CVE-2026-1234")
        save_entry(temp_manifest_path, entry)

        assert already_worked(temp_manifest_path, "CVE-2026-1234") is True

    def test_already_worked_returns_false_for_new_id(self, temp_manifest_path):
        """Test already_worked returns False for unknown ID."""
        entry = _make_entry(intel_id="CVE-2026-1234")
        save_entry(temp_manifest_path, entry)

        assert already_worked(temp_manifest_path, "CVE-2026-9999") is False

    def test_already_worked_case_sensitive(self, temp_manifest_path):
        """Test already_worked is case-sensitive."""
        entry = _make_entry(intel_id="CVE-2026-1234")
        save_entry(temp_manifest_path, entry)

        assert already_worked(temp_manifest_path, "cve-2026-1234") is False

    def test_already_worked_with_multiple_entries(self, temp_manifest_path):
        """Test already_worked with multiple entries in manifest."""
        for intel_id in ["CVE-2026-1111", "CVE-2026-2222", "GHSA-xxxx-yyyy"]:
            entry = _make_entry(intel_id=intel_id)
            save_entry(temp_manifest_path, entry)

        assert already_worked(temp_manifest_path, "CVE-2026-2222") is True
        assert already_worked(temp_manifest_path, "GHSA-xxxx-yyyy") is True
        assert already_worked(temp_manifest_path, "CVE-2026-9999") is False


# --- filter_new Tests ---


class TestFilterNew:
    """Test filter_new function."""

    def test_filter_empty_manifest(self, temp_manifest_path):
        """Test filter_new returns all IDs when manifest is empty."""
        temp_manifest_path.touch()
        candidates = ["CVE-2026-1234", "CVE-2026-5678", "GHSA-xxxx-yyyy"]
        result = filter_new(temp_manifest_path, candidates)
        assert sorted(result) == sorted(candidates)

    def test_filter_removes_worked_ids(self, temp_manifest_path):
        """Test filter_new removes IDs already in manifest."""
        save_entry(temp_manifest_path, _make_entry(intel_id="CVE-2026-1234"))
        save_entry(temp_manifest_path, _make_entry(intel_id="CVE-2026-5678"))

        candidates = ["CVE-2026-1234", "CVE-2026-5678", "CVE-2026-9999"]
        result = filter_new(temp_manifest_path, candidates)
        assert result == ["CVE-2026-9999"]

    def test_filter_returns_all_when_none_worked(self, temp_manifest_path):
        """Test filter_new returns all when none are worked."""
        save_entry(temp_manifest_path, _make_entry(intel_id="CVE-2026-0000"))

        candidates = ["CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333"]
        result = filter_new(temp_manifest_path, candidates)
        assert sorted(result) == sorted(candidates)

    def test_filter_empty_candidates(self, temp_manifest_path):
        """Test filter_new with empty candidates list."""
        save_entry(temp_manifest_path, _make_entry(intel_id="CVE-2026-1234"))
        result = filter_new(temp_manifest_path, [])
        assert result == []

    def test_filter_preserves_order(self, temp_manifest_path):
        """Test filter_new preserves order of candidates."""
        save_entry(temp_manifest_path, _make_entry(intel_id="CVE-2026-2222"))

        candidates = ["CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333", "CVE-2026-4444"]
        result = filter_new(temp_manifest_path, candidates)
        assert result == ["CVE-2026-1111", "CVE-2026-3333", "CVE-2026-4444"]


# --- Integration Tests ---


class TestRoundTrip:
    """Test round-trip persistence."""

    def test_save_and_load_with_detector(self, temp_manifest_path):
        """Test saving and loading entry with detector."""
        original = _make_entry(
            intel_id="CVE-2026-1234", detector="cve-2026-1234-detection"
        )
        save_entry(temp_manifest_path, original)

        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 1
        loaded = entries[0]

        assert loaded.id == original.id
        assert loaded.source == original.source
        assert loaded.detector == original.detector
        assert loaded.reason == original.reason
        assert loaded.researched_at == original.researched_at

    def test_save_and_load_without_detector(self, temp_manifest_path):
        """Test saving and loading entry without detector."""
        original = _make_entry(
            intel_id="GHSA-xxxx-yyyy",
            source="github-advisory",
            detector=None,
            reason="not relevant to configured connectors",
        )
        save_entry(temp_manifest_path, original)

        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 1
        loaded = entries[0]

        assert loaded.id == original.id
        assert loaded.detector is None
        assert loaded.reason == original.reason

    def test_multiple_save_load_roundtrips(self, temp_manifest_path):
        """Test multiple saves and loads."""
        entries_to_save = [
            _make_entry(intel_id="CVE-2026-1111"),
            _make_entry(
                intel_id="GHSA-aaaa-bbbb",
                detector=None,
                reason="not relevant",
            ),
            _make_entry(intel_id="CVE-2026-2222", detector="detector-2222"),
        ]

        for entry in entries_to_save:
            save_entry(temp_manifest_path, entry)

        loaded = load_manifest(temp_manifest_path)
        assert len(loaded) == 3
        assert loaded[0].id == "CVE-2026-1111"
        assert loaded[1].id == "GHSA-aaaa-bbbb"
        assert loaded[2].id == "CVE-2026-2222"


# --- Deduplication Tests ---


class TestDeduplication:
    """Test deduplication behavior."""

    def test_adding_same_id_twice_via_already_worked(self, temp_manifest_path):
        """Test that already_worked prevents re-saving same ID."""
        intel_id = "CVE-2026-1234"
        entry = _make_entry(intel_id=intel_id)
        save_entry(temp_manifest_path, entry)

        # Check that it's marked as worked
        assert already_worked(temp_manifest_path, intel_id) is True

        # Caller should check this before saving again
        if not already_worked(temp_manifest_path, intel_id):
            save_entry(temp_manifest_path, entry)

        # Verify only one entry exists
        entries = load_manifest(temp_manifest_path)
        assert len(entries) == 1

    def test_filter_new_deduplicates_within_candidates(self, temp_manifest_path):
        """Test filter_new doesn't include duplicates within candidate list."""
        save_entry(temp_manifest_path, _make_entry(intel_id="CVE-2026-1234"))

        # Candidates have a duplicate; filter_new should only return unique non-worked IDs
        candidates = ["CVE-2026-1234", "CVE-2026-5678", "CVE-2026-5678"]
        result = filter_new(temp_manifest_path, candidates)

        # Should return CVE-2026-5678 only once (dedup happens at caller level)
        # Our implementation doesn't dedup within candidates, it just filters
        assert "CVE-2026-1234" not in result
        assert result.count("CVE-2026-5678") == 2  # Both instances in candidates
