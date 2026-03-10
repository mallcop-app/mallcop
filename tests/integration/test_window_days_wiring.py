"""Test that config.baseline.window_days flows through detect CLI to baseline computation."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml

from mallcop.cli import _run_detect_pipeline
from mallcop.schemas import Event, Severity
from mallcop.store import JsonlStore


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str,
    source: str = "azure",
    timestamp: datetime | None = None,
    actor: str = "admin@example.com",
    event_type: str = "role_assignment",
) -> Event:
    return Event(
        id=id,
        timestamp=timestamp or _utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type=event_type,
        actor=actor,
        action="create",
        target="/subscriptions/123",
        severity=Severity.WARN,
        metadata={},
        raw={},
    )


class TestWindowDaysWiring:
    def test_detect_passes_window_days_from_config_to_update_baseline(self, tmp_path: Path) -> None:
        """config.baseline.window_days flows through detect to store.update_baseline."""
        # Write config with explicit window_days=7
        config = {
            "connectors": {"azure": {"type": "azure"}},
            "baseline": {"window_days": 7},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config))

        # Create store and seed with an event so baseline update gets called
        store = JsonlStore(tmp_path)
        now = _utcnow()
        event = _make_event("evt_1", timestamp=now - timedelta(days=2))
        store.append_events([event])

        captured_kwargs: dict = {}
        original_update = store.update_baseline

        def spy_update_baseline(events, **kwargs):
            captured_kwargs.update(kwargs)
            return original_update(events, **kwargs)

        # Patch run_detect (imported locally in _run_detect_pipeline) to return no findings,
        # and spy on update_baseline to capture window_days
        with patch("mallcop.detect.run_detect", return_value=[]), \
             patch.object(store, "update_baseline", side_effect=spy_update_baseline):
            # Also patch JsonlStore constructor to return our store
            with patch("mallcop.cli.JsonlStore", return_value=store):
                _run_detect_pipeline(tmp_path)

        assert captured_kwargs.get("window_days") == 7

    def test_detect_uses_default_window_days_without_config(self, tmp_path: Path) -> None:
        """Without config, detect uses default window_days (30)."""
        from mallcop.config import BaselineConfig

        # No mallcop.yaml
        store = JsonlStore(tmp_path)
        now = _utcnow()
        event = _make_event("evt_1", timestamp=now - timedelta(days=2))
        store.append_events([event])

        captured_kwargs: dict = {}
        original_update = store.update_baseline

        def spy_update_baseline(events, **kwargs):
            captured_kwargs.update(kwargs)
            return original_update(events, **kwargs)

        with patch("mallcop.detect.run_detect", return_value=[]), \
             patch.object(store, "update_baseline", side_effect=spy_update_baseline):
            with patch("mallcop.cli.JsonlStore", return_value=store):
                _run_detect_pipeline(tmp_path)

        default_window = BaselineConfig().window_days
        assert captured_kwargs.get("window_days") == default_window

    def test_window_days_affects_baseline_frequency_tables(self, tmp_path: Path) -> None:
        """End-to-end: window_days=7 excludes events older than 7 days from frequency tables."""
        config = {
            "connectors": {"azure": {"type": "azure"}},
            "baseline": {"window_days": 7},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config))

        store = JsonlStore(tmp_path)
        now = _utcnow()
        old_event = _make_event("evt_old", timestamp=now - timedelta(days=20), actor="old_user")
        recent_event = _make_event("evt_recent", timestamp=now - timedelta(days=2), actor="recent_user")
        store.append_events([old_event, recent_event])

        with patch("mallcop.detect.run_detect", return_value=[]):
            _run_detect_pipeline(tmp_path)

        # Read with fresh store to get the persisted baseline (avoids cache)
        baseline = JsonlStore(tmp_path).get_baseline()

        # With window_days=7, old_event (20 days ago) should be excluded from freq tables.
        # Actor names may be wrapped in sanitization markers in the frequency key.
        freq_keys_with_old = [k for k in baseline.frequency_tables if "old_user" in k]
        freq_keys_with_recent = [k for k in baseline.frequency_tables if "recent_user" in k]
        assert len(freq_keys_with_old) == 0, "Old event should be excluded by window_days=7"
        assert len(freq_keys_with_recent) > 0, "Recent event should be included"
