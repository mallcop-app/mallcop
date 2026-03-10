"""Tests for mallcop.connectors._util shared utilities."""

from datetime import datetime, timedelta, timezone

from mallcop.connectors._util import (
    DEFAULT_FIRST_POLL_LOOKBACK,
    DEFAULT_TOKEN_EXPIRY_MARGIN,
    make_event_id,
    parse_iso_timestamp,
)


class TestParseIsoTimestamp:
    def test_z_suffix(self):
        result = parse_iso_timestamp("2026-03-10T14:30:00Z")
        assert result == datetime(2026, 3, 10, 14, 30, 0, tzinfo=timezone.utc)

    def test_plus_offset(self):
        result = parse_iso_timestamp("2026-03-10T14:30:00+00:00")
        assert result == datetime(2026, 3, 10, 14, 30, 0, tzinfo=timezone.utc)

    def test_fractional_seconds(self):
        result = parse_iso_timestamp("2026-03-10T14:30:00.123456Z")
        assert result == datetime(2026, 3, 10, 14, 30, 0, 123456, tzinfo=timezone.utc)

    def test_non_utc_offset(self):
        result = parse_iso_timestamp("2026-03-10T14:30:00+05:30")
        assert result.utcoffset() == timedelta(hours=5, minutes=30)

    def test_returns_datetime(self):
        result = parse_iso_timestamp("2026-01-01T00:00:00Z")
        assert isinstance(result, datetime)


class TestConstants:
    def test_default_first_poll_lookback(self):
        assert DEFAULT_FIRST_POLL_LOOKBACK == timedelta(days=7)

    def test_default_token_expiry_margin(self):
        assert DEFAULT_TOKEN_EXPIRY_MARGIN == 60


class TestMakeEventId:
    def test_deterministic(self):
        a = make_event_id("test-source-id")
        b = make_event_id("test-source-id")
        assert a == b

    def test_prefix(self):
        result = make_event_id("anything")
        assert result.startswith("evt_")
