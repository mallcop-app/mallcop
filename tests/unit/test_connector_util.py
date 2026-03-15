"""Tests for mallcop.connectors._util shared utilities."""

from datetime import datetime, timedelta, timezone

import pytest

from mallcop.connectors._util import (
    DEFAULT_FIRST_POLL_LOOKBACK,
    DEFAULT_TOKEN_EXPIRY_MARGIN,
    make_event_id,
    parse_iso_timestamp,
    validate_next_link,
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


class TestValidateNextLink:
    def test_accepts_valid_azure_link(self):
        validate_next_link(
            "https://management.azure.com/subscriptions/sub-001/resources?$skiptoken=abc",
            "azure",
        )

    def test_accepts_valid_github_link(self):
        validate_next_link(
            "https://api.github.com/orgs/acme/repos?page=2",
            "github",
        )

    def test_rejects_http_scheme(self):
        with pytest.raises(ValueError, match="non-HTTPS"):
            validate_next_link(
                "http://management.azure.com/subscriptions/sub-001",
                "azure",
            )

    def test_rejects_ssrf_metadata_endpoint(self):
        with pytest.raises(ValueError, match="non-HTTPS"):
            validate_next_link(
                "http://169.254.169.254/latest/meta-data/",
                "azure",
            )

    def test_rejects_wrong_host_for_azure(self):
        with pytest.raises(ValueError, match="unexpected host"):
            validate_next_link(
                "https://evil.com/exfiltrate",
                "azure",
            )

    def test_rejects_wrong_host_for_github(self):
        with pytest.raises(ValueError, match="unexpected host"):
            validate_next_link(
                "https://management.azure.com/not-github",
                "github",
            )

    def test_rejects_unknown_api_type(self):
        with pytest.raises(ValueError, match="Unknown API type"):
            validate_next_link("https://example.com", "unknown")

    def test_accepts_log_analytics_link(self):
        validate_next_link(
            "https://api.loganalytics.io/v1/workspaces/ws-001/query?page=2",
            "log_analytics",
        )

    def test_accepts_m365_manage_office(self):
        validate_next_link(
            "https://manage.office.com/api/v1.0/audit/blobs?page=2",
            "m365",
        )

    def test_accepts_m365_graph(self):
        validate_next_link(
            "https://graph.microsoft.com/v1.0/auditLogs?page=2",
            "m365",
        )

    def test_rejects_wrong_host_for_m365(self):
        with pytest.raises(ValueError, match="unexpected host"):
            validate_next_link(
                "https://evil.com/steal-token",
                "m365",
            )


class TestMakeEventId:
    def test_deterministic(self):
        a = make_event_id("test-source-id")
        b = make_event_id("test-source-id")
        assert a == b

    def test_prefix(self):
        result = make_event_id("anything")
        assert result.startswith("evt_")
