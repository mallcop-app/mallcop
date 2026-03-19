"""Tests for Teams channel: SSRF validation and delivery error paths."""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

from mallcop.actors.notify_base import validate_webhook_url as _validate_webhook_url, DeliveryResult
from mallcop.actors.notify_teams.channel import (
    deliver_digest,
    format_digest,
)
from mallcop.schemas import Finding, Severity, FindingStatus

_PUBLIC_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("52.96.0.1", 0))]


# --- Helpers ----------------------------------------------------------------


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001"],
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


class TestValidateWebhookUrl:
    """SSRF validation for Teams webhook URLs."""

    def test_valid_https_url_passes(self):
        # Should not raise
        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=_PUBLIC_ADDRINFO):
            _validate_webhook_url("https://outlook.office.com/webhook/abc123")

    def test_valid_power_automate_url_passes(self):
        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=_PUBLIC_ADDRINFO):
            _validate_webhook_url("https://prod-42.westus.logic.azure.com/workflows/abc")

    def test_http_rejected(self):
        with pytest.raises(ValueError, match="HTTPS required"):
            _validate_webhook_url("http://example.com/webhook")

    def test_no_scheme_rejected(self):
        with pytest.raises(ValueError, match="HTTPS required"):
            _validate_webhook_url("example.com/webhook")

    def test_private_ip_127_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://127.0.0.1/webhook")

    def test_private_ip_10_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://10.0.0.1/webhook")

    def test_private_ip_172_16_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://172.16.0.1/webhook")

    def test_private_ip_192_168_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://192.168.1.1/webhook")

    def test_link_local_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://169.254.1.1/webhook")

    def test_ipv6_loopback_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://[::1]/webhook")

    def test_localhost_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://localhost/webhook")


# --- Delivery error paths ---------------------------------------------------


class TestDeliverDigestErrors:
    """Delivery error paths: HTTP errors, timeouts, connection failures."""

    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ):
            result = deliver_digest(
                [_make_finding()], "https://outlook.office.com/webhook/test"
            )

        assert result.success is True
        assert result.error is None

    def test_http_403_returns_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ):
            result = deliver_digest(
                [_make_finding()], "https://outlook.office.com/webhook/test"
            )

        assert result.success is False
        assert "403" in result.error

    def test_http_500_returns_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ):
            result = deliver_digest(
                [_make_finding()], "https://outlook.office.com/webhook/test"
            )

        assert result.success is False
        assert "500" in result.error

    def test_timeout_returns_failure(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.Timeout("Connection timed out"),
        ):
            result = deliver_digest(
                [_make_finding()], "https://outlook.office.com/webhook/test"
            )

        assert result.success is False
        assert "timed out" in result.error

    def test_connection_error_returns_failure(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.ConnectionError("Connection refused"),
        ):
            result = deliver_digest(
                [_make_finding()], "https://outlook.office.com/webhook/test"
            )

        assert result.success is False
        assert "Connection error" in result.error

    def test_generic_request_error_returns_failure(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.RequestException("something broke"),
        ):
            result = deliver_digest(
                [_make_finding()], "https://outlook.office.com/webhook/test"
            )

        assert result.success is False
        assert "Request failed" in result.error

    def test_ssrf_rejects_private_ip_on_delivery(self):
        """deliver_digest raises ValueError for private IP webhook URLs."""
        with pytest.raises(ValueError, match="private/reserved"):
            deliver_digest(
                [_make_finding()], "https://10.0.0.1/webhook"
            )


# --- Teams markdown injection prevention (ak1n.1.13) ------------------------


class TestFormatDigestTeamsInjectionPrevention:
    """Teams AdaptiveCard activityTitle and facts render markdown.

    Attacker-controlled finding.title can inject markdown links or formatting.
    Escape < > & in user-data fields before embedding in Teams payload.
    """

    def _make_finding_with_title(self, title: str):
        from mallcop.schemas import Annotation
        return Finding(
            id="fnd_001",
            timestamp=__import__("datetime").datetime(2026, 3, 10, 12, 0, 0,
                tzinfo=__import__("datetime").timezone.utc),
            detector="test",
            event_ids=["evt_001"],
            title=title,
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )

    def _get_all_text(self, payload: dict) -> str:
        import json
        return json.dumps(payload)

    def test_html_angle_brackets_in_title_escaped(self):
        """< > in finding title must be escaped before embedding in Teams fact value."""
        f = self._make_finding_with_title("<script>alert(1)</script>")
        payload = format_digest([f])
        text = self._get_all_text(payload)
        assert "<script>" not in text
        assert "&lt;script&gt;" in text or "\\u003c" in text.lower()

    def test_ampersand_in_title_escaped(self):
        """& in finding title must be escaped for Teams payload."""
        f = self._make_finding_with_title("foo & bar")
        payload = format_digest([f])
        text = self._get_all_text(payload)
        assert "foo &amp; bar" in text or '"foo & bar"' not in text

    def test_safe_title_unmodified(self):
        """Normal text passes through without modification."""
        f = self._make_finding_with_title("Brute force from 1.2.3.4")
        payload = format_digest([f])
        text = self._get_all_text(payload)
        assert "Brute force from 1.2.3.4" in text
