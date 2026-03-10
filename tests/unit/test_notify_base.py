"""Tests for shared webhook delivery base: validation, posting, DeliveryResult."""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

from mallcop.actors.notify_base import (
    DeliveryResult,
    validate_webhook_url,
    post_webhook,
)
from mallcop.schemas import Severity, SEVERITY_ORDER


# --- SEVERITY_ORDER constant ------------------------------------------------


class TestSeverityOrder:
    """Shared severity ordering constant."""

    def test_critical_is_highest(self):
        assert SEVERITY_ORDER[Severity.CRITICAL] == 0

    def test_warn_is_middle(self):
        assert SEVERITY_ORDER[Severity.WARN] == 1

    def test_info_is_lowest(self):
        assert SEVERITY_ORDER[Severity.INFO] == 2

    def test_all_severities_present(self):
        for sev in Severity:
            assert sev in SEVERITY_ORDER

    def test_sorting_by_severity_order(self):
        severities = [Severity.INFO, Severity.CRITICAL, Severity.WARN]
        result = sorted(severities, key=SEVERITY_ORDER.get)
        assert result == [Severity.CRITICAL, Severity.WARN, Severity.INFO]


# --- DeliveryResult ---------------------------------------------------------


class TestDeliveryResult:
    def test_success_defaults(self):
        r = DeliveryResult(success=True)
        assert r.success is True
        assert r.error is None

    def test_failure_with_error(self):
        r = DeliveryResult(success=False, error="boom")
        assert r.success is False
        assert r.error == "boom"


# --- validate_webhook_url ---------------------------------------------------


class TestValidateWebhookUrl:
    """SSRF validation for webhook URLs (shared across teams + slack)."""

    def test_valid_https_url_passes(self):
        # Mock DNS to return public IP
        public_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("34.198.0.1", 0))]
        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=public_addrinfo):
            validate_webhook_url("https://hooks.slack.com/services/T00/B00/xxx")

    def test_http_rejected(self):
        with pytest.raises(ValueError, match="HTTPS required"):
            validate_webhook_url("http://example.com/webhook")

    def test_no_scheme_rejected(self):
        with pytest.raises(ValueError, match="HTTPS required"):
            validate_webhook_url("example.com/webhook")

    def test_private_ip_127_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("https://127.0.0.1/webhook")

    def test_private_ip_10_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("https://10.0.0.1/webhook")

    def test_private_ip_172_16_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("https://172.16.0.1/webhook")

    def test_private_ip_192_168_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("https://192.168.1.1/webhook")

    def test_link_local_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("https://169.254.1.1/webhook")

    def test_ipv6_loopback_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("https://[::1]/webhook")

    def test_localhost_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("https://localhost/webhook")

    def test_dns_rebinding_private_ip(self):
        """Hostname resolving to private IP must be rejected."""
        private_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))]
        with patch(
            "mallcop.actors.notify_base.socket.getaddrinfo",
            return_value=private_addrinfo,
        ):
            with pytest.raises(ValueError, match="private/reserved"):
                validate_webhook_url("https://evil.example.com/hook")

    def test_dns_rebinding_mixed_ips(self):
        """If any resolved IP is private, reject."""
        mixed_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("34.198.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0)),
        ]
        with patch(
            "mallcop.actors.notify_base.socket.getaddrinfo",
            return_value=mixed_addrinfo,
        ):
            with pytest.raises(ValueError, match="private/reserved"):
                validate_webhook_url("https://evil.example.com/hook")

    def test_dns_failure_rejects(self):
        """DNS resolution failure must raise ValueError."""
        with patch(
            "mallcop.actors.notify_base.socket.getaddrinfo",
            side_effect=socket.gaierror("Name or service not known"),
        ):
            with pytest.raises(ValueError, match="DNS resolution failed"):
                validate_webhook_url("https://nonexistent.example.com/hook")


# --- post_webhook -----------------------------------------------------------


class TestPostWebhook:
    """Shared webhook POST with error handling."""

    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("mallcop.actors.notify_base.requests.post", return_value=mock_resp):
            result = post_webhook("https://hooks.example.com/test", {"key": "val"})

        assert result.success is True
        assert result.error is None

    def test_http_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"

        with patch("mallcop.actors.notify_base.requests.post", return_value=mock_resp):
            result = post_webhook("https://hooks.example.com/test", {"key": "val"})

        assert result.success is False
        assert "403" in result.error

    def test_timeout(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.Timeout("timed out"),
        ):
            result = post_webhook("https://hooks.example.com/test", {})

        assert result.success is False
        assert "timed out" in result.error

    def test_connection_error(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.ConnectionError("refused"),
        ):
            result = post_webhook("https://hooks.example.com/test", {})

        assert result.success is False
        assert "Connection error" in result.error

    def test_generic_request_error(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.RequestException("something broke"),
        ):
            result = post_webhook("https://hooks.example.com/test", {})

        assert result.success is False
        assert "Request failed" in result.error

    def test_custom_timeout(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("mallcop.actors.notify_base.requests.post", return_value=mock_resp) as mock_post:
            post_webhook("https://hooks.example.com/test", {}, timeout=15)

        mock_post.assert_called_once()
        assert mock_post.call_args[1]["timeout"] == 15

    def test_posts_json_payload(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        payload = {"blocks": [{"type": "section"}]}

        with patch("mallcop.actors.notify_base.requests.post", return_value=mock_resp) as mock_post:
            post_webhook("https://hooks.example.com/test", payload)

        assert mock_post.call_args[1]["json"] == payload
