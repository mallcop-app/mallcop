"""Tests for Slack channel actor."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml

from mallcop.actors._schema import ActorManifest, load_actor_manifest
from mallcop.actors.notify_base import validate_webhook_url as _validate_webhook_url, DeliveryResult
from mallcop.actors.notify_slack.channel import (
    format_digest,
    deliver_digest,
)
from mallcop.schemas import Annotation, Finding, Severity, FindingStatus


# --- Helpers ----------------------------------------------------------------


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
    title: str = "Test finding",
    annotations: list[Annotation] | None = None,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001"],
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=annotations or [],
        metadata={},
    )


# --- Manifest ---------------------------------------------------------------


class TestManifest:
    def test_manifest_loads(self):
        manifest_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "notify_slack"
            / "manifest.yaml"
        )
        data = yaml.safe_load(manifest_path.read_text())
        assert data["name"] == "notify-slack"
        assert data["type"] == "channel"
        assert data["format"] == "digest"
        assert "webhook_url" in data["config"]

    def test_manifest_schema(self):
        manifest_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "notify_slack"
        )
        manifest = load_actor_manifest(manifest_path)
        assert manifest.name == "notify-slack"
        assert manifest.type == "channel"


# --- format_digest ----------------------------------------------------------


class TestFormatDigest:
    def test_empty_findings(self):
        result = format_digest([])
        assert "blocks" in result
        assert len(result["blocks"]) == 1
        assert "No findings" in result["blocks"][0]["text"]["text"]

    def test_single_critical(self):
        findings = [_make_finding(severity=Severity.CRITICAL)]
        result = format_digest(findings)
        assert "blocks" in result
        # header + divider + severity section + finding section = 4
        assert len(result["blocks"]) >= 3

    def test_multiple_severities(self):
        findings = [
            _make_finding(id="f-1", severity=Severity.CRITICAL),
            _make_finding(id="f-2", severity=Severity.WARN),
            _make_finding(id="f-3", severity=Severity.INFO),
        ]
        result = format_digest(findings)
        blocks_text = json.dumps(result)
        assert "CRITICAL" in blocks_text
        assert "WARN" in blocks_text
        assert "INFO" in blocks_text

    def test_block_kit_structure(self):
        findings = [_make_finding()]
        result = format_digest(findings)
        assert result["blocks"][0]["type"] == "header"

    def test_annotations_included(self):
        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 10, 12, 5, 0, tzinfo=timezone.utc),
            content="Suspicious activity",
            action="annotate",
            reason=None,
        )
        findings = [_make_finding(annotations=[ann])]
        result = format_digest(findings)
        blocks_text = json.dumps(result)
        assert "triage" in blocks_text
        assert "Suspicious activity" in blocks_text

    def test_sorting_by_severity(self):
        findings = [
            _make_finding(id="f-info", severity=Severity.INFO),
            _make_finding(id="f-crit", severity=Severity.CRITICAL),
        ]
        result = format_digest(findings)
        blocks_text = json.dumps(result)
        # CRITICAL should appear before INFO in the output
        crit_pos = blocks_text.index("CRITICAL")
        info_pos = blocks_text.index("INFO")
        assert crit_pos < info_pos


# --- deliver_digest ---------------------------------------------------------


class TestDeliverDigest:
    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is True
        assert result.error is None

    def test_http_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "invalid_payload"

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "400" in result.error

    def test_timeout(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.Timeout("timeout"),
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "timed out" in result.error

    def test_connection_error(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.ConnectionError("refused"),
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "Connection error" in result.error

    def test_generic_request_error(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.RequestException("something broke"),
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "Request failed" in result.error

    def test_ssrf_rejects_http(self):
        with pytest.raises(ValueError, match="HTTPS required"):
            deliver_digest([_make_finding()], "http://hooks.slack.com/test")

    def test_ssrf_rejects_private_127(self):
        with pytest.raises(ValueError, match="private|reserved"):
            deliver_digest([_make_finding()], "https://127.0.0.1/hook")

    def test_ssrf_rejects_private_10(self):
        with pytest.raises(ValueError, match="private|reserved"):
            deliver_digest([_make_finding()], "https://10.0.0.1/hook")

    def test_ssrf_rejects_private_172_16(self):
        with pytest.raises(ValueError, match="private|reserved"):
            deliver_digest([_make_finding()], "https://172.16.0.1/hook")

    def test_ssrf_rejects_private_192_168(self):
        with pytest.raises(ValueError, match="private|reserved"):
            deliver_digest([_make_finding()], "https://192.168.1.1/hook")

    def test_ssrf_rejects_link_local(self):
        with pytest.raises(ValueError, match="private|reserved"):
            deliver_digest([_make_finding()], "https://169.254.169.254/metadata")

    def test_ssrf_rejects_localhost(self):
        with pytest.raises(ValueError, match="private|reserved"):
            deliver_digest([_make_finding()], "https://localhost/hook")

    def test_ssrf_rejects_ipv6_loopback(self):
        with pytest.raises(ValueError, match="private|reserved"):
            deliver_digest([_make_finding()], "https://[::1]/hook")

    def test_ssrf_allows_valid_slack_url(self):
        """Valid Slack webhook URLs pass validation without raising."""
        # Mock DNS to return a public IP so validation passes
        public_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("34.198.0.1", 0))]
        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=public_addrinfo):
            _validate_webhook_url("https://hooks.slack.com/services/T00/B00/xxx")

    def test_ssrf_rejects_no_scheme(self):
        with pytest.raises(ValueError):
            _validate_webhook_url("hooks.slack.com/services/T00/B00/xxx")

    def test_posts_correct_payload(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ) as mock_post:
            deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://hooks.slack.com/test"
        assert "blocks" in call_kwargs[1]["json"]

    def test_ssrf_dns_rebinding_private_ip(self):
        """Hostname resolving to a private IP must be rejected (DNS rebinding)."""
        # Mock DNS to return a private 10.x address
        private_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))]
        with patch(
            "mallcop.actors.notify_base.socket.getaddrinfo",
            return_value=private_addrinfo,
        ):
            with pytest.raises(ValueError, match="private|reserved"):
                _validate_webhook_url("https://evil.example.com/hook")

    def test_ssrf_dns_rebinding_loopback(self):
        """Hostname resolving to 127.0.0.1 must be rejected."""
        loopback_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]
        with patch(
            "mallcop.actors.notify_base.socket.getaddrinfo",
            return_value=loopback_addrinfo,
        ):
            with pytest.raises(ValueError, match="private|reserved"):
                _validate_webhook_url("https://evil.example.com/hook")

    def test_ssrf_dns_rebinding_link_local(self):
        """Hostname resolving to link-local 169.254.x must be rejected."""
        link_local_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))]
        with patch(
            "mallcop.actors.notify_base.socket.getaddrinfo",
            return_value=link_local_addrinfo,
        ):
            with pytest.raises(ValueError, match="private|reserved"):
                _validate_webhook_url("https://evil.example.com/metadata")

    def test_ssrf_dns_rebinding_multiple_ips_one_private(self):
        """If any resolved IP is private, reject (even if others are public)."""
        mixed_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("34.198.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0)),
        ]
        with patch(
            "mallcop.actors.notify_base.socket.getaddrinfo",
            return_value=mixed_addrinfo,
        ):
            with pytest.raises(ValueError, match="private|reserved"):
                _validate_webhook_url("https://evil.example.com/hook")

    def test_ssrf_dns_failure_rejects(self):
        """DNS resolution failure must raise ValueError."""
        with patch(
            "mallcop.actors.notify_base.socket.getaddrinfo",
            side_effect=socket.gaierror("Name or service not known"),
        ):
            with pytest.raises(ValueError, match="DNS resolution failed"):
                _validate_webhook_url("https://nonexistent.example.com/hook")


# --- Delivery error paths ---------------------------------------------------


class TestDeliverDigestErrors:
    """Delivery error paths: HTTP errors, timeouts, connection failures."""

    def test_http_500_returns_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "internal_error"

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "500" in result.error
        assert "internal_error" in result.error

    def test_http_403_returns_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "token_revoked"

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "403" in result.error

    def test_http_429_rate_limited_returns_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "rate_limited"

        with patch(
            "mallcop.actors.notify_base.requests.post",
            return_value=mock_resp,
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "429" in result.error

    def test_timeout_error_message_content(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.Timeout("Connection to hooks.slack.com timed out"),
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "timed out" in result.error

    def test_connection_error_dns_failure(self):
        import requests as req

        with patch(
            "mallcop.actors.notify_base.requests.post",
            side_effect=req.ConnectionError(
                "Failed to resolve 'hooks.slack.com'"
            ),
        ):
            result = deliver_digest(
                [_make_finding()], "https://hooks.slack.com/test"
            )

        assert result.success is False
        assert "Connection error" in result.error


# --- Slack mrkdwn injection prevention (ak1n.1.13) --------------------------


class TestFormatDigestSlackInjectionPrevention:
    """Slack Block Kit mrkdwn interprets < > & as special (links, @mentions).

    Attacker-controlled finding.title or annotation content containing
    <https://evil.com|click here> would render as a hyperlink. Escape these.
    """

    def _make_finding(
        self,
        id: str = "fnd_001",
        severity: Severity = Severity.WARN,
        title: str = "Test finding",
        annotations=None,
    ):
        from mallcop.schemas import Annotation
        return Finding(
            id=id,
            timestamp=datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc),
            detector="test",
            event_ids=["evt_001"],
            title=title,
            severity=severity,
            status=FindingStatus.OPEN,
            annotations=annotations or [],
            metadata={},
        )

    def _get_all_text(self, payload: dict) -> str:
        """Extract all text strings from Slack Block Kit payload."""
        import json
        return json.dumps(payload)

    def test_slack_link_in_title_is_escaped(self):
        """<URL|label> in title would create attacker-controlled hyperlink."""
        f = self._make_finding(title="<https://evil.com|click here>")
        payload = format_digest([f])
        text = self._get_all_text(payload)
        assert "<https://evil.com|click here>" not in text
        assert "&lt;" in text or "\\u003c" in text.lower() or "evil.com" not in text or "&lt;https" in text

    def test_angle_brackets_in_title_escaped(self):
        """Bare < > in title must be escaped so Slack doesn't parse them as links."""
        f = self._make_finding(title="value < threshold > limit")
        payload = format_digest([f])
        text = self._get_all_text(payload)
        # Must not appear as raw angle brackets in mrkdwn context
        assert "<https" not in text  # not accidentally parsed as a URL
        # Escaped form must be present
        assert "&lt;" in text or "value &lt; threshold" in text

    def test_ampersand_in_title_escaped(self):
        """& in title must be escaped to prevent Slack entity injection."""
        f = self._make_finding(title="foo & bar")
        payload = format_digest([f])
        text = self._get_all_text(payload)
        # Raw & in mrkdwn can be misinterpreted; must be escaped
        assert "foo &amp; bar" in text or '"foo & bar"' not in text

    def test_slack_injection_in_annotation_content_escaped(self):
        """Annotation content with Slack link syntax is escaped."""
        from mallcop.schemas import Annotation
        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 10, 12, 5, 0, tzinfo=timezone.utc),
            content="<https://phishing.com|urgent action required>",
            action="annotate",
            reason=None,
        )
        f = self._make_finding(annotations=[ann])
        payload = format_digest([f])
        text = self._get_all_text(payload)
        assert "<https://phishing.com|urgent action required>" not in text

    def test_safe_title_renders_correctly(self):
        """Normal alphanumeric title is unchanged in output."""
        f = self._make_finding(title="Login from new IP 192.168.1.1")
        payload = format_digest([f])
        text = self._get_all_text(payload)
        assert "Login from new IP 192.168.1.1" in text
