"""Tests for Email channel actor."""

from __future__ import annotations

import smtplib
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml

from mallcop.actors._schema import ActorManifest, load_actor_manifest
from mallcop.actors.notify_email.channel import (
    format_digest,
    deliver_digest,
    DeliveryResult,
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


def _email_kwargs(**overrides) -> dict:
    """Return email config kwargs with sensible defaults."""
    cfg = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "from_addr": "mallcop@example.com",
        "to_addrs": "admin@example.com",
        "username": "user",
        "password": "pass",
    }
    cfg.update(overrides)
    return cfg


# --- Manifest ---------------------------------------------------------------


class TestManifest:
    def test_manifest_loads(self):
        manifest_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "notify_email"
            / "manifest.yaml"
        )
        data = yaml.safe_load(manifest_path.read_text())
        assert data["name"] == "notify-email"
        assert data["type"] == "channel"
        assert data["format"] == "digest"
        assert "smtp_host" in data["config"]

    def test_manifest_schema(self):
        manifest_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "notify_email"
        )
        manifest = load_actor_manifest(manifest_path)
        assert manifest.name == "notify-email"
        assert manifest.type == "channel"

    def test_manifest_has_individual_config_fields(self):
        manifest_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "notify_email"
            / "manifest.yaml"
        )
        data = yaml.safe_load(manifest_path.read_text())
        config = data["config"]
        assert "smtp_host" in config
        assert "smtp_port" in config
        assert "from_addr" in config
        assert "to_addrs" in config
        assert "username" in config
        assert "password" in config
        # No webhook_url — email uses structured config
        assert "webhook_url" not in config


# --- format_digest ----------------------------------------------------------


class TestFormatDigest:
    def test_empty_findings(self):
        result = format_digest([])
        assert "No findings" in result

    def test_html_output(self):
        findings = [_make_finding(severity=Severity.CRITICAL)]
        result = format_digest(findings)
        assert "<h2>" in result
        assert "CRITICAL" in result

    def test_multiple_severities(self):
        findings = [
            _make_finding(id="f-1", severity=Severity.CRITICAL),
            _make_finding(id="f-2", severity=Severity.WARN),
        ]
        result = format_digest(findings)
        assert "CRITICAL" in result
        assert "WARN" in result

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
        assert "triage" in result
        assert "Suspicious activity" in result

    def test_severity_colors(self):
        findings = [_make_finding(severity=Severity.CRITICAL)]
        result = format_digest(findings)
        assert "#dc3545" in result

    def test_finding_ids_in_output(self):
        findings = [_make_finding(id="fnd_xyz")]
        result = format_digest(findings)
        assert "fnd_xyz" in result


# --- deliver_digest ---------------------------------------------------------


class TestDeliverDigest:
    def test_success(self):
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest([_make_finding()], **_email_kwargs())

        assert result.success is True
        assert result.error is None

    def test_missing_required_fields(self):
        result = deliver_digest([_make_finding()], smtp_host="smtp.example.com")
        assert result.success is False
        assert "Missing required" in result.error

    def test_missing_smtp_host(self):
        result = deliver_digest(
            [_make_finding()], from_addr="a@b.com", to_addrs="c@d.com"
        )
        assert result.success is False
        assert "Missing required" in result.error

    def test_smtp_error(self):
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_smtp.side_effect = smtplib.SMTPException("auth failed")
            result = deliver_digest([_make_finding()], **_email_kwargs())

        assert result.success is False
        assert "SMTP error" in result.error

    def test_connection_error(self):
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_smtp.side_effect = OSError("Connection refused")
            result = deliver_digest([_make_finding()], **_email_kwargs())

        assert result.success is False
        assert "Connection error" in result.error

    def test_comma_separated_recipients(self):
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                **_email_kwargs(to_addrs="a@b.com, c@d.com"),
            )

        assert result.success is True
        # Verify sendmail was called with both addresses
        mock_server.sendmail.assert_called_once()
        call_args = mock_server.sendmail.call_args
        assert call_args[0][1] == ["a@b.com", "c@d.com"]

    def test_list_recipients(self):
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                **_email_kwargs(to_addrs=["a@b.com", "c@d.com"]),
            )

        assert result.success is True

    def test_no_auth_when_no_credentials(self):
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                **_email_kwargs(username="", password=""),
            )

        assert result.success is True
        mock_server.login.assert_not_called()

    def test_rejects_integer_to_addrs(self):
        """deliver_digest must raise TypeError for non-string, non-list to_addrs."""
        with pytest.raises(TypeError, match="to_addrs"):
            deliver_digest(
                [_make_finding()],
                smtp_host="smtp.example.com",
                from_addr="a@b.com",
                to_addrs=42,
            )

    def test_rejects_none_to_addrs_type(self):
        """deliver_digest must raise TypeError for None to_addrs (not just falsy check)."""
        with pytest.raises(TypeError, match="to_addrs"):
            deliver_digest(
                [_make_finding()],
                smtp_host="smtp.example.com",
                from_addr="a@b.com",
                to_addrs=None,
            )

    def test_starttls_called_with_explicit_ssl_context(self):
        """deliver_digest must call starttls with an explicit SSLContext (mallcop-ak1n.1.17).

        The explicit context ensures cert verification and hostname checking are
        enforced regardless of Python version defaults.
        """
        import ssl
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            deliver_digest([_make_finding()], **_email_kwargs())

        # starttls must be called with a keyword context= argument
        mock_server.starttls.assert_called_once()
        call_kwargs = mock_server.starttls.call_args[1]
        assert "context" in call_kwargs, "starttls must receive an explicit ssl context"
        ctx = call_kwargs["context"]
        assert isinstance(ctx, ssl.SSLContext), "context must be an ssl.SSLContext"
        assert ctx.verify_mode == ssl.CERT_REQUIRED, "cert verification must be required"
        assert ctx.check_hostname is True, "hostname checking must be enabled"

    def test_default_port(self):
        """Port defaults to 587 when not specified."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                smtp_host="smtp.example.com",
                from_addr="a@b.com",
                to_addrs="c@d.com",
                username="user",
                password="pass",
            )

        assert result.success is True
        mock_smtp.assert_called_once_with("smtp.example.com", 587, timeout=30)


# --- Edge cases: whitespace, invalid emails, port types ----------------------


class TestDeliverDigestEdgeCases:
    @pytest.mark.parametrize(
        "to_addrs,expected_addrs",
        [
            ("  admin@example.com  ", ["admin@example.com"]),
            (" a@b.com , c@d.com ", ["a@b.com", "c@d.com"]),
            ("  x@y.com  ,  z@w.com  ,  q@r.com  ", ["x@y.com", "z@w.com", "q@r.com"]),
        ],
        ids=["single-padded", "two-padded", "three-padded"],
    )
    def test_whitespace_around_email_addresses_is_stripped(self, to_addrs, expected_addrs):
        """Whitespace around email addresses in to_addrs should be stripped."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                **_email_kwargs(to_addrs=to_addrs),
            )

        assert result.success is True
        call_args = mock_server.sendmail.call_args
        assert call_args[0][1] == expected_addrs

    @pytest.mark.parametrize(
        "to_addrs",
        [
            "not-an-email",
            "plaintext",
            "@missing-local",
        ],
        ids=["no-at", "plaintext", "missing-local"],
    )
    def test_invalid_email_format_still_attempts_delivery(self, to_addrs):
        """Invalid but parseable email formats are passed through — SMTP server decides."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                **_email_kwargs(to_addrs=to_addrs),
            )

        # deliver_digest delegates format validation to SMTP for parseable addrs
        assert result.success is True
        mock_server.sendmail.assert_called_once()

    def test_unparseable_email_rejected(self):
        """Addresses that parseaddr returns empty for are rejected."""
        with pytest.raises(ValueError, match="[Ii]nvalid.*to"):
            deliver_digest(
                [_make_finding()],
                **_email_kwargs(to_addrs="missing-domain@"),
            )

    # --- Header injection validation -------------------------------------------

    @pytest.mark.parametrize(
        "from_addr",
        [
            "valid@example.com",
            "user+tag@example.com",
            "admin@sub.domain.com",
        ],
        ids=["simple", "plus-tag", "subdomain"],
    )
    def test_valid_from_addr_passes_validation(self, from_addr):
        """Valid from addresses are accepted."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                **_email_kwargs(from_addr=from_addr),
            )

        assert result.success is True

    @pytest.mark.parametrize(
        "from_addr",
        [
            "evil@example.com\r\nBcc: victim@example.com",
            "evil@example.com\nBcc: victim@example.com",
            "evil@example.com\rBcc: victim@example.com",
        ],
        ids=["crlf-injection", "lf-injection", "cr-injection"],
    )
    def test_from_addr_with_newlines_rejected(self, from_addr):
        """From addresses containing newlines are rejected (header injection)."""
        with pytest.raises(ValueError, match="[Ii]nvalid.*from"):
            deliver_digest(
                [_make_finding()],
                **_email_kwargs(from_addr=from_addr),
            )

    def test_empty_from_addr_rejected_by_validation(self):
        """Empty string from_addr is caught by missing-required check."""
        result = deliver_digest(
            [_make_finding()],
            **_email_kwargs(from_addr=""),
        )
        assert result.success is False

    @pytest.mark.parametrize(
        "to_addrs",
        [
            "evil@example.com\r\nBcc: victim@example.com",
            "evil@example.com\nBcc: victim@example.com",
            "evil@example.com\rBcc: victim@example.com",
        ],
        ids=["crlf-injection", "lf-injection", "cr-injection"],
    )
    def test_to_addr_with_newlines_rejected(self, to_addrs):
        """To addresses containing newlines are rejected (header injection)."""
        with pytest.raises(ValueError, match="[Ii]nvalid.*to"):
            deliver_digest(
                [_make_finding()],
                **_email_kwargs(to_addrs=to_addrs),
            )

    def test_to_addr_list_with_newlines_rejected(self):
        """To addresses in list form containing newlines are rejected."""
        with pytest.raises(ValueError, match="[Ii]nvalid.*to"):
            deliver_digest(
                [_make_finding()],
                **_email_kwargs(to_addrs=["ok@example.com", "bad@evil.com\nBcc: x@y.com"]),
            )

    def test_from_header_uses_formataddr(self):
        """From header should use email.utils.formataddr for proper formatting."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            deliver_digest(
                [_make_finding()],
                **_email_kwargs(from_addr="mallcop@example.com"),
            )

        call_args = mock_server.sendmail.call_args
        msg_str = call_args[0][2]
        assert "Mallcop" in msg_str
        assert "mallcop@example.com" in msg_str

    @pytest.mark.parametrize(
        "port",
        [587, 465, 25],
        ids=["port-587", "port-465", "port-25"],
    )
    def test_port_as_int(self, port):
        """Port supplied as int works correctly."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                **_email_kwargs(smtp_port=port),
            )

        assert result.success is True
        mock_smtp.assert_called_once_with("smtp.example.com", port, timeout=30)

    def test_port_as_string_passed_through_to_smtp(self):
        """Port supplied as string (from YAML config) is passed directly to SMTP."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = deliver_digest(
                [_make_finding()],
                **_email_kwargs(smtp_port="587"),  # type: ignore[arg-type]
            )

        # String port gets passed to smtplib.SMTP — it handles coercion
        assert result.success is True
        mock_smtp.assert_called_once_with("smtp.example.com", "587", timeout=30)

    def test_empty_to_addrs_string_fails(self):
        """Empty string for to_addrs should fail with missing required."""
        result = deliver_digest(
            [_make_finding()],
            **_email_kwargs(to_addrs=""),
        )
        assert result.success is False
        assert "Missing required" in result.error

    def test_empty_to_addrs_list_fails(self):
        """Empty list for to_addrs is falsy — triggers missing required check."""
        result = deliver_digest(
            [_make_finding()],
            **_email_kwargs(to_addrs=[]),
        )
        assert result.success is False
        assert "Missing required" in result.error


# --- Delivery error paths ---------------------------------------------------


class TestDeliverDigestErrors:
    """SMTP delivery error paths: auth failures, TLS errors, connection refused."""

    def test_smtp_auth_failure(self):
        """SMTP login failure returns DeliveryResult(success=False)."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
            mock_server.login.side_effect = smtplib.SMTPAuthenticationError(
                535, b"Authentication credentials invalid"
            )

            result = deliver_digest([_make_finding()], **_email_kwargs())

        assert result.success is False
        assert "SMTP error" in result.error

    def test_smtp_starttls_failure(self):
        """TLS handshake failure during starttls returns error."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
            mock_server.starttls.side_effect = smtplib.SMTPException(
                "STARTTLS extension not supported by server"
            )

            result = deliver_digest([_make_finding()], **_email_kwargs())

        assert result.success is False
        assert "SMTP error" in result.error

    def test_smtp_connection_refused(self):
        """Connection refused at socket level returns Connection error."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_smtp.side_effect = ConnectionRefusedError(
                "[Errno 111] Connection refused"
            )

            result = deliver_digest([_make_finding()], **_email_kwargs())

        assert result.success is False
        assert "Connection error" in result.error

    def test_smtp_connection_timeout(self):
        """Socket timeout on connect returns Connection error."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_smtp.side_effect = OSError("Connection timed out")

            result = deliver_digest([_make_finding()], **_email_kwargs())

        assert result.success is False
        assert "Connection error" in result.error

    def test_smtp_sendmail_rejected_recipients(self):
        """SMTPRecipientsRefused during sendmail returns SMTP error."""
        with patch("mallcop.actors.notify_email.channel.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
            mock_server.sendmail.side_effect = smtplib.SMTPRecipientsRefused(
                {"bad@example.com": (550, b"User unknown")}
            )

            result = deliver_digest([_make_finding()], **_email_kwargs())

        assert result.success is False
        assert "SMTP error" in result.error


# --- XSS prevention in HTML body (ak1n.1.12) --------------------------------


class TestFormatDigestXSSPrevention:
    """HTML-escape user-controlled fields before embedding in email body.

    Finding fields (title, id, annotation actor/content) come from attacker-controlled
    event data. Embedding them verbatim creates XSS if the email client renders HTML.
    """

    def test_html_special_chars_in_title_are_escaped(self):
        """< > & in finding.title must be HTML-escaped."""
        f = _make_finding(title='<script>alert("xss")</script>')
        result = format_digest([f])
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_ampersand_in_title_is_escaped(self):
        """& in finding.title must be escaped to &amp;."""
        f = _make_finding(title="foo & bar")
        result = format_digest([f])
        assert "foo & bar" not in result
        assert "foo &amp; bar" in result

    def test_html_in_annotation_actor_is_escaped(self):
        """< > in annotation actor field must be HTML-escaped."""
        ann = Annotation(
            actor='<b>attacker</b>',
            timestamp=datetime(2026, 3, 10, 12, 5, 0, tzinfo=timezone.utc),
            content="normal content",
            action="annotate",
            reason=None,
        )
        f = _make_finding(annotations=[ann])
        result = format_digest([f])
        assert "<b>attacker</b>" not in result
        assert "&lt;b&gt;attacker&lt;/b&gt;" in result

    def test_html_in_annotation_content_is_escaped(self):
        """< > in annotation content must be HTML-escaped."""
        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 10, 12, 5, 0, tzinfo=timezone.utc),
            content='<img src=x onerror=alert(1)>',
            action="annotate",
            reason=None,
        )
        f = _make_finding(annotations=[ann])
        result = format_digest([f])
        assert "<img" not in result
        assert "&lt;img" in result

    def test_finding_id_with_html_is_escaped(self):
        """finding.id containing HTML is escaped in <code> block."""
        f = _make_finding(id='fnd_<evil>')
        result = format_digest([f])
        assert "<evil>" not in result
        assert "&lt;evil&gt;" in result

    def test_safe_text_renders_correctly_after_escaping(self):
        """Normal text without special chars still renders correctly."""
        f = _make_finding(title="Login from new IP 192.168.1.1")
        result = format_digest([f])
        assert "Login from new IP 192.168.1.1" in result
