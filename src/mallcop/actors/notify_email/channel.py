"""Email channel delivery: format findings into HTML email and send via SMTP."""

from __future__ import annotations

import email.utils
import html
import smtplib
import ssl
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from mallcop.schemas import Finding, Severity, SEVERITY_ORDER

_SEVERITY_COLOR = {
    "critical": "#dc3545",
    "warn": "#ffc107",
    "info": "#17a2b8",
}


def _validate_email_addr(addr: str, field: str) -> str:
    """Validate an email address for header injection.

    Uses email.utils.parseaddr to check structure. Rejects addresses
    containing newline characters (header injection vectors).

    Args:
        addr: The email address to validate.
        field: Field name for error messages ('from' or 'to').

    Returns:
        The validated address string.

    Raises:
        ValueError: If the address is empty or contains newlines.
    """
    if "\r" in addr or "\n" in addr:
        raise ValueError(f"Invalid {field} address: contains newline characters")
    _, parsed = email.utils.parseaddr(addr)
    if not parsed:
        raise ValueError(f"Invalid {field} address: {addr!r}")
    return addr


@dataclass
class DeliveryResult:
    success: bool
    error: str | None = None


def format_digest(findings: list[Finding]) -> str:
    """Format findings as HTML email body."""
    if not findings:
        return "<p>Mallcop: No findings to report.</p>"

    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )

    total = len(findings)
    html_parts = [f"<h2>Mallcop: {total} finding{'s' if total != 1 else ''}</h2>"]

    groups: dict[str, list[Finding]] = {}
    for f in sorted_findings:
        key = f.severity.value
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    for sev in ["critical", "warn", "info"]:
        if sev not in groups:
            continue
        group = groups[sev]
        color = _SEVERITY_COLOR.get(sev, "#6c757d")
        html_parts.append(f'<h3 style="color: {color}">{sev.upper()} ({len(group)})</h3>')
        html_parts.append("<ul>")
        for f in group:
            line = f"<li><code>{html.escape(f.id)}</code> {html.escape(f.title)}"
            if f.annotations:
                last = f.annotations[-1]
                line += f"<br><em>{html.escape(last.actor)}: {html.escape(last.content)}</em>"
            line += "</li>"
            html_parts.append(line)
        html_parts.append("</ul>")

    return "\n".join(html_parts)


def deliver_digest(
    findings: list[Finding],
    *,
    smtp_host: str = "",
    smtp_port: int = 587,
    from_addr: str = "",
    to_addrs: str | list[str] = "",
    username: str = "",
    password: str = "",
) -> DeliveryResult:
    """Send formatted digest via SMTP.

    Args:
        findings: List of findings to include in the digest.
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port (default 587).
        from_addr: Sender email address.
        to_addrs: Recipient(s) — comma-separated string or list.
        username: SMTP auth username (optional).
        password: SMTP auth password (optional).
    """
    if not isinstance(to_addrs, (str, list)):
        raise TypeError(
            f"to_addrs must be a string or list of strings, got {type(to_addrs).__name__}"
        )

    to_addrs_raw = to_addrs

    if not smtp_host or not from_addr or not to_addrs_raw:
        return DeliveryResult(
            success=False,
            error="Missing required email config: smtp_host, from_addr, to_addrs",
        )

    # Validate from_addr
    _validate_email_addr(from_addr, "from")

    # to_addrs can be comma-separated string or list
    if isinstance(to_addrs_raw, list):
        to_addrs = to_addrs_raw
    else:
        to_addrs = [a.strip() for a in to_addrs_raw.split(",")]

    # Validate each recipient
    for addr in to_addrs:
        _validate_email_addr(addr, "to")

    html_body = format_digest(findings)
    total = len(findings)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Mallcop: {total} security finding{'s' if total != 1 else ''}"
    msg["From"] = email.utils.formataddr(("Mallcop", from_addr))
    msg["To"] = ", ".join(to_addrs)
    msg.attach(MIMEText(html_body, "html"))

    try:
        # Explicit hardened SSLContext: cert verification + hostname check enforced.
        # Python's default starttls() context is already correct, but we make the
        # security intent explicit to guard against future Python version changes (mallcop-ak1n.1.17).
        _ssl_ctx = ssl.create_default_context()
        _ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        _ssl_ctx.check_hostname = True
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.starttls(context=_ssl_ctx)
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
        return DeliveryResult(success=True)
    except smtplib.SMTPException as e:
        return DeliveryResult(success=False, error=f"SMTP error: {e}")
    except OSError as e:
        return DeliveryResult(success=False, error=f"Connection error: {e}")
