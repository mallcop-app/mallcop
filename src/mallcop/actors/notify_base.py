"""Shared webhook delivery: validation, posting, DeliveryResult.

Used by notify_teams and notify_slack channel actors. Email uses SMTP,
not webhooks, so it does not use post_webhook.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import requests


@dataclass
class DeliveryResult:
    success: bool
    error: str | None = None


_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

_BLOCKED_HOSTNAMES = {"localhost"}


def validate_webhook_url(url: str, *, resolve_dns: bool = True) -> None:
    """Validate webhook URL to prevent SSRF attacks.

    Checks scheme (HTTPS only), blocked hostnames, and IP-literal addresses.
    When resolve_dns=True (default), also resolves hostnames via DNS to catch
    rebinding attacks. Use resolve_dns=False for config-time validation where
    the hostname may not be resolvable yet.

    Raises:
        ValueError: If the URL fails any validation check.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"HTTPS required for webhook URL, got {parsed.scheme!r}")

    hostname = parsed.hostname or ""

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Webhook URL points to private/reserved address: {hostname}")

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # Not an IP literal
        if not resolve_dns:
            return
        # Resolve via DNS and check all results
        try:
            addrinfo = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            raise ValueError(f"DNS resolution failed for {hostname}: {e}")
        for family, _type, _proto, _canonname, sockaddr in addrinfo:
            resolved_ip = ipaddress.ip_address(sockaddr[0])
            for network in _BLOCKED_NETWORKS:
                if resolved_ip in network:
                    raise ValueError(
                        f"Webhook URL points to private/reserved address: "
                        f"{hostname} resolves to {sockaddr[0]}"
                    )
        return

    for network in _BLOCKED_NETWORKS:
        if addr in network:
            raise ValueError(
                f"Webhook URL points to private/reserved address: {hostname}"
            )


def post_webhook(
    url: str, payload: dict, timeout: int = 30
) -> DeliveryResult:
    """POST JSON payload to a webhook URL with standard error handling.

    Args:
        url: The webhook URL (must already be validated).
        payload: JSON-serializable dict to send.
        timeout: Request timeout in seconds.

    Returns:
        DeliveryResult with success/error status.
    """
    try:
        response = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        if response.status_code >= 400:
            return DeliveryResult(
                success=False,
                error=f"HTTP {response.status_code}: {response.text}",
            )
        return DeliveryResult(success=True)
    except requests.Timeout as e:
        return DeliveryResult(success=False, error=f"Request timed out: {e}")
    except requests.ConnectionError as e:
        return DeliveryResult(success=False, error=f"Connection error: {e}")
    except requests.RequestException as e:
        return DeliveryResult(success=False, error=f"Request failed: {e}")
