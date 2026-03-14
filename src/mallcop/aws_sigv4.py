"""AWS Signature Version 4 signing — shared implementation.

Used by both ``llm.bedrock`` (Bedrock Converse API) and
``connectors.aws_cloudtrail`` (STS / CloudTrail APIs).
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, quote, urlparse


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def sign_v4_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
    timestamp: datetime | None = None,
    session_token: str = "",
) -> dict[str, str]:
    """AWS Signature Version 4 signing.

    Returns a **new** headers dict containing all original headers plus
    ``host``, ``x-amz-date``, and ``Authorization``.  The caller's
    *headers* dict is **not** mutated.

    When *session_token* is provided (e.g. from STS / SSO temporary
    credentials), it is included as ``x-amz-security-token`` and signed.
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = timestamp.strftime("%Y%m%d")

    # Parse URL components
    parsed = urlparse(url)
    host = parsed.hostname or ""
    canonical_uri = quote(parsed.path or "/", safe="/")

    # Canonical query string: sorted key=value pairs
    qs_parts = parse_qs(parsed.query, keep_blank_values=True)
    canonical_qs_items = []
    for k in sorted(qs_parts.keys()):
        for v in sorted(qs_parts[k]):
            canonical_qs_items.append(
                f"{quote(k, safe='')}={quote(v, safe='')}"
            )
    canonical_querystring = "&".join(canonical_qs_items)

    # Build headers to sign (copy to avoid mutating caller's dict)
    result_headers = dict(headers)
    result_headers["host"] = host
    result_headers["x-amz-date"] = amz_date
    if session_token:
        result_headers["x-amz-security-token"] = session_token

    # Canonical headers (lowercase, sorted)
    signed_header_keys = sorted(result_headers.keys())
    canonical_headers = ""
    for k in signed_header_keys:
        canonical_headers += f"{k.lower()}:{result_headers[k].strip()}\n"
    signed_headers = ";".join(k.lower() for k in signed_header_keys)

    # Payload hash
    payload_hash = _sha256_hex(body)

    # Canonical request
    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    # String to sign
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        algorithm,
        amz_date,
        credential_scope,
        _sha256_hex(canonical_request.encode("utf-8")),
    ])

    # Signing key
    k_date = _hmac_sha256(f"AWS4{secret_key}".encode("utf-8"), date_stamp.encode("utf-8"))
    k_region = _hmac_sha256(k_date, region.encode("utf-8"))
    k_service = _hmac_sha256(k_region, service.encode("utf-8"))
    k_signing = _hmac_sha256(k_service, b"aws4_request")

    # Signature
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    # Authorization header
    result_headers["Authorization"] = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return result_headers
