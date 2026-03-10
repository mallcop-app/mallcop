"""Unit tests for mallcop.aws_sigv4 — shared SigV4 signing."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mallcop.aws_sigv4 import sign_v4_request


class TestSignV4Request:
    """Tests for the canonical sign_v4_request function."""

    def test_produces_authorization_header(self) -> None:
        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        headers = sign_v4_request(
            method="POST",
            url="https://sts.us-east-1.amazonaws.com/",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=b"Action=GetCallerIdentity&Version=2011-06-15",
            region="us-east-1",
            service="sts",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            timestamp=ts,
        )

        assert "Authorization" in headers
        auth = headers["Authorization"]
        assert auth.startswith("AWS4-HMAC-SHA256")
        assert "Credential=AKIAIOSFODNN7EXAMPLE/20260310/us-east-1/sts/aws4_request" in auth
        assert "SignedHeaders=" in auth
        assert "Signature=" in auth

    def test_adds_amz_date_header(self) -> None:
        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        headers = sign_v4_request(
            method="POST",
            url="https://sts.us-east-1.amazonaws.com/",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=b"test",
            region="us-east-1",
            service="sts",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        assert headers["x-amz-date"] == "20260310T120000Z"

    def test_adds_host_header(self) -> None:
        headers = sign_v4_request(
            method="POST",
            url="https://cloudtrail.us-west-2.amazonaws.com/",
            headers={"content-type": "application/x-amz-json-1.1"},
            body=b"{}",
            region="us-west-2",
            service="cloudtrail",
            access_key="AKIATEST",
            secret_key="secret",
        )

        assert headers["host"] == "cloudtrail.us-west-2.amazonaws.com"

    def test_different_bodies_produce_different_signatures(self) -> None:
        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        common = dict(
            method="POST",
            url="https://sts.us-east-1.amazonaws.com/",
            region="us-east-1",
            service="sts",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        h1 = sign_v4_request(headers={"content-type": "text/plain"}, body=b"body1", **common)
        h2 = sign_v4_request(headers={"content-type": "text/plain"}, body=b"body2", **common)

        sig1 = h1["Authorization"].split("Signature=")[1]
        sig2 = h2["Authorization"].split("Signature=")[1]
        assert sig1 != sig2

    def test_is_deterministic(self) -> None:
        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        kwargs = dict(
            method="POST",
            url="https://sts.us-east-1.amazonaws.com/",
            body=b"test",
            region="us-east-1",
            service="sts",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        h1 = sign_v4_request(headers={"content-type": "text/plain"}, **kwargs)
        h2 = sign_v4_request(headers={"content-type": "text/plain"}, **kwargs)

        assert h1["Authorization"] == h2["Authorization"]

    def test_does_not_mutate_input_headers(self) -> None:
        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        original = {"content-type": "application/json"}
        original_copy = dict(original)

        sign_v4_request(
            method="POST",
            url="https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse",
            headers=original,
            body=b"{}",
            region="us-east-1",
            service="bedrock",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        assert original == original_copy, "sign_v4_request must not mutate input headers"

    def test_handles_query_string(self) -> None:
        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        headers = sign_v4_request(
            method="GET",
            url="https://example.amazonaws.com/path?foo=bar&baz=qux",
            headers={},
            body=b"",
            region="us-east-1",
            service="execute-api",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        assert "Authorization" in headers

    def test_bedrock_service(self) -> None:
        """Verify signing works for bedrock service (the other original caller)."""
        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        headers = sign_v4_request(
            method="POST",
            url="https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-haiku-20240307-v1:0/converse",
            headers={"content-type": "application/json"},
            body=b'{"modelId":"test","messages":[]}',
            region="us-east-1",
            service="bedrock",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        assert "Authorization" in headers
        assert "bedrock" in headers["Authorization"]
