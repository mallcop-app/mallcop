"""Tests for ProClient.verify_email_request, verify_email_confirm, and notify."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from mallcop.pro import ProClient


@pytest.fixture
def client():
    return ProClient(account_url="https://test.example.com")


def _mock_response(status_code: int = 200, json_data: dict | None = None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = str(json_data or {})
    return resp


# --- verify_email_request ---


@patch("mallcop.pro.requests.post")
def test_verify_email_request_success(mock_post, client):
    mock_post.return_value = _mock_response(200, {"status": "otp_sent"})
    client.verify_email_request("acct-1", "tok-1")
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://test.example.com/accounts/acct-1/email/verify-request"
    assert kwargs["headers"]["Authorization"] == "Bearer tok-1"


@patch("mallcop.pro.requests.post")
def test_verify_email_request_error(mock_post, client):
    mock_post.return_value = _mock_response(500)
    with pytest.raises(RuntimeError, match="verify_email_request"):
        client.verify_email_request("acct-1", "tok-1")


# --- verify_email_confirm ---


@patch("mallcop.pro.requests.post")
def test_verify_email_confirm_success(mock_post, client):
    mock_post.return_value = _mock_response(200, {"email_verified": True})
    client.verify_email_confirm("acct-1", "123456", "tok-1")
    args, kwargs = mock_post.call_args
    assert args[0] == "https://test.example.com/accounts/acct-1/email/verify-confirm"
    assert kwargs["json"] == {"otp": "123456"}


@patch("mallcop.pro.requests.post")
def test_verify_email_confirm_bad_otp(mock_post, client):
    mock_post.return_value = _mock_response(400)
    with pytest.raises(RuntimeError, match="verify_email_confirm"):
        client.verify_email_confirm("acct-1", "wrong", "tok-1")


# --- notify ---


@patch("mallcop.pro.requests.post")
def test_notify_sent(mock_post, client):
    mock_post.return_value = _mock_response(200, {"status": "sent"})
    result = client.notify(
        "acct-1", "tok-1",
        subject="Alert", findings=[{"id": "f1"}], trigger="manual",
    )
    assert result == {"status": "sent"}
    _, kwargs = mock_post.call_args
    assert kwargs["json"]["subject"] == "Alert"
    assert kwargs["json"]["trigger"] == "manual"


@patch("mallcop.pro.requests.post")
def test_notify_deduped(mock_post, client):
    mock_post.return_value = _mock_response(200, {"status": "deduped"})
    result = client.notify(
        "acct-1", "tok-1",
        subject="Alert", findings=[{"id": "f1"}], trigger="manual",
    )
    assert result["status"] == "deduped"


@patch("mallcop.pro.requests.post")
def test_notify_email_not_verified(mock_post, client):
    mock_post.return_value = _mock_response(403, {"detail": "email_not_verified"})
    with pytest.raises(RuntimeError, match="email_not_verified"):
        client.notify(
            "acct-1", "tok-1",
            subject="Alert", findings=[], trigger="manual",
        )


@patch("mallcop.pro.requests.post")
def test_notify_rate_limited(mock_post, client):
    mock_post.return_value = _mock_response(
        429, {"detail": "rate_limited", "retry_after": 542},
    )
    with pytest.raises(RuntimeError, match=r"rate_limited:542"):
        client.notify(
            "acct-1", "tok-1",
            subject="Alert", findings=[], trigger="manual",
        )


@patch("mallcop.pro.requests.post")
def test_notify_server_error(mock_post, client):
    mock_post.return_value = _mock_response(500)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        client.notify(
            "acct-1", "tok-1",
            subject="Alert", findings=[], trigger="manual",
        )
