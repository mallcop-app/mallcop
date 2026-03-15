"""Tests for ProClient public API — all HTTP mocked, no live calls."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest
import requests

from mallcop.pro import AccountInfo, ProClient


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


# --- create_account ---


@patch("mallcop.pro.requests.post")
def test_create_account_success(mock_post, client):
    mock_post.return_value = _mock_response(200, {"account_id": "acc-1", "service_token": "tok-1"})
    aid, tok = client.create_account("user@example.com")
    assert aid == "acc-1"
    assert tok == "tok-1"


@patch("mallcop.pro.requests.post")
def test_create_account_http_error(mock_post, client):
    mock_post.return_value = _mock_response(500)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        client.create_account("user@example.com")


# --- get_account ---


@patch("mallcop.pro.requests.get")
def test_get_account_success(mock_get, client):
    mock_get.return_value = _mock_response(200, {
        "account_id": "acc-1", "email": "u@x.com",
        "plan_tier": "pro", "status": "active",
    })
    info = client.get_account("acc-1", "tok-1")
    assert isinstance(info, AccountInfo)
    assert info.plan_tier == "pro"
    assert info.account_id == "acc-1"


@patch("mallcop.pro.requests.get")
def test_get_account_401(mock_get, client):
    mock_get.return_value = _mock_response(401)
    with pytest.raises(RuntimeError, match="HTTP 401"):
        client.get_account("acc-1", "bad-tok")


# --- validate_token ---


@patch("mallcop.pro.requests.get")
def test_validate_token_valid(mock_get, client):
    mock_get.return_value = _mock_response(200, {
        "account_id": "acc-1", "email": "u@x.com",
        "plan_tier": "pro", "status": "active",
    })
    info = client.validate_token("tok-1")
    assert info is not None
    assert info.account_id == "acc-1"


@patch("mallcop.pro.requests.get")
def test_validate_token_invalid(mock_get, client):
    mock_get.return_value = _mock_response(401)
    assert client.validate_token("bad-tok") is None


@patch("mallcop.pro.requests.get")
def test_validate_token_request_exception(mock_get, client):
    mock_get.side_effect = requests.ConnectionError("down")
    assert client.validate_token("tok-1") is None


@patch("mallcop.pro.requests.get")
def test_validate_token_malformed_json(mock_get, client):
    mock_get.return_value = _mock_response(200, {"unexpected": "shape"})
    assert client.validate_token("tok-1") is None


# --- record_usage ---


@patch("mallcop.pro.requests.post")
def test_record_usage_success(mock_post, client):
    mock_post.return_value = _mock_response(200, {"status": "ok"})
    result = client.record_usage("acc-1", "claude-3", 100, 50, "tok-1")
    assert result == {"status": "ok"}


@patch("mallcop.pro.requests.post")
def test_record_usage_http_error(mock_post, client):
    mock_post.return_value = _mock_response(429)
    with pytest.raises(RuntimeError, match="HTTP 429"):
        client.record_usage("acc-1", "claude-3", 100, 50, "tok-1")


# --- subscribe ---


@patch("mallcop.pro.requests.post")
def test_subscribe_returns_checkout_url(mock_post, client):
    mock_post.return_value = _mock_response(200, {"checkout_url": "https://checkout.example.com/xyz"})
    url = client.subscribe("acc-1", "pro", "tok-1")
    assert url == "https://checkout.example.com/xyz"


@patch("mallcop.pro.requests.post")
def test_subscribe_http_error(mock_post, client):
    mock_post.return_value = _mock_response(500)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        client.subscribe("acc-1", "pro", "tok-1")


# --- check_subscription ---


@patch("mallcop.pro.requests.get")
def test_check_subscription_extracts_fields(mock_get, client):
    mock_get.return_value = _mock_response(200, {
        "account_id": "acc-1", "email": "u@x.com",
        "plan_tier": "sentinel", "status": "active",
    })
    result = client.check_subscription("acc-1", "tok-1")
    assert result == {"plan_tier": "sentinel", "status": "active"}


# --- get_usage ---


@patch("mallcop.pro.requests.get")
def test_get_usage_returns_raw(mock_get, client):
    usage_data = {"total_tokens": 5000, "records": []}
    mock_get.return_value = _mock_response(200, usage_data)
    result = client.get_usage("acc-1", "tok-1")
    assert result == usage_data


# --- recommend_plan ---


@patch("mallcop.pro.requests.post")
def test_recommend_plan_success(mock_post, client):
    plan_data = {"recommended_tier": "pro", "estimated_donuts": 1000}
    mock_post.return_value = _mock_response(200, plan_data)
    result = client.recommend_plan(["github"])
    assert result == plan_data


@patch("mallcop.pro.requests.post")
def test_recommend_plan_network_error(mock_post, client):
    mock_post.side_effect = requests.ConnectionError("unreachable")
    with pytest.raises(RuntimeError, match="Could not reach mallcop.app"):
        client.recommend_plan(["github"])


@patch("mallcop.pro.requests.post")
def test_recommend_plan_non_200(mock_post, client):
    mock_post.return_value = _mock_response(503)
    with pytest.raises(RuntimeError, match="Could not reach mallcop.app"):
        client.recommend_plan(["github"])


# --- _api_call error prefix ---


@patch("mallcop.pro.requests.get")
def test_api_call_error_includes_caller_name(mock_get, client):
    mock_get.return_value = _mock_response(500)
    with pytest.raises(RuntimeError, match=r"ProClient\.get_account"):
        client.get_account("acc-1", "tok-1")


@patch("mallcop.pro.requests.post")
def test_api_call_error_prefix_record_usage(mock_post, client):
    mock_post.return_value = _mock_response(500)
    with pytest.raises(RuntimeError, match=r"ProClient\.record_usage"):
        client.record_usage("acc-1", "m", 0, 0, "tok-1")
