"""Integration tests for services/inference/app.py."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi.testclient import TestClient


# The ACCOUNT_SECRET used for signing test tokens — must match the env var.
import os
_TEST_SECRET = os.environ.get("ACCOUNT_SECRET", "test-secret")


def _make_token(sub: str = "acct_123", plan: str = "small") -> str:
    """Create a valid JWT service token."""
    return jwt.encode({"sub": sub, "plan": plan}, _TEST_SECRET, algorithm="HS256")


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _sample_body() -> dict:
    return {
        "model": "haiku",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "Hello"}],
    }


_FAKE_RESPONSE = {
    "id": "msg_fake",
    "type": "message",
    "role": "assistant",
    "content": [{"type": "text", "text": "Hi there"}],
    "model": "haiku",
    "usage": {"input_tokens": 10, "output_tokens": 5},
    "stop_reason": "end_turn",
}


@pytest.fixture()
def client(tmp_path):
    """Create a TestClient with mocked meter.

    The app's lifespan creates a real Meter; we let it run against a temp DB,
    then swap in our mock so tests can assert on calls.
    """
    from services.inference.app import app
    from services.inference.dependencies import get_meter, set_meter

    mock_meter = MagicMock()
    mock_meter.get_usage.return_value = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "requests": 0}

    # Point the real lifespan at a throwaway DB so it doesn't pollute cwd
    with patch.dict("os.environ", {"METERING_DB_PATH": str(tmp_path / "test.db")}):
        with TestClient(app, raise_server_exceptions=False) as c:
            # Swap the real meter for our mock after lifespan has initialised
            real_meter = get_meter()
            set_meter(mock_meter)
            try:
                yield c, mock_meter
            finally:
                set_meter(real_meter)


class TestCreateMessageValidToken:
    """POST /v1/messages with a valid token returns provider response."""

    @patch("services.inference.router.route_request")
    def test_returns_200_with_response(self, mock_route, client):
        c, _meter = client
        mock_route.return_value = _FAKE_RESPONSE

        resp = c.post("/v1/messages", json=_sample_body(), headers=_auth_header(_make_token()))

        assert resp.status_code == 200
        data = resp.json()
        assert data["content"][0]["text"] == "Hi there"
        assert data["usage"]["input_tokens"] == 10
        mock_route.assert_called_once()


class TestCreateMessageInvalidToken:
    """POST /v1/messages with an invalid JWT returns 401."""

    def test_invalid_jwt_returns_401(self, client):
        c, _ = client
        resp = c.post(
            "/v1/messages",
            json=_sample_body(),
            headers={"Authorization": "Bearer this.is.garbage"},
        )
        assert resp.status_code == 401
        assert "Invalid service token" in resp.json()["detail"]


class TestCreateMessageMissingAuth:
    """POST /v1/messages with no Authorization header returns 401."""

    def test_no_header_returns_401(self, client):
        c, _ = client
        resp = c.post("/v1/messages", json=_sample_body())
        assert resp.status_code == 401
        assert "Missing" in resp.json()["detail"]

    def test_non_bearer_returns_401(self, client):
        c, _ = client
        resp = c.post(
            "/v1/messages",
            json=_sample_body(),
            headers={"Authorization": "Basic abc123"},
        )
        assert resp.status_code == 401


class TestCreateMessageUpstreamError:
    """POST /v1/messages returns 502 when the upstream provider fails."""

    @patch("services.inference.router.route_request", side_effect=RuntimeError("Bedrock error 500: boom"))
    def test_upstream_error_returns_502(self, mock_route, client):
        c, _ = client
        resp = c.post("/v1/messages", json=_sample_body(), headers=_auth_header(_make_token()))

        assert resp.status_code == 502
        assert "Upstream provider error" in resp.json()["detail"]


class TestCreateMessageRecordsUsage:
    """POST /v1/messages records token usage via the meter."""

    @patch("services.inference.router.route_request")
    def test_records_usage_after_success(self, mock_route, client):
        c, mock_meter = client
        mock_route.return_value = _FAKE_RESPONSE

        resp = c.post("/v1/messages", json=_sample_body(), headers=_auth_header(_make_token(sub="acct_456")))

        assert resp.status_code == 200
        mock_meter.record.assert_called_once_with(
            account_id="acct_456",
            model="haiku",
            input_tokens=10,
            output_tokens=5,
        )

    @patch("services.inference.router.route_request")
    def test_checks_plan_limit_before_routing(self, mock_route, client):
        c, mock_meter = client
        # Simulate already at limit
        mock_meter.get_usage.return_value = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 500_000, "requests": 100}

        resp = c.post("/v1/messages", json=_sample_body(), headers=_auth_header(_make_token(plan="small")))

        assert resp.status_code == 429
        assert "Daily token limit exceeded" in resp.json()["detail"]
        mock_route.assert_not_called()
