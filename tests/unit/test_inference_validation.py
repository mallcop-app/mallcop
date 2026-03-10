"""Tests for request validation on the inference endpoint (mallcop-223)."""
from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

import jwt as _jwt
import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

_SECRET = os.environ.get("ACCOUNT_SECRET", "test-secret")


def _make_token(sub: str = "acct_test", plan: str = "free") -> str:
    return _jwt.encode(
        {"sub": sub, "plan": plan, "iat": int(time.time()), "exp": int(time.time()) + 3600},
        _SECRET,
        algorithm="HS256",
    )


@pytest.fixture()
def client(tmp_path):
    """TestClient with mocked meter for inference app."""
    from services.inference.app import app
    from services.inference.dependencies import get_meter, set_meter

    mock_meter = MagicMock()
    mock_meter.get_usage.return_value = {
        "input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "requests": 0,
    }

    with patch.dict("os.environ", {"METERING_DB_PATH": str(tmp_path / "test.db")}):
        with TestClient(app, raise_server_exceptions=False) as c:
            real_meter = get_meter()
            set_meter(mock_meter)
            try:
                yield c
            finally:
                set_meter(real_meter)


class TestMalformedRequestBody:
    """Malformed request bodies return 422."""

    def test_empty_body_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            content=b"",
            headers={
                "Authorization": f"Bearer {_make_token()}",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 422

    def test_invalid_json_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            content=b"not json at all",
            headers={
                "Authorization": f"Bearer {_make_token()}",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 422

    def test_array_instead_of_object_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            content=b'[1, 2, 3]',
            headers={
                "Authorization": f"Bearer {_make_token()}",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 422


class TestMissingRequiredFields:
    """Missing required fields return 422."""

    def test_missing_model_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            json={"messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": f"Bearer {_make_token()}"},
        )
        assert resp.status_code == 422
        body = resp.json()
        # FastAPI returns structured validation errors
        assert "detail" in body

    def test_missing_messages_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            json={"model": "haiku"},
            headers={"Authorization": f"Bearer {_make_token()}"},
        )
        assert resp.status_code == 422

    def test_missing_both_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            json={},
            headers={"Authorization": f"Bearer {_make_token()}"},
        )
        assert resp.status_code == 422


class TestWrongFieldTypes:
    """Wrong field types return 422."""

    def test_model_not_string_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            json={"model": 123, "messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": f"Bearer {_make_token()}"},
        )
        assert resp.status_code == 422

    def test_messages_not_list_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            json={"model": "haiku", "messages": "not a list"},
            headers={"Authorization": f"Bearer {_make_token()}"},
        )
        assert resp.status_code == 422

    def test_temperature_not_float_returns_422(self, client):
        resp = client.post(
            "/v1/messages",
            json={"model": "haiku", "messages": [], "temperature": "warm"},
            headers={"Authorization": f"Bearer {_make_token()}"},
        )
        assert resp.status_code == 422


class TestValidRequests:
    """Valid requests pass validation and reach the route handler."""

    @patch("services.inference.router.route_request")
    def test_minimal_valid_request_passes(self, mock_route, client):
        mock_route.return_value = {
            "type": "message",
            "content": [{"type": "text", "text": "ok"}],
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        resp = client.post(
            "/v1/messages",
            json={"model": "haiku", "messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": f"Bearer {_make_token()}"},
        )
        assert resp.status_code == 200
        mock_route.assert_called_once()

    @patch("services.inference.router.route_request")
    def test_full_request_passes(self, mock_route, client):
        mock_route.return_value = {
            "type": "message",
            "content": [{"type": "text", "text": "ok"}],
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        resp = client.post(
            "/v1/messages",
            json={
                "model": "haiku",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 1024,
                "system": "You are helpful.",
                "temperature": 0.7,
                "tools": [{"name": "test", "description": "test", "input_schema": {}}],
            },
            headers={"Authorization": f"Bearer {_make_token()}"},
        )
        assert resp.status_code == 200
