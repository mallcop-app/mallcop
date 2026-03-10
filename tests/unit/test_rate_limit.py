"""Tests for rate limiting middleware on account and inference services."""
from __future__ import annotations

import os
import time
from unittest.mock import patch

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
import jwt as _jwt


_SECRET = os.environ.get("ACCOUNT_SECRET", "test-secret")


def _make_token(account_id: str = "acct_test", plan: str = "free") -> str:
    return _jwt.encode(
        {"sub": account_id, "plan": plan, "iat": int(time.time()), "exp": int(time.time()) + 3600},
        _SECRET,
        algorithm="HS256",
    )


class TestAccountRateLimit:
    """Rate limiting on account service endpoints."""

    def test_public_endpoint_429_after_threshold(self):
        from services.account.app import app, reset_rate_limiter

        with TestClient(app) as client:
            reset_rate_limiter()
            # Public endpoint: POST /accounts — limit 10/min
            for i in range(10):
                resp = client.post("/accounts", json={"email": f"rl{i}@example.com"})
                assert resp.status_code in (200, 409), f"Request {i} got {resp.status_code}"

            # 11th request should be rate-limited
            resp = client.post("/accounts", json={"email": "rl_extra@example.com"})
            assert resp.status_code == 429
            assert "rate limit" in resp.json()["detail"].lower()

    def test_authenticated_endpoint_higher_limit(self):
        from services.account.app import app, reset_rate_limiter

        with TestClient(app) as client:
            reset_rate_limiter()
            # Create account to get token
            create_resp = client.post("/accounts", json={"email": "auth_rl@example.com"})
            data = create_resp.json()
            token = data["service_token"]
            account_id = data["account_id"]
            headers = {"Authorization": f"Bearer {token}"}

            # Authenticated endpoint: GET /accounts/{id} — limit 100/min
            # Should handle well past 10 requests without 429
            for i in range(20):
                resp = client.get(f"/accounts/{account_id}", headers=headers)
                assert resp.status_code == 200, f"Authenticated request {i} got {resp.status_code}"


class TestInferenceRateLimit:
    """Rate limiting on inference service endpoints."""

    def test_unauthenticated_request_429_after_threshold(self):
        import services.inference.app as _app
        from services.inference.app import reset_rate_limiter
        from services.inference.dependencies import get_meter, set_meter

        original_meter = get_meter()
        set_meter(None)
        try:
            client = TestClient(_app.app)
            reset_rate_limiter()
            # No auth → 401, but rate limit fires first after threshold
            for _ in range(10):
                resp = client.post(
                    "/v1/messages",
                    json={"model": "haiku", "messages": []},
                )
                assert resp.status_code == 401

            # 11th should be 429
            resp = client.post(
                "/v1/messages",
                json={"model": "haiku", "messages": []},
            )
            assert resp.status_code == 429
        finally:
            set_meter(original_meter)

    def test_authenticated_request_allows_more(self):
        import services.inference.app as _app
        from services.inference.app import reset_rate_limiter
        from services.inference.dependencies import get_meter, set_meter

        original_meter = get_meter()
        set_meter(None)
        try:
            client = TestClient(_app.app)
            reset_rate_limiter()
            token = _make_token()
            headers = {"Authorization": f"Bearer {token}"}

            # Authenticated requests should allow up to 100/min
            # We'll do 15 to prove it's past the public limit
            with patch("services.inference.router.route_request") as mock_route:
                mock_route.return_value = {
                    "type": "message",
                    "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
                for i in range(15):
                    resp = client.post(
                        "/v1/messages",
                        json={"model": "haiku", "messages": [{"role": "user", "content": "hi"}]},
                        headers=headers,
                    )
                    assert resp.status_code == 200, f"Auth request {i} got {resp.status_code}"
        finally:
            set_meter(original_meter)


class TestInferenceRequestSize:
    """Request body size limits on inference service."""

    def test_oversized_request_returns_413(self):
        import services.inference.app as _app
        from services.inference.dependencies import get_meter, set_meter

        original_meter = get_meter()
        set_meter(None)
        try:
            client = TestClient(_app.app)
            token = _make_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Length": str(2 * 1024 * 1024),  # 2MB
            }

            # Send a request claiming to be >1MB
            resp = client.post(
                "/v1/messages",
                json={"model": "haiku", "messages": [{"role": "user", "content": "hi"}]},
                headers=headers,
            )
            assert resp.status_code == 413
            assert "too large" in resp.json()["detail"].lower()
        finally:
            set_meter(original_meter)

    def test_normal_sized_request_passes(self):
        import services.inference.app as _app
        from services.inference.dependencies import get_meter, set_meter

        original_meter = get_meter()
        set_meter(None)
        try:
            client = TestClient(_app.app)
            token = _make_token()
            headers = {"Authorization": f"Bearer {token}"}

            with patch("services.inference.router.route_request") as mock_route:
                mock_route.return_value = {
                    "type": "message",
                    "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
                resp = client.post(
                    "/v1/messages",
                    json={"model": "haiku", "messages": [{"role": "user", "content": "hi"}]},
                    headers=headers,
                )
                assert resp.status_code == 200
        finally:
            set_meter(original_meter)
