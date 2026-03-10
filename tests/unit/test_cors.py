"""Unit tests for CORS configuration on account and inference services."""
from __future__ import annotations

import importlib
import os
import sys

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient


class TestAccountCorsDisabled:
    """When CORS_ALLOWED_ORIGINS is empty/unset, no CORS headers."""

    def test_no_cors_headers_by_default(self):
        from services.account.app import app, reset_rate_limiter

        with TestClient(app) as client:
            reset_rate_limiter()
            resp = client.options(
                "/accounts",
                headers={"Origin": "http://evil.com", "Access-Control-Request-Method": "POST"},
            )
            # No CORS middleware → no access-control-allow-origin header
            assert "access-control-allow-origin" not in resp.headers


class TestInferenceCorsDisabled:
    """When CORS_ALLOWED_ORIGINS is empty/unset, no CORS headers."""

    def test_no_cors_headers_by_default(self):
        from services.inference.app import app, reset_rate_limiter

        with TestClient(app) as client:
            reset_rate_limiter()
            resp = client.options(
                "/v1/messages",
                headers={"Origin": "http://evil.com", "Access-Control-Request-Method": "POST"},
            )
            assert "access-control-allow-origin" not in resp.headers


class TestCorsEnabled:
    """Test that CORS middleware works correctly when origins are configured.

    We test this by creating a minimal FastAPI app with CORSMiddleware
    using the same pattern as the production code, since the production
    apps read the env var at import time.
    """

    def _make_app_with_cors(self, origins: list[str]) -> FastAPI:
        test_app = FastAPI()
        test_app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        @test_app.get("/test")
        async def test_endpoint():
            return {"ok": True}

        @test_app.post("/test")
        async def test_post():
            return {"ok": True}

        return test_app

    def test_cors_headers_present_for_allowed_origin(self):
        app = self._make_app_with_cors(["http://dashboard.mallcop.dev"])
        client = TestClient(app)
        resp = client.get("/test", headers={"Origin": "http://dashboard.mallcop.dev"})
        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == "http://dashboard.mallcop.dev"
        assert resp.headers.get("access-control-allow-credentials") == "true"

    def test_cors_preflight_returns_200(self):
        app = self._make_app_with_cors(["http://dashboard.mallcop.dev"])
        client = TestClient(app)
        resp = client.options(
            "/test",
            headers={
                "Origin": "http://dashboard.mallcop.dev",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == "http://dashboard.mallcop.dev"
        assert "POST" in resp.headers.get("access-control-allow-methods", "")

    def test_cors_rejects_unlisted_origin(self):
        app = self._make_app_with_cors(["http://dashboard.mallcop.dev"])
        client = TestClient(app)
        resp = client.get("/test", headers={"Origin": "http://evil.com"})
        assert resp.status_code == 200
        # Origin not in whitelist → no CORS header
        assert "access-control-allow-origin" not in resp.headers

    def test_multiple_origins(self):
        app = self._make_app_with_cors(["http://a.com", "http://b.com"])
        client = TestClient(app)

        resp_a = client.get("/test", headers={"Origin": "http://a.com"})
        assert resp_a.headers["access-control-allow-origin"] == "http://a.com"

        resp_b = client.get("/test", headers={"Origin": "http://b.com"})
        assert resp_b.headers["access-control-allow-origin"] == "http://b.com"

        resp_c = client.get("/test", headers={"Origin": "http://c.com"})
        assert "access-control-allow-origin" not in resp_c.headers


class TestCorsEnvParsing:
    """Test that the env var parsing logic works correctly."""

    def test_empty_string_produces_no_origins(self):
        origins = [o.strip() for o in "".split(",") if o.strip()]
        assert origins == []

    def test_single_origin(self):
        origins = [o.strip() for o in "http://localhost:3000".split(",") if o.strip()]
        assert origins == ["http://localhost:3000"]

    def test_multiple_origins_with_spaces(self):
        origins = [o.strip() for o in "http://a.com , http://b.com, http://c.com ".split(",") if o.strip()]
        assert origins == ["http://a.com", "http://b.com", "http://c.com"]

    def test_trailing_comma_ignored(self):
        origins = [o.strip() for o in "http://a.com,".split(",") if o.strip()]
        assert origins == ["http://a.com"]
