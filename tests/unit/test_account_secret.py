"""Tests for hardcoded secret removal (mallcop-186) and authorization checks (mallcop-188)."""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from services.account.auth import create_service_token


# ---------------------------------------------------------------------------
# mallcop-186: ACCOUNT_SECRET must be required (no default)
# ---------------------------------------------------------------------------


class TestAccountSecretRequired:
    """ACCOUNT_SECRET env var must be set — no hardcoded fallback."""

    def test_account_app_raises_without_secret(self, monkeypatch):
        """Importing account app with no ACCOUNT_SECRET raises RuntimeError."""
        monkeypatch.delenv("ACCOUNT_SECRET", raising=False)
        # Must reimport to trigger the module-level check
        result = subprocess.run(
            [sys.executable, "-c", "from services.account.app import app"],
            capture_output=True,
            text=True,
            env={k: v for k, v in os.environ.items() if k != "ACCOUNT_SECRET"},
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        )
        assert result.returncode != 0
        assert "ACCOUNT_SECRET" in result.stderr

    def test_inference_app_raises_without_secret(self, monkeypatch):
        """Importing inference app with no ACCOUNT_SECRET raises RuntimeError."""
        monkeypatch.delenv("ACCOUNT_SECRET", raising=False)
        result = subprocess.run(
            [sys.executable, "-c", "from services.inference.app import app"],
            capture_output=True,
            text=True,
            env={k: v for k, v in os.environ.items() if k != "ACCOUNT_SECRET"},
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        )
        assert result.returncode != 0
        assert "ACCOUNT_SECRET" in result.stderr


# ---------------------------------------------------------------------------
# mallcop-188: Authorization checks on account endpoints
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _set_account_secret(monkeypatch):
    """Ensure ACCOUNT_SECRET is set for all tests in this module."""
    monkeypatch.setenv("ACCOUNT_SECRET", "test-secret-for-unit")


@pytest.fixture
def client():
    """Create a TestClient with fresh in-memory DB per test."""
    # Force reimport so module picks up patched env
    for mod_name in list(sys.modules):
        if mod_name.startswith("services.account.app"):
            del sys.modules[mod_name]
    from services.account.app import app as account_app

    with TestClient(account_app) as c:
        yield c


def _create_account(client: TestClient, email: str = "a@example.com") -> dict:
    resp = client.post("/accounts", json={"email": email})
    assert resp.status_code == 200
    return resp.json()


class TestAuthorizationChecks:
    """Endpoints must verify the caller owns the account."""

    def test_get_own_account_succeeds(self, client):
        data = _create_account(client, "own@example.com")
        account_id = data["account_id"]
        token = data["service_token"]

        resp = client.get(
            f"/accounts/{account_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["account_id"] == account_id

    def test_get_other_account_returns_403(self, client):
        user_a = _create_account(client, "a@example.com")
        user_b = _create_account(client, "b@example.com")

        # User A tries to access user B's account
        resp = client.get(
            f"/accounts/{user_b['account_id']}",
            headers={"Authorization": f"Bearer {user_a['service_token']}"},
        )
        assert resp.status_code == 403

    def test_rotate_own_token_succeeds(self, client):
        data = _create_account(client, "rot@example.com")
        account_id = data["account_id"]
        token = data["service_token"]

        resp = client.post(
            f"/accounts/{account_id}/tokens",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["service_token"] != token

    def test_rotate_other_token_returns_403(self, client):
        user_a = _create_account(client, "a2@example.com")
        user_b = _create_account(client, "b2@example.com")

        resp = client.post(
            f"/accounts/{user_b['account_id']}/tokens",
            headers={"Authorization": f"Bearer {user_a['service_token']}"},
        )
        assert resp.status_code == 403

    def test_missing_auth_header_returns_401(self, client):
        data = _create_account(client, "noauth@example.com")
        account_id = data["account_id"]

        resp = client.get(f"/accounts/{account_id}")
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, client):
        data = _create_account(client, "badtoken@example.com")
        account_id = data["account_id"]

        resp = client.get(
            f"/accounts/{account_id}",
            headers={"Authorization": "Bearer garbage.token.here"},
        )
        assert resp.status_code == 401
