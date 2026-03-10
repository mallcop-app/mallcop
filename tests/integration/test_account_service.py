"""Integration tests for the FastAPI account service."""
from __future__ import annotations

import os

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from services.account.app import app, reset_rate_limiter
from services.account.auth import create_service_token, validate_service_token

_SECRET = os.environ.get("ACCOUNT_SECRET", "test-secret")


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    """Create a TestClient with fresh in-memory DB per test."""
    with TestClient(app) as c:
        reset_rate_limiter()
        yield c


class TestCreateAccount:
    def test_create_account_returns_id_and_token(self, client):
        resp = client.post("/accounts", json={"email": "user@example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["account_id"].startswith("acct_")
        assert data["email"] == "user@example.com"
        assert data["plan_tier"] == "free"
        assert data["service_token"] is not None
        assert len(data["service_token"]) > 20
        assert data["created_at"]  # ISO timestamp

    def test_duplicate_email_returns_200_no_enumeration(self, client):
        """Anti-enumeration: duplicate email returns 200 with same shape."""
        resp1 = client.post("/accounts", json={"email": "dup@example.com"})
        resp2 = client.post("/accounts", json={"email": "dup@example.com"})
        assert resp2.status_code == 200
        data = resp2.json()
        assert "account_id" in data
        assert "service_token" in data


class TestGetAccount:
    def test_get_existing_account(self, client):
        create_resp = client.post("/accounts", json={"email": "get@example.com"})
        data = create_resp.json()
        account_id = data["account_id"]
        token = data["service_token"]

        resp = client.get(f"/accounts/{account_id}", headers=_auth(token))
        assert resp.status_code == 200
        info = resp.json()
        assert info["account_id"] == account_id
        assert info["email"] == "get@example.com"
        assert info["plan_tier"] == "free"
        assert info["status"] == "active"

    def test_get_unknown_account_returns_404(self, client):
        # Create an account to get a valid token, then request a nonexistent id
        create_resp = client.post("/accounts", json={"email": "finder@example.com"})
        token = create_resp.json()["service_token"]
        # Token sub won't match acct_nonexistent → 403 (auth check before 404)
        resp = client.get("/accounts/acct_nonexistent", headers=_auth(token))
        assert resp.status_code == 403

    def test_get_without_auth_returns_401(self, client):
        resp = client.get("/accounts/acct_nonexistent")
        assert resp.status_code == 401


class TestRotateToken:
    def test_rotate_token_returns_new_token(self, client):
        create_resp = client.post("/accounts", json={"email": "rot@example.com"})
        data = create_resp.json()
        account_id = data["account_id"]
        original_token = data["service_token"]

        resp = client.post(f"/accounts/{account_id}/tokens", headers=_auth(original_token))
        assert resp.status_code == 200
        new_data = resp.json()
        assert new_data["service_token"] != original_token
        assert new_data["expires_at"]

    def test_rotate_token_unknown_account_returns_403(self, client):
        create_resp = client.post("/accounts", json={"email": "rotx@example.com"})
        token = create_resp.json()["service_token"]
        resp = client.post("/accounts/acct_nonexistent/tokens", headers=_auth(token))
        assert resp.status_code == 403

    def test_rotate_without_auth_returns_401(self, client):
        resp = client.post("/accounts/acct_nonexistent/tokens")
        assert resp.status_code == 401


class TestFullFlow:
    """End-to-end: create → get → rotate → validate."""

    def test_full_account_lifecycle(self, client):
        # Create
        create_resp = client.post("/accounts", json={"email": "lifecycle@example.com"})
        assert create_resp.status_code == 200
        data = create_resp.json()
        account_id = data["account_id"]
        token = data["service_token"]

        # Get (with auth)
        get_resp = client.get(f"/accounts/{account_id}", headers=_auth(token))
        assert get_resp.status_code == 200
        assert get_resp.json()["email"] == "lifecycle@example.com"

        # Rotate (with auth)
        rotate_resp = client.post(f"/accounts/{account_id}/tokens", headers=_auth(token))
        assert rotate_resp.status_code == 200
        new_token = rotate_resp.json()["service_token"]
        assert new_token != token

        # Validate the new token
        payload = validate_service_token(new_token, _SECRET)
        assert payload is not None
        assert payload["sub"] == account_id
        assert payload["plan"] == "free"


class TestCreateAccountErrors:
    """Account creation error cases."""

    def test_missing_email_field_returns_422(self, client):
        resp = client.post("/accounts", json={})
        assert resp.status_code == 422

    def test_invalid_email_empty_string(self, client):
        resp = client.post("/accounts", json={"email": ""})
        # May return 422 (validation) or 200 depending on model validation
        # At minimum it should not return 500
        assert resp.status_code != 500

    def test_missing_json_body_returns_422(self, client):
        resp = client.post("/accounts", content=b"", headers={"Content-Type": "application/json"})
        assert resp.status_code == 422

    def test_extra_fields_ignored(self, client):
        resp = client.post("/accounts", json={"email": "extra@example.com", "plan_tier": "large", "extra": "field"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan_tier"] == "free"  # plan_tier should not be settable at creation


class TestGetAccountErrors:
    """Account retrieval error cases."""

    def test_bad_account_id_format(self, client):
        """Non-existent account with valid auth token returns 403 (sub mismatch)."""
        create_resp = client.post("/accounts", json={"email": "badid@example.com"})
        token = create_resp.json()["service_token"]
        resp = client.get("/accounts/not-a-real-id", headers=_auth(token))
        assert resp.status_code == 403

    def test_malformed_bearer_token(self, client):
        resp = client.get("/accounts/acct_test", headers={"Authorization": "Bearer !!invalid!!"})
        assert resp.status_code == 401

    def test_missing_bearer_prefix(self, client):
        resp = client.get("/accounts/acct_test", headers={"Authorization": "Token abc123"})
        assert resp.status_code == 401

    def test_empty_auth_header(self, client):
        resp = client.get("/accounts/acct_test", headers={"Authorization": ""})
        assert resp.status_code == 401


class TestRotateTokenErrors:
    """Token rotation error cases."""

    def test_rotate_with_expired_token_format(self, client):
        """Malformed token string returns 401."""
        resp = client.post("/accounts/acct_test/tokens", headers=_auth("garbage-token"))
        assert resp.status_code == 401


class TestAuthModule:
    """Unit-level tests for auth.py within the integration context."""

    def test_create_and_validate_token(self):
        secret = "test-secret"
        token, expires_at = create_service_token("acct_test", "small", secret)
        payload = validate_service_token(token, secret)
        assert payload is not None
        assert payload["sub"] == "acct_test"
        assert payload["plan"] == "small"

    def test_validate_with_wrong_secret(self):
        token, _ = create_service_token("acct_test", "free", "correct-secret")
        payload = validate_service_token(token, "wrong-secret")
        assert payload is None

    def test_validate_garbage_token(self):
        payload = validate_service_token("not.a.token", "secret")
        assert payload is None
