"""Unit tests for audit logging in account service."""
from __future__ import annotations

import os

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from services.account.app import app, reset_rate_limiter, get_db
from services.account.db import AccountDB

_SECRET = os.environ.get("ACCOUNT_SECRET", "test-secret")


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    with TestClient(app) as c:
        reset_rate_limiter()
        yield c


def _get_db() -> AccountDB:
    """Access the live DB from the running app."""
    return get_db()


class TestAuditLogSchema:
    """Test that audit_log table exists and works at the DB level."""

    def test_write_and_read_audit_log(self):
        db = AccountDB(":memory:")
        db.write_audit_log(action="test_action", account_id="acct_123", source_ip="1.2.3.4", detail="hello")
        entries = db.get_audit_log()
        assert len(entries) == 1
        e = entries[0]
        assert e["action"] == "test_action"
        assert e["account_id"] == "acct_123"
        assert e["source_ip"] == "1.2.3.4"
        assert e["detail"] == "hello"
        assert e["timestamp"] > 0
        db.close()

    def test_filter_by_account_id(self):
        db = AccountDB(":memory:")
        db.write_audit_log(action="a1", account_id="acct_aaa")
        db.write_audit_log(action="a2", account_id="acct_bbb")
        db.write_audit_log(action="a3", account_id="acct_aaa")
        entries = db.get_audit_log(account_id="acct_aaa")
        assert len(entries) == 2
        assert all(e["account_id"] == "acct_aaa" for e in entries)
        db.close()

    def test_limit(self):
        db = AccountDB(":memory:")
        for i in range(5):
            db.write_audit_log(action=f"a{i}", account_id="acct_x")
        entries = db.get_audit_log(limit=3)
        assert len(entries) == 3
        db.close()


class TestAuditLogOnAccountCreation:
    def test_account_creation_logged(self, client):
        resp = client.post("/accounts", json={"email": "audit1@example.com"})
        assert resp.status_code == 200
        account_id = resp.json()["account_id"]

        db = _get_db()
        entries = db.get_audit_log(account_id=account_id)
        assert len(entries) == 1
        assert entries[0]["action"] == "account_created"
        assert "audit1@example.com" in entries[0]["detail"]


class TestAuditLogOnTokenRotation:
    def test_token_rotation_logged(self, client):
        resp = client.post("/accounts", json={"email": "audit2@example.com"})
        data = resp.json()
        account_id = data["account_id"]
        token = data["service_token"]

        client.post(f"/accounts/{account_id}/tokens", headers=_auth(token))

        db = _get_db()
        entries = db.get_audit_log(account_id=account_id)
        actions = [e["action"] for e in entries]
        assert "token_rotated" in actions
        assert "account_created" in actions


class TestAuditLogOnFailedAuth:
    def test_missing_token_logged(self, client):
        # No auth header → 401
        resp = client.get("/accounts/acct_fake123")
        assert resp.status_code == 401

        db = _get_db()
        entries = db.get_audit_log(account_id="acct_fake123")
        assert len(entries) >= 1
        assert entries[0]["action"] == "auth_failed"
        assert entries[0]["detail"] == "missing_token"

    def test_invalid_token_logged(self, client):
        resp = client.get("/accounts/acct_fake456", headers=_auth("garbage.token.here"))
        assert resp.status_code == 401

        db = _get_db()
        entries = db.get_audit_log(account_id="acct_fake456")
        assert len(entries) >= 1
        assert entries[0]["action"] == "auth_failed"
        assert entries[0]["detail"] == "invalid_token"

    def test_owner_mismatch_logged(self, client):
        # Create account to get a valid token
        resp = client.post("/accounts", json={"email": "audit3@example.com"})
        token = resp.json()["service_token"]

        # Try to access a different account
        resp = client.get("/accounts/acct_other999", headers=_auth(token))
        assert resp.status_code == 403

        db = _get_db()
        entries = db.get_audit_log(account_id="acct_other999")
        assert len(entries) >= 1
        assert entries[0]["action"] == "auth_failed"
        assert entries[0]["detail"] == "owner_mismatch"
