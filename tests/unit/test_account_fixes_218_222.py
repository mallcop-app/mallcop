"""Tests for mallcop-218 through mallcop-222 account service fixes.

218: Missing endpoints (POST /webhooks/stripe, GET /auth/validate)
219: Subscription status updates (cancellation -> cancelled, payment_failed -> suspended)
220: JWT revocation (jti_blacklist table, blacklist on rotate)
221: Remove dict bypass in handle_stripe_event
222: Email enumeration prevention (duplicate email returns 200)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Make services/account importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "account"))

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _set_account_secret(monkeypatch):
    monkeypatch.setenv("ACCOUNT_SECRET", "test-secret-218-222")


@pytest.fixture
def client():
    """Fresh TestClient with in-memory DB per test."""
    for mod_name in list(sys.modules):
        if mod_name.startswith("services.account.app"):
            del sys.modules[mod_name]
    from services.account.app import app as account_app
    with TestClient(account_app) as c:
        yield c


def _create_account(client, email="user@example.com"):
    resp = client.post("/accounts", json={"email": email})
    assert resp.status_code == 200
    return resp.json()


def _make_stripe_signature(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    ts = timestamp or int(time.time())
    signed = f"{ts}.".encode() + payload
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


# ---------------------------------------------------------------------------
# 218: POST /webhooks/stripe endpoint
# ---------------------------------------------------------------------------

class TestWebhookEndpoint:
    """POST /webhooks/stripe must exist and handle valid/invalid signatures."""

    WEBHOOK_SECRET = "whsec_test_218"

    def _patch_webhook_secret(self):
        """Patch STRIPE_WEBHOOK_SECRET in all possible module locations."""
        import billing as billing_direct
        import services.account.billing as billing_pkg
        billing_direct.STRIPE_WEBHOOK_SECRET = self.WEBHOOK_SECRET
        billing_pkg.STRIPE_WEBHOOK_SECRET = self.WEBHOOK_SECRET

    def test_webhook_valid_signature(self, client, monkeypatch):
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", self.WEBHOOK_SECRET)
        self._patch_webhook_secret()

        acct = _create_account(client, "webhook@example.com")

        event = {
            "type": "checkout.session.completed",
            "data": {"object": {
                "client_reference_id": acct["account_id"],
                "metadata": {"plan_tier": "small"},
                "customer": "cus_wh",
                "subscription": "sub_wh",
            }},
        }
        payload = json.dumps(event).encode()
        sig = _make_stripe_signature(payload, self.WEBHOOK_SECRET)

        resp = client.post(
            "/webhooks/stripe",
            content=payload,
            headers={"Stripe-Signature": sig},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_webhook_invalid_signature(self, client, monkeypatch):
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", self.WEBHOOK_SECRET)
        self._patch_webhook_secret()

        payload = b'{"type":"test","data":{"object":{}}}'
        bad_sig = _make_stripe_signature(payload, "wrong_secret")

        resp = client.post(
            "/webhooks/stripe",
            content=payload,
            headers={"Stripe-Signature": bad_sig},
        )
        assert resp.status_code == 400

    def test_webhook_missing_signature(self, client, monkeypatch):
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", self.WEBHOOK_SECRET)
        self._patch_webhook_secret()

        payload = b'{"type":"test","data":{"object":{}}}'
        resp = client.post(
            "/webhooks/stripe",
            content=payload,
            headers={"Stripe-Signature": ""},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 218: GET /auth/validate endpoint
# ---------------------------------------------------------------------------

class TestAuthValidateEndpoint:
    """GET /auth/validate must return account info for valid tokens."""

    def test_validate_valid_token(self, client):
        acct = _create_account(client, "validate@example.com")
        token = acct["service_token"]

        resp = client.get(
            "/auth/validate",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["account_id"] == acct["account_id"]
        assert data["email"] == "validate@example.com"
        assert "plan_tier" in data
        assert "status" in data

    def test_validate_missing_token(self, client):
        resp = client.get("/auth/validate")
        assert resp.status_code == 401

    def test_validate_invalid_token(self, client):
        resp = client.get(
            "/auth/validate",
            headers={"Authorization": "Bearer garbage.token.here"},
        )
        assert resp.status_code == 401

    def test_validate_malformed_auth_header(self, client):
        resp = client.get(
            "/auth/validate",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 219: Subscription status updates
# ---------------------------------------------------------------------------

class TestSubscriptionStatusUpdates:
    """Subscription events must update account status via subscription_id lookup."""

    def test_subscription_deleted_sets_cancelled(self, client):
        from db import AccountDB
        from services.account.app import get_db

        acct = _create_account(client, "cancel@example.com")
        account_id = acct["account_id"]
        token = acct["service_token"]

        # Manually set subscription_id on the account
        db = get_db()
        db.update_account(account_id, stripe_subscription_id="sub_cancel_123", status="active")

        # Simulate subscription.deleted event via bytes
        import billing
        event = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"id": "sub_cancel_123"}},
        }
        billing.handle_stripe_event(json.dumps(event).encode(), db)

        updated = db.get_account(account_id)
        assert updated["status"] == "cancelled"

    def test_payment_failed_sets_suspended(self, client):
        from db import AccountDB
        from services.account.app import get_db

        acct = _create_account(client, "suspended@example.com")
        account_id = acct["account_id"]

        db = get_db()
        db.update_account(account_id, stripe_subscription_id="sub_fail_123", status="active")

        import billing
        event = {
            "type": "invoice.payment_failed",
            "data": {"object": {"subscription": "sub_fail_123"}},
        }
        billing.handle_stripe_event(json.dumps(event).encode(), db)

        updated = db.get_account(account_id)
        assert updated["status"] == "suspended"

    def test_get_account_by_subscription_id(self, client):
        from services.account.app import get_db

        acct = _create_account(client, "lookup@example.com")
        db = get_db()
        db.update_account(acct["account_id"], stripe_subscription_id="sub_lookup_99")

        found = db.get_account_by_subscription_id("sub_lookup_99")
        assert found is not None
        assert found["account_id"] == acct["account_id"]

    def test_get_account_by_subscription_id_not_found(self, client):
        from services.account.app import get_db
        db = get_db()
        assert db.get_account_by_subscription_id("sub_nonexistent") is None


# ---------------------------------------------------------------------------
# 220: JWT revocation via jti_blacklist
# ---------------------------------------------------------------------------

class TestJTIBlacklist:
    """Blacklisted JTIs must be rejected by validate_service_token."""

    def test_blacklisted_jti_rejected_by_validate(self):
        from auth import create_service_token, validate_service_token
        from db import AccountDB

        db = AccountDB(":memory:")
        secret = "test-secret-220"
        token, expires_at = create_service_token("acct_jti", "free", secret)

        # Token valid before blacklisting
        payload = validate_service_token(token, secret, db=db)
        assert payload is not None
        jti = payload["jti"]

        # Blacklist
        db.blacklist_jti(jti, expires_at)

        # Now rejected
        assert validate_service_token(token, secret, db=db) is None
        db.close()

    def test_validate_without_db_ignores_blacklist(self):
        """Without db parameter, blacklist is not checked (backward compat)."""
        from auth import create_service_token, validate_service_token
        from db import AccountDB

        db = AccountDB(":memory:")
        secret = "test-secret-220b"
        token, expires_at = create_service_token("acct_jti2", "free", secret)

        payload = validate_service_token(token, secret)
        assert payload is not None
        jti = payload["jti"]

        db.blacklist_jti(jti, expires_at)

        # Still valid without db
        assert validate_service_token(token, secret) is not None
        db.close()

    def test_rotate_blacklists_old_token(self, client):
        """Token rotation must blacklist the old token's JTI."""
        acct = _create_account(client, "rotate@example.com")
        old_token = acct["service_token"]
        account_id = acct["account_id"]

        # Rotate
        resp = client.post(
            f"/accounts/{account_id}/tokens",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert resp.status_code == 200
        new_token = resp.json()["service_token"]
        assert new_token != old_token

        # Old token should be blacklisted — verify via /auth/validate
        resp_old = client.get(
            "/auth/validate",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert resp_old.status_code == 401

        # New token should work
        resp_new = client.get(
            "/auth/validate",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp_new.status_code == 200

    def test_expired_blacklist_entries_cleaned(self):
        """Expired blacklist entries are cleaned up on read."""
        from db import AccountDB

        db = AccountDB(":memory:")
        # Add an entry that expired in the past
        db.blacklist_jti("old-jti", time.time() - 100)

        # Should not be found (expired, cleaned on read)
        assert db.is_jti_blacklisted("old-jti") is False
        db.close()

    def test_non_expired_blacklist_entry_persists(self):
        from db import AccountDB

        db = AccountDB(":memory:")
        db.blacklist_jti("active-jti", time.time() + 3600)
        assert db.is_jti_blacklisted("active-jti") is True
        db.close()


# ---------------------------------------------------------------------------
# 221: Dict payload rejected
# ---------------------------------------------------------------------------

class TestDictPayloadRejected:
    """handle_stripe_event must reject dict payloads."""

    def test_dict_payload_raises_type_error(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        with pytest.raises(TypeError, match="payload must be bytes"):
            handle_stripe_event({"type": "test"}, mock_db)

    def test_string_payload_raises_type_error(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        with pytest.raises(TypeError, match="payload must be bytes"):
            handle_stripe_event('{"type": "test"}', mock_db)

    def test_bytes_payload_accepted(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        payload = json.dumps({"type": "unknown", "data": {"object": {}}}).encode()
        # Should not raise
        handle_stripe_event(payload, mock_db)


# ---------------------------------------------------------------------------
# 222: Email enumeration prevention
# ---------------------------------------------------------------------------

class TestEmailEnumerationPrevention:
    """Duplicate email must return 200, not 409, to prevent enumeration."""

    def test_duplicate_email_returns_200(self, client):
        """Creating an account with an existing email returns 200, not 409."""
        _create_account(client, "dup@example.com")
        resp = client.post("/accounts", json={"email": "dup@example.com"})
        assert resp.status_code == 200

    def test_duplicate_email_response_has_same_shape(self, client):
        """Response for duplicate email has the same fields as new account."""
        first = _create_account(client, "shape@example.com")
        resp = client.post("/accounts", json={"email": "shape@example.com"})
        second = resp.json()

        # Same keys in response
        assert set(first.keys()) == set(second.keys())
        # Both have account_id and service_token
        assert "account_id" in second
        assert "service_token" in second
        assert "email" in second

    def test_duplicate_email_returns_different_account_id(self, client):
        """Duplicate email should NOT return the real account_id."""
        first = _create_account(client, "diff@example.com")
        resp = client.post("/accounts", json={"email": "diff@example.com"})
        second = resp.json()
        # The fake account_id must differ from the real one
        assert second["account_id"] != first["account_id"]

    def test_new_email_still_works(self, client):
        """New emails still create real accounts."""
        resp = client.post("/accounts", json={"email": "new@example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "new@example.com"
        assert data["account_id"].startswith("acct_")
