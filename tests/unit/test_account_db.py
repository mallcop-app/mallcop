"""Tests for services.account.db — SQL injection whitelist."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make services/account importable without install
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "account"))

from db import AccountDB  # noqa: E402


@pytest.fixture()
def db(tmp_path):
    adb = AccountDB(str(tmp_path / "test.db"))
    yield adb
    adb.close()


class TestUpdateAccountWhitelist:
    """update_account must reject column names not in the whitelist."""

    def test_rejects_malicious_column(self, db):
        acct = db.create_account("a@b.com")
        with pytest.raises(ValueError, match="Invalid columns"):
            db.update_account(acct["account_id"], **{"evil_col; DROP TABLE accounts--": "x"})

    def test_rejects_unknown_column(self, db):
        acct = db.create_account("a@b.com")
        with pytest.raises(ValueError, match="Invalid columns"):
            db.update_account(acct["account_id"], nonexistent="val")

    def test_accepts_plan_tier(self, db):
        acct = db.create_account("a@b.com")
        assert db.update_account(acct["account_id"], plan_tier="pro") is True
        updated = db.get_account(acct["account_id"])
        assert updated["plan_tier"] == "pro"

    def test_accepts_status(self, db):
        acct = db.create_account("a@b.com")
        assert db.update_account(acct["account_id"], status="suspended") is True
        updated = db.get_account(acct["account_id"])
        assert updated["status"] == "suspended"

    def test_accepts_stripe_fields(self, db):
        acct = db.create_account("a@b.com")
        assert db.update_account(
            acct["account_id"],
            stripe_customer_id="cus_123",
            stripe_subscription_id="sub_456",
        ) is True
        updated = db.get_account(acct["account_id"])
        assert updated["stripe_customer_id"] == "cus_123"
        assert updated["stripe_subscription_id"] == "sub_456"

    def test_mixed_valid_and_invalid_rejected(self, db):
        acct = db.create_account("a@b.com")
        with pytest.raises(ValueError, match="Invalid columns"):
            db.update_account(acct["account_id"], plan_tier="pro", hacked="yes")
