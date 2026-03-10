"""Tests for services.account.auth — JWT token lifetime."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Make services/account importable without install
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "account"))

import jwt as pyjwt

from auth import _TOKEN_LIFETIME, create_service_token, validate_service_token  # noqa: E402

SECRET = "test-secret-key"


class TestTokenLifetime:
    """JWT tokens must expire after 24 hours."""

    def test_lifetime_is_24_hours(self):
        assert _TOKEN_LIFETIME == 24 * 3600

    def test_exp_claim_matches_lifetime(self):
        fake_now = 1_700_000_000.0
        with patch("auth.time.time", return_value=fake_now):
            token, expires_at = create_service_token("acct-1", "small", SECRET)

        assert expires_at == pytest.approx(fake_now + 24 * 3600)

        # Decode without exp verification (fake_now is in the past) to inspect claims.
        payload = pyjwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})
        assert payload["exp"] == int(fake_now + 24 * 3600)
        assert payload["iat"] == int(fake_now)

    def test_expired_token_rejected(self):
        """A token issued 25 hours ago must be rejected."""
        past = time.time() - 25 * 3600
        with patch("auth.time.time", return_value=past):
            token, _ = create_service_token("acct-1", "small", SECRET)

        # Now (real time) is 25 hours after issuance — token has expired.
        assert validate_service_token(token, SECRET) is None
