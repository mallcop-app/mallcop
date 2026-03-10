"""Tests for Stripe key validation in billing module."""
import pytest

from services.account import billing


class TestStripeKeyValidation:
    """Stripe API key must be set before billing functions are called."""

    def test_create_checkout_without_stripe_key_raises(self, monkeypatch):
        monkeypatch.setattr(billing, "STRIPE_API_KEY", "")
        with pytest.raises(RuntimeError, match="STRIPE_SECRET_KEY"):
            billing.create_checkout("acct-123", "small")

    def test_create_checkout_with_stripe_key_set(self, monkeypatch):
        """When key is set, function proceeds (will fail on network, not on key check)."""
        monkeypatch.setattr(billing, "STRIPE_API_KEY", "sk_test_fake123")
        # Should not raise RuntimeError — it will try the HTTP call and fail differently
        with pytest.raises(Exception) as exc_info:
            billing.create_checkout("acct-123", "small")
        # The error should NOT be about missing key
        assert "STRIPE_SECRET_KEY" not in str(exc_info.value)
