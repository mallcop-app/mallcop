"""Tests for email validation on CreateAccountRequest."""
import pytest
from pydantic import ValidationError

from services.account.models import CreateAccountRequest


class TestEmailValidation:
    """Email validation on CreateAccountRequest."""

    @pytest.mark.parametrize("email", [
        "user@example.com",
        "user@sub.example.com",
        "user+tag@example.com",
        "a@b.co",
        "long.name@very-long-domain.org",
    ])
    def test_valid_emails(self, email):
        req = CreateAccountRequest(email=email)
        assert req.email == email

    @pytest.mark.parametrize("email,reason", [
        ("", "empty string"),
        ("noatsign", "no @ symbol"),
        ("@example.com", "no local part"),
        ("user@", "no domain"),
        ("user@ example.com", "whitespace in domain"),
        ("user @example.com", "whitespace in local"),
        ("user@example", "no TLD"),
        ("user@example.c", "single-char TLD"),
        ("a" * 255 + "@example.com", "too long"),
    ])
    def test_invalid_emails(self, email, reason):
        with pytest.raises(ValidationError):
            CreateAccountRequest(email=email)
