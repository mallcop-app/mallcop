"""Tests for inference service configuration (mallcop-236)."""
from __future__ import annotations

import os

import pytest

from services.inference.config import PLAN_LIMITS, get_provider_config


# ---------------------------------------------------------------------------
# get_provider_config() — provider routing
# ---------------------------------------------------------------------------


class TestGetProviderConfig:
    """get_provider_config returns correct structure based on INFERENCE_PROVIDER."""

    def test_bedrock_provider(self, monkeypatch):
        """INFERENCE_PROVIDER=bedrock returns bedrock config dict."""
        monkeypatch.setenv("INFERENCE_PROVIDER", "bedrock")
        monkeypatch.setenv("AWS_REGION", "us-west-2")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret123")

        cfg = get_provider_config()

        assert cfg["provider"] == "bedrock"
        assert cfg["region"] == "us-west-2"
        assert cfg["access_key"] == "AKIAEXAMPLE"
        assert cfg["secret_key"] == "secret123"

    def test_openai_compat_provider(self, monkeypatch):
        """INFERENCE_PROVIDER=openai-compat returns openai config dict."""
        monkeypatch.setenv("INFERENCE_PROVIDER", "openai-compat")
        monkeypatch.setenv("OPENAI_ENDPOINT", "https://api.example.com/v1")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        cfg = get_provider_config()

        assert cfg["provider"] == "openai-compat"
        assert cfg["endpoint"] == "https://api.example.com/v1"
        assert cfg["api_key"] == "sk-test-key"

    def test_default_provider_is_bedrock(self, monkeypatch):
        """No INFERENCE_PROVIDER env var defaults to bedrock."""
        monkeypatch.delenv("INFERENCE_PROVIDER", raising=False)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIADEFAULT")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "defaultsecret")

        cfg = get_provider_config()

        assert cfg["provider"] == "bedrock"

    def test_default_aws_region(self, monkeypatch):
        """Missing AWS_REGION defaults to us-east-1."""
        monkeypatch.setenv("INFERENCE_PROVIDER", "bedrock")
        monkeypatch.delenv("AWS_REGION", raising=False)

        cfg = get_provider_config()

        assert cfg["region"] == "us-east-1"

    def test_missing_aws_credentials_returns_empty_strings(self, monkeypatch):
        """Missing AWS_ACCESS_KEY_ID/SECRET returns empty strings (not KeyError)."""
        monkeypatch.setenv("INFERENCE_PROVIDER", "bedrock")
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

        cfg = get_provider_config()

        assert cfg["access_key"] == ""
        assert cfg["secret_key"] == ""

    def test_missing_openai_credentials_returns_empty_strings(self, monkeypatch):
        """Missing OPENAI_ENDPOINT/API_KEY returns empty strings."""
        monkeypatch.setenv("INFERENCE_PROVIDER", "openai-compat")
        monkeypatch.delenv("OPENAI_ENDPOINT", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        cfg = get_provider_config()

        assert cfg["endpoint"] == ""
        assert cfg["api_key"] == ""

    def test_unknown_provider_returns_openai_compat_shape(self, monkeypatch):
        """Any non-bedrock provider falls through to openai-compat config."""
        monkeypatch.setenv("INFERENCE_PROVIDER", "something-else")

        cfg = get_provider_config()

        assert cfg["provider"] == "openai-compat"

    def test_bedrock_config_has_exactly_four_keys(self, monkeypatch):
        """Bedrock config dict has provider, region, access_key, secret_key."""
        monkeypatch.setenv("INFERENCE_PROVIDER", "bedrock")

        cfg = get_provider_config()

        assert set(cfg.keys()) == {"provider", "region", "access_key", "secret_key"}

    def test_openai_config_has_exactly_three_keys(self, monkeypatch):
        """OpenAI-compat config dict has provider, endpoint, api_key."""
        monkeypatch.setenv("INFERENCE_PROVIDER", "openai-compat")

        cfg = get_provider_config()

        assert set(cfg.keys()) == {"provider", "endpoint", "api_key"}


# ---------------------------------------------------------------------------
# PLAN_LIMITS — plan tier token budgets
# ---------------------------------------------------------------------------


class TestPlanLimits:
    """PLAN_LIMITS dict has correct keys and integer values."""

    def test_has_all_plan_tiers(self):
        """PLAN_LIMITS contains free, small, medium, large."""
        assert set(PLAN_LIMITS.keys()) == {"free", "small", "medium", "large"}

    def test_all_values_are_ints(self):
        """Every plan limit is an integer."""
        for tier, limit in PLAN_LIMITS.items():
            assert isinstance(limit, int), f"{tier} limit is {type(limit)}, expected int"

    def test_limits_are_ascending(self):
        """Plan limits increase: free < small < medium < large."""
        assert PLAN_LIMITS["free"] < PLAN_LIMITS["small"]
        assert PLAN_LIMITS["small"] < PLAN_LIMITS["medium"]
        assert PLAN_LIMITS["medium"] < PLAN_LIMITS["large"]

    def test_free_tier_value(self):
        """Free tier is 10,000 tokens/day."""
        assert PLAN_LIMITS["free"] == 10_000

    def test_all_values_positive(self):
        """All plan limits are positive."""
        for tier, limit in PLAN_LIMITS.items():
            assert limit > 0, f"{tier} limit is {limit}, expected positive"
