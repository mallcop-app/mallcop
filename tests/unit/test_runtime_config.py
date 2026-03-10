"""Tests for _resolve_channel_config env var resolution and webhook URL validation."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from mallcop.actors._schema import ActorManifest
from mallcop.actors.runtime import _resolve_channel_config, _validate_webhook_url


class _FakeConfig:
    """Minimal stand-in for runtime config with an actors dict."""
    def __init__(self, actors: dict | None = None):
        self.actors = actors or {}


def _make_manifest(name: str = "notify-slack", config: dict | None = None) -> ActorManifest:
    """Build a minimal ActorManifest with the given config defaults."""
    return ActorManifest(
        name=name,
        type="channel",
        description="test",
        version="1.0",
        model=None,
        tools=[],
        permissions=[],
        routes_to=None,
        max_iterations=None,
        config=config or {},
    )


# --- Env var resolution ---

class TestEnvVarResolution:
    """_resolve_channel_config must raise when env var is missing/empty."""

    def test_missing_env_var_raises(self):
        manifest = _make_manifest(config={"webhook_url": "${MISSING_VAR_XYZ}"})
        cfg = _FakeConfig()
        with patch.dict(os.environ, {}, clear=False):
            # Ensure the var is truly absent
            os.environ.pop("MISSING_VAR_XYZ", None)
            with pytest.raises(ValueError, match="Environment variable MISSING_VAR_XYZ is not set"):
                _resolve_channel_config(manifest, cfg)

    def test_empty_env_var_raises(self):
        manifest = _make_manifest(config={"webhook_url": "${EMPTY_VAR_XYZ}"})
        cfg = _FakeConfig()
        with patch.dict(os.environ, {"EMPTY_VAR_XYZ": ""}, clear=False):
            with pytest.raises(ValueError, match="Environment variable EMPTY_VAR_XYZ is not set"):
                _resolve_channel_config(manifest, cfg)

    def test_set_env_var_resolves(self):
        manifest = _make_manifest(config={"webhook_url": "${MY_WEBHOOK}"})
        cfg = _FakeConfig()
        with patch.dict(os.environ, {"MY_WEBHOOK": "https://hooks.example.com/abc"}, clear=False):
            result = _resolve_channel_config(manifest, cfg)
            assert result["webhook_url"] == "https://hooks.example.com/abc"


# --- Webhook URL validation ---

class TestValidateWebhookUrl:
    """_validate_webhook_url in runtime.py rejects non-https and private IPs."""

    def test_https_required(self):
        with pytest.raises(ValueError, match="HTTPS required"):
            _validate_webhook_url("http://example.com/webhook")

    def test_valid_https_passes(self):
        # Should not raise
        _validate_webhook_url("https://hooks.slack.com/services/T00/B00/xxx")

    def test_private_ip_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://10.0.0.1/webhook")

    def test_loopback_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://127.0.0.1/webhook")

    def test_link_local_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://169.254.1.1/webhook")

    def test_localhost_rejected(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://localhost/webhook")


# --- Integration: resolved URL is validated ---

class TestResolvedUrlValidation:
    """After env var resolution, webhook_url must be validated."""

    def test_resolved_non_https_rejected(self):
        manifest = _make_manifest(config={"webhook_url": "${BAD_WEBHOOK}"})
        cfg = _FakeConfig()
        with patch.dict(os.environ, {"BAD_WEBHOOK": "http://example.com/hook"}, clear=False):
            with pytest.raises(ValueError, match="HTTPS required"):
                _resolve_channel_config(manifest, cfg)

    def test_resolved_private_ip_rejected(self):
        manifest = _make_manifest(config={"webhook_url": "${PRIV_WEBHOOK}"})
        cfg = _FakeConfig()
        with patch.dict(os.environ, {"PRIV_WEBHOOK": "https://192.168.1.1/hook"}, clear=False):
            with pytest.raises(ValueError, match="private/reserved"):
                _resolve_channel_config(manifest, cfg)
