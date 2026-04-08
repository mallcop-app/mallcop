"""Tests for GitHub connector app token loading and device flow scope."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from mallcop.connectors.github.connector import GitHubConnector
from mallcop.github_auth import start_device_flow


class TestGitHubConnectorAppToken:
    def test_load_app_token_prefers_saved_credentials(self, tmp_path: Path) -> None:
        """Connector uses saved .github-credentials over GITHUB_TOKEN env var."""
        creds = {
            "access_token": "ghu_saved_token_xyz",
            "refresh_token": "ghr_refresh_xyz",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=7)).isoformat(),
            "token_type": "bearer",
            "scope": "repo admin:org",
        }
        creds_path = tmp_path / ".mallcop" / ".github-credentials"
        creds_path.parent.mkdir(parents=True)
        creds_path.write_text(json.dumps(creds))

        connector = GitHubConnector()
        with patch.object(connector, "_load_app_token") as mock_load:
            mock_load.return_value = "ghu_saved_token_xyz"
            # authenticate should use the saved token
            from mallcop.secrets import EnvSecretProvider
            import os
            os.environ["GITHUB_TOKEN"] = "ghp_env_token_will_be_ignored"
            os.environ["GITHUB_ORG"] = "test-org"
            try:
                with patch.object(connector, "_validate_token"):
                    connector.authenticate(EnvSecretProvider())
                assert connector._token == "ghu_saved_token_xyz"
            finally:
                del os.environ["GITHUB_TOKEN"]
                del os.environ["GITHUB_ORG"]

    def test_load_app_token_falls_back_to_env(self, tmp_path: Path) -> None:
        """When no saved credentials exist, connector falls back to GITHUB_TOKEN."""
        from mallcop.secrets import EnvSecretProvider
        connector = GitHubConnector()
        with patch.object(connector, "_load_app_token", return_value=None):
            import os
            os.environ["GITHUB_TOKEN"] = "ghp_fallback_token"
            os.environ["GITHUB_ORG"] = "test-org"
            try:
                with patch.object(connector, "_validate_token"):
                    connector.authenticate(EnvSecretProvider())
                assert connector._token == "ghp_fallback_token"
            finally:
                del os.environ["GITHUB_TOKEN"]
                del os.environ["GITHUB_ORG"]


class TestDeviceFlowScope:
    def test_device_flow_requests_admin_org_scope(self) -> None:
        """start_device_flow must request admin:org scope for audit log access."""
        captured_params = {}

        def fake_post_json(url, params):
            captured_params.update(params)
            return {
                "device_code": "dc_test",
                "user_code": "ABCD-1234",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 5,
            }

        with patch("mallcop.github_auth._post_json", side_effect=fake_post_json):
            start_device_flow("test-client-id")

        scope = captured_params.get("scope", "")
        assert "admin:org" in scope, f"Expected admin:org in scope, got: {scope!r}"
        assert "repo" in scope, f"Expected repo in scope, got: {scope!r}"
