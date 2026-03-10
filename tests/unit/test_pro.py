"""Tests for Pro account client and config integration."""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
import requests

from mallcop.pro import AccountInfo, ProClient


class TestProClientCreateAccount:
    """ProClient.create_account with mocked HTTP."""

    def test_create_account_success(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "account_id": "acct_abc123",
            "service_token": "tok_xyz",
        }
        with patch("mallcop.pro.requests.post", return_value=mock_resp) as mock_post:
            account_id, token = client.create_account("user@example.com")
            assert account_id == "acct_abc123"
            assert token == "tok_xyz"
            mock_post.assert_called_once_with(
                "http://localhost:8000/accounts",
                json={"email": "user@example.com"},
                timeout=30,
            )

    def test_create_account_duplicate_email(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 409
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(ValueError, match="Email already registered"):
                client.create_account("dup@example.com")

    def test_create_account_server_error(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="ProClient.create_account"):
                client.create_account("user@example.com")

    def test_create_account_error_does_not_leak_response_body(self):
        """Error message must not contain resp.text."""
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "SENSITIVE_SERVER_ERROR_DETAILS_789"
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError) as exc_info:
                client.create_account("user@example.com")
            assert "SENSITIVE_SERVER_ERROR_DETAILS_789" not in str(exc_info.value)
            assert "500" in str(exc_info.value)



class TestProClientGetAccount:
    """ProClient.get_account with mocked HTTP."""

    def test_get_account_success(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "account_id": "acct_abc123",
            "email": "user@example.com",
            "plan_tier": "free",
            "status": "active",
        }
        with patch("mallcop.pro.requests.get", return_value=mock_resp) as mock_get:
            info = client.get_account("acct_abc123", "tok_xyz")
            assert isinstance(info, AccountInfo)
            assert info.account_id == "acct_abc123"
            assert info.email == "user@example.com"
            assert info.plan_tier == "free"
            assert info.status == "active"
            mock_get.assert_called_once_with(
                "http://localhost:8000/accounts/acct_abc123",
                headers={"Authorization": "Bearer tok_xyz"},
                timeout=30,
            )

    def test_get_account_not_found(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="ProClient.get_account"):
                client.get_account("acct_nope", "tok_xyz")


class TestProClientValidateToken:
    """ProClient.validate_token validates via server API call."""

    def test_validate_valid_token_calls_server(self):
        """validate_token should call the server, not decode locally."""
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "account_id": "acct_abc123",
            "email": "user@example.com",
            "plan_tier": "small",
            "status": "active",
        }
        with patch("mallcop.pro.requests.get", return_value=mock_resp) as mock_get:
            info = client.validate_token("tok_xyz")
            assert info is not None
            assert info.account_id == "acct_abc123"
            assert info.email == "user@example.com"
            assert info.plan_tier == "small"
            assert info.status == "active"
            mock_get.assert_called_once_with(
                "http://localhost:8000/auth/validate",
                headers={"Authorization": "Bearer tok_xyz"},
                timeout=30,
            )

    def test_validate_forged_token_rejected_by_server(self):
        """A forged JWT must not be accepted -- server returns 401."""
        client = ProClient(account_url="http://localhost:8000")
        now = int(time.time())
        forged = jwt.encode(
            {"sub": "acct_evil", "plan": "large", "iat": now, "exp": now + 3600},
            "wrong-secret",
            algorithm="HS256",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            info = client.validate_token(forged)
            assert info is None

    def test_validate_invalid_token_server_rejects(self):
        """Garbage token string should return None when server rejects."""
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            info = client.validate_token("not-a-jwt")
            assert info is None

    def test_validate_token_network_error_returns_none(self):
        """Network errors during validation should return None, not raise."""
        client = ProClient(account_url="http://localhost:8000")
        with patch("mallcop.pro.requests.get", side_effect=requests.ConnectionError("refused")):
            info = client.validate_token("tok_xyz")
            assert info is None

    def test_validate_token_server_error_returns_none(self):
        """Server 500 during validation should return None."""
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            info = client.validate_token("tok_xyz")
            assert info is None


class TestProClientSubscribe:
    """ProClient.subscribe error sanitization."""

    def test_subscribe_error_does_not_leak_response_body(self):
        """subscribe error must not contain resp.text."""
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "SENSITIVE_STRIPE_ERROR_DETAILS"
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError) as exc_info:
                client.subscribe("acct_123", "small", "tok_xyz")
            assert "SENSITIVE_STRIPE_ERROR_DETAILS" not in str(exc_info.value)
            assert "500" in str(exc_info.value)


class TestProClientErrorMessageConsistency:
    """All ProClient RuntimeError messages must follow 'ProClient.<method>: <detail>' format."""

    def _assert_error_format(self, exc_info, method_name: str):
        msg = str(exc_info.value)
        assert msg.startswith(f"ProClient.{method_name}: "), (
            f"Expected 'ProClient.{method_name}: ...', got: {msg!r}"
        )

    def test_create_account_error_format(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "err"
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError) as exc_info:
                client.create_account("user@example.com")
            self._assert_error_format(exc_info, "create_account")

    def test_get_account_error_format(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError) as exc_info:
                client.get_account("acct_nope", "tok_xyz")
            self._assert_error_format(exc_info, "get_account")

    def test_record_usage_error_format(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError) as exc_info:
                client.record_usage("acct_abc", "haiku", 100, 50, "tok_xyz")
            self._assert_error_format(exc_info, "record_usage")

    def test_subscribe_error_format(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "err"
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError) as exc_info:
                client.subscribe("acct_123", "small", "tok_xyz")
            self._assert_error_format(exc_info, "subscribe")

    def test_check_subscription_error_format(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError) as exc_info:
                client.check_subscription("acct_nope", "tok_xyz")
            self._assert_error_format(exc_info, "check_subscription")

    def test_get_usage_error_format(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError) as exc_info:
                client.get_usage("acct_abc", "tok_xyz")
            self._assert_error_format(exc_info, "get_usage")


class TestProClientSpecificExceptions:
    """ProClient methods should catch specific exceptions, not bare Exception."""

    def test_create_account_catches_request_exception(self):
        """create_account propagates requests.RequestException as-is (not bare catch)."""
        client = ProClient(account_url="http://localhost:8000")
        with patch("mallcop.pro.requests.post", side_effect=requests.ConnectionError("refused")):
            with pytest.raises(requests.RequestException):
                client.create_account("user@example.com")

    def test_subscribe_catches_request_exception(self):
        """subscribe propagates requests.RequestException as-is (not bare catch)."""
        client = ProClient(account_url="http://localhost:8000")
        with patch("mallcop.pro.requests.post", side_effect=requests.ConnectionError("refused")):
            with pytest.raises(requests.RequestException):
                client.subscribe("acct_123", "small", "tok_xyz")


class TestProConfigInLoadConfig:
    """ProConfig parsing in load_config."""

    def test_load_config_without_pro_section(self, tmp_path):
        """Config without pro section should have pro=None."""
        (tmp_path / "mallcop.yaml").write_text(
            "secrets:\n  backend: env\nconnectors: {}\nrouting: {}\nactor_chain: {}\n"
        )
        from mallcop.config import load_config

        config = load_config(tmp_path)
        assert config.pro is None

    def test_load_config_with_pro_section(self, tmp_path):
        """Config with pro section should parse ProConfig."""
        (tmp_path / "mallcop.yaml").write_text(
            "secrets:\n  backend: env\nconnectors: {}\nrouting: {}\nactor_chain: {}\n"
            "pro:\n  account_id: acct_test123\n  account_url: http://localhost:8000\n"
            "  inference_url: http://localhost:8001\n"
        )
        from mallcop.config import load_config

        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.account_id == "acct_test123"
        assert config.pro.account_url == "http://localhost:8000"
        assert config.pro.inference_url == "http://localhost:8001"
        assert config.pro.service_token == ""

    def test_load_config_pro_with_env_token(self, tmp_path, monkeypatch):
        """Pro service_token should resolve ${VAR} references."""
        monkeypatch.setenv("MALLCOP_SERVICE_TOKEN", "my-secret-token")
        (tmp_path / "mallcop.yaml").write_text(
            "secrets:\n  backend: env\nconnectors: {}\nrouting: {}\nactor_chain: {}\n"
            "pro:\n  account_id: acct_test123\n  service_token: ${MALLCOP_SERVICE_TOKEN}\n"
        )
        from mallcop.config import load_config

        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.service_token == "my-secret-token"

    def test_load_config_pro_missing_env_token_graceful(self, tmp_path):
        """Pro with unresolvable service_token should fall back to empty string."""
        (tmp_path / "mallcop.yaml").write_text(
            "secrets:\n  backend: env\nconnectors: {}\nrouting: {}\nactor_chain: {}\n"
            "pro:\n  account_id: acct_test123\n  service_token: ${NONEXISTENT_VAR}\n"
        )
        from mallcop.config import load_config

        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.service_token == ""


class TestProClientRecordUsage:
    """ProClient.record_usage with mocked HTTP."""

    def test_record_usage_success(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok", "total_tokens": 150}
        with patch("mallcop.pro.requests.post", return_value=mock_resp) as mock_post:
            result = client.record_usage("acct_abc", "haiku", 100, 50, "tok_xyz")
            assert result["status"] == "ok"
            assert result["total_tokens"] == 150
            mock_post.assert_called_once_with(
                "http://localhost:8000/accounts/acct_abc/usage",
                json={"model": "haiku", "input_tokens": 100, "output_tokens": 50},
                headers={"Authorization": "Bearer tok_xyz"},
                timeout=30,
            )

    def test_record_usage_server_error(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="ProClient.record_usage: HTTP 500"):
                client.record_usage("acct_abc", "haiku", 100, 50, "tok_xyz")

    def test_record_usage_unauthorized(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="ProClient.record_usage: HTTP 401"):
                client.record_usage("acct_abc", "haiku", 100, 50, "bad_token")

    def test_record_usage_network_error_propagates(self):
        client = ProClient(account_url="http://localhost:8000")
        with patch("mallcop.pro.requests.post", side_effect=requests.ConnectionError("refused")):
            with pytest.raises(requests.RequestException):
                client.record_usage("acct_abc", "haiku", 100, 50, "tok_xyz")


class TestProClientCheckSubscription:
    """ProClient.check_subscription with mocked HTTP."""

    def test_check_subscription_success(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "account_id": "acct_abc",
            "email": "user@example.com",
            "plan_tier": "small",
            "status": "active",
        }
        with patch("mallcop.pro.requests.get", return_value=mock_resp) as mock_get:
            result = client.check_subscription("acct_abc", "tok_xyz")
            assert result["plan_tier"] == "small"
            assert result["status"] == "active"
            mock_get.assert_called_once_with(
                "http://localhost:8000/accounts/acct_abc",
                headers={"Authorization": "Bearer tok_xyz"},
                timeout=30,
            )

    def test_check_subscription_not_found(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="ProClient.check_subscription: HTTP 404"):
                client.check_subscription("acct_nope", "tok_xyz")

    def test_check_subscription_returns_only_plan_and_status(self):
        """check_subscription should return only plan_tier and status, not full account data."""
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "account_id": "acct_abc",
            "email": "user@example.com",
            "plan_tier": "large",
            "status": "active",
        }
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            result = client.check_subscription("acct_abc", "tok_xyz")
            assert set(result.keys()) == {"plan_tier", "status"}


class TestProClientGetUsage:
    """ProClient.get_usage with mocked HTTP."""

    def test_get_usage_success(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "input_tokens": 1000,
            "output_tokens": 500,
            "total_tokens": 1500,
            "requests": 10,
        }
        with patch("mallcop.pro.requests.get", return_value=mock_resp) as mock_get:
            result = client.get_usage("acct_abc", "tok_xyz")
            assert result["total_tokens"] == 1500
            assert result["requests"] == 10
            mock_get.assert_called_once_with(
                "http://localhost:8000/accounts/acct_abc/usage",
                headers={"Authorization": "Bearer tok_xyz"},
                timeout=30,
            )

    def test_get_usage_server_error(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="ProClient.get_usage: HTTP 500"):
                client.get_usage("acct_abc", "tok_xyz")

    def test_get_usage_unauthorized(self):
        client = ProClient(account_url="http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="ProClient.get_usage: HTTP 401"):
                client.get_usage("acct_abc", "bad_token")
