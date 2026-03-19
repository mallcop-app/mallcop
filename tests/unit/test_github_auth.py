"""Tests for GitHub OAuth device flow client."""

import json
import os
import stat
import time
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import pytest

from mallcop.github_auth import (
    DeviceFlowPending,
    GitHubAuthError,
    GitHubTokenSet,
    is_token_expired,
    load_credentials,
    poll_for_token,
    refresh_access_token,
    save_credentials,
    start_device_flow,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(data: dict, status: int = 200):
    """Return a mock urllib response object."""
    body = json.dumps(data).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.status = status
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# start_device_flow
# ---------------------------------------------------------------------------

class TestStartDeviceFlow:
    def test_returns_device_flow_pending(self):
        resp_data = {
            "device_code": "dev123",
            "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5,
        }
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)):
            result = start_device_flow("myclient")

        assert isinstance(result, DeviceFlowPending)
        assert result.device_code == "dev123"
        assert result.user_code == "ABCD-1234"
        assert result.verification_uri == "https://github.com/login/device"
        assert result.expires_in == 900
        assert result.interval == 5

    def test_posts_to_correct_url(self):
        resp_data = {
            "device_code": "x",
            "user_code": "y",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5,
        }
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)) as mock_open:
            start_device_flow("myclient")

        req = mock_open.call_args[0][0]
        assert "github.com/login/device" in req.full_url
        assert req.get_header("Accept") == "application/json"


# ---------------------------------------------------------------------------
# poll_for_token
# ---------------------------------------------------------------------------

class TestPollForToken:
    def test_succeeds_immediately(self):
        now = datetime.now(timezone.utc)
        resp_data = {
            "access_token": "gho_abc",
            "refresh_token": "ghr_xyz",
            "expires_in": 28800,
            "refresh_token_expires_in": 15897600,
            "token_type": "bearer",
            "scope": "repo",
        }
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)):
            with patch("time.sleep"):
                result = poll_for_token("myclient", "devcode", interval=5)

        assert isinstance(result, GitHubTokenSet)
        assert result.access_token == "gho_abc"
        assert result.refresh_token == "ghr_xyz"
        assert result.token_type == "bearer"
        assert result.scope == "repo"
        # expires_at should be roughly now + 8h
        assert result.expires_at > now + timedelta(hours=7)

    def test_succeeds_after_authorization_pending(self):
        pending = {"error": "authorization_pending"}
        success = {
            "access_token": "gho_abc",
            "refresh_token": "ghr_xyz",
            "expires_in": 28800,
            "refresh_token_expires_in": 15897600,
            "token_type": "bearer",
            "scope": "repo",
        }
        responses = [
            _make_response(pending),
            _make_response(pending),
            _make_response(success),
        ]
        with patch("urllib.request.urlopen", side_effect=responses):
            with patch("time.sleep") as mock_sleep:
                result = poll_for_token("myclient", "devcode", interval=5)

        assert result.access_token == "gho_abc"
        assert mock_sleep.call_count == 2
        mock_sleep.assert_called_with(5)

    def test_slow_down_increases_interval(self):
        slow_down = {"error": "slow_down"}
        success = {
            "access_token": "gho_abc",
            "refresh_token": "ghr_xyz",
            "expires_in": 28800,
            "refresh_token_expires_in": 15897600,
            "token_type": "bearer",
            "scope": "repo",
        }
        responses = [
            _make_response(slow_down),
            _make_response(success),
        ]
        with patch("urllib.request.urlopen", side_effect=responses):
            with patch("time.sleep") as mock_sleep:
                result = poll_for_token("myclient", "devcode", interval=5)

        assert result.access_token == "gho_abc"
        # First sleep should be 5+5=10 after slow_down
        mock_sleep.assert_called_with(10)

    def test_raises_on_expired_token(self):
        resp_data = {"error": "expired_token"}
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)):
            with patch("time.sleep"):
                with pytest.raises(GitHubAuthError) as exc_info:
                    poll_for_token("myclient", "devcode", interval=5)

        assert exc_info.value.error_code == "expired_token"

    def test_raises_on_access_denied(self):
        resp_data = {"error": "access_denied"}
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)):
            with patch("time.sleep"):
                with pytest.raises(GitHubAuthError) as exc_info:
                    poll_for_token("myclient", "devcode", interval=5)

        assert exc_info.value.error_code == "access_denied"

    def test_raises_on_timeout(self):
        pending = {"error": "authorization_pending"}
        with patch("urllib.request.urlopen", return_value=_make_response(pending)):
            with patch("time.sleep"):
                with patch("time.time", side_effect=[0, 0, 1000]):
                    with pytest.raises(GitHubAuthError) as exc_info:
                        poll_for_token("myclient", "devcode", interval=5, timeout=300)

        assert exc_info.value.error_code == "timeout"


# ---------------------------------------------------------------------------
# refresh_access_token
# ---------------------------------------------------------------------------

class TestRefreshAccessToken:
    def test_returns_new_token_set(self):
        resp_data = {
            "access_token": "gho_new",
            "refresh_token": "ghr_new",
            "expires_in": 28800,
            "refresh_token_expires_in": 15897600,
            "token_type": "bearer",
            "scope": "repo",
        }
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)):
            result = refresh_access_token("myclient", "ghr_old")

        assert isinstance(result, GitHubTokenSet)
        assert result.access_token == "gho_new"
        assert result.refresh_token == "ghr_new"

    def test_raises_on_expired_refresh_token(self):
        resp_data = {"error": "token_expired", "error_description": "refresh token expired"}
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)):
            with pytest.raises(GitHubAuthError) as exc_info:
                refresh_access_token("myclient", "ghr_old")

        assert exc_info.value.error_code in ("token_expired", "refresh_token_expired")

    def test_posts_correct_grant_type(self):
        resp_data = {
            "access_token": "gho_new",
            "refresh_token": "ghr_new",
            "expires_in": 28800,
            "refresh_token_expires_in": 15897600,
            "token_type": "bearer",
            "scope": "repo",
        }
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)) as mock_open:
            refresh_access_token("myclient", "ghr_old")

        req = mock_open.call_args[0][0]
        body = req.data.decode()
        assert "grant_type=refresh_token" in body
        assert "ghr_old" in body


# ---------------------------------------------------------------------------
# save_credentials / load_credentials
# ---------------------------------------------------------------------------

class TestCredentialStorage:
    def _make_tokens(self) -> GitHubTokenSet:
        return GitHubTokenSet(
            access_token="gho_abc",
            refresh_token="ghr_xyz",
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            token_type="bearer",
            scope="repo",
        )

    def test_save_writes_json(self, tmp_path):
        tokens = self._make_tokens()
        path = tmp_path / "creds.json"
        save_credentials(path, tokens)

        assert path.exists()
        data = json.loads(path.read_text())
        assert data["access_token"] == "gho_abc"
        assert data["refresh_token"] == "ghr_xyz"

    def test_save_sets_permissions_600(self, tmp_path):
        tokens = self._make_tokens()
        path = tmp_path / "creds.json"
        save_credentials(path, tokens)

        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    def test_load_returns_token_set(self, tmp_path):
        tokens = self._make_tokens()
        path = tmp_path / "creds.json"
        save_credentials(path, tokens)

        loaded = load_credentials(path)
        assert isinstance(loaded, GitHubTokenSet)
        assert loaded.access_token == "gho_abc"
        assert loaded.refresh_token == "ghr_xyz"
        assert loaded.expires_at == datetime(2030, 1, 1, tzinfo=timezone.utc)

    def test_load_returns_none_for_missing_file(self, tmp_path):
        result = load_credentials(tmp_path / "nonexistent.json")
        assert result is None

    def test_load_returns_none_for_corrupt_file(self, tmp_path):
        path = tmp_path / "creds.json"
        path.write_text("not json {{{")
        result = load_credentials(path)
        assert result is None


# ---------------------------------------------------------------------------
# is_token_expired
# ---------------------------------------------------------------------------

class TestIsTokenExpired:
    def _tokens_expiring_at(self, dt: datetime) -> GitHubTokenSet:
        return GitHubTokenSet(
            access_token="gho_abc",
            refresh_token="ghr_xyz",
            expires_at=dt,
            token_type="bearer",
            scope="repo",
        )

    def test_not_expired_when_far_future(self):
        far_future = datetime.now(timezone.utc) + timedelta(hours=8)
        tokens = self._tokens_expiring_at(far_future)
        assert is_token_expired(tokens) is False

    def test_expired_when_past(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        tokens = self._tokens_expiring_at(past)
        assert is_token_expired(tokens) is True

    def test_expired_within_grace_period(self):
        # 3 minutes from now — within 5-minute grace period, should be "expired"
        near_future = datetime.now(timezone.utc) + timedelta(minutes=3)
        tokens = self._tokens_expiring_at(near_future)
        assert is_token_expired(tokens) is True

    def test_not_expired_outside_grace_period(self):
        # 7 minutes from now — outside 5-minute grace period, should not be "expired"
        comfortable = datetime.now(timezone.utc) + timedelta(minutes=7)
        tokens = self._tokens_expiring_at(comfortable)
        assert is_token_expired(tokens) is False


# ---------------------------------------------------------------------------
# Additional edge cases (mallcop-ak1n.5.15)
# ---------------------------------------------------------------------------


class TestPollForTokenUnknownErrorCode:
    """poll_for_token unknown error codes should raise GitHubAuthError with error_code set."""

    def test_unknown_error_code_raises_with_error_code(self):
        """An unrecognized error code in the token response raises GitHubAuthError with error_code."""
        resp_data = {
            "error": "some_novel_error",
            "error_description": "Something unexpected happened",
        }
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)):
            with pytest.raises(GitHubAuthError) as exc_info:
                poll_for_token("myclient", "dev123", interval=0, timeout=1)

        err = exc_info.value
        assert err.error_code == "some_novel_error"
        assert "Something unexpected happened" in str(err)

    def test_unknown_error_without_description_uses_error_code_as_message(self):
        """When error_description is absent, error itself becomes the message."""
        resp_data = {"error": "mystery_code"}
        with patch("urllib.request.urlopen", return_value=_make_response(resp_data)):
            with pytest.raises(GitHubAuthError) as exc_info:
                poll_for_token("myclient", "dev123", interval=0, timeout=1)

        err = exc_info.value
        assert err.error_code == "mystery_code"
        assert "mystery_code" in str(err)


class TestPostJsonNetworkError:
    """_post_json network failures propagate as URLError (not swallowed)."""

    def test_url_error_propagates_from_start_device_flow(self):
        """URLError from urlopen propagates through start_device_flow uncaught."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            with pytest.raises(urllib.error.URLError):
                start_device_flow("myclient")

    def test_url_error_propagates_from_refresh_access_token(self):
        """URLError from urlopen propagates through refresh_access_token uncaught."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network unreachable")):
            with pytest.raises(urllib.error.URLError):
                refresh_access_token("myclient", "ghr_old")


class TestSaveCredentialsParentDirectory:
    """save_credentials creates parent directories when they do not exist."""

    def test_save_credentials_creates_parent_directory(self, tmp_path):
        """Parent directory is created if it does not exist."""
        nested_path = tmp_path / "level1" / "level2" / "creds.json"
        assert not nested_path.parent.exists()

        tokens = GitHubTokenSet(
            access_token="gho_abc",
            refresh_token="ghr_xyz",
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            token_type="bearer",
            scope="repo",
        )
        save_credentials(nested_path, tokens)

        assert nested_path.exists()
        data = json.loads(nested_path.read_text())
        assert data["access_token"] == "gho_abc"
