"""GitHub OAuth device flow client.

Uses stdlib urllib only — no requests/httpx dependency.
"""

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_DEVICE_URL = "https://github.com/login/device/code"
_TOKEN_URL = "https://github.com/login/oauth/access_token"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class GitHubTokenSet:
    access_token: str
    refresh_token: str
    expires_at: datetime       # access token expiry (typically 8h)
    token_type: str            # "bearer"
    scope: str                 # granted scopes


@dataclass
class DeviceFlowPending:
    device_code: str
    user_code: str
    verification_uri: str      # github.com/login/device
    expires_in: int
    interval: int              # polling interval seconds


class GitHubAuthError(Exception):
    def __init__(self, message: str, error_code: str = ""):
        super().__init__(message)
        self.error_code = error_code


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _post_json(url: str, params: dict) -> dict:
    """POST url-encoded params, return parsed JSON response."""
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _parse_token_response(data: dict) -> GitHubTokenSet:
    """Convert a successful token response dict to GitHubTokenSet."""
    expires_in = int(data.get("expires_in", 28800))
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    return GitHubTokenSet(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token", ""),
        expires_at=expires_at,
        token_type=data.get("token_type", "bearer"),
        scope=data.get("scope", ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_device_flow(client_id: str) -> DeviceFlowPending:
    """Initiate GitHub OAuth device flow.

    POST https://github.com/login/device/code with client_id and scope="repo".
    Returns DeviceFlowPending containing the user_code to show the user.
    """
    data = _post_json(_DEVICE_URL, {"client_id": client_id, "scope": "repo"})
    return DeviceFlowPending(
        device_code=data["device_code"],
        user_code=data["user_code"],
        verification_uri=data["verification_uri"],
        expires_in=int(data.get("expires_in", 900)),
        interval=int(data.get("interval", 5)),
    )


def poll_for_token(
    client_id: str,
    device_code: str,
    interval: int,
    timeout: int = 900,
) -> GitHubTokenSet:
    """Poll GitHub token endpoint until device flow completes or times out.

    Handles authorization_pending (keep polling), slow_down (backoff),
    expired_token and access_denied (raise immediately), and timeout.
    """
    deadline = time.time() + timeout
    current_interval = interval

    while True:
        if time.time() > deadline:
            raise GitHubAuthError("Device flow timed out", error_code="timeout")

        data = _post_json(
            _TOKEN_URL,
            {
                "client_id": client_id,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )

        error = data.get("error")
        if not error:
            return _parse_token_response(data)

        if error == "authorization_pending":
            time.sleep(current_interval)
        elif error == "slow_down":
            current_interval += 5
            time.sleep(current_interval)
        elif error == "expired_token":
            raise GitHubAuthError("Device code expired", error_code="expired_token")
        elif error == "access_denied":
            raise GitHubAuthError("User denied access", error_code="access_denied")
        else:
            raise GitHubAuthError(
                data.get("error_description", error),
                error_code=error,
            )


def refresh_access_token(client_id: str, refresh_token: str) -> GitHubTokenSet:
    """Exchange a refresh token for a new GitHubTokenSet.

    Raises GitHubAuthError if the refresh token has expired or is invalid.
    """
    data = _post_json(
        _TOKEN_URL,
        {
            "client_id": client_id,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
    )

    error = data.get("error")
    if error:
        raise GitHubAuthError(
            data.get("error_description", error),
            error_code=error,
        )

    return _parse_token_response(data)


def save_credentials(path: Path, tokens: GitHubTokenSet) -> None:
    """Write GitHubTokenSet as JSON to path with 0o600 permissions."""
    data = {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at.isoformat(),
        "token_type": tokens.token_type,
        "scope": tokens.scope,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    os.chmod(path, 0o600)


def load_credentials(path: Path) -> Optional[GitHubTokenSet]:
    """Read GitHubTokenSet from JSON file, or None if missing/corrupt."""
    try:
        data = json.loads(path.read_text())
        return GitHubTokenSet(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_at=datetime.fromisoformat(data["expires_at"]),
            token_type=data.get("token_type", "bearer"),
            scope=data.get("scope", ""),
        )
    except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError):
        return None


def is_token_expired(tokens: GitHubTokenSet) -> bool:
    """Return True if access token is expired or within 5-minute grace period."""
    grace = timedelta(minutes=5)
    return datetime.now(timezone.utc) + grace >= tokens.expires_at


def ensure_fresh_token(credentials_path: Path, client_id: str) -> Optional[GitHubTokenSet]:
    """Load credentials, refresh if expired, return fresh token or None.

    - If no credentials file exists: return None.
    - If token is not expired: return as-is.
    - If token is expired: attempt refresh via refresh_access_token().
      On success: save new tokens and return them.
      On GitHubAuthError (refresh token expired): print guidance to stderr, return None.
    """
    import sys

    tokens = load_credentials(credentials_path)
    if tokens is None:
        return None

    if not is_token_expired(tokens):
        return tokens

    try:
        new_tokens = refresh_access_token(client_id, tokens.refresh_token)
        save_credentials(credentials_path, new_tokens)
        return new_tokens
    except GitHubAuthError:
        print(
            "GitHub token expired. Re-authorize: mallcop setup openclaw",
            file=sys.stderr,
        )
        return None
