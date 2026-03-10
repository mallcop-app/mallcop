"""Pro account management: client-side operations for mallcop Pro."""
from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass

import requests

_log = logging.getLogger(__name__)

_DEFAULT_ACCOUNT_URL = "https://api.mallcop.dev"


@dataclass
class AccountInfo:
    account_id: str
    email: str
    plan_tier: str
    status: str


class ProClient:
    """Client for the mallcop account service."""

    def __init__(self, account_url: str = _DEFAULT_ACCOUNT_URL) -> None:
        self._url = account_url.rstrip("/")

    def _api_call(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json: dict | None = None,
    ) -> dict:
        """Make an API call with standard error handling.

        Args:
            method: HTTP method ("get" or "post").
            path: URL path (appended to base URL).
            token: Bearer token for Authorization header.
            json: JSON body for POST requests.

        Returns:
            Parsed JSON response as dict.

        Raises:
            RuntimeError: On non-200 status with ``ProClient.<caller>`` prefix.
        """
        caller = inspect.stack()[1].function
        url = f"{self._url}{path}"
        kwargs: dict = {"timeout": 30}
        if token is not None:
            kwargs["headers"] = {"Authorization": f"Bearer {token}"}
        if json is not None:
            kwargs["json"] = json
        fn = requests.get if method == "get" else requests.post
        resp = fn(url, **kwargs)
        if resp.status_code != 200:
            _log.debug("%s failed: HTTP %d: %s", caller, resp.status_code, resp.text)
            raise RuntimeError(f"ProClient.{caller}: HTTP {resp.status_code}")
        return resp.json()

    def create_account(self, email: str) -> tuple[str, str]:
        """Create account. Returns (account_id, service_token)."""
        resp = requests.post(
            f"{self._url}/accounts",
            json={"email": email},
            timeout=30,
        )
        if resp.status_code == 409:
            raise ValueError("Email already registered")
        if resp.status_code != 200:
            _log.debug("Account creation failed: HTTP %d: %s", resp.status_code, resp.text)
            raise RuntimeError(f"ProClient.create_account: HTTP {resp.status_code}")
        data = resp.json()
        return data["account_id"], data["service_token"]

    def get_account(self, account_id: str, service_token: str) -> AccountInfo:
        """Get account details."""
        data = self._api_call("get", f"/accounts/{account_id}", token=service_token)
        return AccountInfo(
            account_id=data["account_id"],
            email=data["email"],
            plan_tier=data["plan_tier"],
            status=data["status"],
        )

    def validate_token(self, service_token: str) -> AccountInfo | None:
        """Validate token via server API call.

        Returns AccountInfo if valid, None if invalid or on error.
        Server-side validation ensures forged tokens are rejected.
        """
        try:
            resp = requests.get(
                f"{self._url}/auth/validate",
                headers={"Authorization": f"Bearer {service_token}"},
                timeout=30,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            return AccountInfo(
                account_id=data["account_id"],
                email=data.get("email", ""),
                plan_tier=data.get("plan_tier", "free"),
                status=data.get("status", "active"),
            )
        except (requests.RequestException, KeyError, ValueError):
            return None

    def record_usage(self, account_id: str, model: str, input_tokens: int, output_tokens: int, service_token: str) -> dict:
        """Record token usage."""
        return self._api_call(
            "post",
            f"/accounts/{account_id}/usage",
            token=service_token,
            json={"model": model, "input_tokens": input_tokens, "output_tokens": output_tokens},
        )

    def subscribe(self, account_id: str, plan_tier: str, service_token: str) -> str:
        """Create subscription. Returns Stripe checkout URL."""
        data = self._api_call(
            "post",
            f"/accounts/{account_id}/subscribe",
            token=service_token,
            json={"plan_tier": plan_tier},
        )
        return data["checkout_url"]

    def check_subscription(self, account_id: str, service_token: str) -> dict:
        """Check subscription status."""
        data = self._api_call("get", f"/accounts/{account_id}", token=service_token)
        return {"plan_tier": data["plan_tier"], "status": data["status"]}

    def get_usage(self, account_id: str, service_token: str) -> dict:
        """Get usage summary."""
        return self._api_call("get", f"/accounts/{account_id}/usage", token=service_token)
