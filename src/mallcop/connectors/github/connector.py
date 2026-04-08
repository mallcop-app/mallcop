"""GitHub org audit log + security alerts connector — implements ConnectorBase."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

_log = logging.getLogger(__name__)

from mallcop.connectors._base import ConnectorBase
from mallcop.connectors._util import build_checkpoint, make_event_id, validate_next_link
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity
from mallcop.secrets import ConfigError, SecretProvider

_API_BASE = "https://api.github.com"

# GitHub audit log cursors are base64-encoded strings.
# Max length is set conservatively to detect tampered or oversized values.
_CURSOR_MAX_LEN = 1000
# Valid cursor characters: base64 URL-safe alphabet + padding
import re as _re
_CURSOR_RE = _re.compile(r'^[A-Za-z0-9+/=_\-]+$')


def _validate_cursor(cursor: str) -> None:
    """Validate a checkpoint cursor value before passing to the GitHub API.

    Guards against tampered checkpoints from a compromised deployment repo.
    An invalid cursor could skip events or manipulate pagination.

    Raises:
        ValueError: if the cursor contains invalid characters, newlines,
                    null bytes, or exceeds the maximum allowed length.
    """
    if len(cursor) > _CURSOR_MAX_LEN:
        raise ValueError(
            f"Invalid cursor: length {len(cursor)} exceeds maximum {_CURSOR_MAX_LEN}"
        )
    if "\n" in cursor or "\r" in cursor or "\x00" in cursor:
        raise ValueError(
            "Invalid cursor: contains control characters (newline or null byte)"
        )
    if not _CURSOR_RE.match(cursor):
        raise ValueError(
            f"Invalid cursor: contains unexpected characters (expected base64 alphabet)"
        )

# Map GitHub audit log actions to mallcop event types
_ACTION_MAP: list[tuple[str, str]] = [
    ("org.add_member", "collaborator_added"),
    ("repo.add_member", "collaborator_added"),
    ("org.remove_member", "collaborator_removed"),
    ("repo.access", "repo_visibility_changed"),
    ("protected_branch.", "branch_protection_changed"),
    ("deploy_key.create", "deploy_key_added"),
    ("oauth_authorization.create", "oauth_app_authorized"),
    ("secret_scanning_alert.create", "secret_scanning_alert"),
    ("dependabot_alert.create", "dependabot_alert"),
    ("git.push", "push"),
    ("team.", "permission_change"),
    ("org.update_member", "permission_change"),
]

_DEFAULT_EVENT_TYPE = "github_other"

# Map event types to default severities
_SEVERITY_MAP: dict[str, Severity] = {
    "collaborator_added": Severity.WARN,
    "collaborator_removed": Severity.INFO,
    "repo_visibility_changed": Severity.CRITICAL,
    "branch_protection_changed": Severity.WARN,
    "deploy_key_added": Severity.WARN,
    "oauth_app_authorized": Severity.WARN,
    "secret_scanning_alert": Severity.CRITICAL,
    "dependabot_alert": Severity.WARN,
    "push": Severity.INFO,
    "permission_change": Severity.WARN,
}


def _classify_action(action: str) -> str:
    for prefix, event_type in _ACTION_MAP:
        if action == prefix or action.startswith(prefix):
            return event_type
    return _DEFAULT_EVENT_TYPE


def _map_severity(event_type: str) -> Severity:
    return _SEVERITY_MAP.get(event_type, Severity.INFO)



def _ts_from_epoch_ms(epoch_ms: int) -> datetime:
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)


class GitHubConnector(ConnectorBase):
    def __init__(self) -> None:
        self._token: str | None = None
        self._org: str | None = None
        self._installation_id: int | None = None

    def configure(self, config: dict) -> None:
        if "installation_id" in config:
            self._installation_id = int(config["installation_id"])

    def discover(self) -> DiscoveryResult:
        try:
            repos = self._list_repos()
            members = self._list_members()
        except Exception:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=["GITHUB_TOKEN", "GITHUB_ORG"],
                notes=["Could not authenticate to GitHub. Check credentials."],
            )

        resources = [f"repo: {r['full_name']}" for r in repos]
        resources += [f"member: {m['login']}" for m in members]

        return DiscoveryResult(
            available=True,
            resources=resources,
            suggested_config={"org": self._org},
            missing_credentials=[],
            notes=[f"Found {len(repos)} repo(s) and {len(members)} member(s)."],
        )

    def authenticate(self, secrets: SecretProvider) -> None:
        self._org = secrets.resolve("GITHUB_ORG")
        # Pick up installation_id from env if not already set via configure().
        # This handles the case where authenticate() runs before configure()
        # in the pipeline, and allows GHA workflows to set it as a secret.
        if self._installation_id is None:
            import os
            env_id = os.environ.get("GITHUB_INSTALLATION_ID")
            if env_id:
                self._installation_id = int(env_id)
        # Priority:
        # 1. Installation token via mallcop-pro (when installation_id is set)
        # 2. Saved GitHub App credentials (device flow from init)
        # 3. GITHUB_TOKEN env var
        token = None
        if self._installation_id is not None:
            token = self._fetch_installation_token(secrets)
        if token is None:
            token = self._load_app_token()
        if token is None:
            token = secrets.resolve("GITHUB_TOKEN")
        self._token = token
        self._validate_token()

    def _fetch_installation_token(self, secrets: SecretProvider) -> str | None:
        """Get a GitHub installation token from mallcop-pro.

        Calls POST /v1/github/token with the customer's service token and
        installation_id. mallcop-pro holds the GitHub App private key server-side.
        """
        import os
        from mallcop.config import DEFAULT_INFERENCE_URL

        api_base = os.environ.get("MALLCOP_API_URL", DEFAULT_INFERENCE_URL).rstrip("/")
        try:
            service_token = secrets.resolve("MALLCOP_SERVICE_TOKEN")
        except ConfigError:
            _log.debug("MALLCOP_SERVICE_TOKEN not set, skipping installation token flow")
            return None

        try:
            resp = requests.post(
                f"{api_base}/v1/github/token",
                headers={"Authorization": f"Bearer {service_token}"},
                json={"installation_id": self._installation_id},
                timeout=10,
            )
            if resp.status_code != 200:
                _log.warning(
                    "mallcop-pro /v1/github/token returned %d: %s",
                    resp.status_code, resp.text[:200],
                )
                return None
            return resp.json().get("token")
        except Exception as e:
            _log.warning("Failed to fetch installation token from mallcop-pro: %s", e)
            return None

    def _load_app_token(self) -> str | None:
        """Load and refresh the GitHub App OAuth token from .mallcop/.github-credentials."""
        from pathlib import Path
        try:
            from mallcop.github_auth import ensure_fresh_token
        except ImportError:
            return None

        creds_path = Path.cwd() / ".mallcop" / ".github-credentials"
        if not creds_path.exists():
            return None

        client_id = "Iv23li2NjQafyaxgyTUF"
        tokens = ensure_fresh_token(creds_path, client_id)
        if tokens is not None:
            return tokens.access_token
        return None

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        raw_entries, pagination_cursor = self._fetch_audit_log(checkpoint)

        events: list[Event] = []
        now = datetime.now(timezone.utc)

        last_doc_id: str | None = None
        for entry in raw_entries:
            action = entry.get("action", "")
            event_type = _classify_action(action)
            severity = _map_severity(event_type)

            ts_ms = entry.get("@timestamp") or entry.get("created_at")
            if not ts_ms:
                _log.warning("GitHub audit entry missing timestamp, skipping: %s", entry.get("_document_id", "unknown"))
                continue
            timestamp = _ts_from_epoch_ms(ts_ms)

            doc_id = entry.get("_document_id", "")

            evt = Event(
                id=make_event_id(doc_id),
                timestamp=timestamp,
                ingested_at=now,
                source="github",
                event_type=event_type,
                actor=entry.get("actor", "unknown"),
                action=action,
                target=entry.get("repo", entry.get("org", "")),
                severity=severity,
                metadata={"org": self._org, "action_detail": action},
                raw=entry,
            )
            events.append(evt)

            if doc_id:
                last_doc_id = doc_id

        # Prefer the pagination cursor from the Link header; fall back to the
        # last entry's _document_id when the response fits in a single page.
        cursor_value = pagination_cursor or last_doc_id

        # Build checkpoint from cursor
        new_checkpoint = build_checkpoint("github", cursor_value, checkpoint, now, default_value="")

        return PollResult(events=events, checkpoint=new_checkpoint)

    def event_types(self) -> list[str]:
        return [
            "collaborator_added",
            "collaborator_removed",
            "repo_visibility_changed",
            "branch_protection_changed",
            "deploy_key_added",
            "oauth_app_authorized",
            "secret_scanning_alert",
            "dependabot_alert",
            "push",
            "permission_change",
        ]

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _validate_token(self) -> None:
        # Installation tokens are app tokens — /user doesn't work for them.
        # Validate by checking org access instead.
        if self._installation_id is not None:
            resp = requests.get(
                f"{_API_BASE}/orgs/{self._org}",
                headers=self._auth_headers(),
            )
        else:
            resp = requests.get(f"{_API_BASE}/user", headers=self._auth_headers())
        if resp.status_code != 200:
            raise ConfigError(
                f"GitHub authentication failed (HTTP {resp.status_code}): {resp.text}"
            )

    def _list_repos(self) -> list[dict[str, Any]]:
        results, _ = self._get_paginated(f"{_API_BASE}/orgs/{self._org}/repos")
        return results

    def _list_members(self) -> list[dict[str, Any]]:
        results, _ = self._get_paginated(f"{_API_BASE}/orgs/{self._org}/members")
        return results

    def _get_paginated(
        self, url: str, params: dict[str, str] | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """GET a paginated GitHub API endpoint, following Link header rel=next.

        Returns (results, last_after_cursor). The cursor is the ``after`` query
        param from the last page's Link header, suitable for checkpoint storage.
        """
        results: list[dict[str, Any]] = []
        headers = self._auth_headers()
        last_cursor: str | None = None

        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            results.extend(data)
        elif isinstance(data, dict):
            for key in ("value", "data", "items"):
                if key in data and isinstance(data[key], list):
                    results.extend(data[key])
                    break
            else:
                results.append(data)
        else:
            raise TypeError(
                f"Expected JSON array or object from GitHub API, got {type(data).__name__}"
            )

        # Extract cursor from current page's Link header
        cursor = self._parse_after_cursor(resp.headers.get("Link", ""))
        if cursor:
            last_cursor = cursor

        # Follow Link header pagination
        while True:
            next_url = self._parse_next_link(resp.headers.get("Link", ""))
            if not next_url:
                break
            validate_next_link(next_url, "github")
            resp = requests.get(next_url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                results.extend(data)
            elif isinstance(data, dict):
                for key in ("value", "data", "items"):
                    if key in data and isinstance(data[key], list):
                        results.extend(data[key])
                        break
                else:
                    results.append(data)

            cursor = self._parse_after_cursor(resp.headers.get("Link", ""))
            if cursor:
                last_cursor = cursor

        return results, last_cursor

    def _fetch_audit_log(
        self, checkpoint: Checkpoint | None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fetch org audit log entries, using cursor for incremental polling.

        Returns (entries, last_after_cursor).
        """
        url = f"{_API_BASE}/orgs/{self._org}/audit-log"
        params: dict[str, str] = {"per_page": "100"}
        if checkpoint is not None and checkpoint.value:
            _validate_cursor(checkpoint.value)
            params["after"] = checkpoint.value

        return self._get_paginated(url, params=params)

    @staticmethod
    def _parse_next_link(link_header: str) -> str | None:
        if not link_header:
            return None
        for part in link_header.split(","):
            part = part.strip()
            if 'rel="next"' in part:
                # Extract URL from <...>
                start = part.index("<") + 1
                end = part.index(">")
                return part[start:end]
        return None

    @staticmethod
    def _parse_after_cursor(link_header: str) -> str | None:
        """Extract the ``after`` query parameter from the Link header's next URL.

        GitHub audit log pagination uses ``after=<cursor>`` in the next link.
        This cursor is suitable for checkpoint storage.
        """
        if not link_header:
            return None
        for part in link_header.split(","):
            part = part.strip()
            if 'rel="next"' in part:
                start = part.index("<") + 1
                end = part.index(">")
                url = part[start:end]
                parsed = urlparse(url)
                after_vals = parse_qs(parsed.query).get("after")
                if after_vals:
                    return after_vals[0]
        return None
