"""OpenClaw AI agent connector — implements ConnectorBase.

Monitors a local OpenClaw installation for skill changes and config drift.
No API calls needed — all data is on the local filesystem.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mallcop.connectors._base import ConnectorBase, SecretProvider
from mallcop.connectors._util import make_event_id
from mallcop.connectors.openclaw.skills import enumerate_skills, hash_file, parse_skill_md
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity


_REDACT_PLACEHOLDER = "[REDACTED]"

# Field name patterns that may contain secrets.
# Any config key containing one of these substrings (case-insensitive) will be redacted.
_SECRET_FIELD_PATTERNS = (
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "credential",
    "auth",
    "private_key",
    "access_key",
)


def _redact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of config with sensitive fields replaced by a placeholder.

    Any top-level key whose name contains a known secret pattern is redacted.
    Nested structures are not traversed — the caller should avoid nesting secrets.
    """
    redacted: dict[str, Any] = {}
    for key, value in config.items():
        key_lower = key.lower()
        if any(pattern in key_lower for pattern in _SECRET_FIELD_PATTERNS):
            redacted[key] = _REDACT_PLACEHOLDER
        else:
            redacted[key] = value
    return redacted


_EVENT_TYPES = [
    "skill_installed",
    "skill_modified",
    "skill_removed",
    "config_changed",
    "gateway_connection",
    "tool_invocation",
    "mcp_call",
    "auth_attempt",
    "secret_access",
]

_DEFAULT_OPENCLAW_HOME = Path("~/.openclaw").expanduser()


class OpenClawConnector(ConnectorBase):
    """Monitors a local OpenClaw installation for security events."""

    def __init__(self) -> None:
        self._openclaw_home: Path = _DEFAULT_OPENCLAW_HOME

    def configure(self, config: dict) -> None:
        """Apply connector config: openclaw_home override."""
        if "openclaw_home" in config:
            self._openclaw_home = Path(config["openclaw_home"]).expanduser()

    def discover(self) -> DiscoveryResult:
        """Probe local filesystem for OpenClaw installation."""
        if not self._openclaw_home.exists():
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={"openclaw_home": str(_DEFAULT_OPENCLAW_HOME)},
                missing_credentials=[],
                notes=[f"OpenClaw home directory not found: {self._openclaw_home}"],
            )

        resources: list[str] = [f"openclaw_home: {self._openclaw_home}"]

        # Enumerate skills
        skills_dir = self._openclaw_home / "skills"
        skill_map = enumerate_skills(skills_dir)
        for skill_name in sorted(skill_map):
            resources.append(f"skill: {skill_name}")

        # Check config
        config_path = self._openclaw_home / "openclaw.json"
        if config_path.exists():
            resources.append("config: openclaw.json")

        notes = [
            f"Found {len(skill_map)} skill(s) installed.",
        ]
        if not config_path.exists():
            notes.append("openclaw.json not found — gateway config unavailable.")

        return DiscoveryResult(
            available=True,
            resources=resources,
            suggested_config={"openclaw_home": str(self._openclaw_home)},
            missing_credentials=[],
            notes=notes,
        )

    def authenticate(self, secrets: SecretProvider) -> None:
        """No-op: OpenClaw connector reads local filesystem, no credentials needed."""

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        """Scan local OpenClaw state and emit change events.

        Compares current skill hashes and config hash against the checkpoint.
        Emits skill_installed, skill_modified, skill_removed, and config_changed events.
        """
        now = datetime.now(timezone.utc)
        events: list[Event] = []

        # Decode previous checkpoint state
        prev_state = _decode_checkpoint(checkpoint)
        prev_skill_hashes: dict[str, str] = prev_state.get("skill_hashes", {})
        prev_config_hash: str = prev_state.get("config_hash", "")

        # --- Skill change detection ---
        skills_dir = self._openclaw_home / "skills"
        current_skill_map = enumerate_skills(skills_dir)
        current_skill_hashes: dict[str, str] = {}

        for skill_name, skill_md_path in sorted(current_skill_map.items()):
            current_hash = hash_file(skill_md_path)
            current_skill_hashes[skill_name] = current_hash

            if skill_name not in prev_skill_hashes:
                # New skill installed
                info = parse_skill_md(skill_md_path)
                evt = _make_skill_event(
                    event_type="skill_installed",
                    skill_name=skill_name,
                    skill_info_dict=_skill_info_to_dict(info),
                    timestamp=now,
                    openclaw_home=self._openclaw_home,
                )
                events.append(evt)
            elif current_hash != prev_skill_hashes[skill_name]:
                # Existing skill was modified
                info = parse_skill_md(skill_md_path)
                evt = _make_skill_event(
                    event_type="skill_modified",
                    skill_name=skill_name,
                    skill_info_dict=_skill_info_to_dict(info),
                    timestamp=now,
                    openclaw_home=self._openclaw_home,
                )
                events.append(evt)

        # Detect removed skills (in prev but not in current)
        for skill_name in sorted(prev_skill_hashes):
            if skill_name not in current_skill_hashes:
                evt = _make_skill_event(
                    event_type="skill_removed",
                    skill_name=skill_name,
                    skill_info_dict={"skill_name": skill_name},
                    timestamp=now,
                    openclaw_home=self._openclaw_home,
                )
                events.append(evt)

        # --- Config change detection ---
        config_path = self._openclaw_home / "openclaw.json"
        current_config_hash = ""
        current_config: dict[str, Any] = {}

        if config_path.exists():
            current_config_hash = hash_file(config_path)
            if current_config_hash != prev_config_hash:
                try:
                    current_config = json.loads(config_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    current_config = {}

                evt = Event(
                    id=make_event_id(f"openclaw:config_changed:{current_config_hash}"),
                    timestamp=now,
                    ingested_at=now,
                    source="openclaw",
                    event_type="config_changed",
                    actor="filesystem",
                    action="config_changed",
                    target=str(config_path),
                    severity=Severity.WARN,
                    metadata={
                        "config": _redact_config(current_config),
                        "config_hash": current_config_hash,
                        "openclaw_home": str(self._openclaw_home),
                    },
                    raw={
                        "config_hash": current_config_hash,
                        "path": str(config_path),
                        "config_raw": config_path.read_text(encoding="utf-8"),
                    },
                )
                events.append(evt)

        # Build new checkpoint
        new_state = {
            "skill_hashes": current_skill_hashes,
            "config_hash": current_config_hash,
        }
        new_checkpoint = Checkpoint(
            connector="openclaw",
            value=json.dumps(new_state),
            updated_at=now,
        )

        return PollResult(events=events, checkpoint=new_checkpoint)

    def event_types(self) -> list[str]:
        return list(_EVENT_TYPES)


# --- Helpers ---


def _decode_checkpoint(checkpoint: Checkpoint | None) -> dict[str, Any]:
    """Decode a checkpoint value into a state dict."""
    if checkpoint is None or not checkpoint.value:
        return {}
    try:
        return json.loads(checkpoint.value)
    except (json.JSONDecodeError, TypeError):
        return {}


def _skill_info_to_dict(info: object) -> dict[str, Any]:
    """Convert a SkillInfo to a metadata-friendly dict.

    skill_content is included because the malicious-skill detector performs
    static pattern matching against it to detect encoded payloads, quarantine
    bypasses, and external binary downloads. Removing it would disable that
    detection path.

    Defense-in-depth note (mallcop-o8cj): the content is wrapped in USER_DATA
    markers by sanitize_tool_result() before reaching any LLM actor. The actor
    system prompt explicitly instructs the model to treat USER_DATA as untrusted.
    Additionally, newlines are now replaced with [NEWLINE] placeholders by
    sanitize_field(), preventing multi-line injection payloads from mimicking
    system-level prompt formatting (fixed via mallcop-ux2g).

    A size cap of 4096 chars is applied here to bound storage bloat from large
    SKILL.md files while preserving enough content for pattern matching.
    """
    content = info.content  # type: ignore[attr-defined]
    if content and len(content) > 4096:
        content = content[:4096]
    return {
        "skill_name": info.name,  # type: ignore[attr-defined]
        "skill_description": info.description,  # type: ignore[attr-defined]
        "skill_version": info.version,  # type: ignore[attr-defined]
        "skill_author": info.author,  # type: ignore[attr-defined]
        "skill_content": content,
        "skill_hash": getattr(info, "hash", None),  # type: ignore[attr-defined]
        "skill_path": str(info.path),  # type: ignore[attr-defined]
    }


def _make_skill_event(
    *,
    event_type: str,
    skill_name: str,
    skill_info_dict: dict[str, Any],
    timestamp: datetime,
    openclaw_home: Path,
) -> Event:
    """Create an Event for a skill change."""
    event_id = make_event_id(f"openclaw:{event_type}:{skill_name}:{timestamp.isoformat()}")
    return Event(
        id=event_id,
        timestamp=timestamp,
        ingested_at=timestamp,
        source="openclaw",
        event_type=event_type,
        actor="filesystem",
        action=event_type,
        target=skill_name,
        severity=Severity.INFO,
        metadata={
            **skill_info_dict,
            "openclaw_home": str(openclaw_home),
        },
        raw={"skill_name": skill_name, "event_type": event_type},
    )
