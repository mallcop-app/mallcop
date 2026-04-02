"""ConversationStore — append-only JSONL writer/reader for conversation messages.

Each line is a JSON object matching the ConversationMessage schema.
Advisory flock on write: warn-and-proceed on lock failure (non-blocking).

Also provides CampfireConversationAdapter — a campfire-backed store that
implements the same append/load_session interface using ``cf`` CLI commands.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import re
import secrets
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _new_msg_id() -> str:
    return "msg_" + secrets.token_hex(8)


@dataclass
class ConversationMessage:
    id: str
    session_id: str
    surface: str
    timestamp: str
    role: str
    content: str
    finding_refs: list[str] = field(default_factory=list)
    tokens_used: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ConversationMessage":
        return cls(
            id=d["id"],
            session_id=d["session_id"],
            surface=d["surface"],
            timestamp=d["timestamp"],
            role=d["role"],
            content=d["content"],
            finding_refs=d.get("finding_refs", []),
            tokens_used=d.get("tokens_used", 0),
        )

    @classmethod
    def from_json(cls, line: str) -> "ConversationMessage":
        return cls.from_dict(json.loads(line))


class ConversationStore:
    """Append-only JSONL store for conversation messages.

    Advisory flock is taken on write. If the lock cannot be acquired,
    a warning is logged and the write proceeds anyway (advisory, not enforced).
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        session_id: str,
        surface: str,
        role: str,
        content: str,
        finding_refs: list[str] | None = None,
        tokens_used: int = 0,
        msg_id: str | None = None,
        timestamp: str | None = None,
    ) -> ConversationMessage:
        """Append a message to the store. Returns the written ConversationMessage."""
        msg = ConversationMessage(
            id=msg_id or _new_msg_id(),
            session_id=session_id,
            surface=surface,
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            role=role,
            content=content,
            finding_refs=finding_refs or [],
            tokens_used=tokens_used,
        )
        with open(self._path, "a") as f:
            # Advisory lock — warn and proceed if unavailable
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError:
                logger.warning(
                    "ConversationStore: could not acquire advisory lock on %s; proceeding without lock",
                    self._path,
                )
                locked = False
            try:
                f.write(msg.to_json() + "\n")
            finally:
                if locked:
                    fcntl.flock(f, fcntl.LOCK_UN)
        return msg

    def load_session(self, session_id: str) -> list[ConversationMessage]:
        """Return all messages for session_id in chronological order (by timestamp)."""
        if not self._path.exists():
            return []
        results: list[ConversationMessage] = []
        text = self._path.read_text()
        for line_num, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                msg = ConversationMessage.from_json(line)
            except Exception:
                logger.warning(
                    "ConversationStore: skipping corrupt line %d in %s",
                    line_num,
                    self._path,
                )
                continue
            if msg.session_id == session_id:
                results.append(msg)
        # Sort chronologically by timestamp string (ISO8601 sorts lexicographically)
        results.sort(key=lambda m: m.timestamp)
        return results


# ---------------------------------------------------------------------------
# CampfireConversationAdapter
# ---------------------------------------------------------------------------


class CampfireAdapterError(RuntimeError):
    """Raised when a campfire operation fails in CampfireConversationAdapter."""


_INSTANCE_TO_ROLE = {"user": "user", "mallcop": "assistant"}
_ROLE_TO_INSTANCE = {"user": "user", "assistant": "mallcop"}

# Tag used to scope all chat messages in a campfire.
_CHAT_TAG = "chat"


class CampfireConversationAdapter:
    """Campfire-backed conversation store.

    Implements the same ``append`` / ``load_session`` interface as
    :class:`ConversationStore` but persists messages to a campfire using the
    ``cf`` CLI.

    Tag mapping
    -----------
    - ``session_id``   → ``session:<sanitized-id>``
    - ``surface``      → ``platform:<name>``
    - ``role``         → ``--instance user`` (role=="user") or ``--instance mallcop``
    - ``finding_refs`` → ``finding_ref:<MC-ID>`` (one tag per ref)
    - All chat messages receive the ``chat`` tag for easy filtering.

    Parameters
    ----------
    campfire_id:
        The campfire ID (hex string) to read/write.
    cf_bin:
        Path to the ``cf`` binary.  Defaults to ``cf`` (resolved via PATH).
    cf_home:
        Optional ``--cf-home`` override forwarded to every ``cf`` invocation.
    """

    def __init__(
        self,
        campfire_id: str,
        cf_bin: str = "cf",
        cf_home: str | None = None,
    ) -> None:
        self._campfire_id = campfire_id
        self._cf_bin = cf_bin
        self._cf_home = cf_home

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _cf(self, *args: str) -> str:
        """Run a cf command and return stdout.  Raises on non-zero exit."""
        cmd = [self._cf_bin]
        if self._cf_home:
            cmd += ["--cf-home", self._cf_home]
        cmd += list(args)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise RuntimeError(
                f"cf binary not found or not executable: {exc}"
            ) from exc
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        if proc.returncode != 0:
            raise RuntimeError(
                f"cf command failed (exit {proc.returncode}): "
                f"{' '.join(args)!r}\nstderr: {stderr.decode(errors='replace').strip()}"
            )
        return stdout.decode(errors="replace").strip()

    @staticmethod
    def _sanitize_session_id(session_id: str) -> str:
        """Sanitize session_id for safe embedding in tag names.

        Replaces any character that is not alphanumeric, underscore, or hyphen
        with an underscore, preventing tag namespace collisions (e.g. a colon
        producing ``session:abc:def``) and CLI arg parsing issues from spaces
        or slashes.
        """
        return re.sub(r"[^a-zA-Z0-9_-]", "_", session_id)

    def _build_tags(
        self,
        session_id: str,
        surface: str,
        finding_refs: list[str],
    ) -> list[str]:
        safe_session_id = self._sanitize_session_id(session_id)
        tags = [_CHAT_TAG, f"session:{safe_session_id}", f"platform:{surface}"]
        for ref in finding_refs:
            if ref:
                tags.append(f"finding_ref:{ref}")
        return tags

    @staticmethod
    def _extract_finding_refs(tags: list[str]) -> list[str]:
        refs = []
        for tag in tags:
            if tag.startswith("finding_ref:"):
                ref = tag[len("finding_ref:"):]
                if ref:
                    refs.append(ref)
        return refs

    @staticmethod
    def _extract_surface(tags: list[str]) -> str:
        for tag in tags:
            if tag.startswith("platform:"):
                return tag[len("platform:"):]
        return "unknown"

    @staticmethod
    def _extract_session_id(tags: list[str]) -> str:
        for tag in tags:
            if tag.startswith("session:"):
                return tag[len("session:"):]
        return ""

    # ------------------------------------------------------------------
    # Public API (mirrors ConversationStore)
    # ------------------------------------------------------------------

    async def append(
        self,
        session_id: str,
        surface: str,
        role: str,
        content: str,
        finding_refs: list[str] | None = None,
        tokens_used: int = 0,
        msg_id: str | None = None,
        timestamp: str | None = None,
    ) -> ConversationMessage:
        """Append a message to the campfire.  Returns the written ConversationMessage."""
        finding_refs = finding_refs or []
        timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        msg_id = msg_id or _new_msg_id()

        tags = self._build_tags(session_id, surface, finding_refs)
        # Encode metadata not natively captured by campfire in the payload as
        # a JSON envelope so we can reconstruct the full ConversationMessage
        # on read.
        if not isinstance(tokens_used, int):
            try:
                tokens_used = int(tokens_used)
            except (TypeError, ValueError) as exc:
                raise TypeError(
                    f"tokens_used must be an int or int-convertible, got {type(tokens_used).__name__!r}"
                ) from exc
        envelope: dict[str, Any] = {
            "id": msg_id,
            "timestamp": timestamp,
            "tokens_used": tokens_used,
            "content": content,
        }
        payload = json.dumps(envelope)

        instance = _ROLE_TO_INSTANCE.get(role, role)

        cmd_args = ["send", self._campfire_id, "--instance", instance]
        for tag in tags:
            cmd_args += ["--tag", tag]
        cmd_args.append(payload)
        try:
            await self._cf(*cmd_args)
        except (RuntimeError, OSError) as exc:
            logger.error(
                "campfire=%s session=%s append failed: %s",
                self._campfire_id, session_id, exc,
            )
            raise CampfireAdapterError(
                f"CampfireConversationAdapter: append failed for session {session_id!r}: {exc}"
            ) from exc

        return ConversationMessage(
            id=msg_id,
            session_id=session_id,
            surface=surface,
            timestamp=timestamp,
            role=role,
            content=content,
            finding_refs=finding_refs,
            tokens_used=tokens_used,
        )

    async def load_session(self, session_id: str) -> list[ConversationMessage]:
        """Return all messages for *session_id* in chronological order."""
        safe_session_id = self._sanitize_session_id(session_id)
        try:
            raw = await self._cf(
                "read", self._campfire_id,
                "--all", "--json",
                "--tag", _CHAT_TAG,
                "--tag", f"session:{safe_session_id}",
            )
        except (RuntimeError, OSError) as exc:
            logger.warning(
                "campfire=%s session=%s load_session failed: %s",
                self._campfire_id, session_id, exc,
            )
            return []
        if not raw:
            return []
        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning(
                "campfire=%s session=%s could not parse cf read output",
                self._campfire_id, session_id,
            )
            return []

        # Guard against non-list JSON (e.g. "null", "{}", "true")
        if not isinstance(items, list):
            logger.warning(
                "campfire=%s session=%s expected JSON list from cf read, got %r; returning []",
                self._campfire_id, session_id, type(items).__name__,
            )
            return []

        results: list[ConversationMessage] = []
        for item in items:
            tags: list[str] = item.get("tags", [])
            item_session = self._extract_session_id(tags)
            if item_session != safe_session_id:
                continue

            payload_raw = item.get("payload", "")
            try:
                envelope = json.loads(payload_raw)
            except (json.JSONDecodeError, TypeError):
                logger.warning(
                    "campfire=%s session=%s skipping message with non-JSON payload: %r",
                    self._campfire_id, session_id, payload_raw,
                )
                continue

            instance = item.get("instance", "user")
            role = _INSTANCE_TO_ROLE.get(instance, instance)
            surface = self._extract_surface(tags)
            finding_refs = self._extract_finding_refs(tags)

            try:
                msg_id = envelope.get("id")
                if msg_id is None:
                    msg_id = _new_msg_id()
                msg_ts = envelope.get("timestamp")
                if msg_ts is None:
                    msg_ts = datetime.now(timezone.utc).isoformat()
                msg = ConversationMessage(
                    id=msg_id,
                    session_id=session_id,
                    surface=surface,
                    timestamp=msg_ts,
                    role=role,
                    content=envelope["content"],
                    finding_refs=finding_refs,
                    tokens_used=envelope.get("tokens_used", 0),
                )
                results.append(msg)
            except (KeyError, TypeError) as exc:
                logger.warning(
                    "campfire=%s session=%s skipping malformed envelope: %s",
                    self._campfire_id, session_id, exc,
                )
                continue

        results.sort(key=lambda m: m.timestamp)
        return results
