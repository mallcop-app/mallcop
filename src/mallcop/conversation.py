"""ConversationStore — append-only JSONL writer/reader for conversation messages.

Each line is a JSON object matching the ConversationMessage schema.
Advisory flock on write: warn-and-proceed on lock failure (non-blocking).
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import secrets
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
