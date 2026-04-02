"""campfire_dispatch — async campfire dispatch loop for mallcop.

Polls a campfire for chat-tagged messages, dispatches them through
chat_turn(), and publishes findings to campfire as a secondary channel
(findings.jsonl remains the primary store).

Design notes
------------
- Single-threaded asyncio — no threads, no multiprocessing.
- ``cf`` CLI invocations use asyncio.create_subprocess_exec.
- Campfire cursor is managed by ``cf`` itself: reading without --all
  advances the cursor so subsequent reads return only new messages.
- ConversationStore is NOT used — CampfireConversationAdapter is used
  for chat state so the session lives in campfire.
- chat_turn() is called without modification — its signature is:

      chat_turn(question, session_id, managed_client, store,
                context_manager, root) -> dict

  where ``store`` is any object implementing append()/load_session().
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from mallcop.conversation import CampfireConversationAdapter
from mallcop.context_window import ContextWindowManager

_log = logging.getLogger(__name__)

# Surface identifier stored in conversation messages.
_SURFACE = "campfire"

# Tag prefix for the sender's session identity.
_SESSION_TAG_PREFIX = "session:"


class CampfireError(RuntimeError):
    """Base exception for all campfire dispatch errors."""


class _SubprocessError(CampfireError):
    """Raised when a cf subprocess exits non-zero."""


# Seconds to wait for a cf subprocess before giving up.
_CF_TIMEOUT = 30.0

# Tag constants — avoids magic string literals throughout the module.
_TAG_CHAT = "chat"
_TAG_RESPONSE = "response"
_TAG_PLATFORM_ERROR = "platform-error"
_TAG_BUDGET_WARNING = "budget-warning"
_TAG_FINDING = "finding"
_INSTANCE_MALLCOP = "mallcop"


async def _run_cf(*args: str, cf_bin: str = "cf", cf_home: str | None = None, timeout: float = _CF_TIMEOUT) -> str:
    """Run a cf command via asyncio subprocess. Returns stdout. Raises on non-zero exit.

    Raises
    ------
    RuntimeError
        When the cf binary is not found or not executable (wraps OSError).
    asyncio.TimeoutError
        When the subprocess does not complete within ``_CF_TIMEOUT`` seconds.
    _SubprocessError
        When the subprocess exits with a non-zero return code.
    """
    cmd = [cf_bin]
    if cf_home:
        cmd += ["--cf-home", cf_home]
    cmd += list(args)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        _log.error("campfire_dispatch: cf binary not found or not executable: %s", exc)
        raise RuntimeError(
            f"cf binary not found or not executable: {exc}"
        ) from exc

    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

    if proc.returncode != 0:
        raise _SubprocessError(
            f"cf command failed (exit {proc.returncode}): {args!r}\n"
            f"stderr: {stderr.decode(errors='replace').strip()}"
        )
    return stdout.decode(errors="replace").strip()


class CampfireDispatcher:
    """Async campfire dispatch loop.

    Polls *campfire_id* for ``chat``-tagged messages, dispatches each
    through :func:`mallcop.chat.chat_turn`, and posts the response back
    to campfire.

    Parameters
    ----------
    campfire_id:
        The campfire to poll and respond on.
    managed_client:
        ManagedClient instance forwarded to chat_turn().
    root:
        Deployment root directory (findings.jsonl lives here).
    poll_interval:
        Seconds between polls (default 3).
    cf_bin:
        Path to the cf binary (default: ``cf`` from PATH).
    cf_home:
        Optional --cf-home override for every cf invocation.
    """

    def __init__(
        self,
        campfire_id: str,
        managed_client: Any,
        root: Path,
        poll_interval: float = 3.0,
        cf_bin: str = "cf",
        cf_home: str | None = None,
        cf_timeout: float = _CF_TIMEOUT,
    ) -> None:
        self._campfire_id = campfire_id
        self._managed_client = managed_client
        self._root = Path(root)
        self._poll_interval = poll_interval
        self._cf_bin = cf_bin
        self._cf_home = cf_home
        self._cf_timeout = cf_timeout

        # One CampfireConversationAdapter per dispatcher; session IDs
        # are derived per-message from the sender's session tag.
        self._adapter = CampfireConversationAdapter(
            campfire_id=campfire_id,
            cf_bin=cf_bin,
            cf_home=cf_home,
        )
        self._context_manager = ContextWindowManager(managed_client=managed_client)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _cf(self, *args: str) -> str:
        return await _run_cf(
            *args,
            cf_bin=self._cf_bin,
            cf_home=self._cf_home,
            timeout=self._cf_timeout,
        )

    async def _read_new_messages(self) -> list[dict[str, Any]]:
        """Poll campfire for new chat-tagged messages (advances cursor)."""
        try:
            raw = await self._cf(
                "read", self._campfire_id,
                "--json",
                "--tag", _TAG_CHAT,
            )
        except _SubprocessError as exc:
            _log.warning("campfire_dispatch: read error: %s", exc)
            return []

        if not raw:
            return []

        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            _log.warning("campfire_dispatch: non-JSON from cf read: %r", raw[:200])
            return []

        if not isinstance(items, list):
            return []

        return items

    @staticmethod
    def _extract_session_id(tags: list[str]) -> str | None:
        """Extract session:<uuid> from message tags."""
        for tag in tags:
            if tag.startswith(_SESSION_TAG_PREFIX):
                return tag[len(_SESSION_TAG_PREFIX):]
        return None

    async def _post_response(self, session_id: str, result: dict[str, Any]) -> None:
        """Post a chat_turn() result back to campfire (response + optional budget warning)."""
        response_text = result.get("response", "")
        if not response_text:
            return

        session_tag = f"{_SESSION_TAG_PREFIX}{session_id}"
        payload = json.dumps({
            "content": response_text,
            "tokens_used": result.get("tokens_used", 0),
        })

        send_args = [
            "send", self._campfire_id,
            "--instance", _INSTANCE_MALLCOP,
            "--tag", _TAG_CHAT,
            "--tag", session_tag,
            "--tag", f"platform:{_SURFACE}",
            "--tag", _TAG_RESPONSE,
        ]
        if result.get("is_platform_error"):
            send_args += ["--tag", _TAG_PLATFORM_ERROR]
        send_args.append(payload)

        try:
            await self._cf(*send_args)
        except _SubprocessError as exc:
            _log.error("campfire_dispatch: failed to post response: %s", exc)

        # Fix (mallcop-pro-6p0): forward budget_warning to campfire so
        # clients can see it.  Without this, budget warnings returned by
        # chat_turn() are silently dropped.
        budget_warning = result.get("budget_warning")
        if budget_warning:
            warning_payload = json.dumps({"budget_warning": budget_warning})
            try:
                await self._cf(
                    "send", self._campfire_id,
                    "--instance", _INSTANCE_MALLCOP,
                    "--tag", _TAG_CHAT,
                    "--tag", session_tag,
                    "--tag", _TAG_BUDGET_WARNING,
                    warning_payload,
                )
            except _SubprocessError as exc:
                _log.error(
                    "campfire_dispatch: failed to post budget_warning: %s", exc
                )

    async def _dispatch_message(self, msg: dict[str, Any]) -> None:
        """Dispatch one chat message through chat_turn() and post response."""
        # Import here to avoid circular import at module level.
        from mallcop.chat import chat_turn

        tags: list[str] = msg.get("tags", [])
        payload_raw = msg.get("payload", "")
        instance = msg.get("instance", "user")

        # Skip messages sent by us (instance == _INSTANCE_MALLCOP).
        if instance == _INSTANCE_MALLCOP:
            _log.debug("campfire_dispatch: skipping our own message %s", msg.get("id"))
            return

        # Extract question text. Payload may be a JSON envelope (if
        # written by CampfireConversationAdapter) or plain text.
        question: str = payload_raw
        try:
            envelope = json.loads(payload_raw)
            if isinstance(envelope, dict) and "content" in envelope:
                question = envelope["content"]
        except (json.JSONDecodeError, TypeError):
            pass  # treat raw payload as the question

        if not question:
            _log.debug("campfire_dispatch: empty question in message %s", msg.get("id"))
            return

        # Derive session_id from tags.  A session: tag is required for
        # multi-turn history to work correctly — without it, load_session()
        # cannot reconstruct the conversation because the original inbound
        # message was never tagged with a stable session identifier.
        # Decision (mallcop-pro-cr9): reject messages without a session: tag
        # rather than falling back to sender, which would silently break
        # multi-turn history.
        session_id = self._extract_session_id(tags)
        if not session_id:
            _log.warning(
                "campfire_dispatch: skipping message %s — no session: tag present. "
                "Clients must include a session:<uuid> tag for multi-turn history.",
                msg.get("id"),
            )
            return

        _log.debug(
            "campfire_dispatch: dispatching message %s (session %s)",
            msg.get("id"), session_id,
        )

        try:
            result = await chat_turn(
                question=question,
                session_id=session_id,
                managed_client=self._managed_client,
                store=self._adapter,
                context_manager=self._context_manager,
                root=self._root,
            )
        except Exception as exc:
            _log.error("campfire_dispatch: chat_turn error: %s", exc)
            return

        await self._post_response(session_id, result)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_once(self) -> None:
        """Read all pending campfire messages in a single pass and dispatch each.

        Calls ``_read_new_messages()`` exactly once, then dispatches every
        returned message via ``_dispatch_message()``.  Returns immediately
        after processing — no loop, no sleep, no retry.

        This is useful for one-shot processing (e.g. in tests or cron-style
        invocations) and is also the core of the :meth:`run` loop.
        """
        messages = await self._read_new_messages()
        for msg in messages:
            await self._dispatch_message(msg)

    async def run(self) -> None:
        """Poll campfire in a loop, dispatching chat messages indefinitely.

        Runs until cancelled (asyncio.CancelledError).

        On consecutive poll failures (``_SubprocessError`` from
        ``_read_new_messages``), an exponential backoff is applied starting
        after the 5th consecutive error:

            sleep = min(poll_interval * 2 ** (consecutive_errors - 5), 300)

        The counter resets to zero on any successful poll.

        Raises
        ------
        RuntimeError
            When the cf binary is not found or not executable on the first
            poll attempt.  The error is re-raised so the caller can surface a
            clear message rather than a raw OSError.
        """
        _log.info(
            "campfire_dispatch: starting loop on %s (poll_interval=%.1fs)",
            self._campfire_id, self._poll_interval,
        )
        _consecutive_errors: int = 0
        try:
            while True:
                try:
                    await self.run_once()
                    _consecutive_errors = 0
                except _SubprocessError:
                    # _read_new_messages already logs a warning and returns [].
                    # We only reach here if it re-raises, which it currently
                    # does not — this branch is a safety net for future changes.
                    _consecutive_errors += 1

                # Backoff after 5 or more consecutive errors.
                if _consecutive_errors >= 5:
                    backoff = min(
                        self._poll_interval * 2 ** (_consecutive_errors - 5),
                        300.0,
                    )
                    _log.warning(
                        "campfire_dispatch: %d consecutive cf errors — "
                        "backing off for %.1fs",
                        _consecutive_errors, backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    await asyncio.sleep(self._poll_interval)
        except asyncio.CancelledError:
            _log.info("campfire_dispatch: loop cancelled — shutting down")
            raise

    async def publish_finding(self, finding: Any) -> None:
        """Publish a finding to campfire as a secondary channel.

        findings.jsonl is the primary store. This method writes to campfire
        in addition to whatever the caller already wrote to findings.jsonl.

        Tags written:
            finding
            severity:<level>     (e.g. severity:critical)
            connector:<name>     (from finding.detector or finding.metadata)
            id:<MC-ID>           (finding.id)

        Parameters
        ----------
        finding:
            A :class:`mallcop.schemas.Finding` instance (or any object
            with .id, .severity, .detector, .title, .to_dict() attributes).
        """
        finding_id: str = getattr(finding, "id", "unknown")
        severity_val = getattr(finding, "severity", "")
        if hasattr(severity_val, "value"):
            severity_val = severity_val.value
        severity_str = str(severity_val).lower() or "unknown"

        # Connector name: prefer metadata["connector"], fall back to detector.
        metadata = getattr(finding, "metadata", {}) or {}
        connector_name = metadata.get("connector") or getattr(finding, "detector", "unknown")

        # Payload: full finding dict as JSON.
        try:
            payload = json.dumps(finding.to_dict())
        except Exception:
            payload = json.dumps({"id": finding_id, "severity": severity_str})

        _log.debug(
            "campfire_dispatch: publishing finding %s (severity=%s, connector=%s)",
            finding_id, severity_str, connector_name,
        )

        try:
            await self._cf(
                "send", self._campfire_id,
                "--instance", _INSTANCE_MALLCOP,
                "--tag", _TAG_FINDING,
                "--tag", f"severity:{severity_str}",
                "--tag", f"connector:{connector_name}",
                "--tag", f"id:{finding_id}",
                payload,
            )
        except _SubprocessError as exc:
            _log.error(
                "campfire_dispatch: failed to publish finding %s: %s",
                finding_id, exc,
            )
