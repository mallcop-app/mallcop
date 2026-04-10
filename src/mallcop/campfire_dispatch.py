"""campfire_dispatch — async campfire dispatch loop for mallcop.

Polls a campfire for inbound messages (via the mallcop-relay convention),
dispatches them through chat_turn(), and publishes findings and responses
back using convention operations.

Design notes
------------
- Single-threaded asyncio — no threads, no multiprocessing.
- ``cf`` CLI invocations use asyncio.create_subprocess_exec.
- Campfire cursor is managed by ``cf`` itself: reading without --all
  advances the cursor so subsequent reads return only new messages.
- ConversationStore is NOT used — CampfireConversationAdapter is used
  for chat state so the session lives in campfire.
- chat_turn() is called without modification — its signature is:

      chat_turn(question, session_id, interactive_runner, store, root) -> dict

  where ``store`` is any object implementing append()/load_session().

Convention operations (mallcop-relay v0.2)
------------------------------------------
All messaging uses the ``mallcop-relay`` convention declared on the
campfire at registration time.  Operations:

- ``inbound-message`` — relayed Telegram messages (read by daemon)
  tags: relay:inbound, relay:from_id:<from_id>
- ``response``        — daemon posts inference response
  tags: relay:response, relay:session_id:<session_id>
- ``finding``         — daemon posts a security finding
  tags: finding, finding:severity:<severity>
- ``status``          — daemon lifecycle events (budget-warning, platform-error)
  tags: agent:status
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Optional

from mallcop.conversation import CampfireConversationAdapter

_log = logging.getLogger(__name__)

# Surface identifier stored in conversation messages.
_SURFACE = "campfire"

# Tag for filtering inbound messages from the mallcop-relay convention.
_TAG_RELAY_INBOUND = "relay:inbound"


async def _typing_heartbeat(bridge: Any, chat_id: str) -> None:
    """Send typing indicator every 4s until cancelled."""
    while True:
        try:
            await bridge.notify_typing(chat_id)
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(4)


class CampfireError(RuntimeError):
    """Base exception for all campfire dispatch errors."""


class _SubprocessError(CampfireError):
    """Raised when a cf subprocess exits non-zero."""


# Seconds to wait for a cf subprocess before giving up.
_CF_TIMEOUT = 30.0


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
    """Async campfire dispatch loop using mallcop-relay convention operations.

    Polls *campfire_id* for ``relay:inbound``-tagged messages (convention
    operation: inbound-message), dispatches each through
    :func:`mallcop.chat.chat_turn`, and posts the response back using the
    ``response`` convention operation.

    Parameters
    ----------
    campfire_id:
        The campfire to poll and respond on.
    interactive_runner:
        InteractiveRuntime instance forwarded to chat_turn(), or None for
        non-pro deployments (chat_turn returns a platform error in that case).
    root:
        Deployment root directory.
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
        interactive_runner: Any,
        root: Path,
        poll_interval: float = 3.0,
        cf_bin: str = "cf",
        cf_home: str | None = None,
        cf_timeout: float = _CF_TIMEOUT,
        bridge: Optional[Any] = None,
    ) -> None:
        self._campfire_id = campfire_id
        self._interactive_runner = interactive_runner
        self._root = Path(root)
        self._poll_interval = poll_interval
        self._cf_bin = cf_bin
        self._cf_home = cf_home
        self._cf_timeout = cf_timeout
        self._bridge = bridge

        # One CampfireConversationAdapter per dispatcher; session IDs
        # are derived per-message from the sender's session tag.
        self._adapter = CampfireConversationAdapter(
            campfire_id=campfire_id,
            cf_bin=cf_bin,
            cf_home=cf_home,
        )

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
        """Poll campfire for new inbound messages via mallcop-relay convention."""
        try:
            raw = await self._cf(
                "read", self._campfire_id,
                "--json",
                "--tag", _TAG_RELAY_INBOUND,
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
    def _extract_session_id(msg: dict[str, Any]) -> str | None:
        """Extract session ID from an inbound-message convention payload.

        Convention operations pack args as a JSON payload. The inbound-message
        operation includes from_id which serves as the session identifier.
        Also checks tags for relay:from_id:<value> as a fallback.
        """
        # Primary: parse from convention payload args.
        payload_raw = msg.get("payload", "")
        try:
            envelope = json.loads(payload_raw)
            if isinstance(envelope, dict):
                from_id = envelope.get("from_id")
                if from_id:
                    return str(from_id)
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: extract from relay:from_id:* tag.
        for tag in msg.get("tags", []):
            if tag.startswith("relay:from_id:"):
                return tag[len("relay:from_id:"):]

        return None

    async def _post_response(self, session_id: str, result: dict[str, Any]) -> None:
        """Post a chat_turn() result back to campfire via response convention operation."""
        response_text = result.get("response", "")
        if not response_text:
            return

        # Use the response convention operation.
        op_args = [
            self._campfire_id, "response",
            "--content", response_text,
            "--session_id", session_id,
        ]
        tokens_used = result.get("tokens_used", 0)
        if tokens_used:
            op_args += ["--tokens_used", str(tokens_used)]

        try:
            await self._cf(*op_args)
        except _SubprocessError as exc:
            _log.error("campfire_dispatch: failed to post response: %s", exc)

        # Platform error: send a status operation so clients can filter.
        if result.get("is_platform_error"):
            try:
                await self._cf(
                    self._campfire_id, "status",
                    "--state", "platform-error",
                    "--reason", response_text,
                )
            except _SubprocessError as exc:
                _log.error("campfire_dispatch: failed to post platform-error status: %s", exc)

        # Budget warning: send a status operation.
        budget_warning = result.get("budget_warning")
        if budget_warning:
            try:
                await self._cf(
                    self._campfire_id, "status",
                    "--state", "budget-warning",
                    "--reason", budget_warning,
                )
            except _SubprocessError as exc:
                _log.error(
                    "campfire_dispatch: failed to post budget_warning status: %s",
                    exc,
                )

    async def _dispatch_message(
        self,
        msg: dict[str, Any],
        bridge: Optional[Any] = None,
    ) -> None:
        """Dispatch one inbound message through chat_turn() and post response."""
        # Import here to avoid circular import at module level.
        from mallcop.chat import chat_turn

        payload_raw = msg.get("payload", "")

        # Extract question text from convention payload.
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

        # Derive session_id from the convention payload's from_id.
        session_id = self._extract_session_id(msg)
        if not session_id:
            _log.warning(
                "campfire_dispatch: skipping message %s — no from_id in payload or relay:from_id tag. "
                "Convention inbound-message must include from_id.",
                msg.get("id"),
            )
            return

        _log.debug(
            "campfire_dispatch: dispatching message %s (session %s)",
            msg.get("id"), session_id,
        )

        # Start typing heartbeat if a bridge is provided.
        heartbeat_task: Optional[asyncio.Task] = None
        if bridge is not None:
            heartbeat_task = asyncio.create_task(
                _typing_heartbeat(bridge, session_id)
            )

        try:
            result = await chat_turn(
                question=question,
                session_id=session_id,
                interactive_runner=self._interactive_runner,
                store=self._adapter,
                root=self._root,
            )
        except Exception as exc:
            _log.error("campfire_dispatch: chat_turn error: %s", exc)
            return
        finally:
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass

        await self._post_response(session_id, result)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def drain_cursor(self, keep_recent_seconds: int = 120) -> None:
        """Advance the read cursor, keeping only recent messages.

        A fresh cf identity starts at cursor 0 and would re-process every
        historical inbound message.  This reads all messages via ``--all``,
        filters to those within ``keep_recent_seconds``, and re-queues only
        those for processing.  The cursor advances to the end.
        """
        _log.info("campfire_dispatch: draining relay:inbound cursor (skipping history)")
        try:
            raw = await self._cf(
                "read", self._campfire_id, "--all", "--json",
                "--tag", _TAG_RELAY_INBOUND,
            )
            if not raw:
                return
            items = json.loads(raw)
            if not isinstance(items, list):
                return
            # Filter to recent messages only
            import datetime as _dt
            cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=keep_recent_seconds)
            recent = []
            for item in items:
                ts_str = item.get("timestamp", "")
                try:
                    ts = _dt.datetime.fromisoformat(ts_str)
                    if ts >= cutoff:
                        recent.append(item)
                except (ValueError, TypeError):
                    pass
            _log.info(
                "campfire_dispatch: drained %d historical, kept %d recent inbound messages",
                len(items) - len(recent), len(recent),
            )
            # Process the recent ones immediately
            for msg in recent:
                await self._dispatch_message(msg, bridge=self._bridge)
        except Exception as exc:
            _log.warning("campfire_dispatch: drain_cursor failed: %s", exc)

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
            await self._dispatch_message(msg, bridge=self._bridge)

    async def run(self) -> None:
        """Poll campfire in a loop, dispatching inbound messages indefinitely.

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
        """Publish a finding to campfire via the finding convention operation.

        findings.jsonl is the primary store. This method writes to campfire
        in addition to whatever the caller already wrote to findings.jsonl.

        Uses the ``finding`` operation from the mallcop-relay convention:
            - finding_id (required)
            - severity (required)
            - summary (required)
            - connector (optional)

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

        # Summary: use finding title.
        summary = getattr(finding, "title", finding_id)

        _log.debug(
            "campfire_dispatch: publishing finding %s (severity=%s, connector=%s)",
            finding_id, severity_str, connector_name,
        )

        op_args = [
            self._campfire_id, "finding",
            "--finding_id", finding_id,
            "--severity", severity_str,
            "--summary", summary,
        ]
        if connector_name and connector_name != "unknown":
            op_args += ["--connector", connector_name]

        try:
            await self._cf(*op_args)
        except _SubprocessError as exc:
            _log.error(
                "campfire_dispatch: failed to publish finding %s: %s",
                finding_id, exc,
            )
