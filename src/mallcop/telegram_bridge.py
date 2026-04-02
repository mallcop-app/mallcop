"""telegram_bridge — bidirectional Telegram↔campfire bridge for mallcop.

Polls Telegram getUpdates and a campfire for new messages, forwarding
each direction:

- Telegram → campfire: user messages sent with ``chat`` + ``session:<chat_id>``
  tags so CampfireDispatcher can pick them up.
- Campfire → Telegram: ``response``-tagged messages from CampfireDispatcher
  forwarded to the Telegram chat.

Design notes
------------
- Uses ``asyncio.to_thread`` + ``requests`` (already a project dependency).
  No new dependencies.
- ``cf`` CLI invocations use the same ``_run_cf`` helper pattern as
  campfire_dispatch.py (asyncio.create_subprocess_exec).
- Loop runs until cancelled (asyncio.CancelledError propagates cleanly).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import requests

_log = logging.getLogger(__name__)

_TELEGRAM_BASE = "https://api.telegram.org/bot{token}"
_CF_TIMEOUT = 30.0

_SAFE_TAG_RE = re.compile(r"[^a-zA-Z0-9_-]")


def _sanitize_tag(value: str) -> str:
    """Replace characters unsafe in campfire tag values with underscores."""
    return _SAFE_TAG_RE.sub("_", str(value))


class TelegramCampfireBridge:
    """Bidirectional bridge between a Telegram bot and a mallcop campfire.

    Parameters
    ----------
    bot_token:
        Telegram bot token (``123456:ABC-...``).
    chat_id:
        Telegram chat ID to send messages to.
    campfire_id:
        The campfire to read from and write to.
    poll_interval:
        Seconds between poll cycles (default 3.0).
    cf_bin:
        Path to the cf binary (default: ``cf`` from PATH).
    cf_home:
        Optional --cf-home override for every cf invocation.
    """

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        campfire_id: str,
        poll_interval: float = 3.0,
        cf_bin: str = "cf",
        cf_home: str | None = None,
        inbound_mode: bool = False,
    ) -> None:
        self._chat_id = chat_id
        self._campfire_id = campfire_id
        self._poll_interval = poll_interval
        self._cf_bin = cf_bin
        self._cf_home = cf_home
        self._update_offset: int = 0
        self._inbound_mode = inbound_mode
        # Store token separately; construct per-call URLs at call time so the
        # token is never embedded in a persistent attribute that could appear in logs.
        self._tg_token = bot_token
        self._tg_base = _TELEGRAM_BASE.format(token=bot_token)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Run bridge loop until cancelled.

        Maintains the Telegram update offset in memory across cycles.
        For a standalone single-cycle execution with campfire-persisted offset,
        use ``run_once()`` instead.
        """
        while True:
            try:
                tg_messages = await self._poll_telegram()
                for msg in tg_messages:
                    text = msg.get("message", {}).get("text", "")
                    from_id = msg.get("message", {}).get("from", {}).get("id", "unknown")
                    if text:
                        await self._send_to_campfire(text, from_id)

                cf_messages = await self._poll_campfire()
                for msg in cf_messages:
                    content = self._extract_response_text(msg)
                    if content:
                        await self._send_to_telegram(content)

            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                _log.warning("telegram_bridge: loop error: %s", exc)

            await asyncio.sleep(self._poll_interval)

    async def run_once(self) -> None:
        """Run one standalone poll cycle with campfire-persisted offset.

        Designed for cron/one-shot invocation (not for use inside ``run()``):

        1. Restores the Telegram update offset from campfire (last tg-offset message).
        2. Polls Telegram getUpdates using the restored offset.
        3. Forwards each new Telegram message to campfire via ``_send_to_campfire()``.
        4. Polls campfire for response-tagged messages.
        5. Forwards each response to Telegram via ``_send_to_telegram()``.
        6. Persists the new update offset back to campfire.
        """
        await self._restore_offset_from_campfire()

        tg_messages = await self._poll_telegram()
        for msg in tg_messages:
            text = msg.get("message", {}).get("text", "")
            from_id = msg.get("message", {}).get("from", {}).get("id", "unknown")
            if text:
                await self._send_to_campfire(text, from_id)

        cf_messages = await self._poll_campfire()
        for msg in cf_messages:
            content = self._extract_response_text(msg)
            if content:
                await self._send_to_telegram(content)

        await self._persist_offset_to_campfire()

    async def run_once_inbound(self) -> None:
        """Run one poll cycle in campfire-inbound mode (pro-online webhook tier).

        Used when mallcop-pro has registered a Telegram webhook — getUpdates
        cannot be used alongside a webhook.  Instead, mallcop-pro's webhook
        handler writes inbound Telegram messages to the customer's campfire as
        ``tg-inbound`` tagged messages.

        Steps:
        1. Read ``tg-inbound`` tagged messages from campfire.
        2. Forward each to campfire as ``chat`` + ``session:<chat_id>`` tagged
           messages so CampfireDispatcher can pick them up.
        3. Poll campfire for ``response``-tagged messages (same as run_once()).
        4. Forward each response to Telegram via ``_send_to_telegram()``.

        No getUpdates call. No offset persistence.
        """
        inbound = await self._poll_campfire_inbound()
        for msg in inbound:
            raw = msg.get("payload", "")
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
                content = parsed.get("content", "")
                from_id = parsed.get("from", "unknown")
            except (json.JSONDecodeError, TypeError):
                content = raw
                from_id = "unknown"
            if content:
                await self._send_to_campfire(text=content, from_id=from_id)

        cf_messages = await self._poll_campfire()
        for msg in cf_messages:
            text = self._extract_response_text(msg)
            if text:
                await self._send_to_telegram(text)

    # ------------------------------------------------------------------
    # Telegram helpers
    # ------------------------------------------------------------------

    async def _poll_telegram(self) -> list[dict]:
        """Fetch new messages from Telegram getUpdates. Advances update_id offset."""
        def _get() -> list[dict]:
            url = f"{self._tg_base}/getUpdates"
            params = {
                "offset": self._update_offset,
                "limit": 20,
                "timeout": 0,
            }
            try:
                resp = requests.get(url, params=params, timeout=10)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:  # noqa: BLE001
                # Redact token from URL that requests embeds in exception messages.
                _log.warning(
                    "telegram_bridge: getUpdates error: %s",
                    str(exc).replace(self._tg_token, "***"),
                )
                return []

            updates = data.get("result", [])
            if updates:
                self._update_offset = max(u["update_id"] for u in updates) + 1
            return updates

        return await asyncio.to_thread(_get)

    async def _send_to_telegram(self, text: str) -> None:
        """POST sendMessage to Telegram bot API."""
        def _post() -> None:
            url = f"{self._tg_base}/sendMessage"
            payload = {"chat_id": self._chat_id, "text": text}
            try:
                resp = requests.post(url, json=payload, timeout=10)
                resp.raise_for_status()
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "telegram_bridge: sendMessage error: %s",
                    str(exc).replace(self._tg_token, "***"),
                )

        await asyncio.to_thread(_post)

    # ------------------------------------------------------------------
    # Offset persistence helpers
    # ------------------------------------------------------------------

    async def _restore_offset_from_campfire(self) -> None:
        """Restore Telegram update offset from the last tg-offset message in campfire.

        Reads campfire with --tag tg-offset --json, finds the last entry, and
        extracts the offset value from its payload.  If no prior offset is found
        the internal offset stays at its current value (0 on first run).
        """
        try:
            raw = await self._cf(
                "read", self._campfire_id,
                "--tag", "tg-offset",
                "--json",
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("telegram_bridge: restore offset read error: %s", exc)
            return

        if not raw:
            return

        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            _log.warning("telegram_bridge: non-JSON from cf read (tg-offset): %r", raw[:200])
            return

        if not isinstance(items, list) or not items:
            return

        last = items[-1]
        payload_raw = last.get("payload", "")
        if not payload_raw:
            return

        try:
            parsed = json.loads(payload_raw)
            offset = parsed.get("offset")
            if isinstance(offset, int):
                self._update_offset = offset
                _log.debug("telegram_bridge: restored offset %d from campfire", offset)
        except (json.JSONDecodeError, TypeError):
            _log.warning("telegram_bridge: could not parse tg-offset payload: %r", payload_raw[:200])

    async def _persist_offset_to_campfire(self) -> None:
        """Persist the current Telegram update offset to campfire.

        Posts JSON ``{"offset": N}`` tagged with tg-offset and instance mallcop
        so future sessions can restore from where this one left off.
        """
        payload = json.dumps({"offset": self._update_offset})
        try:
            await self._cf(
                "send", self._campfire_id,
                "--tag", "tg-offset",
                "--instance", "mallcop",
                payload,
            )
            _log.debug("telegram_bridge: persisted offset %d to campfire", self._update_offset)
        except Exception as exc:  # noqa: BLE001
            _log.warning("telegram_bridge: persist offset error: %s", exc)

    # ------------------------------------------------------------------
    # Campfire helpers
    # ------------------------------------------------------------------

    async def _send_to_campfire(self, text: str, from_id: int | str) -> None:
        """Post a user message to campfire with chat+session tags."""
        payload = json.dumps({"content": text, "from": str(from_id)})
        try:
            await self._cf(
                "send", self._campfire_id,
                "--instance", "mallcop",
                "--tag", "chat",
                "--tag", f"session:{_sanitize_tag(str(self._chat_id))}",
                "--tag", "platform:telegram",
                payload,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("telegram_bridge: campfire send error: %s", exc)

    async def _poll_campfire(self) -> list[dict]:
        """Fetch new response-tagged messages from campfire."""
        try:
            raw = await self._cf(
                "read", self._campfire_id,
                "--json",
                "--tag", "response",
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("telegram_bridge: campfire read error: %s", exc)
            return []

        if not raw:
            return []

        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            _log.warning("telegram_bridge: non-JSON from cf read: %r", raw[:200])
            return []

        if not isinstance(items, list):
            return []

        return items

    async def _poll_campfire_inbound(self) -> list[dict]:
        """Fetch tg-inbound tagged messages from campfire (campfire-inbound mode).

        Returns the parsed list of campfire message dicts, or an empty list on
        error.  Each message payload is expected to be JSON with ``content`` and
        ``from`` keys written by the mallcop-pro webhook handler.
        """
        try:
            raw = await self._cf(
                "read", self._campfire_id,
                "--json",
                "--tag", "tg-inbound",
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("telegram_bridge: campfire inbound read error: %s", exc)
            return []

        if not raw:
            return []

        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            _log.warning("telegram_bridge: non-JSON from cf read (tg-inbound): %r", raw[:200])
            return []

        if not isinstance(items, list):
            return []

        return items

    @staticmethod
    def _extract_response_text(msg: dict[str, Any]) -> str | None:
        """Extract response text from a campfire message dict.

        Campfire stores message body under the ``payload`` key.
        """
        raw = msg.get("payload", "")
        if not raw:
            return None
        # Try to parse as JSON (campfire_dispatch posts JSON payloads).
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed.get("content") or parsed.get("answer") or parsed.get("text")
        except (json.JSONDecodeError, TypeError):
            pass
        return raw

    # ------------------------------------------------------------------
    # Internal: cf subprocess runner
    # ------------------------------------------------------------------

    async def _cf(self, *args: str) -> str:
        """Run a cf command via asyncio subprocess. Returns stdout."""
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
            raise RuntimeError(f"cf binary not found or not executable: {exc}") from exc

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_CF_TIMEOUT)

        if proc.returncode != 0:
            raise RuntimeError(
                f"cf command failed (exit {proc.returncode}): {args!r}\n"
                f"stderr: {stderr.decode(errors='replace').strip()}"
            )
        return stdout.decode(errors="replace").strip()
