"""daemon — async daemon loop for mallcop watch --daemon.

Runs CampfireDispatcher (chat dispatch) and a periodic scan loop
concurrently. Runs until cancelled (KeyboardInterrupt / SIGTERM).
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mallcop.campfire_dispatch import CampfireDispatcher

_log = logging.getLogger(__name__)


async def _idle_watchdog(
    campfire_id: str,
    idle_timeout_seconds: float,
    cf_bin: str = "cf",
    cf_home: str | None = None,
) -> None:
    """Cancel all tasks after idle_timeout_seconds with no tg-inbound messages.

    Polls campfire every 10s for tg-inbound tagged messages. Resets the
    idle clock whenever a new message arrives. When the idle window expires,
    cancels all running asyncio tasks (which triggers clean daemon exit).
    """
    poll_interval = 10.0
    last_message_time = asyncio.get_event_loop().time()
    seen_message_ids: set[str] = set()

    env = dict(os.environ)
    if cf_home is not None:
        env["CF_HOME"] = cf_home

    while True:
        await asyncio.sleep(poll_interval)

        # Poll campfire for tg-inbound messages.
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [cf_bin, "read", campfire_id, "--tag", "tg-inbound", "--json"],
                capture_output=True,
                text=True,
                env=env,
            )
            output = result.stdout.strip()
        except Exception as exc:
            _log.warning("idle_watchdog: cf read failed: %s", exc)
            output = ""

        # Check for new messages by scanning for message IDs.
        if output:
            import json as _json
            try:
                messages = _json.loads(output)
                if not isinstance(messages, list):
                    messages = [messages]
                for msg in messages:
                    msg_id = msg.get("id") or msg.get("message_id") or str(msg)
                    if msg_id not in seen_message_ids:
                        seen_message_ids.add(msg_id)
                        last_message_time = asyncio.get_event_loop().time()
                        _log.debug("idle_watchdog: new tg-inbound message, reset idle clock")
            except Exception:
                # Non-JSON or unexpected format — treat as activity if non-empty.
                last_message_time = asyncio.get_event_loop().time()

        # Check idle timeout.
        idle_elapsed = asyncio.get_event_loop().time() - last_message_time
        if idle_elapsed > idle_timeout_seconds:
            _log.info(
                "idle_watchdog: no tg-inbound messages for %.1fs (limit %.1fs), shutting down",
                idle_elapsed,
                idle_timeout_seconds,
            )
            # Cancel all tasks in the current event loop to trigger clean exit.
            current = asyncio.current_task()
            for task in asyncio.all_tasks():
                if task is not current:
                    task.cancel()
            return


async def _daemon_loop(
    dispatcher: "CampfireDispatcher",
    root: Path,
    scan_interval: float,
    idle_timeout_seconds: float = 300.0,
) -> None:
    """Run campfire dispatch and periodic scan concurrently."""
    campfire_id = getattr(dispatcher, "campfire_id", "")
    cf_home = os.environ.get("CF_HOME")

    scan_task = asyncio.create_task(_scan_loop(dispatcher, root, scan_interval))
    dispatch_task = asyncio.create_task(dispatcher.run())
    watchdog_task = asyncio.create_task(
        _idle_watchdog(campfire_id, idle_timeout_seconds, cf_home=cf_home)
    )
    try:
        await asyncio.gather(scan_task, dispatch_task, watchdog_task)
    except asyncio.CancelledError:
        scan_task.cancel()
        dispatch_task.cancel()
        watchdog_task.cancel()
        # Suppress CancelledError — idle timeout is a clean exit, not an error.


async def _scan_loop(
    dispatcher: "CampfireDispatcher",
    root: Path,
    interval: float,
) -> None:
    """Periodically run scan → detect → escalate, publish new findings to campfire."""
    while True:
        try:
            findings = await asyncio.to_thread(_run_one_scan, root)
            for finding in findings:
                asyncio.create_task(dispatcher.publish_finding(finding))
        except Exception as exc:
            _log.error("daemon: scan failed: %s", exc)
        await asyncio.sleep(interval)


def _run_one_scan(root: Path) -> list[Any]:
    """Run scan pipeline synchronously and return new findings."""
    from mallcop.cli_pipeline import run_scan_pipeline, run_detect_pipeline

    run_scan_pipeline(root)
    detect_result = run_detect_pipeline(root)
    if not detect_result:
        return []
    return detect_result.get("findings", [])
