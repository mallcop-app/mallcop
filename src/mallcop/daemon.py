"""daemon — async daemon loop for mallcop watch --daemon.

Runs CampfireDispatcher (chat dispatch) and a periodic scan loop
concurrently. Runs until cancelled (KeyboardInterrupt / SIGTERM).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mallcop.campfire_dispatch import CampfireDispatcher

_log = logging.getLogger(__name__)


async def _daemon_loop(
    dispatcher: "CampfireDispatcher",
    root: Path,
    scan_interval: float,
) -> None:
    """Run campfire dispatch and periodic scan concurrently."""
    scan_task = asyncio.create_task(_scan_loop(dispatcher, root, scan_interval))
    dispatch_task = asyncio.create_task(dispatcher.run())
    try:
        await asyncio.gather(scan_task, dispatch_task)
    except asyncio.CancelledError:
        scan_task.cancel()
        dispatch_task.cancel()
        raise


async def _scan_loop(
    dispatcher: "CampfireDispatcher",
    root: Path,
    interval: float,
) -> None:
    """Periodically run scan → detect → escalate, publish new findings to campfire."""
    while True:
        try:
            await asyncio.to_thread(_run_one_scan, dispatcher, root)
        except Exception as exc:
            _log.error("daemon: scan failed: %s", exc)
        await asyncio.sleep(interval)


def _run_one_scan(dispatcher: "CampfireDispatcher", root: Path) -> None:
    """Run scan pipeline synchronously and publish any new findings."""
    from mallcop.cli_pipeline import run_scan_pipeline, run_detect_pipeline

    run_scan_pipeline(root)
    detect_result = run_detect_pipeline(root)
    findings: list[Any] = detect_result.get("findings", [])
    loop = asyncio.get_event_loop()
    for finding in findings:
        loop.call_soon_threadsafe(
            lambda f=finding: asyncio.ensure_future(dispatcher.publish_finding(f))
        )
