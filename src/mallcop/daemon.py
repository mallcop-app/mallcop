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
    bridge=None,
) -> None:
    """Run campfire dispatch and periodic scan concurrently."""
    campfire_id = getattr(dispatcher, "campfire_id", "")
    cf_home = os.environ.get("CF_HOME")

    scan_task = asyncio.create_task(_scan_loop(dispatcher, root, scan_interval))
    dispatch_task = asyncio.create_task(dispatcher.run())
    watchdog_task = asyncio.create_task(
        _idle_watchdog(campfire_id, idle_timeout_seconds, cf_home=cf_home)
    )
    tasks = [scan_task, dispatch_task, watchdog_task]
    if bridge is not None:
        bridge_task = asyncio.create_task(_bridge_inbound_loop(bridge))
        tasks.append(bridge_task)
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        # Suppress CancelledError — idle timeout is a clean exit, not an error.


async def _bridge_inbound_loop(bridge, interval: float = 3.0) -> None:
    """Poll bridge.run_once_inbound() in a loop."""
    while True:
        try:
            await bridge.run_once_inbound()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log.warning("bridge inbound error: %s", exc)
        await asyncio.sleep(interval)


async def _scan_loop(
    dispatcher: "CampfireDispatcher",
    root: Path,
    interval: float,
) -> None:
    """Periodically trigger scans and publish new findings to campfire.

    In container mode (MALLCOP_PRO_SERVICE_TOKEN set), dispatches scans to
    GitHub Actions on the deploy repo. Otherwise runs scans locally.
    """
    service_token = os.environ.get("MALLCOP_PRO_SERVICE_TOKEN")
    if service_token:
        await _gha_scan_loop(dispatcher, interval)
    else:
        await _local_scan_loop(dispatcher, root, interval)


async def _gha_scan_loop(
    dispatcher: "CampfireDispatcher",
    interval: float,
) -> None:
    """Dispatch scans to GitHub Actions on the deploy repo."""
    import requests

    api_base = os.environ.get("MALLCOP_PRO_INFERENCE_URL", "https://api.mallcop.app")
    service_token = os.environ.get("MALLCOP_PRO_SERVICE_TOKEN", "")
    deploy_repo_raw = os.environ.get("MALLCOP_DEPLOY_REPO", "")
    installation_id = os.environ.get("MALLCOP_INSTALLATION_ID", "") or os.environ.get("GITHUB_INSTALLATION_ID", "")

    # Extract owner/repo from git URL (https://github.com/org/repo.git → org/repo)
    deploy_repo = deploy_repo_raw
    if deploy_repo.startswith("https://github.com/"):
        deploy_repo = deploy_repo.removeprefix("https://github.com/").removesuffix(".git")

    if not deploy_repo:
        _log.info("daemon: MALLCOP_DEPLOY_REPO not set, skipping GHA scan dispatch")
        # Just sleep forever — chat dispatch still runs
        while True:
            await asyncio.sleep(interval)
        return

    while True:
        try:
            # Get a GitHub installation token from mallcop-pro
            token_resp = await asyncio.to_thread(
                requests.post,
                f"{api_base}/v1/github/token",
                headers={"Authorization": f"Bearer {service_token}"},
                json={"installation_id": int(installation_id)} if installation_id else {},
                timeout=10,
            )
            if token_resp.status_code != 200:
                _log.warning("daemon: failed to get GitHub token: %d", token_resp.status_code)
                await asyncio.sleep(interval)
                continue

            gh_token = token_resp.json().get("token", "")

            # Trigger workflow_dispatch on the deploy repo
            dispatch_resp = await asyncio.to_thread(
                requests.post,
                f"https://api.github.com/repos/{deploy_repo}/actions/workflows/mallcop.yml/dispatches",
                headers={
                    "Authorization": f"Bearer {gh_token}",
                    "Accept": "application/vnd.github+json",
                },
                json={"ref": "main"},
                timeout=10,
            )
            if dispatch_resp.status_code == 204:
                _log.info("daemon: triggered scan on %s", deploy_repo)
            else:
                _log.warning(
                    "daemon: GHA dispatch failed: %d %s",
                    dispatch_resp.status_code,
                    dispatch_resp.text[:200],
                )
        except Exception as exc:
            _log.error("daemon: GHA scan dispatch failed: %s", exc)
        await asyncio.sleep(interval)


async def _local_scan_loop(
    dispatcher: "CampfireDispatcher",
    root: Path,
    interval: float,
) -> None:
    """Run scan pipeline locally and publish findings to campfire."""
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
