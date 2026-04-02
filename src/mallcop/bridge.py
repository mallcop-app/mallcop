"""Bridge polling loop: connects mallcop watch to the mallcop-pro browser bridge.

The bridge thread polls GET /v1/bridge/poll for pending messages from browser
sessions, runs local inference on each message (with findings context), and
posts responses via POST /v1/bridge/respond.

The thread runs as a daemon so it exits automatically when the main process exits.
"""

from __future__ import annotations

import json
import logging
import time
import threading
from pathlib import Path
from typing import Any

import requests

_log = logging.getLogger(__name__)

# Poll interval in seconds (nominal; reset to this on success)
POLL_INTERVAL: float = 3.0

# Backoff sequence on error (seconds): 3, 6, 12, 24, 60, 60, …
_BACKOFF_STEPS = [3, 6, 12, 24, 60]

# Max tokens for bridge inference response
_MAX_TOKENS = 1024

# System prompt for bridge inference
_BRIDGE_SYSTEM_PROMPT = (
    "You are a security analyst assistant for mallcop. "
    "Answer the user's question about their security posture, findings, and events. "
    "Be concise and actionable. Ground your answers in the findings provided."
)


def _load_findings_context(findings_path: Path) -> str:
    """Load findings from findings.jsonl and return as a context string."""
    if not findings_path.exists():
        return ""
    lines: list[str] = []
    try:
        for line in findings_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                finding_id = obj.get("id", "")
                severity = obj.get("severity", "")
                title = obj.get("title", obj.get("summary", ""))
                if title:
                    lines.append(f"[{severity}] {finding_id}: {title}")
            except Exception:
                pass
    except Exception as exc:
        _log.debug("bridge: could not load findings: %s", exc)
    return "\n".join(lines)


def _build_system_prompt(findings_context: str) -> str:
    """Build system prompt optionally including findings context."""
    if not findings_context:
        return _BRIDGE_SYSTEM_PROMPT
    return f"{_BRIDGE_SYSTEM_PROMPT}\n\nCurrent findings:\n{findings_context}"


def run_inference(
    msg: dict[str, Any],
    findings_path: Path,
    service_token: str,
    inference_url: str,
) -> dict[str, Any]:
    """Run inference for a bridge message.

    Sends a POST to the managed inference endpoint and returns a dict with
    keys: content (str), tokens_used (int).

    Falls back to an error response if the inference call fails.
    """
    findings_context = _load_findings_context(findings_path)
    system_prompt = _build_system_prompt(findings_context)
    user_content = msg.get("content", "")

    payload = {
        "model": "detective",
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_content}],
        "max_tokens": _MAX_TOKENS,
    }
    headers = {"Authorization": f"Bearer {service_token}", "Content-Type": "application/json"}

    resp = requests.post(
        f"{inference_url}/v1/messages",
        headers=headers,
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    # Parse Anthropic-style response
    content = ""
    content_blocks = data.get("content", [])
    if isinstance(content_blocks, list):
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                content += block.get("text", "")
    elif isinstance(content_blocks, str):
        content = content_blocks

    tokens_used = 0
    usage = data.get("usage", {})
    if isinstance(usage, dict):
        tokens_used = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

    return {"content": content, "tokens_used": tokens_used}


def bridge_poll_loop(
    inference_url: str,
    service_token: str,
    findings_path: Path,
    stop_event: threading.Event | None = None,
) -> None:
    """Poll for bridge messages, run inference, post responses.

    Runs until the thread is killed (daemon) or stop_event is set.

    Args:
        inference_url: Base URL for the mallcop-pro API (e.g. https://api.mallcop.app).
        service_token: Bearer token for authentication.
        findings_path: Path to findings.jsonl for context.
        stop_event: Optional threading.Event; loop exits when set.
    """
    backoff_idx = 0
    poll_url = f"{inference_url}/v1/bridge/poll"
    respond_url = f"{inference_url}/v1/bridge/respond"
    headers = {"Authorization": f"Bearer {service_token}"}

    while True:
        if stop_event is not None and stop_event.is_set():
            _log.debug("bridge: stop_event set, exiting poll loop")
            return

        try:
            resp = requests.get(poll_url, headers=headers, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                messages = data.get("messages", [])
                pending = len(messages)
                print(f"bridge: connected, last poll {POLL_INTERVAL:.0f}s ago, {pending} pending")

                for msg in messages:
                    session_id = msg.get("session_id", "")
                    try:
                        inference_result = run_inference(
                            msg, findings_path, service_token, inference_url
                        )
                        requests.post(
                            respond_url,
                            headers={**headers, "Content-Type": "application/json"},
                            json={
                                "session_id": session_id,
                                "content": inference_result["content"],
                                "metadata": {"tokens_used": inference_result["tokens_used"]},
                            },
                            timeout=10,
                        )
                    except Exception as exc:
                        _log.warning("bridge: inference/respond failed for %s: %s", session_id, exc)

                # Success: reset backoff
                backoff_idx = 0

            else:
                _log.warning("bridge: poll returned HTTP %d", resp.status_code)
                backoff_idx = min(backoff_idx + 1, len(_BACKOFF_STEPS) - 1)
                wait = _BACKOFF_STEPS[backoff_idx]
                print(f"bridge: error — HTTP {resp.status_code}, retrying in {wait}s")
                _interruptible_sleep(wait, stop_event)
                continue

        except Exception as exc:
            backoff_idx = min(backoff_idx + 1, len(_BACKOFF_STEPS) - 1)
            wait = _BACKOFF_STEPS[backoff_idx]
            print(f"bridge: error — {exc}, retrying in {wait}s")
            _log.debug("bridge: poll exception: %s", exc, exc_info=True)
            _interruptible_sleep(wait, stop_event)
            continue

        _interruptible_sleep(POLL_INTERVAL, stop_event)


def _interruptible_sleep(seconds: float, stop_event: threading.Event | None) -> None:
    """Sleep in small increments so stop_event is checked frequently."""
    if stop_event is None:
        time.sleep(seconds)
        return
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if stop_event.is_set():
            return
        time.sleep(min(0.1, deadline - time.monotonic()))


def start_bridge_thread(
    inference_url: str,
    service_token: str,
    findings_path: Path,
) -> threading.Thread:
    """Start the bridge poll loop in a daemon thread.

    Returns the thread (already started). The thread exits when the main
    process exits (daemon=True).
    """
    t = threading.Thread(
        target=bridge_poll_loop,
        args=(inference_url, service_token, findings_path),
        daemon=True,
        name="mallcop-bridge",
    )
    t.start()
    _log.info("bridge: started poll thread (interval=%.0fs)", POLL_INTERVAL)
    return t
