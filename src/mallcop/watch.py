"""Watch command logic: scan + detect + escalate pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


def run_watch(
    root: Path,
    scan_fn: Callable[[Path], dict[str, Any]],
    detect_fn: Callable[[Path], dict[str, Any]],
    escalate_fn: Callable[..., dict[str, Any]],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run the scan -> detect -> escalate pipeline.

    Fail-fast: if scan fails, detect and escalate don't run.
    Dry-run: runs scan + detect but skips escalate.

    Args:
        root: Deployment repo directory.
        scan_fn: Function to run scan step.
        detect_fn: Function to run detect step.
        escalate_fn: Function to run escalate step.
        dry_run: If True, skip escalate.

    Returns:
        Combined result dict.
    """
    result: dict[str, Any] = {"command": "watch", "dry_run": dry_run}

    # Step 1: scan
    try:
        scan_result = scan_fn(root)
        result["scan"] = scan_result
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"scan failed: {e}"
        return result

    # Step 2: detect
    try:
        detect_result = detect_fn(root)
        result["detect"] = detect_result
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"detect failed: {e}"
        result["scan"] = scan_result
        return result

    # Step 3: escalate (skip on dry-run)
    if not dry_run:
        try:
            escalate_result = escalate_fn(root)
            result["escalate"] = escalate_result
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"escalate failed: {e}"
            return result

    result["status"] = "ok"
    return result
