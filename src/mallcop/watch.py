"""Watch command logic: scan + detect + escalate pipeline."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from mallcop.pro import ProClient

_log = logging.getLogger(__name__)


def run_watch(
    root: Path,
    scan_fn: Callable[[Path], dict[str, Any]],
    detect_fn: Callable[[Path], dict[str, Any]],
    escalate_fn: Callable[..., dict[str, Any]],
    dry_run: bool = False,
    pro_config: Any = None,
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
        pro_config: Optional ProConfig. If set, calls ProClient.record_usage()
            after escalate with total tokens consumed. Failures are logged as
            warnings and do not fail the watch run.

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

        # Step 4: report usage to Pro account service (graceful on failure)
        if pro_config is not None and pro_config.account_id and pro_config.service_token:
            tokens_used = result.get("escalate", {}).get("donuts_used", 0)
            try:
                client = ProClient(pro_config.account_url)
                client.record_usage(
                    account_id=pro_config.account_id,
                    model="managed",
                    input_tokens=tokens_used,
                    output_tokens=0,
                    service_token=pro_config.service_token,
                )
            except Exception as exc:
                _log.warning("Failed to report usage to Pro account service: %s", exc)

    result["status"] = "ok"
    return result
