"""Watch command logic: scan + detect + escalate pipeline."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable

from mallcop.config import GitHubConfig
from mallcop.pro import ProClient

_log = logging.getLogger(__name__)


def run_watch(
    root: Path,
    scan_fn: Callable[[Path], dict[str, Any]],
    detect_fn: Callable[[Path], dict[str, Any]],
    escalate_fn: Callable[..., dict[str, Any]],
    dry_run: bool = False,
    pro_config: Any = None,
    github_config: GitHubConfig | None = None,
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
        # NOTE: The actor runtime tracks total tokens only (no input/output split).
        # We pass total as input_tokens with output_tokens=0. The server computes
        # donuts from the sum, so billing is correct. Analytics will show all tokens
        # as input, which is a known limitation.
        if pro_config is not None and pro_config.account_id and pro_config.service_token:
            total_tokens = result.get("escalate", {}).get("donuts_used", 0)
            try:
                client = ProClient(pro_config.account_url)
                client.record_usage(
                    account_id=pro_config.account_id,
                    model="managed",
                    input_tokens=total_tokens,
                    output_tokens=0,
                    service_token=pro_config.service_token,
                )
            except Exception as exc:
                _log.warning("Failed to report usage to Pro account service: %s", exc)

    # Step 5: push to GitHub findings repo
    result["push"] = _push_to_github(root, github_config, dry_run)

    result["status"] = "ok"
    return result


def _push_to_github(
    root: Path,
    github_config: GitHubConfig | None,
    dry_run: bool,
) -> dict[str, Any]:
    """Push findings to GitHub. Non-fatal on failure."""
    if dry_run:
        return {"status": "skipped", "reason": "dry_run"}
    if github_config is None:
        return {"status": "skipped", "reason": "not_configured"}

    try:
        # In GitHub Actions, use GITHUB_TOKEN directly
        if os.environ.get("GITHUB_ACTIONS") == "true":
            token = os.environ.get("GITHUB_TOKEN", "")
        else:
            from mallcop.github_auth import ensure_fresh_token

            cred = ensure_fresh_token(github_config.credentials_path, github_config.client_id)
            if cred is None:
                return {"status": "skipped", "reason": "no_credentials"}
            token = cred.access_token

        from mallcop.git_push import clone_or_pull, commit_and_push

        # In Actions, the repo is already checked out; skip clone_or_pull.
        if os.environ.get("GITHUB_ACTIONS") != "true":
            clone_or_pull(root, token)
        commit_and_push(root, token)
        return {"status": "ok"}
    except Exception as e:
        _log.warning("GitHub push failed: %s", e)
        return {"status": "error", "error": str(e)}
