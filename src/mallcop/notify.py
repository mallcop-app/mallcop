"""Watch-cycle notify dispatch: route findings to channels via /v1/notify.

Flow:
1. Filter findings that have notify channels in their severity's routing config.
2. If no findings have channels, return early (no balance check).
3. Check /v1/balance once.
4. For each finding:
   - balance=0 + info/warn  → suppress (skip)
   - balance=0 + critical   → send with summary=null (no LLM call)
   - balance>0              → generate summary via ManagedClient patrol lane, then send
5. Return dispatch summary dict.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from mallcop.config import RouteConfig
from mallcop.schemas import Finding, Severity

_log = logging.getLogger(__name__)

# Balance below this threshold triggers a low-balance warning flag.
LOW_BALANCE_THRESHOLD = 100

# Severities that are suppressed when balance=0 (non-critical).
_SUPPRESS_ON_ZERO_BALANCE = frozenset({Severity.INFO, Severity.WARN})


def compute_low_balance_warning(balance: int) -> bool:
    """Return True if balance is below LOW_BALANCE_THRESHOLD."""
    return balance < LOW_BALANCE_THRESHOLD


def _check_balance(api_base_url: str, api_key: str) -> int:
    """Fetch current donut balance from /v1/balance. Returns 0 on error."""
    url = f"{api_base_url.rstrip('/')}/v1/balance"
    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return int(resp.json().get("balance", 0))
        _log.warning("Balance check returned HTTP %d", resp.status_code)
        return 0
    except Exception:
        _log.warning("Balance check failed", exc_info=True)
        return 0


def _generate_summary(finding: Finding, managed_client: Any) -> str | None:
    """Generate a pre-rendered summary for a finding via the patrol lane.

    Returns the text summary, or None if generation fails.
    """
    prompt = (
        f"Summarize this security finding in 2-3 sentences for an operator notification.\n\n"
        f"Finding: {finding.title}\n"
        f"Severity: {finding.severity.value}\n"
        f"Detector: {finding.detector}\n"
        f"ID: {finding.id}"
    )
    try:
        resp = managed_client.chat(
            model="patrol",
            system_prompt="You are a security analyst writing concise operator alerts.",
            messages=[{"role": "user", "content": prompt}],
            tools=[],
        )
        # Extract text from raw_resolution or any text attribute
        if hasattr(resp, "raw_resolution") and resp.raw_resolution:
            return str(resp.raw_resolution)
        # Fallback: use title as summary if chat returns nothing useful
        return finding.title
    except Exception:
        _log.warning("Summary generation failed for finding %s", finding.id, exc_info=True)
        return None


def _send_notify(
    api_base_url: str,
    api_key: str,
    finding: Finding,
    channels: list[str],
    summary: str | None,
) -> bool:
    """POST /v1/notify for a single finding. Returns True on success."""
    url = f"{api_base_url.rstrip('/')}/v1/notify"
    payload: dict[str, Any] = {
        "finding_id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "detector": finding.detector,
        "channels": channels,
        "summary": summary,
    }
    try:
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            json=payload,
            timeout=15,
        )
        if resp.status_code == 200:
            return True
        _log.warning(
            "notify dispatch failed for %s: HTTP %d", finding.id, resp.status_code
        )
        return False
    except Exception:
        _log.warning("notify dispatch error for %s", finding.id, exc_info=True)
        return False


def dispatch_notify(
    *,
    findings: list[Finding],
    routing: dict[str, RouteConfig | None],
    managed_client: Any,
    api_base_url: str,
    api_key: str,
) -> dict[str, Any]:
    """Dispatch findings to notify channels via POST /v1/notify.

    Args:
        findings: List of findings from the current watch cycle.
        routing: Routing config keyed by severity. Each RouteConfig has a
            ``notify`` field listing channel names.
        managed_client: ManagedClient (patrol lane) for summary generation.
        api_base_url: Base URL for mallcop API (e.g. https://api.mallcop.app).
        api_key: Customer or service API key (mallcop-sk-*).

    Returns:
        Dict with keys: dispatched (int), suppressed (int), low_balance (bool).
    """
    # Filter findings that have at least one notify channel in their routing.
    notifiable: list[tuple[Finding, list[str]]] = []
    for finding in findings:
        route = routing.get(finding.severity.value)
        if route is None:
            continue
        channels = route.notify
        if not channels:
            continue
        notifiable.append((finding, list(channels)))

    # No findings need notification — skip balance check entirely.
    if not notifiable:
        return {"dispatched": 0, "suppressed": 0, "low_balance": False}

    # Check balance once before any summary generation.
    balance = _check_balance(api_base_url, api_key)
    low_balance = compute_low_balance_warning(balance)
    balance_zero = balance == 0

    dispatched = 0
    suppressed = 0

    for finding, channels in notifiable:
        if balance_zero and finding.severity in _SUPPRESS_ON_ZERO_BALANCE:
            # Suppress non-critical findings when balance is exhausted.
            _log.info(
                "notify suppressed for %s (balance=0, severity=%s)",
                finding.id,
                finding.severity.value,
            )
            suppressed += 1
            continue

        if balance_zero:
            # Critical finding with zero balance: send with summary=null.
            summary: str | None = None
        else:
            # Generate summary via patrol lane before sending.
            summary = _generate_summary(finding, managed_client)

        ok = _send_notify(api_base_url, api_key, finding, channels, summary)
        if ok:
            dispatched += 1
        else:
            _log.warning("notify failed for finding %s", finding.id)

    return {"dispatched": dispatched, "suppressed": suppressed, "low_balance": low_balance}
