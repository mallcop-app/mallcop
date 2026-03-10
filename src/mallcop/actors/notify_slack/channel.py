"""Slack channel delivery: format findings into Block Kit and POST to webhook."""

from __future__ import annotations

from typing import Any

from mallcop.actors.notify_base import DeliveryResult, validate_webhook_url, post_webhook
from mallcop.schemas import Finding, Severity, SEVERITY_ORDER

_SEVERITY_EMOJI = {"critical": "\U0001f534", "warn": "\U0001f7e1", "info": "\U0001f535"}


def format_digest(findings: list[Finding]) -> dict[str, Any]:
    """Format findings as Slack Block Kit message."""
    if not findings:
        return {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "Mallcop: No findings to report",
                    },
                }
            ]
        }

    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )

    blocks: list[dict[str, Any]] = []

    # Header
    total = len(findings)
    blocks.append(
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Mallcop: {total} finding{'s' if total != 1 else ''}",
            },
        }
    )

    # Group by severity
    groups: dict[str, list[Finding]] = {}
    for f in sorted_findings:
        key = f.severity.value
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    for sev in ["critical", "warn", "info"]:
        if sev not in groups:
            continue
        group = groups[sev]
        emoji = _SEVERITY_EMOJI.get(sev, "\u26aa")

        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{sev.upper()}* ({len(group)})",
                },
            }
        )

        for f in group:
            text = f"\u2022 `{f.id}` {f.title}"
            if f.annotations:
                last = f.annotations[-1]
                text += f"\n  _{last.actor}: {last.content}_"
            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": text}}
            )

    return {"blocks": blocks}


def deliver_digest(
    findings: list[Finding], webhook_url: str
) -> DeliveryResult:
    """POST formatted digest to Slack incoming webhook."""
    validate_webhook_url(webhook_url)
    payload = format_digest(findings)
    return post_webhook(webhook_url, payload)
