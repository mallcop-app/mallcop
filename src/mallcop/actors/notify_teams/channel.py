"""Teams channel delivery: format findings into digest and POST to webhook."""

from __future__ import annotations

from typing import Any

from mallcop.actors.notify_base import DeliveryResult, validate_webhook_url, post_webhook
from mallcop.schemas import Finding, Severity, SEVERITY_ORDER


def format_digest(findings: list[Finding]) -> dict[str, Any]:
    if not findings:
        return {
            "type": "message",
            "summary": "Mallcop: No findings to report",
            "sections": [],
        }

    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )

    # Group by severity
    groups: dict[str, list[Finding]] = {}
    for f in sorted_findings:
        key = f.severity.value
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    sections: list[dict[str, Any]] = []
    for severity_val in ["critical", "warn", "info"]:
        if severity_val not in groups:
            continue
        group = groups[severity_val]
        facts: list[dict[str, str]] = []
        for f in group:
            value = f.title
            if f.annotations:
                last_ann = f.annotations[-1]
                value += f" | {last_ann.actor}: {last_ann.content}"
            facts.append({"name": f.id, "value": value})
        sections.append({
            "activityTitle": f"{severity_val.upper()} ({len(group)})",
            "facts": facts,
        })

    total = len(findings)
    summary = f"Mallcop: {total} finding{'s' if total != 1 else ''}"

    return {
        "type": "message",
        "summary": summary,
        "sections": sections,
    }


def deliver_digest(
    findings: list[Finding], webhook_url: str
) -> DeliveryResult:
    validate_webhook_url(webhook_url)
    payload = format_digest(findings)
    return post_webhook(webhook_url, payload)
