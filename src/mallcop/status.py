"""Status command logic: event/finding counts, connector health, cost trends."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mallcop.budget import CostEntry
from mallcop.store import JsonlStore


def _load_cost_entries(root: Path) -> list[CostEntry]:
    costs_file = root / ".mallcop" / "costs.jsonl"
    if not costs_file.exists():
        return []
    entries: list[CostEntry] = []
    text = costs_file.read_text().strip()
    if not text:
        return []
    for line in text.split("\n"):
        if line.strip():
            entries.append(CostEntry.from_dict(json.loads(line)))
    return entries


def run_status(root: Path, costs: bool = False) -> dict[str, Any]:
    """Generate status summary.

    Args:
        root: Deployment repo directory.
        costs: If True, include cost trend data from costs.jsonl.

    Returns:
        Summary dict.
    """
    store = JsonlStore(root)

    # Event counts by source
    all_events = store.query_events()
    events_by_source: dict[str, int] = {}
    for evt in all_events:
        events_by_source[evt.source] = events_by_source.get(evt.source, 0) + 1

    # Finding counts by status and severity
    all_findings = store.query_findings()
    findings_by_status: dict[str, int] = {}
    findings_by_severity: dict[str, int] = {}
    for f in all_findings:
        status_key = f.status.value
        findings_by_status[status_key] = findings_by_status.get(status_key, 0) + 1
        sev_key = f.severity.value
        findings_by_severity[sev_key] = findings_by_severity.get(sev_key, 0) + 1

    result: dict[str, Any] = {
        "status": "ok",
        "total_events": len(all_events),
        "total_findings": len(all_findings),
        "events_by_source": events_by_source,
        "findings_by_status": findings_by_status,
        "findings_by_severity": findings_by_severity,
    }

    if costs:
        entries = _load_cost_entries(root)
        total_runs = len(entries)

        if total_runs > 0:
            total_donuts = sum(e.donuts_used for e in entries)
            avg_donuts = total_donuts / total_runs
            total_cost = sum(e.estimated_cost_usd for e in entries)
            circuit_breaker_count = sum(
                1 for e in entries if not e.actors_invoked
            )
            avg_events = sum(e.events for e in entries) / total_runs
            avg_findings = sum(e.findings for e in entries) / total_runs
            budget_exhausted_count = sum(
                1 for e in entries
                if e.actors_invoked and e.budget_remaining_pct <= 0
            )

            result["costs"] = {
                "total_runs": total_runs,
                "avg_events_per_run": round(avg_events, 1),
                "avg_findings_per_run": round(avg_findings, 1),
                "avg_donuts_per_run": round(avg_donuts, 1),
                "total_donuts": total_donuts,
                "estimated_total_usd": round(total_cost, 6),
                "circuit_breaker_triggered": circuit_breaker_count,
                "budget_exhausted": budget_exhausted_count,
            }
        else:
            result["costs"] = {
                "total_runs": 0,
                "avg_events_per_run": 0,
                "avg_findings_per_run": 0,
                "avg_donuts_per_run": 0,
                "total_donuts": 0,
                "estimated_total_usd": 0,
                "circuit_breaker_triggered": 0,
                "budget_exhausted": 0,
            }

    return result
