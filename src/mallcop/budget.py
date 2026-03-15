"""Budget controls: circuit breaker, donut tracking, severity ordering, cost logging."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mallcop.schemas import Finding, Severity, FindingStatus, SEVERITY_ORDER


@dataclass
class BudgetConfig:
    max_findings_for_actors: int = 25
    max_donuts_per_run: int = 50000
    max_donuts_per_finding: int = 5000

    # Backward-compat aliases: old field names still work programmatically.
    @property
    def max_tokens_per_run(self) -> int:
        return self.max_donuts_per_run

    @property
    def max_tokens_per_finding(self) -> int:
        return self.max_donuts_per_finding


class BudgetTracker:
    def __init__(self, config: BudgetConfig) -> None:
        self._config = config
        self._donuts_used: int = 0

    @property
    def donuts_used(self) -> int:
        return self._donuts_used

    # Backward-compat alias
    @property
    def tokens_used(self) -> int:
        return self._donuts_used

    def add_donuts(self, count: int) -> None:
        self._donuts_used += count

    # Backward-compat alias
    def add_tokens(self, count: int) -> None:
        self.add_donuts(count)

    def run_budget_exhausted(self) -> bool:
        return self._donuts_used > self._config.max_donuts_per_run

    def run_budget_remaining(self) -> int:
        return max(0, self._config.max_donuts_per_run - self._donuts_used)

    def budget_remaining_pct(self) -> float:
        if self._config.max_donuts_per_run == 0:
            return 0.0
        return (self.run_budget_remaining() / self._config.max_donuts_per_run) * 100.0

    def finding_budget_exhausted(self, finding_donuts: int) -> bool:
        return finding_donuts > self._config.max_donuts_per_finding


def check_circuit_breaker(
    findings: list[Finding], config: BudgetConfig
) -> Finding | None:
    if len(findings) <= config.max_findings_for_actors:
        return None

    # Build severity breakdown
    breakdown: dict[str, int] = {}
    for f in findings:
        key = f.severity.value
        breakdown[key] = breakdown.get(key, 0) + 1

    return Finding(
        id="meta_circuit_breaker",
        timestamp=datetime.now(timezone.utc),
        detector="mallcop-budget",
        event_ids=[],
        title="Volume circuit breaker triggered",
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={
            "finding_count": str(len(findings)),
            "threshold": str(config.max_findings_for_actors),
            "severity_breakdown": breakdown,
        },
    )


def order_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


@dataclass
class CostEntry:
    timestamp: datetime
    events: int
    findings: int
    actors_invoked: bool
    donuts_used: int
    estimated_cost_usd: float
    budget_remaining_pct: float

    # Backward-compat alias for old code reading costs.jsonl files
    @property
    def tokens_used(self) -> int:
        return self.donuts_used

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "events": self.events,
            "findings": self.findings,
            "actors_invoked": self.actors_invoked,
            "donuts_used": self.donuts_used,
            "estimated_cost_usd": self.estimated_cost_usd,
            "budget_remaining_pct": self.budget_remaining_pct,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CostEntry":
        # Accept both new "donuts_used" and old "tokens_used" for backward compat
        donuts_used = data.get("donuts_used", data.get("tokens_used", 0))
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            events=data["events"],
            findings=data["findings"],
            actors_invoked=data["actors_invoked"],
            donuts_used=donuts_used,
            estimated_cost_usd=data["estimated_cost_usd"],
            budget_remaining_pct=data["budget_remaining_pct"],
        )


def append_cost_log(path: Path, entry: CostEntry) -> None:
    with open(path, "a") as f:
        f.write(json.dumps(entry.to_dict()) + "\n")
