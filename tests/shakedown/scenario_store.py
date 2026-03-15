"""In-memory Store implementation backed by canned scenario data."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from mallcop.feedback import FeedbackRecord
from mallcop.schemas import (
    Annotation,
    Baseline,
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import Store


@dataclass
class Mutation:
    """Record of a store mutation for post-run inspection."""

    finding_id: str
    field: str
    value: Any
    timestamp: datetime


class ScenarioStore(Store):
    """Store implementation backed by in-memory scenario data.

    All data is provided at construction time. Mutations (update_finding)
    are tracked for post-run evaluation by the ShakedownEvaluator.
    """

    def __init__(
        self,
        events: list[Event],
        baseline: Baseline,
        findings: list[Finding],
    ) -> None:
        self._events = list(events)
        self._baseline = baseline
        self._findings = [deepcopy(f) for f in findings]
        self._mutations: list[Mutation] = []

    # ── Reads ──

    def query_events(
        self,
        source: str | None = None,
        since: datetime | None = None,
        actor: str | None = None,
        limit: int = 1000,
        event_ids: list[str] | None = None,
    ) -> list[Event]:
        result = self._events
        if event_ids is not None:
            id_set = set(event_ids)
            result = [e for e in result if e.id in id_set]
        if source:
            result = [e for e in result if e.source == source]
        if actor:
            result = [e for e in result if e.actor == actor]
        if since:
            result = [e for e in result if e.timestamp >= since]
        return result[:limit]

    def get_baseline(self) -> Baseline:
        return self._baseline

    def query_findings(
        self,
        status: str | None = None,
        severity: str | None = None,
        actor: str | None = None,
        detector: str | None = None,
        since: datetime | None = None,
    ) -> list[Finding]:
        result = self._findings
        if status:
            result = [f for f in result if f.status.value == status]
        if severity:
            result = [f for f in result if f.severity.value == severity]
        if actor:
            result = [f for f in result if (f.metadata or {}).get("actor") == actor]
        if detector:
            result = [f for f in result if f.detector == detector]
        if since:
            # Normalize timezone awareness for comparison
            for f in result:
                if f.timestamp.tzinfo is not None and since.tzinfo is None:
                    from datetime import timezone
                    since = since.replace(tzinfo=timezone.utc)
                    break
            result = [f for f in result if f.timestamp >= since]
        return result

    def update_finding(self, finding_id: str, **updates: Any) -> None:
        # Track mutation
        for key, value in updates.items():
            self._mutations.append(
                Mutation(
                    finding_id=finding_id,
                    field=key,
                    value=value,
                    timestamp=datetime.now(timezone.utc),
                )
            )

        # Apply to in-memory findings
        for f in self._findings:
            if f.id == finding_id:
                if "status" in updates:
                    status_val = updates["status"]
                    if isinstance(status_val, FindingStatus):
                        f.status = status_val
                    else:
                        f.status = FindingStatus(status_val)
                if "annotations" in updates:
                    f.annotations.extend(updates["annotations"])
                break

    def get_mutations(self) -> list[Mutation]:
        """Return all recorded mutations for post-run inspection."""
        return list(self._mutations)

    # ── No-ops (canned data is read-only) ──

    def append_events(self, events: list[Event]) -> None:
        pass

    def append_findings(self, findings: list[Finding]) -> None:
        pass

    def get_checkpoint(self, connector: str) -> Checkpoint | None:
        return None

    def set_checkpoint(self, checkpoint: Checkpoint) -> None:
        pass

    def update_baseline(
        self, events: list[Event], window_days: int | None = None
    ) -> None:
        pass

    def append_feedback(self, record: FeedbackRecord) -> None:
        pass

    def query_feedback(
        self,
        actor: str | None = None,
        detector: str | None = None,
    ) -> list[FeedbackRecord]:
        return []
