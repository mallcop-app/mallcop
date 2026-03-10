"""Unusual-timing detector: flags events at times not seen in baseline."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mallcop.baseline import hour_bucket
from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


class UnusualTimingDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        freq = baseline.frequency_tables

        # No baseline data means no time patterns to compare against.
        # Without frequency data, every event would appear "unusual" which is meaningless.
        if not freq:
            return []

        # Collect unusual events grouped by actor
        unusual_by_actor: dict[str, list[Event]] = {}
        for evt in events:
            key = (
                f"{evt.source}:{evt.event_type}:{evt.actor}"
                f":{evt.timestamp.weekday()}:{hour_bucket(evt.timestamp.hour)}"
            )
            if freq.get(key, 0) == 0:
                unusual_by_actor.setdefault(evt.actor, []).append(evt)

        findings: list[Finding] = []
        for actor, actor_events in unusual_by_actor.items():
            sources = sorted({e.source for e in actor_events})
            source_str = ", ".join(sources)
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                detector="unusual-timing",
                event_ids=[e.id for e in actor_events],
                title=f"Unusual timing: {actor} active at unexpected time on {source_str}",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={"actor": actor, "sources": sources},
            ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return None
