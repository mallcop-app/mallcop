"""New-actor detector: flags actors not seen in the baseline period."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


class NewActorDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        known_actors: set[str] = set(baseline.known_entities.get("actors", []))

        # Group events by unknown actor
        unknown_actor_events: dict[str, list[Event]] = {}
        for evt in events:
            if evt.actor not in known_actors:
                unknown_actor_events.setdefault(evt.actor, []).append(evt)

        findings: list[Finding] = []
        for actor, actor_events in unknown_actor_events.items():
            # Use the source from the first event for the title
            sources = {e.source for e in actor_events}
            source_str = ", ".join(sorted(sources))
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                detector="new-actor",
                event_ids=[e.id for e in actor_events],
                title=f"New actor: {actor} on {source_str}",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={"actor": actor, "sources": sorted(sources)},
            ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return None
