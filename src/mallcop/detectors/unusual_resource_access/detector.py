"""Unusual-resource-access detector: flags known actors touching new resources."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

# Minimum total events before an actor's relationships are considered "established"
_MIN_EVENTS_FOR_BASELINE = 5


class UnusualResourceAccessDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        known_actors: set[str] = set(baseline.known_entities.get("actors", []))
        rels = baseline.relationships

        # Build per-actor relationship sets and event counts using prefix matching.
        # Keys are "actor:target" — use known_actors to extract by prefix,
        # avoiding ambiguity when actor/target contain colons.
        actor_targets: dict[str, set[str]] = {}
        actor_event_counts: dict[str, int] = {}
        for actor in known_actors:
            prefix = f"{actor}:"
            for rel_key, rel_data in rels.items():
                if rel_key.startswith(prefix):
                    target = rel_key[len(prefix):]
                    actor_targets.setdefault(actor, set()).add(target)
                    actor_event_counts[actor] = actor_event_counts.get(actor, 0) + rel_data.get("count", 0)

        findings: list[Finding] = []
        # Track already-flagged actor+target pairs to avoid duplicates
        flagged: set[tuple[str, str]] = set()

        for evt in events:
            # Skip unknown actors (new-actor detector handles those)
            if evt.actor not in known_actors:
                continue

            # Skip actors with no relationship data (nothing to compare against)
            if evt.actor not in actor_targets:
                continue

            # Skip actors still in learning phase (< 5 total events)
            if actor_event_counts.get(evt.actor, 0) < _MIN_EVENTS_FOR_BASELINE:
                continue

            # Check if this target is new for this actor
            known_targets = actor_targets[evt.actor]
            if evt.target in known_targets:
                continue

            # Avoid duplicate findings for same actor+target
            pair = (evt.actor, evt.target)
            if pair in flagged:
                continue
            flagged.add(pair)

            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                detector="unusual-resource-access",
                event_ids=[evt.id],
                title=f"Unusual resource access: {evt.actor} → {evt.target}",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={
                    "actor": evt.actor,
                    "target": evt.target,
                    "known_targets_count": len(known_targets),
                },
            ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return None
