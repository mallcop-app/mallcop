"""Volume-anomaly detector: fires when event volume exceeds N× baseline frequency."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


class VolumeAnomalyDetector(DetectorBase):
    def __init__(
        self,
        ratio: float = 3.0,
        min_baseline_count: int = 5,
    ) -> None:
        self._ratio = ratio
        self._min_baseline_count = min_baseline_count

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        # 1. Count events in current batch grouped by (source, event_type)
        current_counts: dict[tuple[str, str], int] = defaultdict(int)
        current_event_ids: dict[tuple[str, str], list[str]] = defaultdict(list)
        for evt in events:
            key = (evt.source, evt.event_type)
            current_counts[key] += 1
            current_event_ids[key].append(evt.id)

        # 2. Sum baseline frequency_tables per (source, event_type) across actors
        baseline_counts: dict[tuple[str, str], int] = defaultdict(int)
        for freq_key, count in baseline.frequency_tables.items():
            # Keys are "source:event_type:actor" (3-part aggregate) or
            # "source:event_type:actor:day:hour" (5-part time-dimensioned).
            # Only use aggregate keys to avoid double-counting.
            parts = freq_key.split(":")
            if len(parts) == 3:
                source = parts[0]
                event_type = parts[1]
                baseline_counts[(source, event_type)] += count

        # 3. Compare and emit findings
        findings: list[Finding] = []
        for group_key, current_count in current_counts.items():
            source, event_type = group_key
            bl_count = baseline_counts.get(group_key, 0)

            # Skip zero-baseline groups (new, handled by other detectors)
            if bl_count == 0:
                continue

            # Skip if baseline count is too low to be meaningful
            if bl_count < self._min_baseline_count:
                continue

            # Fire if current count exceeds ratio × baseline count
            if current_count > self._ratio * bl_count:
                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    detector="volume-anomaly",
                    event_ids=current_event_ids[group_key],
                    title=(
                        f"Volume anomaly: {source}:{event_type} — "
                        f"{current_count} events vs baseline {bl_count} "
                        f"({current_count / bl_count:.1f}×)"
                    ),
                    severity=Severity.WARN,
                    status=FindingStatus.OPEN,
                    annotations=[],
                    metadata={
                        "source": source,
                        "event_type": event_type,
                        "current_count": current_count,
                        "baseline_count": bl_count,
                        "ratio": self._ratio,
                    },
                ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return None
