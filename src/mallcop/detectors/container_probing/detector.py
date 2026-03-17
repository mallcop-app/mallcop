"""Container-probing detector: flags unusual request patterns to container services."""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

# HTTP methods considered normal for container services.
_NORMAL_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

# Path traversal patterns.
_PATH_TRAVERSAL_RE = re.compile(r"\.\./|%2e%2e", re.IGNORECASE)

# Known attack patterns in URL paths.
_ATTACK_PATTERNS_RE = re.compile(
    r"(?i)"
    r"(?:union\s+select)"
    r"|(?:;\s*drop\s+table)"
    r"|(?:<!ENTITY)"
    r"|(?:<!\[CDATA\[)"
    r"|(?:/etc/passwd)"
    r"|(?:/proc/self)"
    r"|(?:\.env\b)"
    r"|(?:wp-admin|wp-login)"
    r"|(?:/actuator/)"
    r"|(?:\.git/)"
    r"|(?:TRACE\s+/)"
)


class ContainerProbingDetector(DetectorBase):
    def __init__(self, rate_ratio: float = 3.0, min_baseline_count: int = 5) -> None:
        self._rate_ratio = rate_ratio
        self._min_baseline_count = min_baseline_count

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        findings: list[Finding] = []

        for evt in events:
            method = evt.metadata.get("method", "")
            path = evt.metadata.get("path", "")

            # 1. Unusual HTTP method
            if method and method.upper() not in _NORMAL_METHODS:
                findings.append(self._make_finding(
                    event=evt,
                    title=f"Unusual HTTP method: {method.upper()} to {evt.target}",
                    metadata={"reason": "unusual_method", "method": method.upper()},
                ))

            # 2. Path traversal
            if path and _PATH_TRAVERSAL_RE.search(path):
                findings.append(self._make_finding(
                    event=evt,
                    title=f"Path traversal attempt: {path} on {evt.target}",
                    metadata={"reason": "path_traversal", "path": path},
                ))

            # 3. Known attack patterns
            if path and _ATTACK_PATTERNS_RE.search(path):
                findings.append(self._make_finding(
                    event=evt,
                    title=f"Attack pattern in path: {path} on {evt.target}",
                    metadata={"reason": "attack_pattern", "path": path},
                ))

        # 4. Rate anomaly: events from same actor to same target
        actor_target_counts: dict[tuple[str, str], list[str]] = defaultdict(list)
        for evt in events:
            actor_target_counts[(evt.actor, evt.target)].append(evt.id)

        for (actor, target), event_ids in actor_target_counts.items():
            bl_key = f"container_logs:http_request:{actor}"
            bl_count = baseline.frequency_tables.get(bl_key, 0)
            if bl_count < self._min_baseline_count:
                continue
            if len(event_ids) > self._rate_ratio * bl_count:
                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    detector="container-probing",
                    event_ids=event_ids,
                    title=(
                        f"Request rate anomaly: {actor} to {target} "
                        f"({len(event_ids)} vs baseline {bl_count})"
                    ),
                    severity=Severity.WARN,
                    status=FindingStatus.OPEN,
                    annotations=[],
                    metadata={
                        "reason": "rate_anomaly",
                        "actor": actor,
                        "target": target,
                        "current_count": len(event_ids),
                        "baseline_count": bl_count,
                    },
                ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return ["container_logs"]

    def relevant_event_types(self) -> list[str] | None:
        return ["http_request", "container_access", "container_log"]

    @staticmethod
    def _make_finding(event: Event, title: str, metadata: dict) -> Finding:
        return Finding(
            id=f"fnd_{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc),
            detector="container-probing",
            event_ids=[event.id],
            title=title,
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata=metadata,
        )
