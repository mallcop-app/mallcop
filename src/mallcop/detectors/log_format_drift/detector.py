"""Log-format-drift detector: flags when parser unmatched ratio exceeds threshold."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

_DEFAULT_THRESHOLD = 0.3


class LogFormatDriftDetector(DetectorBase):
    def __init__(self, threshold: float = _DEFAULT_THRESHOLD) -> None:
        self._threshold = threshold

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        findings: list[Finding] = []

        for evt in events:
            if evt.event_type != "parser_summary":
                continue

            unmatched_ratio = evt.metadata.get("unmatched_ratio", 0.0)
            app_name = evt.metadata.get("app_name", "unknown")

            if unmatched_ratio > self._threshold:
                pct = int(unmatched_ratio * 100)
                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    detector="log-format-drift",
                    event_ids=[evt.id],
                    title=(
                        f"{app_name} parser is stale, {pct}% of lines unrecognized. "
                        f"Run `mallcop discover-app {app_name} --refresh` to regenerate."
                    ),
                    severity=Severity.INFO,
                    status=FindingStatus.OPEN,
                    annotations=[],
                    metadata={
                        "app_name": app_name,
                        "unmatched_ratio": unmatched_ratio,
                    },
                ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return ["container-logs"]

    def relevant_event_types(self) -> list[str] | None:
        return ["parser_summary"]
