"""Financial anomalies detector: flags new recipients and transfers above historical max."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

_FINANCIAL_EVENT_TYPES = {"transaction", "transfer", "payment", "withdrawal"}


class FinancialAnomalyDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        known_recipients: set[str] = set(baseline.known_entities.get("recipients", []))

        # Extract historical max amount from frequency_tables.
        # Keys follow "amount_max:<source>" pattern storing the max seen value.
        historical_maxes: dict[str, float] = {}
        for key, value in baseline.frequency_tables.items():
            if key.startswith("amount_max:"):
                source = key[len("amount_max:"):]
                historical_maxes[source] = float(value)

        # Global max across all sources (fallback when no per-source max)
        global_max = max(historical_maxes.values()) if historical_maxes else None

        findings: list[Finding] = []

        # Group events by new recipient for consolidated findings
        new_recipient_events: dict[str, list[Event]] = defaultdict(list)

        for evt in events:
            if evt.event_type not in _FINANCIAL_EVENT_TYPES:
                continue

            # Check for new recipient
            if evt.target and evt.target not in known_recipients:
                new_recipient_events[evt.target].append(evt)

            # Check for amount above historical max
            amount = evt.metadata.get("amount")
            if amount is not None:
                amount = float(amount)
                threshold = historical_maxes.get(evt.source, global_max)
                if threshold is not None and amount > threshold:
                    findings.append(Finding(
                        id=f"fnd_{uuid.uuid4().hex[:8]}",
                        timestamp=datetime.now(timezone.utc),
                        detector="financial-anomaly",
                        event_ids=[evt.id],
                        title=(
                            f"Amount above historical max: {amount} "
                            f"exceeds {threshold} on {evt.source}"
                        ),
                        severity=Severity.WARN,
                        status=FindingStatus.OPEN,
                        annotations=[],
                        metadata={
                            "type": "amount_above_max",
                            "amount": amount,
                            "threshold": threshold,
                            "source": evt.source,
                        },
                    ))

        # Emit one finding per new recipient
        for recipient, recipient_events in new_recipient_events.items():
            sources = {e.source for e in recipient_events}
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                detector="financial-anomaly",
                event_ids=[e.id for e in recipient_events],
                title=f"New recipient: {recipient} on {', '.join(sorted(sources))}",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={
                    "type": "new_recipient",
                    "recipient": recipient,
                    "sources": sorted(sources),
                },
            ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return list(_FINANCIAL_EVENT_TYPES)
