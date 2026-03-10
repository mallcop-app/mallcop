"""Auth-failure-burst detector: fires on N+ auth failures within a time window."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

_AUTH_FAILURE_EVENT_TYPES = frozenset({
    "sign_in_failure",
    "auth_failure",
    "login",
})

_SUCCESS_STATUSES = frozenset({
    "success",
    "succeeded",
    "ok",
})


def _is_login_failure(event: Event) -> bool:
    """Check whether a login event represents a failure.

    For event types that are explicitly failures (sign_in_failure, auth_failure),
    always return True. For generic "login" events, inspect metadata status
    fields to determine outcome. If status metadata is missing, conservatively
    treat as failure.
    """
    if event.event_type in ("sign_in_failure", "auth_failure"):
        return True

    # Generic "login" — check metadata for success indicators
    status = event.metadata.get("status", "")
    result_status = event.metadata.get("result_status", "")

    if status and status.lower() in _SUCCESS_STATUSES:
        return False
    if result_status and result_status.lower() in _SUCCESS_STATUSES:
        return False

    # No status metadata or non-success status → conservatively treat as failure
    return True


def _group_key(event: Event) -> str:
    """Determine grouping key: prefer IP address, fall back to actor."""
    ip = event.metadata.get("ip_address", "")
    if ip:
        return ip
    return event.actor


def _max_window_count(timestamps: list[datetime], window: timedelta) -> tuple[int, list[int]]:
    """Sliding window: find the maximum count of timestamps within `window`.

    Returns (max_count, indices_of_events_in_the_best_window).
    Timestamps must be sorted.
    """
    if not timestamps:
        return 0, []

    best_count = 0
    best_start = 0
    left = 0

    for right in range(len(timestamps)):
        # Shrink window from left until all events fit within window
        while timestamps[right] - timestamps[left] > window:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_start = left

    # Reconstruct indices for the best window
    best_indices = list(range(best_start, best_start + best_count))
    return best_count, best_indices


class AuthFailureBurstDetector(DetectorBase):
    def __init__(
        self,
        window_minutes: int = 30,
        threshold: int = 10,
        critical_threshold: int = 50,
    ) -> None:
        self._window = timedelta(minutes=window_minutes)
        self._threshold = threshold
        self._critical_threshold = critical_threshold

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        # Filter to auth failure event types, excluding successful logins
        auth_events = [
            e for e in events
            if e.event_type in _AUTH_FAILURE_EVENT_TYPES and _is_login_failure(e)
        ]

        # Group by key (IP or actor)
        groups: dict[str, list[Event]] = defaultdict(list)
        for evt in auth_events:
            key = _group_key(evt)
            groups[key].append(evt)

        findings: list[Finding] = []
        for key, group_events in groups.items():
            # Sort by timestamp
            group_events.sort(key=lambda e: e.timestamp)
            timestamps = [e.timestamp for e in group_events]

            count, indices = _max_window_count(timestamps, self._window)

            if count >= self._threshold:
                severity = (
                    Severity.CRITICAL if count >= self._critical_threshold
                    else Severity.WARN
                )
                window_events = [group_events[i] for i in indices]
                sources = sorted({e.source for e in window_events})

                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    detector="auth-failure-burst",
                    event_ids=[e.id for e in window_events],
                    title=(
                        f"Auth failure burst: {count} failures from {key} "
                        f"within {int(self._window.total_seconds() // 60)} min"
                    ),
                    severity=severity,
                    status=FindingStatus.OPEN,
                    annotations=[],
                    metadata={
                        "group_key": key,
                        "count": count,
                        "sources": sources,
                    },
                ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return ["azure", "m365", "container-logs"]

    def relevant_event_types(self) -> list[str] | None:
        return ["sign_in_failure", "auth_failure", "login"]
