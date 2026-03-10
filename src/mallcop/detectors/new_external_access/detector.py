"""New-external-access detector: flags when external entities are granted access."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

_RELEVANT_SOURCES = {"github", "m365"}
_RELEVANT_EVENT_TYPES = {
    "collaborator_added",
    "guest_invited",
    "oauth_consent",
    "sharepoint_sharing",
}

# Sanitization markers applied at store ingest boundary
_SANITIZE_BEGIN = "[USER_DATA_BEGIN]"
_SANITIZE_END = "[USER_DATA_END]"


def _unwrap_sanitized(value: str) -> str:
    """Strip sanitization markers if present, returning the raw value."""
    if value.startswith(_SANITIZE_BEGIN) and value.endswith(_SANITIZE_END):
        return value[len(_SANITIZE_BEGIN):-len(_SANITIZE_END)]
    return value


def _is_external_access(event: Event) -> bool:
    """Determine if an event represents external access being granted.

    Uses event metadata — not baseline — to classify internal vs external.
    Metadata values may be wrapped in sanitization markers from store ingest.
    """
    source = event.source
    event_type = event.event_type

    if source == "github":
        if event_type == "collaborator_added":
            # member_type: "outside" = external collaborator, "member" = org member
            # Missing member_type defaults to external (safe default)
            member_type = _unwrap_sanitized(
                event.metadata.get("member_type", "outside")
            )
            return member_type != "member"

    elif source == "m365":
        if event_type == "guest_invited":
            # Guest invitations are always external by definition
            return True

        if event_type == "oauth_consent":
            # OAuth consent grants access to external applications
            return True

        if event_type == "sharepoint_sharing":
            # Check sharing_type metadata
            sharing_type = _unwrap_sanitized(
                event.metadata.get("sharing_type", "external")
            )
            return sharing_type != "internal"

    return False


class NewExternalAccessDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        findings: list[Finding] = []

        for evt in events:
            # Filter to relevant sources and event types
            if evt.source not in _RELEVANT_SOURCES:
                continue
            if evt.event_type not in _RELEVANT_EVENT_TYPES:
                continue

            if _is_external_access(evt):
                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    detector="new-external-access",
                    event_ids=[evt.id],
                    title=f"External access granted: {evt.event_type} on {evt.source} by {evt.actor}",
                    severity=Severity.WARN,
                    status=FindingStatus.OPEN,
                    annotations=[],
                    metadata={
                        "source": evt.source,
                        "event_type": evt.event_type,
                        "actor": evt.actor,
                        "target": evt.target,
                    },
                ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return sorted(_RELEVANT_SOURCES)

    def relevant_event_types(self) -> list[str] | None:
        return sorted(_RELEVANT_EVENT_TYPES)
