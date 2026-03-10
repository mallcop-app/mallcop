"""Privilege escalation detector: flags events indicating elevated permissions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

_ELEVATION_EVENT_TYPES = {
    "role_assignment",
    "collaborator_added",
    "permission_change",
    "admin_action",
}

_ELEVATED_KEYWORDS = {"admin", "owner", "write", "contributor"}


def _is_elevated(event: Event) -> bool:
    """Check if an event indicates privilege elevation.

    admin_action event type always implies elevation.
    For other types, check metadata for elevated role/permission indicators.
    """
    if event.event_type == "admin_action":
        return True

    role_name = event.metadata.get("role_name", "")
    permission_level = event.metadata.get("permission_level", "")

    for value in (role_name, permission_level):
        if value and value.lower() in _ELEVATED_KEYWORDS:
            return True

    return False


def _role_key(event: Event) -> str:
    """Derive a role identifier from event metadata for deduplication."""
    role_name = event.metadata.get("role_name", "")
    permission_level = event.metadata.get("permission_level", "")
    return role_name or permission_level or event.event_type


def _is_known_role(actor: str, role_key: str, baseline: Baseline) -> bool:
    """Check if actor+role combo is already in baseline known_entities."""
    actor_roles = baseline.known_entities.get("actor_roles", {})
    known_roles = actor_roles.get(actor, [])
    return role_key in known_roles


class PrivEscalationDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        # Group elevation events by (actor, role_key)
        groups: dict[tuple[str, str], list[Event]] = {}
        for evt in events:
            if evt.event_type not in _ELEVATION_EVENT_TYPES:
                continue
            if not _is_elevated(evt):
                continue
            rk = _role_key(evt)
            if _is_known_role(evt.actor, rk, baseline):
                continue
            key = (evt.actor, rk)
            groups.setdefault(key, []).append(evt)

        findings: list[Finding] = []
        for (actor, role_key), group_events in groups.items():
            sources = sorted({e.source for e in group_events})
            source_str = ", ".join(sources)
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                detector="priv-escalation",
                event_ids=[e.id for e in group_events],
                title=f"Privilege escalation: {actor} granted {role_key} on {source_str}",
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={
                    "actor": actor,
                    "role": role_key,
                    "sources": sources,
                },
            ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return ["azure", "github", "m365"]

    def relevant_event_types(self) -> list[str] | None:
        return list(_ELEVATION_EVENT_TYPES)
