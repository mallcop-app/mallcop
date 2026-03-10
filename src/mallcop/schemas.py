"""Core data model: dataclasses, enums, and JSON serialization."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.WARN: 1,
    Severity.INFO: 2,
}


class FindingStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACKED = "acked"


def _dt_to_str(dt: datetime) -> str:
    return dt.isoformat()


def _str_to_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)


@dataclass
class Event:
    id: str
    timestamp: datetime
    ingested_at: datetime
    source: str
    event_type: str
    actor: str
    action: str
    target: str
    severity: Severity
    metadata: dict[str, Any]
    raw: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": _dt_to_str(self.timestamp),
            "ingested_at": _dt_to_str(self.ingested_at),
            "source": self.source,
            "event_type": self.event_type,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "severity": self.severity.value,
            "metadata": self.metadata,
            "raw": self.raw,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        return cls(
            id=data["id"],
            timestamp=_str_to_dt(data["timestamp"]),
            ingested_at=_str_to_dt(data["ingested_at"]),
            source=data["source"],
            event_type=data["event_type"],
            actor=data["actor"],
            action=data["action"],
            target=data["target"],
            severity=Severity(data["severity"]),
            metadata=data["metadata"],
            raw=data["raw"],
        )

    @classmethod
    def from_json(cls, line: str) -> Event:
        return cls.from_dict(json.loads(line))


@dataclass
class Annotation:
    actor: str
    timestamp: datetime
    content: str
    action: str
    reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "timestamp": _dt_to_str(self.timestamp),
            "content": self.content,
            "action": self.action,
            "reason": self.reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Annotation:
        return cls(
            actor=data["actor"],
            timestamp=_str_to_dt(data["timestamp"]),
            content=data["content"],
            action=data["action"],
            reason=data.get("reason"),
        )

    @classmethod
    def from_json(cls, line: str) -> Annotation:
        return cls.from_dict(json.loads(line))


@dataclass
class Finding:
    id: str
    timestamp: datetime
    detector: str
    event_ids: list[str]
    title: str
    severity: Severity
    status: FindingStatus
    annotations: list[Annotation]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": _dt_to_str(self.timestamp),
            "detector": self.detector,
            "event_ids": self.event_ids,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "annotations": [a.to_dict() for a in self.annotations],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=data["id"],
            timestamp=_str_to_dt(data["timestamp"]),
            detector=data["detector"],
            event_ids=data["event_ids"],
            title=data["title"],
            severity=Severity(data["severity"]),
            status=FindingStatus(data["status"]),
            annotations=[Annotation.from_dict(a) for a in data["annotations"]],
            metadata=data["metadata"],
        )

    @classmethod
    def from_json(cls, line: str) -> Finding:
        return cls.from_dict(json.loads(line))


@dataclass
class Checkpoint:
    connector: str
    value: str
    updated_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "value": self.value,
            "updated_at": _dt_to_str(self.updated_at),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Checkpoint:
        return cls(
            connector=data["connector"],
            value=data["value"],
            updated_at=_str_to_dt(data["updated_at"]),
        )

    @classmethod
    def from_json(cls, line: str) -> Checkpoint:
        return cls.from_dict(json.loads(line))


@dataclass
class DiscoveryResult:
    available: bool
    resources: list[str]
    suggested_config: dict[str, Any]
    missing_credentials: list[str]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "resources": self.resources,
            "suggested_config": self.suggested_config,
            "missing_credentials": self.missing_credentials,
            "notes": self.notes,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveryResult:
        return cls(
            available=data["available"],
            resources=data["resources"],
            suggested_config=data["suggested_config"],
            missing_credentials=data["missing_credentials"],
            notes=data["notes"],
        )

    @classmethod
    def from_json(cls, line: str) -> DiscoveryResult:
        return cls.from_dict(json.loads(line))


@dataclass
class PollResult:
    events: list[Event]
    checkpoint: Checkpoint

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [e.to_dict() for e in self.events],
            "checkpoint": self.checkpoint.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PollResult:
        return cls(
            events=[Event.from_dict(e) for e in data["events"]],
            checkpoint=Checkpoint.from_dict(data["checkpoint"]),
        )

    @classmethod
    def from_json(cls, line: str) -> PollResult:
        return cls.from_dict(json.loads(line))


@dataclass
class Baseline:
    frequency_tables: dict[str, Any]
    known_entities: dict[str, Any]
    relationships: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "frequency_tables": self.frequency_tables,
            "known_entities": self.known_entities,
            "relationships": self.relationships,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Baseline:
        return cls(
            frequency_tables=data["frequency_tables"],
            known_entities=data["known_entities"],
            relationships=data["relationships"],
        )

    @classmethod
    def from_json(cls, line: str) -> Baseline:
        return cls.from_dict(json.loads(line))
