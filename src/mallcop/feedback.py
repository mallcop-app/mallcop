"""Feedback capture: FeedbackRecord dataclass and helpers.

Stores human override/agree decisions against agent findings.
Used by the learning flywheel to build actor profiles and improve confidence.

Design note: FeedbackRecord.reason is raw on the dataclass — sanitization happens
at the store/CLI boundary, not inside the record. This follows the same pattern as
Event/Finding fields: external input is sanitized at store ingest.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class HumanAction(str, Enum):
    AGREE = "agree"
    OVERRIDE = "override"


@dataclass
class FeedbackRecord:
    """A single human feedback decision on an agent finding.

    Fields:
        finding_id: The finding this feedback targets.
        human_action: agree (human agrees with agent) or override (human disagrees).
        reason: Human-entered free text explanation. Treated as untrusted input — callers
                must sanitize before persisting to store.
        original_action: The action the agent took (e.g. "escalate", "resolve").
        original_reason: The agent's stated reason (may be None).
        timestamp: When the human submitted this feedback.
        events: Serialized events at snapshot time (list of Event.to_dict()).
        baseline_snapshot: Relevant baseline entries at snapshot time.
        annotations: Agent's investigation trail (list of Annotation.to_dict()).
        detector: Detector that generated the finding (optional, for filtering).
    """

    finding_id: str
    human_action: HumanAction
    reason: str | None
    original_action: str
    original_reason: str | None
    timestamp: datetime
    events: list[dict[str, Any]]
    baseline_snapshot: dict[str, Any]
    annotations: list[dict[str, Any]]
    detector: str | None = field(default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "human_action": self.human_action.value,
            "reason": self.reason,
            "original_action": self.original_action,
            "original_reason": self.original_reason,
            "timestamp": self.timestamp.isoformat(),
            "events": self.events,
            "baseline_snapshot": self.baseline_snapshot,
            "annotations": self.annotations,
            "detector": self.detector,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeedbackRecord:
        return cls(
            finding_id=data["finding_id"],
            human_action=HumanAction(data["human_action"]),
            reason=data.get("reason"),
            original_action=data["original_action"],
            original_reason=data.get("original_reason"),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            events=data.get("events", []),
            baseline_snapshot=data.get("baseline_snapshot", {}),
            annotations=data.get("annotations", []),
            detector=data.get("detector"),
        )

    @classmethod
    def from_json(cls, line: str) -> FeedbackRecord:
        return cls.from_dict(json.loads(line))
