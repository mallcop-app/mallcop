"""Feedback capture: FeedbackRecord dataclass and helpers.

Stores human override/agree decisions against agent findings.
Used by the learning flywheel to build actor profiles and improve confidence.

Design note: FeedbackRecord.reason is raw on the dataclass — sanitization happens
at the store/CLI boundary, not inside the record. This follows the same pattern as
Event/Finding fields: external input is sanitized at store ingest.

extract_context() parses STRUCTURED signals from sanitized feedback reasons.
Only named patterns (locations, timezones, actor types) are extracted — never
raw free text. This is critical: actor_context must not become a free text bag
that an attacker-controlled reason can poison (Kerckhoffs).
"""

from __future__ import annotations

import json
import re
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


# ---------------------------------------------------------------------------
# Structured signal extraction — NO free text storage
# ---------------------------------------------------------------------------

# Known timezone strings (structured allowlist — not regex-extracted free text)
_TIMEZONE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bUS/Eastern\b", re.IGNORECASE), "US/Eastern"),
    (re.compile(r"\bUS/Central\b", re.IGNORECASE), "US/Central"),
    (re.compile(r"\bUS/Mountain\b", re.IGNORECASE), "US/Mountain"),
    (re.compile(r"\bUS/Pacific\b", re.IGNORECASE), "US/Pacific"),
    (re.compile(r"\bEurope/London\b", re.IGNORECASE), "Europe/London"),
    (re.compile(r"\bEurope/Paris\b", re.IGNORECASE), "Europe/Paris"),
    (re.compile(r"\bAsia/Tokyo\b", re.IGNORECASE), "Asia/Tokyo"),
    (re.compile(r"\bAsia/Shanghai\b", re.IGNORECASE), "Asia/Shanghai"),
    (re.compile(r"\bAustralia/Sydney\b", re.IGNORECASE), "Australia/Sydney"),
    (re.compile(r"\bAmerica/New_York\b", re.IGNORECASE), "America/New_York"),
    (re.compile(r"\bAmerica/Los_Angeles\b", re.IGNORECASE), "America/Los_Angeles"),
    (re.compile(r"\bAmerica/Chicago\b", re.IGNORECASE), "America/Chicago"),
    (re.compile(r"\b(?:Eastern|EST|EDT)\b"), "US/Eastern"),
    (re.compile(r"\b(?:Pacific|PST|PDT)\b"), "US/Pacific"),
    (re.compile(r"\b(?:Central|CST|CDT)\b"), "US/Central"),
    (re.compile(r"\b(?:Mountain|MST|MDT)\b"), "US/Mountain"),
    (re.compile(r"\bUTC\b"), "UTC"),
]

# Known location names (structured allowlist)
_LOCATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bLondon\b", re.IGNORECASE), "London"),
    (re.compile(r"\bNew York\b", re.IGNORECASE), "New York"),
    (re.compile(r"\bSan Francisco\b", re.IGNORECASE), "San Francisco"),
    (re.compile(r"\bSeattle\b", re.IGNORECASE), "Seattle"),
    (re.compile(r"\bChicago\b", re.IGNORECASE), "Chicago"),
    (re.compile(r"\bBoston\b", re.IGNORECASE), "Boston"),
    (re.compile(r"\bAustin\b", re.IGNORECASE), "Austin"),
    (re.compile(r"\bDenver\b", re.IGNORECASE), "Denver"),
    (re.compile(r"\bToronto\b", re.IGNORECASE), "Toronto"),
    (re.compile(r"\bParis\b", re.IGNORECASE), "Paris"),
    (re.compile(r"\bBerlin\b", re.IGNORECASE), "Berlin"),
    (re.compile(r"\bAmsterdam\b", re.IGNORECASE), "Amsterdam"),
    (re.compile(r"\bDublin\b", re.IGNORECASE), "Dublin"),
    (re.compile(r"\bTokyo\b", re.IGNORECASE), "Tokyo"),
    (re.compile(r"\bSingapore\b", re.IGNORECASE), "Singapore"),
    (re.compile(r"\bSydney\b", re.IGNORECASE), "Sydney"),
    (re.compile(r"\bMelbourne\b", re.IGNORECASE), "Melbourne"),
]

# Actor type patterns → structured type label
_TYPE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bCI\s+bot\b", re.IGNORECASE), "automation"),
    (re.compile(r"\bCI/CD\b", re.IGNORECASE), "automation"),
    (re.compile(r"\bautomation\b", re.IGNORECASE), "automation"),
    (re.compile(r"\bautomat(?:ed|ic)\b", re.IGNORECASE), "automation"),
    (re.compile(r"\bbot\b", re.IGNORECASE), "automation"),
    (re.compile(r"\bservice\s+account\b", re.IGNORECASE), "service"),
    (re.compile(r"\bsvc\s+account\b", re.IGNORECASE), "service"),
    (re.compile(r"\bservice\b", re.IGNORECASE), "service"),
    (re.compile(r"\bhuman\b", re.IGNORECASE), "human"),
    (re.compile(r"\bemployee\b", re.IGNORECASE), "human"),
    (re.compile(r"\buser\b", re.IGNORECASE), "human"),
]


def extract_context(record: "FeedbackRecord") -> "ActorProfile | None":
    """Extract structured actor context signals from a feedback record.

    Parses sanitized reason text using pattern allowlists. Returns a partial
    ActorProfile if any structured signals are found, or None if no signals match.

    NEVER stores raw free text — only matched structured values from allowlists.
    This ensures actor_context cannot be poisoned by attacker-controlled input.

    Args:
        record: A FeedbackRecord with (possibly None) sanitized reason text.

    Returns:
        ActorProfile with matched fields, or None if no patterns matched.
    """
    from mallcop.schemas import ActorProfile

    reason = record.reason
    if not reason:
        return None

    # Strip USER_DATA markers to get the text content for pattern matching
    text = reason.replace("[USER_DATA_BEGIN]", "").replace("[USER_DATA_END]", "")
    if not text.strip():
        return None

    matched_timezone: str | None = None
    matched_location: str | None = None
    matched_type: str = "human"  # default
    type_matched = False

    for pattern, value in _TIMEZONE_PATTERNS:
        if pattern.search(text):
            matched_timezone = value
            break

    for pattern, value in _LOCATION_PATTERNS:
        if pattern.search(text):
            matched_location = value
            break

    for pattern, value in _TYPE_PATTERNS:
        if pattern.search(text):
            matched_type = value
            type_matched = True
            break

    # Only return a profile if at least one signal was found
    if matched_timezone is None and matched_location is None and not type_matched:
        return None

    return ActorProfile(
        location=matched_location,
        timezone=matched_timezone,
        type=matched_type,
        last_confirmed=record.timestamp,
        source_feedback_ids=[record.finding_id],
    )
