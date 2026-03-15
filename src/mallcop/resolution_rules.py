"""Declarative auto-resolution from human feedback.

Feedback flywheel:
1. Human confirms finding as benign ("this is fine") → FeedbackRecord(AGREE)
2. Pattern counter aggregates confirmed-benign patterns
3. After threshold confirmations, generates a YAML resolution rule
4. Rule evaluates BEFORE LLM routing — deterministic, zero donuts
5. Matched findings auto-resolve with audit trail

Pattern key: detector:actor:event_type:target_prefix
Example: "new-external-access:admin-user:add_collaborator:acme-corp/*"
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import yaml

from mallcop.feedback import FeedbackRecord, HumanAction
from mallcop.schemas import Baseline, Finding, FindingStatus, Severity

_log = logging.getLogger(__name__)

# --- Configuration ---

CONFIRM_THRESHOLD = 5       # Minimum confirmed-benign count to generate a rule
CONFIDENCE_THRESHOLD = 0.7  # Minimum weighted confidence
DECAY_DAYS = 90             # Rules without confirming feedback for this long are removed

# Detectors that NEVER get auto-resolution rules (too dangerous)
_NEVER_AUTO_RESOLVE = frozenset({
    "priv-escalation",
    "boundary-violation",
    "log-format-drift",
})


# --- Pattern counting ---


@dataclass
class PatternCandidate:
    """A confirmed-benign pattern that may become a resolution rule."""

    detector: str
    actor: str
    event_type: str
    target_prefix: str
    count: int = 0
    weighted_confidence: float = 0.0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_finding_ids: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.detector}:{self.actor}:{self.event_type}:{self.target_prefix}"

    @property
    def confidence(self) -> float:
        return self.weighted_confidence / max(self.count, 1)

    @property
    def meets_threshold(self) -> bool:
        return self.count >= CONFIRM_THRESHOLD and self.confidence >= CONFIDENCE_THRESHOLD


def _extract_pattern_key(record: FeedbackRecord) -> tuple[str, str, str, str] | None:
    """Extract (detector, actor, event_type, target_prefix) from a feedback record."""
    detector = record.detector
    if not detector:
        return None
    if detector in _NEVER_AUTO_RESOLVE:
        return None

    # Extract actor and event_type from the events snapshot
    if not record.events:
        return None

    # Use the first event as representative
    evt = record.events[0]
    actor = evt.get("actor", "")
    event_type = evt.get("event_type", "")
    target = evt.get("target", "")

    if not actor or not event_type:
        return None

    # Wildcard target to the first path component
    # "acme-corp/atom-api" → "acme-corp/*"
    if "/" in target:
        target_prefix = target.split("/")[0] + "/*"
    else:
        target_prefix = target

    return (detector, actor, event_type, target_prefix)


def count_patterns(records: list[FeedbackRecord]) -> list[PatternCandidate]:
    """Aggregate confirmed-benign feedback records into pattern candidates.

    Only processes AGREE records (human confirmed agent was right).
    Returns candidates sorted by count descending.
    """
    patterns: dict[str, PatternCandidate] = {}

    for record in records:
        if record.human_action != HumanAction.AGREE:
            continue

        key_parts = _extract_pattern_key(record)
        if key_parts is None:
            continue

        detector, actor, event_type, target_prefix = key_parts
        key = f"{detector}:{actor}:{event_type}:{target_prefix}"

        if key not in patterns:
            patterns[key] = PatternCandidate(
                detector=detector,
                actor=actor,
                event_type=event_type,
                target_prefix=target_prefix,
                first_seen=record.timestamp,
            )

        p = patterns[key]
        p.count += 1
        p.weighted_confidence += record.weight
        p.last_seen = max(p.last_seen, record.timestamp)
        p.source_finding_ids.append(record.finding_id)

    return sorted(patterns.values(), key=lambda p: p.count, reverse=True)


# --- Rule generation ---


@dataclass
class ResolutionRule:
    """A declarative rule that auto-resolves matching findings."""

    id: str
    detector: str
    actor: str
    event_type: str
    target_prefix: str
    action: str = "resolve"
    reason_template: str = ""
    source_feedback_count: int = 0
    confidence: float = 0.0
    generated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_confirmed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "detector": self.detector,
            "conditions": {
                "actor": self.actor,
                "event_type": self.event_type,
                "target_prefix": self.target_prefix,
                "actor_known": True,
                "privilege_change": False,
            },
            "action": self.action,
            "reason_template": self.reason_template,
            "source_feedback_count": self.source_feedback_count,
            "confidence": round(self.confidence, 2),
            "generated": self.generated.isoformat(),
            "last_confirmed": self.last_confirmed.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResolutionRule":
        conditions = data.get("conditions", {})
        return cls(
            id=data["id"],
            detector=data["detector"],
            actor=conditions.get("actor", ""),
            event_type=conditions.get("event_type", ""),
            target_prefix=conditions.get("target_prefix", ""),
            action=data.get("action", "resolve"),
            reason_template=data.get("reason_template", ""),
            source_feedback_count=data.get("source_feedback_count", 0),
            confidence=float(data.get("confidence", 0)),
            generated=datetime.fromisoformat(data["generated"]),
            last_confirmed=datetime.fromisoformat(data["last_confirmed"]),
        )


def generate_rules(candidates: list[PatternCandidate]) -> list[ResolutionRule]:
    """Generate resolution rules from pattern candidates that meet threshold."""
    rules = []
    for c in candidates:
        if not c.meets_threshold:
            continue

        rule_id = f"auto-{c.detector}-{c.actor}-{c.event_type}"
        rule = ResolutionRule(
            id=rule_id,
            detector=c.detector,
            actor=c.actor,
            event_type=c.event_type,
            target_prefix=c.target_prefix,
            reason_template=(
                f"Auto-resolved: {c.actor} has done {c.event_type} "
                f"on {c.target_prefix} (confirmed benign {c.count} times)"
            ),
            source_feedback_count=c.count,
            confidence=c.confidence,
            generated=datetime.now(timezone.utc),
            last_confirmed=c.last_seen,
        )
        rules.append(rule)

    return rules


def save_rules(rules: list[ResolutionRule], path: Any) -> None:
    """Write resolution rules to YAML file."""
    from pathlib import Path
    p = Path(path)
    data = {"rules": [r.to_dict() for r in rules]}
    p.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    _log.info("Wrote %d resolution rules to %s", len(rules), p)


def load_rules(path: Any) -> list[ResolutionRule]:
    """Load resolution rules from YAML file."""
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text())
    if not data or "rules" not in data:
        return []
    return [ResolutionRule.from_dict(r) for r in data["rules"]]


# --- Rule evaluation ---


def _match_target(target: str, target_prefix: str) -> bool:
    """Match a target against a prefix pattern.

    "acme-corp/atom-api" matches "acme-corp/*"
    "acme-corp" matches "acme-corp"
    """
    if target_prefix.endswith("/*"):
        prefix = target_prefix[:-2]
        return target.startswith(prefix + "/") or target == prefix
    return target == target_prefix


def evaluate_rules(
    finding: Finding,
    rules: list[ResolutionRule],
    baseline: Baseline | None = None,
) -> ResolutionRule | None:
    """Check if a finding matches any resolution rule.

    Returns the matching rule, or None if no match.
    """
    detector = finding.detector
    metadata = finding.metadata or {}
    actor = metadata.get("actor", "")
    event_type = metadata.get("event_type", "")
    target = metadata.get("target", "") or metadata.get("resource", "")

    for rule in rules:
        if rule.detector != detector:
            continue
        if rule.actor != actor:
            continue
        if rule.event_type != event_type:
            continue
        if not _match_target(target, rule.target_prefix):
            continue

        # Safety check: never auto-resolve privilege changes
        if detector in _NEVER_AUTO_RESOLVE:
            continue

        # Verify actor is known in baseline (if available)
        if baseline and baseline.known_entities:
            known_actors = baseline.known_entities.get("actors", [])
            if actor not in known_actors:
                _log.info(
                    "Rule %s matched but actor %s not in baseline — skipping",
                    rule.id, actor,
                )
                continue

        _log.info("Rule %s matched finding %s", rule.id, finding.id)
        return rule

    return None


def auto_resolve_finding(finding: Finding, rule: ResolutionRule) -> Finding:
    """Apply a resolution rule to a finding.

    Sets status to RESOLVED and adds an annotation recording the rule.
    """
    from mallcop.schemas import Annotation

    annotation = Annotation(
        actor="auto-resolution",
        timestamp=datetime.now(timezone.utc),
        content=f"Rule {rule.id} (confidence={rule.confidence:.2f}, feedback_count={rule.source_feedback_count})",
        action="resolved",
        reason=rule.reason_template,
    )
    finding.annotations.append(annotation)
    finding.status = FindingStatus.RESOLVED
    return finding
