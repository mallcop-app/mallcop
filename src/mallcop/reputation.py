"""Entity reputation scoring: cross-connector entity scoring with decay.

Entities are identified by type+value (e.g., "user:admin@example.com").
Scores range 0-100 with 50 as neutral. Scores decay toward 50 with a
30-day half-life.

Storage: reputation.jsonl — one JSON line per tracked entity.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mallcop.schemas import Finding, Severity

# Score constants
NEUTRAL_SCORE = 50.0
SCORE_MIN = 0.0
SCORE_MAX = 100.0

# Score deltas per severity
FINDING_DELTA: dict[Severity, float] = {
    Severity.INFO: -5.0,
    Severity.WARN: -10.0,
    Severity.CRITICAL: -20.0,
}

# Baseline match reward
BASELINE_MATCH_DELTA = 2.0

# Decay half-life in days
DECAY_HALF_LIFE_DAYS = 30.0

# Minimum absolute decay to record as a history event
DECAY_RECORD_THRESHOLD = 0.01


@dataclass
class ScoreEvent:
    """Single audit entry recording a score change."""

    timestamp: datetime
    delta: float
    reason: str  # e.g., "finding:unusual-timing", "baseline:consistent", "decay"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "delta": self.delta,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScoreEvent:
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            delta=float(data["delta"]),
            reason=data["reason"],
        )


@dataclass
class EntityScore:
    """Current reputation state for a single entity."""

    entity_type: str  # user, ip, sa, api_key
    entity_value: str
    score: float  # 0-100, 50=neutral
    last_updated: datetime
    history: list[ScoreEvent] = field(default_factory=list)

    @property
    def entity_key(self) -> str:
        return f"{self.entity_type}:{self.entity_value}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "score": self.score,
            "last_updated": self.last_updated.isoformat(),
            "history": [e.to_dict() for e in self.history],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EntityScore:
        return cls(
            entity_type=data["entity_type"],
            entity_value=data["entity_value"],
            score=float(data["score"]),
            last_updated=datetime.fromisoformat(data["last_updated"]),
            history=[ScoreEvent.from_dict(e) for e in data.get("history", [])],
        )


def _clamp(value: float) -> float:
    return max(SCORE_MIN, min(SCORE_MAX, value))


class EntityReputation:
    """Cross-connector entity reputation scoring.

    Usage:
        rep = EntityReputation(path / "reputation.jsonl")
        score = rep.get_score("user", "admin@example.com")
        rep.record_finding("user", "admin@example.com", finding)
        rep.record_baseline_match("user", "admin@example.com")
        rep.save()
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._scores: dict[str, EntityScore] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        text = self._path.read_text().strip()
        if not text:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            es = EntityScore.from_dict(data)
            self._scores[es.entity_key] = es

    def _get_or_create(self, entity_type: str, entity_value: str) -> EntityScore:
        key = f"{entity_type}:{entity_value}"
        if key not in self._scores:
            self._scores[key] = EntityScore(
                entity_type=entity_type,
                entity_value=entity_value,
                score=NEUTRAL_SCORE,
                last_updated=datetime.now(timezone.utc),
                history=[],
            )
        return self._scores[key]

    def get_score(self, entity_type: str, entity_value: str) -> EntityScore:
        """Return current score for entity, applying decay since last update."""
        es = self._get_or_create(entity_type, entity_value)
        return self.apply_decay(es)

    def record_finding(
        self, entity_type: str, entity_value: str, finding: Finding
    ) -> None:
        """Decrease score based on finding severity."""
        es = self._get_or_create(entity_type, entity_value)
        # Apply any pending decay first
        es = self.apply_decay(es)

        delta = FINDING_DELTA.get(finding.severity, -10.0)
        new_score = _clamp(es.score + delta)
        event = ScoreEvent(
            timestamp=datetime.now(timezone.utc),
            delta=delta,
            reason=f"finding:{finding.detector}",
        )
        es.score = new_score
        es.last_updated = datetime.now(timezone.utc)
        es.history.append(event)
        self._scores[es.entity_key] = es

    def record_baseline_match(self, entity_type: str, entity_value: str) -> None:
        """Small increase for consistent baseline behavior."""
        es = self._get_or_create(entity_type, entity_value)
        es = self.apply_decay(es)

        new_score = _clamp(es.score + BASELINE_MATCH_DELTA)
        event = ScoreEvent(
            timestamp=datetime.now(timezone.utc),
            delta=BASELINE_MATCH_DELTA,
            reason="baseline:consistent",
        )
        es.score = new_score
        es.last_updated = datetime.now(timezone.utc)
        es.history.append(event)
        self._scores[es.entity_key] = es

    def apply_decay(self, score: EntityScore) -> EntityScore:
        """Apply 30-day half-life decay toward neutral (50).

        Returns a new EntityScore with decay applied. Does not mutate the
        input or update self._scores — callers that want to persist decay
        must reassign.
        """
        now = datetime.now(timezone.utc)
        elapsed_days = (now - score.last_updated).total_seconds() / 86400.0

        if elapsed_days <= 0:
            return score

        deviation = score.score - NEUTRAL_SCORE
        if deviation == 0.0:
            return score

        # Exponential decay: deviation * 0.5^(elapsed / half_life)
        decay_factor = math.pow(0.5, elapsed_days / DECAY_HALF_LIFE_DAYS)
        new_deviation = deviation * decay_factor
        new_score = _clamp(NEUTRAL_SCORE + new_deviation)
        delta = new_score - score.score

        history = list(score.history)
        if abs(delta) >= DECAY_RECORD_THRESHOLD:
            history.append(ScoreEvent(
                timestamp=now,
                delta=delta,
                reason="decay",
            ))

        return EntityScore(
            entity_type=score.entity_type,
            entity_value=score.entity_value,
            score=new_score,
            last_updated=now,
            history=history,
        )

    def save(self) -> None:
        """Write all entity scores to reputation.jsonl."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            for es in self._scores.values():
                f.write(json.dumps(es.to_dict()) + "\n")

    def enrich_finding(self, finding: Finding) -> Finding:
        """Add reputation context to finding metadata.

        Looks up the actor from finding.metadata["actor"] and
        finding.metadata["actor_type"]. If not present, returns the
        finding unchanged.

        Returns the same Finding object with metadata mutated in place
        (the Finding dataclass is mutable).
        """
        actor = finding.metadata.get("actor")
        actor_type = finding.metadata.get("actor_type")
        if not actor or not actor_type:
            return finding

        score = self.get_score(actor_type, actor)
        finding.metadata["reputation"] = {
            "entity_type": actor_type,
            "entity_value": actor,
            "score": score.score,
        }
        return finding
