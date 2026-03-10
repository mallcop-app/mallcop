"""DeclarativeDetector: interprets YAML detection rules at runtime."""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


def _resolve_field(obj: Event, field: str) -> Any:
    """Resolve a dotted field path on an Event.

    Supports top-level attrs (actor, target, source, event_type, action)
    and metadata.* for nested metadata keys.
    """
    if field.startswith("metadata."):
        key = field[len("metadata."):]
        return obj.metadata.get(key)
    return getattr(obj, field, None)


def _known_entities_key(field: str) -> str:
    """Map a field name to the known_entities dict key.

    Convention: 'target' → 'targets', 'actor' → 'actors',
    'metadata.user_agent' → 'user_agents', 'metadata.ip_address' → 'ips'.
    """
    if field.startswith("metadata."):
        leaf = field[len("metadata."):]
    else:
        leaf = field

    _FIELD_TO_KEY = {
        "target": "targets",
        "actor": "actors",
        "user_agent": "user_agents",
        "ip_address": "ips",
        "ip": "ips",
        "source": "sources",
        "action": "actions",
    }
    return _FIELD_TO_KEY.get(leaf, leaf + "s")


class DeclarativeDetector(DetectorBase):
    """Interprets a single YAML detection rule at runtime."""

    def __init__(self, rule: dict[str, Any]) -> None:
        self._name: str = rule["name"]
        self._description: str = rule.get("description", "")
        self._event_type: str = rule["event_type"]
        self._condition: dict[str, Any] = rule["condition"]
        self._severity = Severity(rule["severity"])

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return [self._event_type]

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        # Filter to relevant event type
        filtered = [e for e in events if e.event_type == self._event_type]

        cond_type = self._condition["type"]
        if cond_type == "count_threshold":
            return self._detect_count_threshold(filtered)
        elif cond_type == "new_value":
            return self._detect_new_value(filtered, baseline)
        elif cond_type == "volume_ratio":
            return self._detect_volume_ratio(filtered, baseline)
        elif cond_type == "regex_match":
            return self._detect_regex_match(filtered)
        else:
            raise ValueError(f"Unknown condition type: {cond_type}")

    # -- count_threshold ---------------------------------------------------

    def _detect_count_threshold(self, events: list[Event]) -> list[Finding]:
        group_by: list[str] = self._condition.get("group_by", ["actor"])
        window_minutes: int = self._condition["window_minutes"]
        threshold: int = self._condition["threshold"]
        window = timedelta(minutes=window_minutes)

        # Group events by the group_by fields
        groups: dict[tuple, list[Event]] = defaultdict(list)
        for evt in events:
            key = tuple(_resolve_field(evt, f) for f in group_by)
            groups[key].append(evt)

        findings: list[Finding] = []
        for key, group_events in groups.items():
            # Sort by timestamp for sliding window
            group_events.sort(key=lambda e: e.timestamp)

            # Sliding window: find max count within window
            best_count = 0
            best_start = 0
            left = 0
            for right in range(len(group_events)):
                while group_events[right].timestamp - group_events[left].timestamp > window:
                    left += 1
                count = right - left + 1
                if count > best_count:
                    best_count = count
                    best_start = left

            if best_count >= threshold:
                window_events = group_events[best_start:best_start + best_count]
                key_str = ", ".join(str(v) for v in key)
                findings.append(self._make_finding(
                    event_ids=[e.id for e in window_events],
                    title=(
                        f"{self._name}: {best_count} events from {key_str} "
                        f"within {window_minutes} min"
                    ),
                ))

        return findings

    # -- new_value ---------------------------------------------------------

    def _detect_new_value(
        self, events: list[Event], baseline: Baseline,
    ) -> list[Finding]:
        field: str = self._condition["field"]
        entities_key = _known_entities_key(field)
        known: set[str] = set(baseline.known_entities.get(entities_key, []))

        # Group events by the field value (deduplicate findings per value)
        value_events: dict[str, list[Event]] = defaultdict(list)
        for evt in events:
            val = _resolve_field(evt, field)
            if val is not None:
                val_str = str(val)
                if val_str not in known:
                    value_events[val_str].append(evt)

        findings: list[Finding] = []
        for val, evts in value_events.items():
            findings.append(self._make_finding(
                event_ids=[e.id for e in evts],
                title=f"{self._name}: new {field} value: {val}",
            ))

        return findings

    # -- volume_ratio ------------------------------------------------------

    def _detect_volume_ratio(
        self, events: list[Event], baseline: Baseline,
    ) -> list[Finding]:
        ratio: float = self._condition["ratio"]
        filter_spec: dict[str, str] | None = self._condition.get("filter")

        # Apply filter if specified
        if filter_spec:
            matched = []
            for evt in events:
                match = True
                for fk, fv in filter_spec.items():
                    evt_val = _resolve_field(evt, fk) if "." in fk else evt.metadata.get(fk)
                    if evt_val is None or str(evt_val) != str(fv):
                        match = False
                        break
                if match:
                    matched.append(evt)
        else:
            matched = events

        current_count = len(matched)
        # frequency_tables keys are "source:event_type:actor" — sum all
        # entries whose event_type part (index 1) matches self._event_type.
        baseline_count = 0
        for key, count in baseline.frequency_tables.items():
            parts = key.split(":")
            if len(parts) >= 2 and parts[1] == self._event_type:
                baseline_count += count

        if baseline_count == 0:
            # Zero baseline: any events fire
            if current_count > 0:
                return [self._make_finding(
                    event_ids=[e.id for e in matched],
                    title=(
                        f"{self._name}: {current_count} events "
                        f"(no baseline)"
                    ),
                )]
            return []

        actual_ratio = current_count / baseline_count
        if actual_ratio >= ratio:
            return [self._make_finding(
                event_ids=[e.id for e in matched],
                title=(
                    f"{self._name}: {current_count} events "
                    f"({actual_ratio:.1f}x baseline of {baseline_count})"
                ),
            )]

        return []

    # -- regex_match -------------------------------------------------------

    def _detect_regex_match(self, events: list[Event]) -> list[Finding]:
        field: str = self._condition["field"]
        pattern = re.compile(self._condition["pattern"])

        findings: list[Finding] = []
        for evt in events:
            val = _resolve_field(evt, field)
            if val is not None and pattern.search(str(val)):
                findings.append(self._make_finding(
                    event_ids=[evt.id],
                    title=f"{self._name}: matched {field}={val}",
                ))

        return findings

    # -- helpers -----------------------------------------------------------

    def _make_finding(self, *, event_ids: list[str], title: str) -> Finding:
        return Finding(
            id=f"fnd_{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc),
            detector=self._name,
            event_ids=event_ids,
            title=title,
            severity=self._severity,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )


def load_declarative_detectors(yaml_path: Path | str) -> list[DeclarativeDetector]:
    """Load all declarative detectors from a detectors.yaml file."""
    yaml_path = Path(yaml_path)
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    rules = data.get("detectors", [])
    return [DeclarativeDetector(rule) for rule in rules]
