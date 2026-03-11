"""Scenario dataclass and YAML loader for shakedown harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


@dataclass
class ConnectorToolDef:
    """Canned connector tool definition from scenario YAML."""

    name: str
    description: str
    parameter_schema: dict[str, Any] = field(default_factory=dict)
    returns: Any = None  # canned return value


@dataclass
class ExpectedOutcome:
    """Expected results for scenario evaluation."""

    chain_action: str  # "resolved" or "escalated"
    triage_action: str  # "resolved" or "escalated"
    reasoning_must_mention: list[str] = field(default_factory=list)
    reasoning_must_not_mention: list[str] = field(default_factory=list)
    investigate_must_use_tools: bool = False
    min_investigate_iterations: int = 1


@dataclass
class Scenario:
    """A single shakedown test scenario."""

    id: str
    failure_mode: str  # KA, AE, CS, etc.
    detector: str
    category: str
    difficulty: str  # benign-obvious, malicious-hard, etc.
    trap_description: str
    trap_resolved_means: str
    finding: Finding
    events: list[Event]
    baseline: Baseline
    expected: ExpectedOutcome
    connector_tools: list[ConnectorToolDef] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def _parse_event(data: dict[str, Any]) -> Event:
    """Parse event dict from YAML into Event dataclass."""
    return Event(
        id=data["id"],
        timestamp=datetime.fromisoformat(data["timestamp"]),
        ingested_at=datetime.fromisoformat(data["ingested_at"]),
        source=data["source"],
        event_type=data["event_type"],
        actor=data["actor"],
        action=data["action"],
        target=data["target"],
        severity=Severity(data["severity"]),
        metadata=data.get("metadata", {}),
        raw=data.get("raw", {}),
    )


def _parse_finding(data: dict[str, Any]) -> Finding:
    """Parse finding dict from YAML into Finding dataclass."""
    return Finding(
        id=data["id"],
        timestamp=datetime.fromisoformat(
            data.get("timestamp", "2026-01-01T00:00:00Z")
        ),
        detector=data["detector"],
        event_ids=data.get("event_ids", []),
        title=data["title"],
        severity=Severity(data["severity"]),
        status=FindingStatus(data.get("status", "open")),
        annotations=[],
        metadata=data.get("metadata", {}),
    )


def _parse_baseline(data: dict[str, Any]) -> Baseline:
    """Parse baseline dict from YAML into Baseline dataclass."""
    return Baseline(
        frequency_tables=data.get("frequency_tables", {}),
        known_entities=data.get("known_entities", {}),
        relationships=data.get("relationships", {}),
    )


def _parse_expected(data: dict[str, Any]) -> ExpectedOutcome:
    """Parse expected outcome dict from YAML."""
    return ExpectedOutcome(
        chain_action=data["chain_action"],
        triage_action=data["triage_action"],
        reasoning_must_mention=data.get("reasoning_must_mention", []),
        reasoning_must_not_mention=data.get("reasoning_must_not_mention", []),
        investigate_must_use_tools=data.get("investigate_must_use_tools", False),
        min_investigate_iterations=data.get("min_investigate_iterations", 1),
    )


def _parse_connector_tool(data: dict[str, Any]) -> ConnectorToolDef:
    """Parse connector tool definition from YAML."""
    return ConnectorToolDef(
        name=data["name"],
        description=data.get("description", ""),
        parameter_schema=data.get("parameter_schema", {}),
        returns=data.get("returns"),
    )


def load_scenario(path: Path) -> Scenario:
    """Load a single scenario from a YAML file."""
    data = yaml.safe_load(path.read_text())

    finding_data = data["finding"]
    # Copy detector from top-level if not in finding
    if "detector" not in finding_data:
        finding_data["detector"] = data["detector"]

    return Scenario(
        id=data["id"],
        failure_mode=data["failure_mode"],
        detector=data["detector"],
        category=data["category"],
        difficulty=data["difficulty"],
        trap_description=data.get("trap_description", ""),
        trap_resolved_means=data.get("trap_resolved_means", ""),
        finding=_parse_finding(finding_data),
        events=[_parse_event(e) for e in data.get("events", [])],
        baseline=_parse_baseline(data.get("baseline", {})),
        expected=_parse_expected(data["expected"]),
        connector_tools=[
            _parse_connector_tool(t) for t in data.get("connector_tools", [])
        ],
        tags=data.get("tags", []),
    )


def load_all_scenarios(base_dir: Path) -> list[Scenario]:
    """Load all scenario YAML files from a directory tree."""
    scenarios = []
    for yaml_file in sorted(base_dir.rglob("*.yaml")):
        if yaml_file.name.startswith("_"):
            continue
        scenarios.append(load_scenario(yaml_file))
    return scenarios


def load_scenarios_tagged(
    base_dir: Path,
    failure_mode: str | None = None,
    detector: str | None = None,
    category: str | None = None,
    difficulty: str | None = None,
) -> list[Scenario]:
    """Load scenarios filtered by tags/attributes."""
    all_scenarios = load_all_scenarios(base_dir)
    result = all_scenarios
    if failure_mode:
        result = [s for s in result if s.failure_mode == failure_mode]
    if detector:
        result = [s for s in result if s.detector == detector]
    if category:
        result = [s for s in result if s.category == category]
    if difficulty:
        result = [s for s in result if s.difficulty == difficulty]
    return result
