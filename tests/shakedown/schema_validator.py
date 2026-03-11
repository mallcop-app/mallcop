"""Schema validation for scenario YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REQUIRED_TOP_LEVEL = {"id", "failure_mode", "detector", "category", "difficulty", "finding", "events", "baseline", "expected"}
REQUIRED_FINDING = {"id", "title", "severity"}
REQUIRED_EXPECTED = {"chain_action", "triage_action"}
REQUIRED_EVENT = {"id", "timestamp", "ingested_at", "source", "event_type", "actor", "action", "target", "severity"}


class SchemaError:
    def __init__(self, path: str, message: str):
        self.path = path
        self.message = message

    def __repr__(self):
        return f"SchemaError({self.path}: {self.message})"


def validate_scenario_file(path: Path) -> list[SchemaError]:
    """Validate a single scenario YAML file against the schema."""
    errors: list[SchemaError] = []

    try:
        data = yaml.safe_load(path.read_text())
    except Exception as e:
        return [SchemaError(str(path), f"Invalid YAML: {e}")]

    if not isinstance(data, dict):
        return [SchemaError(str(path), "Root must be a mapping")]

    # Required top-level fields
    for field in REQUIRED_TOP_LEVEL:
        if field not in data:
            errors.append(SchemaError(str(path), f"Missing required field: {field}"))

    # Finding validation
    finding = data.get("finding", {})
    if isinstance(finding, dict):
        for field in REQUIRED_FINDING:
            if field not in finding:
                errors.append(SchemaError(str(path), f"Missing finding.{field}"))

    # Expected validation
    expected = data.get("expected", {})
    if isinstance(expected, dict):
        for field in REQUIRED_EXPECTED:
            if field not in expected:
                errors.append(SchemaError(str(path), f"Missing expected.{field}"))

    # Event validation
    events = data.get("events", [])
    event_ids = set()
    if isinstance(events, list):
        for i, evt in enumerate(events):
            if isinstance(evt, dict):
                for field in REQUIRED_EVENT:
                    if field not in evt:
                        errors.append(SchemaError(str(path), f"Missing events[{i}].{field}"))
                if "id" in evt:
                    event_ids.add(evt["id"])

    # Cross-reference: finding event_ids must reference existing events
    finding_event_ids = finding.get("event_ids", []) if isinstance(finding, dict) else []
    for eid in finding_event_ids:
        if eid not in event_ids:
            errors.append(SchemaError(str(path), f"Finding references non-existent event: {eid}"))

    return errors


def validate_all_scenarios(base_dir: Path) -> dict[str, list[SchemaError]]:
    """Validate all scenario YAML files in a directory tree."""
    results: dict[str, list[SchemaError]] = {}
    for yaml_file in sorted(base_dir.rglob("*.yaml")):
        if yaml_file.name.startswith("_"):
            continue
        errors = validate_scenario_file(yaml_file)
        if errors:
            results[str(yaml_file)] = errors
    return results
