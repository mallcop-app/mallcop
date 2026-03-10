"""App integration: wire parser runtime and declarative detectors into pipelines."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mallcop.detectors.declarative import DeclarativeDetector, load_declarative_detectors
from mallcop.parsers.runtime import ParserRuntime, ParseResult, load_parser
from mallcop.schemas import Event, Finding, Severity


def find_apps_dir(root: Path) -> Path:
    """Return the apps/ directory under the deployment root."""
    return root / "apps"


def get_configured_app_names(config_connectors: dict[str, dict[str, Any]]) -> list[str]:
    """Extract app names from container-logs connector config."""
    cl_config = config_connectors.get("container-logs")
    if cl_config is None:
        return []
    apps = cl_config.get("apps", [])
    return [a.get("name", "") for a in apps if a.get("name")]


def apply_parsers(
    events: list[Event],
    root: Path,
    app_names: list[str],
) -> list[Event]:
    """Apply parser.yaml transforms to container-logs events.

    For each app that has apps/<name>/parser.yaml:
    1. Collect log_line events from that app
    2. Run them through ParserRuntime
    3. Replace the generic log_line events with structured ones
    4. Append noise summary if configured

    Events from apps without a parser.yaml pass through unchanged.
    Events from non-container-logs sources pass through unchanged.
    """
    apps_dir = find_apps_dir(root)
    if not apps_dir.exists():
        return events

    # Load parsers for configured apps
    parsers: dict[str, ParserRuntime] = {}
    for app_name in app_names:
        parser_path = apps_dir / app_name / "parser.yaml"
        if parser_path.exists():
            manifest = load_parser(parser_path)
            parsers[app_name] = ParserRuntime(
                manifest=manifest,
                source="container-logs",
                app_name=app_name,
            )

    if not parsers:
        return events

    # Separate events: container-logs log_line events for apps with parsers vs. rest
    passthrough: list[Event] = []
    app_lines: dict[str, list[str]] = {name: [] for name in parsers}

    for evt in events:
        app_name = evt.metadata.get("app", "") if evt.metadata else ""
        if (
            evt.source == "container-logs"
            and evt.event_type == "log_line"
            and app_name in parsers
        ):
            # Extract the raw line for parsing
            raw_line = ""
            if evt.raw and isinstance(evt.raw, dict):
                raw_line = evt.raw.get("line", "")
            if raw_line:
                app_lines[app_name].append(raw_line)
        else:
            passthrough.append(evt)

    # Run parsers and collect results
    parsed_events: list[Event] = []
    for app_name, parser in parsers.items():
        lines = app_lines.get(app_name, [])
        if not lines:
            continue
        result = parser.parse(lines)
        parsed_events.extend(result.events)
        if result.summary_event is not None:
            parsed_events.append(result.summary_event)
        # Emit parser_summary event for log-format-drift detector
        parsed_events.append(_make_parser_summary_event(app_name, result))

    return passthrough + parsed_events


def _make_parser_summary_event(app_name: str, result: ParseResult) -> Event:
    """Create a parser_summary event from a ParseResult for drift detection."""
    now = datetime.now(timezone.utc)
    total = result.unmatched_count
    for evt in result.events:
        total += 1
    for count in result.noise_counts.values():
        total += count

    h = hashlib.sha256(
        f"parser_summary:{app_name}:{now.isoformat()}".encode()
    ).hexdigest()[:12]

    return Event(
        id=f"evt_{h}",
        timestamp=now,
        ingested_at=now,
        source="container-logs",
        event_type="parser_summary",
        actor="mallcop",
        action="parse",
        target=app_name,
        severity=Severity.INFO,
        metadata={
            "app_name": app_name,
            "matched_count": total - result.unmatched_count,
            "unmatched_count": result.unmatched_count,
            "total_count": total,
            "unmatched_ratio": result.unmatched_ratio,
        },
        raw={},
    )


def load_app_detectors(
    root: Path,
    app_names: list[str],
) -> list[DeclarativeDetector]:
    """Load declarative detectors from apps/<name>/detectors.yaml for configured apps."""
    apps_dir = find_apps_dir(root)
    if not apps_dir.exists():
        return []

    detectors: list[DeclarativeDetector] = []
    for app_name in app_names:
        detectors_path = apps_dir / app_name / "detectors.yaml"
        if detectors_path.exists():
            detectors.extend(load_declarative_detectors(detectors_path))

    return detectors
