"""Parser runtime: load parser.yaml, apply templates to log lines, produce Events."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from mallcop.schemas import Event, Severity


_SEVERITY_MAP = {
    "info": Severity.INFO,
    "warn": Severity.WARN,
    "critical": Severity.CRITICAL,
}


@dataclass
class ParserTemplate:
    name: str
    pattern: str
    classification: str  # routine | operational | error | security
    event_mapping: dict[str, Any]
    noise_filter: bool

    def __post_init__(self) -> None:
        # Compile the regex early to catch errors at load time
        try:
            self._compiled: re.Pattern[str] = re.compile(self.pattern)
        except re.error as e:
            raise ValueError(
                f"Template '{self.name}' has invalid regex: {e}"
            ) from e

    @property
    def compiled(self) -> re.Pattern[str]:
        return self._compiled


@dataclass
class ParserManifest:
    app: str
    version: int
    generated_at: str
    generated_by: str
    templates: list[ParserTemplate]
    noise_summary: bool
    unmatched_threshold: float


@dataclass
class ParseResult:
    events: list[Event]
    noise_counts: dict[str, int]
    unmatched_count: int
    summary_event: Event | None
    format_drift: bool
    unmatched_ratio: float


def load_parser(path: Path | str) -> ParserManifest:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Parser manifest not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Parser manifest must be a YAML mapping: {path}")

    templates_raw = data.get("templates")
    if not templates_raw:
        raise ValueError(f"Parser manifest must have 'templates': {path}")

    templates: list[ParserTemplate] = []
    for t in templates_raw:
        templates.append(
            ParserTemplate(
                name=t["name"],
                pattern=t["pattern"],
                classification=t["classification"],
                event_mapping=t["event_mapping"],
                noise_filter=t.get("noise_filter", False),
            )
        )

    return ParserManifest(
        app=data["app"],
        version=data["version"],
        generated_at=data.get("generated_at", ""),
        generated_by=data.get("generated_by", ""),
        templates=templates,
        noise_summary=data.get("noise_summary", True),
        unmatched_threshold=data.get("unmatched_threshold", 0.3),
    )


def _make_event_id(app_name: str, line_index: int, line: str) -> str:
    h = hashlib.sha256(f"parser:{app_name}:{line_index}:{line}".encode()).hexdigest()[:12]
    return f"evt_{h}"


def _apply_field_mapping(template_value: str, groups: dict[str, str]) -> str:
    """Replace {field} placeholders with captured regex groups."""
    result = template_value
    for key, val in groups.items():
        result = result.replace(f"{{{key}}}", val)
    return result


def _parse_timestamp(ts_str: str) -> datetime | None:
    """Try to parse a timestamp string from a regex capture."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


class ParserRuntime:
    def __init__(
        self,
        manifest: ParserManifest,
        source: str,
        app_name: str,
    ) -> None:
        self._manifest = manifest
        self._source = source
        self._app_name = app_name

    def parse(self, lines: list[str]) -> ParseResult:
        events: list[Event] = []
        noise_counts: dict[str, int] = {}
        unmatched_count = 0
        total_lines = 0
        now = datetime.now(timezone.utc)

        for line_index, line in enumerate(lines):
            if not line.strip():
                continue

            total_lines += 1
            matched = False

            for template in self._manifest.templates:
                m = template.compiled.search(line)
                if m is None:
                    continue

                matched = True
                groups = m.groupdict()

                if template.noise_filter:
                    noise_counts[template.name] = noise_counts.get(template.name, 0) + 1
                else:
                    evt = self._build_event(
                        template, groups, line, line_index, now
                    )
                    events.append(evt)

                break  # first match wins

            if not matched:
                unmatched_count += 1

        # Compute unmatched ratio
        if total_lines > 0:
            unmatched_ratio = unmatched_count / total_lines
        else:
            unmatched_ratio = 0.0

        format_drift = (
            total_lines > 0
            and unmatched_ratio > self._manifest.unmatched_threshold
        )

        # Build noise summary event
        summary_event: Event | None = None
        if self._manifest.noise_summary and total_lines > 0:
            summary_event = Event(
                id=_make_event_id(self._app_name, -1, f"summary:{total_lines}"),
                timestamp=now,
                ingested_at=now,
                source=self._source,
                event_type="noise_summary",
                actor=self._app_name,
                action="noise_summary",
                target=self._app_name,
                severity=Severity.INFO,
                metadata={
                    "app": self._app_name,
                    "template_counts": dict(noise_counts),
                    "unmatched_count": unmatched_count,
                    "total_lines": total_lines,
                    "format_drift": format_drift,
                },
                raw={},
            )

        return ParseResult(
            events=events,
            noise_counts=noise_counts,
            unmatched_count=unmatched_count,
            summary_event=summary_event,
            format_drift=format_drift,
            unmatched_ratio=unmatched_ratio,
        )

    def _build_event(
        self,
        template: ParserTemplate,
        groups: dict[str, str],
        line: str,
        line_index: int,
        now: datetime,
    ) -> Event:
        mapping = template.event_mapping

        # Extract timestamp from regex group if available
        ts = now
        if "timestamp" in groups:
            parsed = _parse_timestamp(groups["timestamp"])
            if parsed is not None:
                ts = parsed

        # Apply field mappings
        event_type = _apply_field_mapping(mapping.get("event_type", "unknown"), groups)
        actor = _apply_field_mapping(mapping.get("actor", ""), groups)
        action = _apply_field_mapping(mapping.get("action", ""), groups)
        target = _apply_field_mapping(mapping.get("target", ""), groups)
        severity_str = _apply_field_mapping(mapping.get("severity", "info"), groups)
        severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)

        # Default empty actor to app name
        if not actor:
            actor = self._app_name

        # Build metadata from mapping + extras
        metadata: dict[str, Any] = {
            "app": self._app_name,
            "template": template.name,
        }
        mapping_metadata = mapping.get("metadata", {})
        if isinstance(mapping_metadata, dict):
            for key, val_template in mapping_metadata.items():
                metadata[key] = _apply_field_mapping(str(val_template), groups)

        return Event(
            id=_make_event_id(self._app_name, line_index, line),
            timestamp=ts,
            ingested_at=now,
            source=self._source,
            event_type=event_type,
            actor=actor,
            action=action,
            target=target,
            severity=severity,
            metadata=metadata,
            raw={"line": line},
        )
