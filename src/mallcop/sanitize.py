"""Platform-level sanitization — defense layers 1 and 2 from threat model.

Sanitizes all external data at two boundaries:
1. Store ingest: Events and Findings sanitized before persistence
2. Runtime egress: Tool results sanitized before reaching LLM

All attacker-controlled strings get [USER_DATA_BEGIN/END] markers and
control character stripping. This module is the single source of truth
for sanitization — connectors and detectors do NOT sanitize themselves.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any

from mallcop.schemas import Event, Finding


def sanitize_field(value: str | None, max_length: int = 1024) -> str:
    """Sanitize a field value from external data.

    - Strips control characters (preserves \\n, \\r, \\t)
    - Caps length at max_length
    - Wraps with [USER_DATA_BEGIN]/[USER_DATA_END] markers
    """
    if value is None:
        value = ""

    # Strip control characters except \n (0x0a), \r (0x0d), \t (0x09)
    cleaned = []
    for ch in value:
        cat = unicodedata.category(ch)
        if cat.startswith("C"):
            # Control/format/surrogate/private-use/unassigned
            if ch in ("\n", "\r", "\t"):
                cleaned.append(ch)
            # else: strip it
        else:
            cleaned.append(ch)
    result = "".join(cleaned)

    # Strip marker strings from input to prevent breakout attacks
    result = result.replace("[USER_DATA_BEGIN]", "").replace("[USER_DATA_END]", "")

    # Length cap
    if len(result) > max_length:
        result = result[:max_length]

    return f"[USER_DATA_BEGIN]{result}[USER_DATA_END]"


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Sanitize string values in a metadata dict (recursive)."""
    sanitized: dict[str, Any] = {}
    for k, v in metadata.items():
        sanitized[k] = _sanitize_value(v)
    return sanitized


def _sanitize_value(v: Any) -> Any:
    """Recursively sanitize a value: strings get markers, dicts/lists recurse."""
    if isinstance(v, str):
        return sanitize_field(v)
    if isinstance(v, dict):
        return {k: _sanitize_value(val) for k, val in v.items()}
    if isinstance(v, list):
        return [_sanitize_value(item) for item in v]
    return v


def sanitize_event(event: Event) -> Event:
    """Return a new Event with all external string fields sanitized."""
    return Event(
        id=event.id,
        timestamp=event.timestamp,
        ingested_at=event.ingested_at,
        source=event.source,
        event_type=event.event_type,
        actor=sanitize_field(event.actor),
        action=sanitize_field(event.action),
        target=sanitize_field(event.target),
        severity=event.severity,
        metadata=_sanitize_metadata(event.metadata),
        raw=sanitize_tool_result(event.raw),
    )


def _sanitize_annotation(annotation: Any) -> Any:
    """Sanitize an Annotation's attacker-controlled string fields."""
    from mallcop.schemas import Annotation

    if not isinstance(annotation, Annotation):
        return annotation
    return Annotation(
        actor=annotation.actor,
        timestamp=annotation.timestamp,
        content=sanitize_field(annotation.content) if annotation.content else annotation.content,
        action=annotation.action,
        reason=sanitize_field(annotation.reason) if annotation.reason else annotation.reason,
    )


def sanitize_finding(finding: Finding) -> Finding:
    """Return a new Finding with external string fields sanitized."""
    return Finding(
        id=finding.id,
        timestamp=finding.timestamp,
        detector=finding.detector,
        event_ids=finding.event_ids,
        title=sanitize_field(finding.title),
        severity=finding.severity,
        status=finding.status,
        annotations=[_sanitize_annotation(a) for a in finding.annotations],
        metadata=_sanitize_metadata(finding.metadata),
    )


def sanitize_tool_result(result: Any) -> Any:
    """Sanitize a tool result before it reaches the LLM.

    - str: wrap with markers
    - dict: sanitize string values recursively
    - list: sanitize each element
    - other: return as-is
    """
    if isinstance(result, str):
        return sanitize_field(result)
    if isinstance(result, dict):
        return {k: sanitize_tool_result(v) for k, v in result.items()}
    if isinstance(result, list):
        return [sanitize_tool_result(item) for item in result]
    return result
