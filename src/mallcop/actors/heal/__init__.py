"""Heal actor plugin — proposes parser.yaml patches for log format drift."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from mallcop.actors._base import ActorBase
from mallcop.schemas import Annotation, Finding


# ─── Patch data model ─────────────────────────────────────────────────


@dataclass
class ParserPatch:
    """A proposed parser.yaml patch for one drift scenario."""

    scenario: str  # new_field | renamed_field | format_change
    app_name: str
    before: dict[str, Any] | None  # existing template entry, or None if adding new
    after: dict[str, Any]  # proposed new/updated template entry
    reason: str
    confidence: float  # 0.0–1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "app_name": self.app_name,
            "before": self.before,
            "after": self.after,
            "reason": self.reason,
            "confidence": self.confidence,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# ─── Drift analysis ───────────────────────────────────────────────────


def _make_safe_group_name(name: str) -> str:
    """Convert a field name to a valid Python regex named group identifier."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", name)


def _infer_pattern_for_value(value: str) -> str:
    """Heuristically infer a regex fragment for a sample value."""
    # ISO timestamp
    if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", value):
        return r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
    # Simple timestamp HH:MM:SS
    if re.match(r"\d{2}:\d{2}:\d{2}", value):
        return r"\d{2}:\d{2}:\d{2}"
    # Numeric
    if re.match(r"^\d+$", value):
        return r"\d+"
    # Default: non-whitespace word
    return r"\S+"


def analyze_drift(finding: Finding) -> ParserPatch | None:
    """Analyze a log_format_drift finding and produce a patch proposal.

    Returns None if the finding is not a log_format_drift finding or
    there is insufficient metadata to propose a patch.
    """
    if finding.detector != "log-format-drift":
        return None

    meta = finding.metadata or {}
    app_name = meta.get("app_name", "unknown")
    unmatched_ratio = meta.get("unmatched_ratio", 0.0)
    unmatched_lines: list[str] = meta.get("unmatched_lines", [])
    current_patterns: list[str] = meta.get("current_patterns", [])

    if not unmatched_lines and not current_patterns:
        # Insufficient data — produce a low-confidence generic patch
        return _generic_patch(app_name, unmatched_ratio)

    # Detect scenario by comparing current patterns to unmatched lines
    return _detect_scenario(app_name, unmatched_lines, current_patterns, unmatched_ratio)


def _generic_patch(app_name: str, unmatched_ratio: float) -> ParserPatch:
    """Produce a low-confidence placeholder patch when no samples are available."""
    template_name = f"{app_name}_new_format"
    after = {
        "name": template_name,
        "pattern": r"^(?P<timestamp>\S+)\s+(?P<level>\S+)\s+(?P<message>.+)$",
        "classification": "operational",
        "event_mapping": {
            "event_type": "log_line",
            "actor": app_name,
            "action": "log",
            "target": app_name,
            "severity": "info",
        },
        "noise_filter": False,
    }
    pct = int(unmatched_ratio * 100)
    return ParserPatch(
        scenario="new_field",
        app_name=app_name,
        before=None,
        after=after,
        reason=(
            f"{app_name} parser is failing to match {pct}% of lines. "
            "No sample lines provided — this is a generic catch-all template. "
            "Run `mallcop discover-app` to regenerate with real samples."
        ),
        confidence=0.1,
    )


def _detect_scenario(
    app_name: str,
    unmatched_lines: list[str],
    current_patterns: list[str],
    unmatched_ratio: float,
) -> ParserPatch:
    """Detect drift scenario and propose a specific patch."""
    if not unmatched_lines:
        return _generic_patch(app_name, unmatched_ratio)

    sample = unmatched_lines[0]

    # Try to match against current patterns to find partial matches
    # (renamed field or format change scenario)
    for pattern_str in current_patterns:
        try:
            compiled = re.compile(pattern_str)
        except re.error:
            continue

        # Check if removing group names makes it match (renamed field)
        stripped = re.sub(r"\?P<[^>]+>", "", pattern_str)
        try:
            stripped_compiled = re.compile(stripped)
            if stripped_compiled.match(sample):
                return _renamed_field_patch(app_name, pattern_str, sample)
        except re.error:
            pass

        # Check how much of the pattern matches (format change)
        # Try prefix matching
        parts = pattern_str.split(r"\s+")
        matching_parts = 0
        for part in parts:
            if re.search(re.escape(part[:5]) if len(part) > 5 else re.escape(part), sample):
                matching_parts += 1
        if matching_parts > 0 and matching_parts < len(parts):
            return _format_change_patch(app_name, pattern_str, sample)

    # No match found against existing patterns — new field / new format
    return _new_field_patch(app_name, sample, unmatched_ratio)


def _new_field_patch(app_name: str, sample_line: str, unmatched_ratio: float) -> ParserPatch:
    """Propose a new template entry for lines that match nothing."""
    # Try to extract fields from common log formats
    fields = _parse_log_line(sample_line)
    groups = []
    pattern_parts = []

    for name, value in fields.items():
        safe_name = _make_safe_group_name(name)
        frag = _infer_pattern_for_value(value)
        groups.append(safe_name)
        pattern_parts.append(f"(?P<{safe_name}>{frag})")

    if pattern_parts:
        pattern = r"^" + r"\s+".join(pattern_parts) + r"$"
        event_mapping = _build_event_mapping(app_name, groups)
        confidence = min(0.7, 0.3 + 0.1 * len(fields))
    else:
        # Fallback: generic pattern
        pattern = r"^(?P<message>.+)$"
        event_mapping = {
            "event_type": "log_line",
            "actor": app_name,
            "action": "log",
            "target": app_name,
            "severity": "info",
        }
        confidence = 0.2

    template_name = f"{app_name}_auto_{len(sample_line) % 1000}"
    after = {
        "name": template_name,
        "pattern": pattern,
        "classification": "operational",
        "event_mapping": event_mapping,
        "noise_filter": False,
    }
    pct = int(unmatched_ratio * 100)
    return ParserPatch(
        scenario="new_field",
        app_name=app_name,
        before=None,
        after=after,
        reason=(
            f"New log format detected in {app_name}: {pct}% of lines unmatched. "
            f"Sample: {sample_line[:120]!r}. "
            "Proposed new template to capture this format."
        ),
        confidence=confidence,
    )


def _renamed_field_patch(
    app_name: str, old_pattern: str, sample_line: str
) -> ParserPatch:
    """Propose updating named groups in an existing pattern."""
    fields = _parse_log_line(sample_line)
    if not fields:
        # Fall back to updating with generic groups
        new_pattern = re.sub(
            r"\?P<([^>]+)>",
            lambda m: f"?P<{m.group(1)}_v2>",
            old_pattern,
        )
        confidence = 0.3
    else:
        # Replace group names with new detected field names
        field_names = list(fields.keys())
        idx = 0

        def replace_group(m: re.Match[str]) -> str:
            nonlocal idx
            if idx < len(field_names):
                name = _make_safe_group_name(field_names[idx])
                idx += 1
                return f"?P<{name}>"
            return m.group(0)

        new_pattern = re.sub(r"\?P<[^>]+>", replace_group, old_pattern)
        confidence = 0.6

    old_entry = {"pattern": old_pattern}
    new_entry = {"pattern": new_pattern}

    # Copy classification / event_mapping from old if we had a full template
    after = {
        "name": f"{app_name}_renamed",
        "pattern": new_pattern,
        "classification": "operational",
        "event_mapping": _build_event_mapping(app_name, list(fields.keys())),
        "noise_filter": False,
    }
    return ParserPatch(
        scenario="renamed_field",
        app_name=app_name,
        before=old_entry,
        after=after,
        reason=(
            f"Field names changed in {app_name} log format. "
            f"Old pattern groups no longer match. "
            f"Sample: {sample_line[:120]!r}."
        ),
        confidence=confidence,
    )


def _format_change_patch(
    app_name: str, old_pattern: str, sample_line: str
) -> ParserPatch:
    """Propose an updated pattern for structural format change."""
    fields = _parse_log_line(sample_line)
    groups = list(fields.keys()) if fields else ["message"]

    if fields:
        parts = []
        for name, value in fields.items():
            safe = _make_safe_group_name(name)
            frag = _infer_pattern_for_value(value)
            parts.append(f"(?P<{safe}>{frag})")
        new_pattern = r"^" + r"\s+".join(parts) + r"$"
        confidence = 0.55
    else:
        new_pattern = r"^(?P<message>.+)$"
        confidence = 0.25

    old_entry = {"pattern": old_pattern}
    after = {
        "name": f"{app_name}_updated",
        "pattern": new_pattern,
        "classification": "operational",
        "event_mapping": _build_event_mapping(app_name, groups),
        "noise_filter": False,
    }
    return ParserPatch(
        scenario="format_change",
        app_name=app_name,
        before=old_entry,
        after=after,
        reason=(
            f"Log format structure changed in {app_name}. "
            f"Existing pattern partially matches but new format differs. "
            f"Sample: {sample_line[:120]!r}."
        ),
        confidence=confidence,
    )


def _parse_log_line(line: str) -> dict[str, str]:
    """Extract field name/value pairs from a log line using heuristics.

    Tries JSON first, then key=value, then positional.
    Returns {} if nothing can be extracted.
    """
    # JSON log
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                return {k: str(v) for k, v in data.items() if isinstance(v, (str, int, float))}
        except (json.JSONDecodeError, ValueError):
            pass

    # key=value or key="value"
    kv_pattern = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')
    matches = kv_pattern.findall(line)
    if len(matches) >= 2:
        result: dict[str, str] = {}
        for key, quoted, unquoted in matches:
            result[key] = quoted if quoted else unquoted
        return result

    # Positional: split on whitespace, name by position
    tokens = line.split()
    if len(tokens) >= 2:
        names = ["timestamp", "level", "component", "message"]
        result2: dict[str, str] = {}
        for i, token in enumerate(tokens[:4]):
            field_name = names[i] if i < len(names) else f"field_{i}"
            result2[field_name] = token
        # Rest goes to message
        if len(tokens) > 4:
            result2["message"] = " ".join(tokens[4:])
        return result2

    return {}


def _build_event_mapping(app_name: str, groups: list[str]) -> dict[str, str]:
    """Build an event_mapping dict from captured group names."""
    mapping: dict[str, str] = {
        "actor": app_name,
        "action": "log",
        "target": app_name,
        "severity": "info",
    }

    # Map known group names to event fields
    for g in groups:
        g_lower = g.lower()
        if g_lower in ("level", "severity", "log_level"):
            mapping["severity"] = f"{{{g}}}"
        elif g_lower in ("actor", "user", "username", "identity"):
            mapping["actor"] = f"{{{g}}}"
        elif g_lower in ("action", "method", "operation", "verb"):
            mapping["action"] = f"{{{g}}}"
        elif g_lower in ("target", "resource", "path", "url"):
            mapping["target"] = f"{{{g}}}"
        elif g_lower in ("event_type", "event", "type"):
            mapping["event_type"] = f"{{{g}}}"

    if "event_type" not in mapping:
        mapping["event_type"] = "log_line"

    return mapping


# ─── HealActor ────────────────────────────────────────────────────────


class HealActor(ActorBase):
    """Actor that proposes parser.yaml patches for log_format_drift findings.

    This actor does NOT apply patches — it proposes them and stores the
    patch as an annotation on the finding. The `mallcop heal` CLI command
    applies proposed patches.
    """

    def handle(self, findings: list[Finding]) -> list[Finding]:
        """Process findings. Annotates log_format_drift findings with patch proposals."""
        updated: list[Finding] = []
        for finding in findings:
            updated.append(self._process(finding))
        return updated

    def _process(self, finding: Finding) -> Finding:
        if finding.detector != "log-format-drift":
            return finding

        patch = analyze_drift(finding)
        if patch is None:
            return finding

        annotation = Annotation(
            actor="heal",
            timestamp=datetime.now(timezone.utc),
            content=patch.to_json(),
            action="proposed_patch",
            reason=patch.reason,
        )

        return Finding(
            id=finding.id,
            timestamp=finding.timestamp,
            detector=finding.detector,
            event_ids=finding.event_ids,
            title=finding.title,
            severity=finding.severity,
            status=finding.status,
            annotations=list(finding.annotations) + [annotation],
            metadata={
                **finding.metadata,
                "heal_patch": patch.to_dict(),
                "heal_scenario": patch.scenario,
                "heal_confidence": patch.confidence,
            },
        )
