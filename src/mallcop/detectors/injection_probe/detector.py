"""Injection-probe detector: flags events containing prompt injection patterns."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

# Compiled regex patterns for injection detection (case-insensitive).
# Each tuple: (pattern_name, compiled_regex)
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # "ignore previous" family
    ("ignore_previous", re.compile(
        r"ignore\s+(all\s+)?previous\s+(instructions|rules|prompts|context)",
        re.IGNORECASE,
    )),
    # "disregard" family
    ("disregard_instructions", re.compile(
        r"disregard\s+(your|all|any|the)?\s*(instructions|rules|prompts|directives)",
        re.IGNORECASE,
    )),
    # "forget" family
    ("forget_instructions", re.compile(
        r"forget\s+(your|all|any|the)?\s*(instructions|rules|prompts|previous)",
        re.IGNORECASE,
    )),
    # Role-play / identity override
    ("role_play", re.compile(
        r"you\s+are\s+(a|an|now|my)\s+",
        re.IGNORECASE,
    )),
    # System prompt override markers
    ("system_override", re.compile(
        r"\[(SYSTEM|ADMIN|ROOT)\]",
        re.IGNORECASE,
    )),
    # "new instructions" / "real instructions"
    ("new_instructions", re.compile(
        r"(new|real|actual|true)\s+instructions\s*:",
        re.IGNORECASE,
    )),
    # "do not follow" previous
    ("do_not_follow", re.compile(
        r"do\s+not\s+follow\s+(your|the|any)?\s*(previous|original|initial)",
        re.IGNORECASE,
    )),
    # Prompt termination attempts
    ("prompt_termination", re.compile(
        r"<\/?system>|<\/?prompt>|```\s*system",
        re.IGNORECASE,
    )),
]


def _scan_string(value: str) -> list[str]:
    """Return list of pattern names that match in the given string."""
    matched = []
    for name, pattern in _INJECTION_PATTERNS:
        if pattern.search(value):
            matched.append(name)
    return matched


class InjectionProbeDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        findings: list[Finding] = []

        for evt in events:
            all_matched: list[str] = []

            # Scan known string fields on the event
            for field_value in (evt.actor, evt.action, evt.target):
                if isinstance(field_value, str):
                    all_matched.extend(_scan_string(field_value))

            # Scan string values in metadata (top-level only)
            for key, val in evt.metadata.items():
                if isinstance(val, str):
                    all_matched.extend(_scan_string(val))

            if all_matched:
                # Deduplicate pattern names while preserving order
                seen: set[str] = set()
                unique_patterns: list[str] = []
                for p in all_matched:
                    if p not in seen:
                        seen.add(p)
                        unique_patterns.append(p)

                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    detector="injection-probe",
                    event_ids=[evt.id],
                    title=f"Injection probe detected in event {evt.id}",
                    severity=Severity.WARN,
                    status=FindingStatus.OPEN,
                    annotations=[],
                    metadata={
                        "matched_patterns": unique_patterns,
                        "event_source": evt.source,
                    },
                ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return None
