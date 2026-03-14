"""Malicious-skill detector: static analysis of SKILL.md files for known-bad patterns."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


# (rule_name, description, field, compiled_pattern_or_values, condition_type, severity)
_RULES: list[tuple[str, str, str, Any, str, Severity]] = [
    (
        "encoded-payload",
        "Base64 or hex-encoded commands piped to shell",
        "skill_content",
        re.compile(r"(base64\s+-d|echo.*\|.*sh|curl.*\|.*bash|wget.*&&.*chmod)", re.IGNORECASE),
        "regex_match",
        Severity.CRITICAL,
    ),
    (
        "quarantine-bypass",
        "macOS Gatekeeper bypass attempt via xattr removal",
        "skill_content",
        re.compile(r"xattr\s+-[rd]", re.IGNORECASE),
        "regex_match",
        Severity.CRITICAL,
    ),
    (
        "external-binary",
        "Downloads and executes external binary",
        "skill_content",
        re.compile(
            r"(curl|wget).*\.(exe|bin|dmg|pkg|sh).*&&.*(chmod|bash|sh|\.\/)",
            re.IGNORECASE,
        ),
        "regex_match",
        Severity.CRITICAL,
    ),
    (
        "password-protected-archive",
        "Password-protected archive extraction",
        "skill_content",
        re.compile(r"(unzip.*-P|7z.*-p|tar.*--passphrase)", re.IGNORECASE),
        "regex_match",
        Severity.CRITICAL,
    ),
    (
        "known-malicious-author",
        "Skill from a known malicious publisher",
        "skill_author",
        {"hightower6eu"},
        "string_match",
        Severity.CRITICAL,
    ),
]


class MaliciousSkillDetector(DetectorBase):
    """Detects known malicious skill patterns and IOCs in OpenClaw installations."""

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        relevant = [
            e for e in events
            if e.source == "openclaw" and e.event_type in ("skill_installed", "skill_modified")
        ]

        findings: list[Finding] = []
        for evt in relevant:
            for rule_name, description, field, matcher, condition, severity in _RULES:
                value = evt.metadata.get(field)
                if value is None:
                    continue

                matched = False
                if condition == "regex_match":
                    matched = bool(matcher.search(str(value)))
                elif condition == "string_match":
                    matched = str(value) in matcher

                if matched:
                    skill_name = evt.metadata.get("skill_name", evt.target)
                    findings.append(Finding(
                        id=f"fnd_{uuid.uuid4().hex[:8]}",
                        timestamp=datetime.now(timezone.utc),
                        detector="malicious-skill",
                        event_ids=[evt.id],
                        title=f"malicious-skill [{rule_name}]: {skill_name}",
                        severity=severity,
                        status=FindingStatus.OPEN,
                        annotations=[],
                        metadata={
                            "rule": rule_name,
                            "description": description,
                            "skill_name": skill_name,
                            "matched_field": field,
                        },
                    ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return ["openclaw"]

    def relevant_event_types(self) -> list[str] | None:
        return ["skill_installed", "skill_modified"]
