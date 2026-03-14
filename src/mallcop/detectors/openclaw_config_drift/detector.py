"""OpenClaw config-drift detector: insecure gateway configuration detection."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


def _get_nested(data: dict, path: str) -> Any:
    """Resolve a dot-path like 'gateway.auth.enabled' into a nested dict."""
    # Strip leading $. if present (jsonpath-lite style)
    if path.startswith("$."):
        path = path[2:]
    keys = path.split(".")
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


# Plaintext secret patterns
_SECRET_PATTERN = re.compile(
    r"(sk-[a-zA-Z0-9-]{20,}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36})"
)


class OpenClawConfigDriftDetector(DetectorBase):
    """Detects insecure OpenClaw gateway configuration from config_changed events."""

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        relevant = [
            e for e in events
            if e.source == "openclaw" and e.event_type == "config_changed"
        ]

        findings: list[Finding] = []
        for evt in relevant:
            config = evt.metadata.get("config", {})
            config_raw = evt.metadata.get("config_raw", "")

            # --- auth-disabled ---
            auth_enabled = _get_nested(config, "$.gateway.auth.enabled")
            if auth_enabled is False:
                findings.append(self._make_finding(
                    evt=evt,
                    rule="auth-disabled",
                    title="openclaw-config-drift [auth-disabled]: gateway authentication is disabled",
                    severity=Severity.CRITICAL,
                    description="Gateway authentication is disabled — any request is accepted without auth.",
                ))

            # --- plaintext-secrets ---
            if config_raw and _SECRET_PATTERN.search(config_raw):
                findings.append(self._make_finding(
                    evt=evt,
                    rule="plaintext-secrets",
                    title="openclaw-config-drift [plaintext-secrets]: API keys stored in plaintext",
                    severity=Severity.WARN,
                    description=(
                        "API keys found in plaintext in openclaw.json. "
                        "Consider using environment variables instead."
                    ),
                ))

            # --- mdns-enabled ---
            mdns_enabled = _get_nested(config, "$.gateway.mdns.enabled")
            if mdns_enabled is True:
                findings.append(self._make_finding(
                    evt=evt,
                    rule="mdns-enabled",
                    title="openclaw-config-drift [mdns-enabled]: mDNS broadcasting gateway presence on LAN",
                    severity=Severity.WARN,
                    description="mDNS is broadcasting the gateway presence on the local network.",
                ))

            # --- guest-mode-tools ---
            guest_tools = _get_nested(config, "$.gateway.guestMode.tools")
            if guest_tools:  # non-empty list or truthy value
                findings.append(self._make_finding(
                    evt=evt,
                    rule="guest-mode-tools",
                    title="openclaw-config-drift [guest-mode-tools]: dangerous tools accessible in guest mode",
                    severity=Severity.WARN,
                    description="Tools are accessible without authentication via guest mode.",
                ))

            # --- shadow-skill-override ---
            override_type = evt.metadata.get("override_type", "")
            if override_type in ("workspace_overrides_managed", "workspace_overrides_bundled"):
                findings.append(self._make_finding(
                    evt=evt,
                    rule="shadow-skill-override",
                    title=f"openclaw-config-drift [shadow-skill-override]: workspace skill overriding {override_type.split('_overrides_')[1]} skill",
                    severity=Severity.WARN,
                    description="A workspace skill is overriding a managed or bundled skill.",
                ))

        return findings

    def relevant_sources(self) -> list[str] | None:
        return ["openclaw"]

    def relevant_event_types(self) -> list[str] | None:
        return ["config_changed"]

    def _make_finding(
        self,
        *,
        evt: Event,
        rule: str,
        title: str,
        severity: Severity,
        description: str,
    ) -> Finding:
        return Finding(
            id=f"fnd_{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc),
            detector="openclaw-config-drift",
            event_ids=[evt.id],
            title=title,
            severity=severity,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={
                "rule": rule,
                "description": description,
            },
        )
