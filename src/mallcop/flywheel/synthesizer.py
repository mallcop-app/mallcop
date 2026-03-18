"""Academy Flywheel — Scenario Synthesizer.

Converts an anonymized ProductionRunCapture dict into a YAML-serializable
dict matching the shakedown scenario schema.

Schema reference: tests/shakedown/scenarios/_schema.yaml
Design reference: docs/e2e-superintegration-design.md §15.4
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

__all__ = ["Synthesizer"]

# Reference anchor for all synthesized event timestamps.
_ANCHOR_TS = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)

# Connector → category mapping (best-effort; falls back to connector name).
_CONNECTOR_TO_CATEGORY: dict[str, str] = {
    "github": "behavioral",
    "azure": "access",
    "aws": "access",
    "aws_cloudtrail": "access",
    "container_logs": "structural",
    "okta": "identity",
    "gsuite": "identity",
    "slack": "behavioral",
}


class Synthesizer:
    """Synthesizes a shakedown scenario from an anonymized capture dict."""

    def synthesize(self, capture: dict[str, Any]) -> dict[str, Any]:
        """Return a YAML-serializable scenario dict from *capture*."""
        scenario_id = self._make_id(capture)
        events = self._anchor_events(capture.get("events_raw", []))
        expected = self._make_expected(capture)
        ground_truth = self._make_ground_truth(capture)

        result: dict[str, Any] = {
            "id": scenario_id,
            "failure_mode": capture.get("failure_mode", ""),
            "detector": capture.get("detector", ""),
            "category": self._infer_category(capture),
            "difficulty": capture.get("difficulty", "ambiguous"),
            "tags": ["synthetic", "needs-review"],
            "finding": capture.get("finding_raw", {}),
            "events": events,
            "baseline": capture.get("baseline_raw", {}),
            "connector_tools": self._extract_connector_tools(capture),
            "expected": expected,
            "ground_truth": ground_truth,
        }
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # ID construction
    # ──────────────────────────────────────────────────────────────────────────

    def _make_id(self, capture: dict[str, Any]) -> str:
        """Return SYN-{detector}-{date}-{hash[:6]}."""
        detector = capture.get("detector", "unknown")
        # Derive date from captured_at
        captured_at: str = capture.get("captured_at", "")
        try:
            dt = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
            date_str = dt.strftime("%Y-%m-%d")
        except (ValueError, AttributeError):
            date_str = "unknown"

        # Hash from capture_id for uniqueness + determinism
        capture_id = capture.get("capture_id", "")
        digest = hashlib.sha256(capture_id.encode()).hexdigest()[:6]

        return f"SYN-{detector}-{date_str}-{digest}"

    # ──────────────────────────────────────────────────────────────────────────
    # Timestamp anchoring
    # ──────────────────────────────────────────────────────────────────────────

    def _anchor_events(self, events_raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Anchor event timestamps to _ANCHOR_TS while preserving relative timing."""
        if not events_raw:
            return []

        # Parse the first event's timestamp to compute origin.
        first_ts_str = events_raw[0].get("timestamp", "")
        try:
            origin = datetime.fromisoformat(first_ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            origin = _ANCHOR_TS

        anchored = []
        for evt in events_raw:
            evt_copy = dict(evt)
            ts_str = evt.get("timestamp", "")
            try:
                evt_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                delta = evt_dt - origin
                new_ts = _ANCHOR_TS + delta
                evt_copy["timestamp"] = new_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, AttributeError):
                pass  # keep original if unparseable
            anchored.append(evt_copy)

        return anchored

    # ──────────────────────────────────────────────────────────────────────────
    # Expected field
    # ──────────────────────────────────────────────────────────────────────────

    def _make_expected(self, capture: dict[str, Any]) -> dict[str, Any]:
        """Build the expected dict from human_override or actor_chain."""
        actor_chain: dict[str, Any] = capture.get("actor_chain", {})
        human_override: str | None = capture.get("human_override")
        confidence: float = capture.get("confidence_score", 0.0)

        agent_chain_action = actor_chain.get("chain_action", "")
        agent_triage_action = actor_chain.get("triage_action", "")

        if human_override is not None:
            # Human override is ground truth
            chain_action = human_override
            triage_action = human_override
        elif confidence >= 0.85:
            # High-confidence agent decision trusted as ground truth
            chain_action = agent_chain_action
            triage_action = agent_triage_action
        else:
            # Low-confidence: use agent decision but mark uncertain
            chain_action = agent_chain_action
            triage_action = agent_triage_action

        return {
            "chain_action": chain_action,
            "triage_action": triage_action,
            "reasoning_must_mention": [],
            "reasoning_must_not_mention": [],
            "investigate_must_use_tools": True,
            "min_investigate_iterations": 1,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Ground truth
    # ──────────────────────────────────────────────────────────────────────────

    def _make_ground_truth(self, capture: dict[str, Any]) -> dict[str, Any]:
        """Synthesize ground_truth from chain_reason."""
        actor_chain: dict[str, Any] = capture.get("actor_chain", {})
        chain_reason: str = actor_chain.get("chain_reason", "")
        return {
            "expected_conclusion": chain_reason or "See finding and events for context.",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Connector tools
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_connector_tools(self, capture: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract connector tool definitions from tool_calls."""
        seen: set[str] = set()
        tools: list[dict[str, Any]] = []
        for tc in capture.get("connector_tool_calls", []):
            tool_name = tc.get("tool", "")
            if tool_name and tool_name not in seen:
                seen.add(tool_name)
                tools.append({
                    "name": tool_name,
                    "args_schema": tc.get("args_schema", {}),
                })
        return tools

    # ──────────────────────────────────────────────────────────────────────────
    # Category inference
    # ──────────────────────────────────────────────────────────────────────────

    def _infer_category(self, capture: dict[str, Any]) -> str:
        connector = capture.get("connector", "")
        return _CONNECTOR_TO_CATEGORY.get(connector, connector or "unknown")
