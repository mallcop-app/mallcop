"""Academy Flywheel — Quality Gate.

Evaluates a ProductionRunCapture (as a dict) to determine whether it qualifies
as a synthesis candidate for the shakedown scenario corpus.

Gate structure
--------------
1. Mandatory checks — ALL must pass.
2. Hard blocks — ANY causes immediate rejection.
3. Novelty gate — AT LEAST ONE must pass.
4. Signal quality gate — AT LEAST ONE must pass.

See: docs/e2e-superintegration-design.md §15.3
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mallcop.flywheel.anonymizer import is_test_environment

__all__ = ["QualityGate", "QualityGateResult"]

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class QualityGateResult:
    """Result of a quality gate evaluation."""

    passed: bool
    rejection_reason: str | None
    gates_passed: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Quality Gate
# ---------------------------------------------------------------------------


class QualityGate:
    """Evaluates captures for synthesis candidacy."""

    # Number of events below which difficulty is considered underrepresented.
    DIFFICULTY_UNDERREPRESENTED_THRESHOLD = 2

    def evaluate(self, capture: dict[str, Any]) -> QualityGateResult:
        """Return a QualityGateResult for *capture*."""
        gates_passed: list[str] = []

        # ── 1. Mandatory checks ──────────────────────────────────────────────
        mandatory_error = self._check_mandatory(capture)
        if mandatory_error:
            return QualityGateResult(
                passed=False,
                rejection_reason=mandatory_error,
                gates_passed=gates_passed,
            )
        gates_passed.append("mandatory")

        # ── 2. Hard blocks ───────────────────────────────────────────────────
        block_reason = self._check_hard_blocks(capture)
        if block_reason:
            return QualityGateResult(
                passed=False,
                rejection_reason=block_reason,
                gates_passed=gates_passed,
            )

        # ── 3. Novelty gate ──────────────────────────────────────────────────
        novelty_passed = self._check_novelty(capture)
        if not novelty_passed:
            return QualityGateResult(
                passed=False,
                rejection_reason="novelty gate: detector, failure_mode, and difficulty are all well-represented in corpus",
                gates_passed=gates_passed,
            )
        gates_passed.append("novelty")

        # ── 4. Signal quality gate ───────────────────────────────────────────
        signal_passed = self._check_signal_quality(capture)
        if not signal_passed:
            return QualityGateResult(
                passed=False,
                rejection_reason="signal quality gate: no qualifying signal (override, low confidence, high-confidence agreement, or multi-tool path)",
                gates_passed=gates_passed,
            )
        gates_passed.append("signal")

        return QualityGateResult(passed=True, rejection_reason=None, gates_passed=gates_passed)

    # ──────────────────────────────────────────────────────────────────────────
    # Mandatory checks
    # ──────────────────────────────────────────────────────────────────────────

    def _check_mandatory(self, capture: dict[str, Any]) -> str | None:
        """Return an error string if any mandatory check fails, else None."""
        # confidence_score must be present and in [0.0, 1.0]
        if "confidence_score" not in capture:
            return "confidence_score missing"
        score = capture["confidence_score"]
        if not isinstance(score, (int, float)) or score < 0.0 or score > 1.0:
            return f"confidence_score out of range [0, 1]: {score}"

        # events_raw must be non-empty
        events = capture.get("events_raw", [])
        if not events:
            return "events_raw is empty"

        # connector_tool_calls must be non-empty
        tool_calls = capture.get("connector_tool_calls", [])
        if not tool_calls:
            return "connector_tool_calls is empty"

        # anonymization_validated must be True
        if not capture.get("anonymization_validated", False):
            return "anonymization_validated is False or missing"

        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Hard blocks
    # ──────────────────────────────────────────────────────────────────────────

    def _check_hard_blocks(self, capture: dict[str, Any]) -> str | None:
        """Return an error string if any hard block applies, else None."""
        # credential_leak
        if capture.get("credential_leak", False):
            return "hard block: credential_leak=True"

        # connector_error in events_raw
        events = capture.get("events_raw", [])
        for evt in events:
            if isinstance(evt, dict) and evt.get("event_type") == "connector_error":
                return "hard block: connector_error event in events_raw"

        # fewer than 3 events
        if len(events) < 3:
            return f"hard block: events_raw has {len(events)} events (minimum 3)"

        # test/dev hostname
        hostname = capture.get("hostname", "")
        if hostname and is_test_environment(hostname):
            return f"hard block: hostname looks like test/CI environment: {hostname!r}"

        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Novelty gate
    # ──────────────────────────────────────────────────────────────────────────

    def _check_novelty(self, capture: dict[str, Any]) -> bool:
        """Return True if at least one novelty criterion is met."""
        detector = capture.get("detector", "")
        failure_mode = capture.get("failure_mode", "")
        difficulty = capture.get("difficulty", "")
        corpus_detectors: list[str] = capture.get("corpus_detectors", [])
        corpus_failure_modes: list[str] = capture.get("corpus_failure_modes", [])
        corpus_difficulty_counts: dict[str, int] = capture.get("corpus_difficulty_counts", {})

        # Detector not in corpus for this connector
        if detector not in corpus_detectors:
            return True

        # failure_mode not in corpus for this detector
        if failure_mode not in corpus_failure_modes:
            return True

        # Difficulty underrepresented (< 2 scenarios at this difficulty for detector)
        difficulty_key = f"{detector}:{difficulty}"
        count = corpus_difficulty_counts.get(difficulty_key, 0)
        if count < self.DIFFICULTY_UNDERREPRESENTED_THRESHOLD:
            return True

        return False

    # ──────────────────────────────────────────────────────────────────────────
    # Signal quality gate
    # ──────────────────────────────────────────────────────────────────────────

    def _check_signal_quality(self, capture: dict[str, Any]) -> bool:
        """Return True if at least one signal quality criterion is met."""
        confidence: float = capture.get("confidence_score", 0.5)
        human_override: str | None = capture.get("human_override")
        actor_chain: dict[str, Any] = capture.get("actor_chain", {})
        agent_decision = actor_chain.get("chain_action")
        connector_tool_calls: list = capture.get("connector_tool_calls", [])

        # human_override disagrees with agent decision
        if human_override is not None and human_override != agent_decision:
            return True

        # confidence < 0.70 (agent was uncertain)
        if confidence < 0.70:
            return True

        # confidence >= 0.92 AND human agreed (high-confidence teaching example)
        if confidence >= 0.92 and human_override == agent_decision:
            return True

        # Multi-tool investigation path (more than one tool call)
        if len(connector_tool_calls) > 1:
            return True

        return False
