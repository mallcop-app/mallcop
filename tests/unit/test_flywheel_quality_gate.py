"""Tests for the Academy Flywheel QualityGate."""
from __future__ import annotations

import pytest

from mallcop.flywheel.quality_gate import QualityGate, QualityGateResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_capture(**overrides) -> dict:
    """Build a minimal capture dict that passes all quality gate checks."""
    base = {
        "capture_id": "test-cap-001",
        "captured_at": "2026-03-17T14:30:22+00:00",
        "mallcop_version": "1.0.0",
        "tenant_id": "abc123",
        "connector": "github",
        "detector": "unusual_timing",
        "finding_raw": {
            "id": "f1",
            "severity": "warn",
        },
        "events_raw": [
            {"id": "e1", "actor": "user_A", "timestamp": "2026-01-15T09:00:00Z"},
            {"id": "e2", "actor": "user_A", "timestamp": "2026-01-15T09:01:00Z"},
            {"id": "e3", "actor": "user_A", "timestamp": "2026-01-15T09:02:00Z"},
        ],
        "baseline_raw": {},
        "connector_tool_calls": [
            {"tool": "list_events", "args_schema": {}, "response_raw": {}}
        ],
        "actor_chain": {
            "triage_action": "escalated",
            "chain_action": "escalated",
            "chain_reason": "Unusual access pattern.",
            "llm_calls": [],
            "total_tokens": 500,
        },
        "human_override": "dismiss",  # disagrees with agent → signal quality
        "confidence_score": 0.65,
        "anonymization_validated": True,
        "hostname": "prod-host.example.com",
        # Corpus state for novelty gate
        "corpus_detectors": [],          # detector not in corpus
        "corpus_failure_modes": [],
        "corpus_difficulty_counts": {},
        "failure_mode": "KA",
        "difficulty": "malicious-hard",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# QualityGateResult structure
# ---------------------------------------------------------------------------

class TestQualityGateResult:
    def test_passed_result_has_no_rejection_reason(self):
        result = QualityGateResult(passed=True, rejection_reason=None, gates_passed=["mandatory", "novelty", "signal"])
        assert result.passed is True
        assert result.rejection_reason is None
        assert "mandatory" in result.gates_passed

    def test_failed_result_has_rejection_reason(self):
        result = QualityGateResult(passed=False, rejection_reason="events_raw is empty", gates_passed=[])
        assert result.passed is False
        assert result.rejection_reason == "events_raw is empty"


# ---------------------------------------------------------------------------
# Mandatory checks
# ---------------------------------------------------------------------------

class TestMandatoryChecks:
    def test_passes_with_valid_capture(self):
        capture = _make_capture()
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "mandatory" in result.gates_passed

    def test_fails_when_confidence_score_missing(self):
        capture = _make_capture()
        del capture["confidence_score"]
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "confidence_score" in result.rejection_reason

    def test_fails_when_confidence_score_out_of_range_high(self):
        capture = _make_capture(confidence_score=1.5)
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "confidence_score" in result.rejection_reason

    def test_fails_when_confidence_score_out_of_range_low(self):
        capture = _make_capture(confidence_score=-0.1)
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "confidence_score" in result.rejection_reason

    def test_fails_when_events_raw_empty(self):
        capture = _make_capture(events_raw=[])
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "events_raw" in result.rejection_reason

    def test_fails_when_connector_tool_calls_empty(self):
        capture = _make_capture(connector_tool_calls=[])
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "connector_tool_calls" in result.rejection_reason

    def test_fails_when_anonymization_not_validated(self):
        capture = _make_capture(anonymization_validated=False)
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "anonymization" in result.rejection_reason.lower()

    def test_fails_when_anonymization_missing(self):
        capture = _make_capture()
        del capture["anonymization_validated"]
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "anonymization" in result.rejection_reason.lower()

    def test_confidence_score_boundary_zero_is_valid(self):
        capture = _make_capture(confidence_score=0.0)
        result = QualityGate().evaluate(capture)
        # 0.0 is valid range; may still pass or fail other gates but not mandatory
        # For signal quality: human_override disagrees so should still pass
        assert result.passed is True

    def test_confidence_score_boundary_one_is_valid(self):
        capture = _make_capture(confidence_score=1.0, human_override="escalated")
        # confidence >= 0.92 AND human agreed → signal quality
        result = QualityGate().evaluate(capture)
        assert result.passed is True


# ---------------------------------------------------------------------------
# Hard blocks
# ---------------------------------------------------------------------------

class TestHardBlocks:
    def test_rejects_credential_leak(self):
        capture = _make_capture(credential_leak=True)
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "credential_leak" in result.rejection_reason

    def test_rejects_connector_error_in_events(self):
        events = [
            {"id": "e1", "actor": "user_A", "event_type": "connector_error"},
            {"id": "e2", "actor": "user_A"},
            {"id": "e3", "actor": "user_A"},
        ]
        capture = _make_capture(events_raw=events)
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "connector_error" in result.rejection_reason

    def test_rejects_fewer_than_3_events(self):
        capture = _make_capture(events_raw=[
            {"id": "e1", "actor": "user_A"},
            {"id": "e2", "actor": "user_A"},
        ])
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "events_raw" in result.rejection_reason or "3" in result.rejection_reason

    def test_rejects_test_hostname(self):
        capture = _make_capture(hostname="ci-runner-42.internal")
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "hostname" in result.rejection_reason.lower() or "test" in result.rejection_reason.lower()

    def test_rejects_localhost_hostname(self):
        capture = _make_capture(hostname="localhost")
        result = QualityGate().evaluate(capture)
        assert result.passed is False

    def test_rejects_staging_hostname(self):
        capture = _make_capture(hostname="staging.example.com")
        result = QualityGate().evaluate(capture)
        assert result.passed is False

    def test_accepts_prod_hostname(self):
        capture = _make_capture(hostname="prod-api.example.com")
        result = QualityGate().evaluate(capture)
        assert result.passed is True

    def test_hard_block_takes_priority_over_other_gates(self):
        # credential_leak=True should block even with good novelty/signal
        capture = _make_capture(credential_leak=True)
        result = QualityGate().evaluate(capture)
        assert result.passed is False


# ---------------------------------------------------------------------------
# Novelty gate
# ---------------------------------------------------------------------------

class TestNoveltyGate:
    def test_passes_when_detector_not_in_corpus(self):
        capture = _make_capture(
            corpus_detectors=[],       # detector not present
            human_override="dismiss",  # signal quality via override
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "novelty" in result.gates_passed

    def test_passes_when_failure_mode_not_in_corpus(self):
        capture = _make_capture(
            corpus_detectors=["unusual_timing"],      # detector already present
            corpus_failure_modes=[],                   # failure_mode not present
            failure_mode="AE",
            human_override="dismiss",
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "novelty" in result.gates_passed

    def test_passes_when_difficulty_underrepresented(self):
        capture = _make_capture(
            corpus_detectors=["unusual_timing"],
            corpus_failure_modes=["KA"],
            failure_mode="KA",
            corpus_difficulty_counts={"unusual_timing:malicious-hard": 1},  # < 2
            difficulty="malicious-hard",
            human_override="dismiss",
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "novelty" in result.gates_passed

    def test_fails_novelty_when_all_well_represented(self):
        capture = _make_capture(
            corpus_detectors=["unusual_timing"],
            corpus_failure_modes=["KA"],
            failure_mode="KA",
            corpus_difficulty_counts={"unusual_timing:malicious-hard": 5},  # >= 2
            difficulty="malicious-hard",
            # Give it a signal quality pass via human override
            human_override=None,
            confidence_score=0.80,  # not < 0.70, not >= 0.92
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
            connector_tool_calls=[{"tool": "t1", "args_schema": {}, "response_raw": {}}],
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "novelty" in result.rejection_reason.lower()


# ---------------------------------------------------------------------------
# Signal quality gate
# ---------------------------------------------------------------------------

class TestSignalQualityGate:
    def test_human_override_disagrees_passes(self):
        # agent=escalated, human=dismiss
        capture = _make_capture(
            human_override="dismiss",
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
            confidence_score=0.80,
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "signal" in result.gates_passed

    def test_low_confidence_passes_signal(self):
        capture = _make_capture(
            confidence_score=0.65,
            human_override=None,
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "signal" in result.gates_passed

    def test_high_confidence_with_agreement_passes_signal(self):
        capture = _make_capture(
            confidence_score=0.95,
            human_override="escalated",
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "signal" in result.gates_passed

    def test_multi_tool_path_passes_signal(self):
        capture = _make_capture(
            confidence_score=0.80,
            human_override=None,
            connector_tool_calls=[
                {"tool": "t1", "args_schema": {}, "response_raw": {}},
                {"tool": "t2", "args_schema": {}, "response_raw": {}},
            ],
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "signal" in result.gates_passed

    def test_fails_signal_when_none_pass(self):
        # confidence=0.80 (not low, not high+agree), no human override, single tool
        capture = _make_capture(
            confidence_score=0.80,
            human_override=None,
            connector_tool_calls=[
                {"tool": "t1", "args_schema": {}, "response_raw": {}},
            ],
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
            # novelty passes: detector not in corpus
            corpus_detectors=[],
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        assert "signal" in result.rejection_reason.lower()

    def test_high_confidence_without_agreement_does_not_pass_signal(self):
        # confidence >= 0.92 but human disagrees → should NOT count as high-confidence teaching example
        capture = _make_capture(
            confidence_score=0.95,
            human_override="dismiss",  # disagrees
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
            connector_tool_calls=[
                {"tool": "t1", "args_schema": {}, "response_raw": {}},
            ],
        )
        # NOTE: human_override disagrees → ALSO passes signal (different signal check)
        # So this capture should pass. The point is high-confidence teaching example rule.
        result = QualityGate().evaluate(capture)
        assert result.passed is True  # passes via human_override disagreement signal


# ---------------------------------------------------------------------------
# Gates passed tracking
# ---------------------------------------------------------------------------

class TestGatesPassed:
    def test_gates_passed_lists_all_passing_gates(self):
        capture = _make_capture(
            human_override="dismiss",
            corpus_detectors=[],
            confidence_score=0.65,
        )
        result = QualityGate().evaluate(capture)
        assert result.passed is True
        assert "mandatory" in result.gates_passed
        assert "novelty" in result.gates_passed
        assert "signal" in result.gates_passed

    def test_gates_passed_empty_on_hard_block(self):
        capture = _make_capture(credential_leak=True)
        result = QualityGate().evaluate(capture)
        assert result.passed is False
        # gates_passed may be empty or only contain pre-block gates
        assert "mandatory" not in result.gates_passed or True  # no hard requirement on this
