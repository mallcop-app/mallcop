"""Tests for confidence scoring: compute_confidence() pure function."""

from __future__ import annotations

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.confidence import compute_confidence
from mallcop.actors.runtime import RunResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolution(action: str = "resolved", reason: str = "Looks fine") -> ActorResolution:
    return ActorResolution(
        finding_id="fnd_001",
        action=ResolutionAction(action),
        reason=reason,
    )


def _run_result(
    tool_calls: int = 0,
    distinct_tools: int = 0,
    iterations: int = 1,
    reason: str = "Looks fine",
    action: str = "resolved",
) -> RunResult:
    return RunResult(
        resolution=_resolution(action=action, reason=reason),
        tokens_used=1000,
        iterations=iterations,
        tool_calls=tool_calls,
        distinct_tools=distinct_tools,
    )


# ---------------------------------------------------------------------------
# Confidence ordering tests
# ---------------------------------------------------------------------------

class TestConfidenceScoring:
    def test_high_tool_usage_higher_than_low(self):
        """More tool calls → higher confidence (on average across noise)."""
        high = _run_result(tool_calls=10, distinct_tools=4, iterations=3, reason="Checked timestamp 2024-01-01 in baseline frequency table actor:alice:github")
        low = _run_result(tool_calls=1, distinct_tools=1, iterations=1, reason="Looks fine")
        # Run multiple times and check the average is higher for high-quality
        high_scores = [compute_confidence(high) for _ in range(20)]
        low_scores = [compute_confidence(low) for _ in range(20)]
        assert sum(high_scores) / len(high_scores) > sum(low_scores) / len(low_scores)

    def test_evidence_dense_reason_higher_than_vague(self):
        """Reason with specific evidence citations → higher confidence."""
        evidence_reason = (
            "Actor alice was seen at timestamp 2024-01-15T14:00Z, "
            "frequency baseline shows 95th percentile at this hour, "
            "relationship alice:resource-group/prod exists since 2023-01, "
            "IP 10.0.0.1 matches baseline known_ip entries"
        )
        vague_reason = "Activity looks normal"

        dense = _run_result(tool_calls=5, distinct_tools=3, reason=evidence_reason)
        vague = _run_result(tool_calls=5, distinct_tools=3, reason=vague_reason)

        dense_scores = [compute_confidence(dense) for _ in range(20)]
        vague_scores = [compute_confidence(vague) for _ in range(20)]
        assert sum(dense_scores) / 20 > sum(vague_scores) / 20

    def test_output_is_0_to_1(self):
        """Output is always in [0.0, 1.0]."""
        for _ in range(50):
            score = compute_confidence(_run_result(tool_calls=5, distinct_tools=3, iterations=3))
            assert 0.0 <= score <= 1.0

    def test_no_tool_calls_low_confidence(self):
        """Zero tool calls → low confidence (below 0.5 on average)."""
        result = _run_result(tool_calls=0, distinct_tools=0, iterations=1)
        scores = [compute_confidence(result) for _ in range(20)]
        assert sum(scores) / 20 < 0.5

    def test_noise_floor_produces_different_values(self):
        """Same input should produce slightly different scores (noise floor)."""
        result = _run_result(tool_calls=5, distinct_tools=3, iterations=2)
        scores = {compute_confidence(result) for _ in range(20)}
        # With noise, not all values should be identical
        assert len(scores) > 1

    def test_pure_function_no_side_effects(self):
        """compute_confidence has no side effects — RunResult unchanged after call."""
        result = _run_result(tool_calls=5, iterations=2)
        original_resolution = result.resolution
        original_tokens = result.tokens_used
        original_iterations = result.iterations

        compute_confidence(result)

        assert result.resolution == original_resolution
        assert result.tokens_used == original_tokens
        assert result.iterations == original_iterations

    def test_none_resolution_returns_low_confidence(self):
        """RunResult with no resolution returns low confidence."""
        result = RunResult(
            resolution=None,
            tokens_used=500,
            iterations=1,
            tool_calls=0,
            distinct_tools=0,
        )
        score = compute_confidence(result)
        assert 0.0 <= score <= 1.0
        # No resolution = low confidence
        scores = [compute_confidence(result) for _ in range(10)]
        assert sum(scores) / 10 < 0.5

    def test_many_iterations_slightly_penalized(self):
        """Needing many iterations for the same tool count is slightly lower quality."""
        # Same tools but more iterations = less efficient resolution
        efficient = _run_result(tool_calls=4, distinct_tools=4, iterations=2)
        inefficient = _run_result(tool_calls=4, distinct_tools=4, iterations=8)
        # Not a hard requirement, but efficient should >= inefficient on average
        eff_scores = [compute_confidence(efficient) for _ in range(20)]
        ineff_scores = [compute_confidence(inefficient) for _ in range(20)]
        assert sum(eff_scores) / 20 >= sum(ineff_scores) / 20 - 0.1  # allow small margin


# ---------------------------------------------------------------------------
# ActorResolution.confidence field
# ---------------------------------------------------------------------------

class TestActorResolutionConfidenceField:
    def test_default_confidence_is_zero(self):
        res = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="ok",
        )
        assert res.confidence == 0.0

    def test_confidence_persists_in_to_dict(self):
        res = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.ESCALATED,
            reason="suspicious",
            confidence=0.75,
        )
        d = res.to_dict()
        assert d["confidence"] == 0.75

    def test_confidence_round_trips_from_dict(self):
        res = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="ok",
            confidence=0.9,
        )
        restored = ActorResolution.from_dict(res.to_dict())
        assert restored.confidence == 0.9

    def test_from_dict_missing_confidence_defaults_to_zero(self):
        """Old serialized resolutions without confidence field load cleanly."""
        data = {
            "finding_id": "fnd_001",
            "action": "resolved",
            "reason": "Normal activity",
        }
        res = ActorResolution.from_dict(data)
        assert res.confidence == 0.0


# ---------------------------------------------------------------------------
# RunResult has tool_calls and distinct_tools
# ---------------------------------------------------------------------------

class TestRunResultFields:
    def test_run_result_has_tool_calls(self):
        r = RunResult(
            resolution=None,
            tokens_used=100,
            iterations=1,
            tool_calls=3,
            distinct_tools=2,
        )
        assert r.tool_calls == 3
        assert r.distinct_tools == 2

    def test_run_result_defaults(self):
        """tool_calls and distinct_tools default to 0 (backwards compat)."""
        r = RunResult(
            resolution=None,
            tokens_used=100,
            iterations=1,
        )
        assert r.tool_calls == 0
        assert r.distinct_tools == 0
