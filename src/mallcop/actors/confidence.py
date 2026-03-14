"""Confidence scoring: derive investigation quality from observable signals.

The model never self-reports confidence — that's gameable. Instead, confidence
is computed from structural properties of the investigation:
  - How many tool calls were made?
  - How many distinct tools were used?
  - How many evidence citations appear in the reason text?
  - How many iterations were needed?

A random noise floor (±0.05) is added per Kerckhoffs's principle: even with
full algorithm knowledge, an attacker cannot predict the exact score.

This module is a pure function — no side effects, no store access, no LLM calls.
"""

from __future__ import annotations

import random
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mallcop.actors.runtime import RunResult


# Patterns that indicate concrete evidence citations in reason text
# (structural signals — not full NLP, just observable anchors)
_EVIDENCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}"),          # ISO date reference
    re.compile(r"\b\d{2}:\d{2}"),                  # time reference
    re.compile(r"\bbaseline\b", re.IGNORECASE),
    re.compile(r"\bfrequency\b", re.IGNORECASE),
    re.compile(r"\brelationship\b", re.IGNORECASE),
    re.compile(r"\bactor:\w+", re.IGNORECASE),     # actor:name reference
    re.compile(r"\bknown\b", re.IGNORECASE),
    re.compile(r"\bpercentile\b", re.IGNORECASE),
    re.compile(r"\bIP\s+\d+\.\d+", re.IGNORECASE),  # IP address
    re.compile(r"\bfirst_seen\b|\blast_seen\b", re.IGNORECASE),
    re.compile(r"\bcount\b", re.IGNORECASE),
    re.compile(r"\bevents?\b", re.IGNORECASE),
]

# Noise magnitude: ±NOISE_FLOOR uniform random
_NOISE_FLOOR = 0.05

# Score weights
_TOOL_CALL_WEIGHT = 0.04        # per tool call (capped)
_TOOL_CALL_CAP = 8              # cap at 8 tool calls for scoring
_DISTINCT_TOOL_WEIGHT = 0.08    # per distinct tool used (capped)
_DISTINCT_TOOL_CAP = 4          # cap at 4 distinct tools
_EVIDENCE_WEIGHT = 0.04         # per evidence pattern matched (capped)
_EVIDENCE_CAP = 5               # cap at 5 evidence signals
_ITERATION_PENALTY = 0.02       # per iteration above 3 (mild penalty for inefficiency)


def compute_confidence(run_result: "RunResult") -> float:
    """Derive a confidence score (0.0-1.0) from a RunResult.

    Inputs (all observable, none self-reported by model):
      - tool_calls: total tool call count
      - distinct_tools: number of different tools used
      - iterations: loop count (excess iterations signal difficulty)
      - reason text: count of concrete evidence citations

    A random noise floor of ±0.05 is added. Non-deterministic.

    Returns: float in [0.0, 1.0]
    """
    if run_result.resolution is None:
        # No resolution = agent failed to conclude — low confidence
        base = 0.1
        noise = random.uniform(-_NOISE_FLOOR, _NOISE_FLOOR)
        return max(0.0, min(1.0, base + noise))

    # Tool call contribution
    tc_contribution = min(run_result.tool_calls, _TOOL_CALL_CAP) * _TOOL_CALL_WEIGHT

    # Distinct tools contribution
    dt_contribution = min(run_result.distinct_tools, _DISTINCT_TOOL_CAP) * _DISTINCT_TOOL_WEIGHT

    # Evidence density in reason text
    reason = run_result.resolution.reason or ""
    evidence_count = sum(1 for p in _EVIDENCE_PATTERNS if p.search(reason))
    evidence_contribution = min(evidence_count, _EVIDENCE_CAP) * _EVIDENCE_WEIGHT

    # Iteration penalty (efficient resolution > thrashing)
    iter_penalty = max(0, run_result.iterations - 3) * _ITERATION_PENALTY

    base = tc_contribution + dt_contribution + evidence_contribution - iter_penalty

    # Add random noise floor
    noise = random.uniform(-_NOISE_FLOOR, _NOISE_FLOOR)
    score = base + noise

    return max(0.0, min(1.0, score))
