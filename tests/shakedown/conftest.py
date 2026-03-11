"""Pytest fixtures for shakedown tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.shakedown.harness import InstrumentedLLMClient, ShakedownHarness
from tests.shakedown.scenario import load_all_scenarios, Scenario


SCENARIOS_DIR = Path(__file__).parent / "scenarios"


def _build_llm_client():
    """Build LLM client based on environment configuration."""
    backend = os.environ.get("SHAKEDOWN_BACKEND", "api")
    model = os.environ.get("SHAKEDOWN_MODEL", "haiku")

    if backend == "claude-code":
        from mallcop.llm.claude_code import ClaudeCodeClient
        return ClaudeCodeClient(model=model)
    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            pytest.skip(
                "ANTHROPIC_API_KEY not set "
                "(use SHAKEDOWN_BACKEND=claude-code for Claude Max)"
            )
        from mallcop.llm import build_llm_client
        return build_llm_client({"provider": "anthropic", "api_key": api_key})


@pytest.fixture
def shakedown_llm():
    """LLM client for shakedown tests, wrapped in InstrumentedLLMClient."""
    client = _build_llm_client()
    return InstrumentedLLMClient(client)


@pytest.fixture
def shakedown_harness(shakedown_llm):
    """ShakedownHarness configured with the test LLM client."""
    return ShakedownHarness(
        llm=shakedown_llm.inner,  # harness wraps its own instrumented client
        scenario_dir=SCENARIOS_DIR,
    )


@pytest.fixture
def all_scenarios():
    """Load all scenario YAML files from the scenarios directory."""
    if not SCENARIOS_DIR.exists():
        return []
    return load_all_scenarios(SCENARIOS_DIR)


def pytest_collection_modifyitems(config, items):
    """Add 'shakedown' mark to tests in the shakedown directory."""
    for item in items:
        if "shakedown" in str(item.fspath):
            item.add_marker(pytest.mark.shakedown)
