"""Pytest fixtures for shakedown tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mallcop.config import LLMConfig
from tests.shakedown.evaluator import JudgeEvaluator
from tests.shakedown.harness import ShakedownHarness
from tests.shakedown.runs import RunRecorder
from tests.shakedown.scenario import load_all_scenarios, Scenario


SCENARIOS_DIR = Path(__file__).parent / "scenarios"


def _build_llm_client(backend: str | None = None, model: str | None = None):
    """Build LLM client based on environment configuration."""
    if backend is None:
        backend = os.environ.get("SHAKEDOWN_BACKEND", "api")
    if model is None:
        model = os.environ.get("SHAKEDOWN_MODEL", "haiku")

    if backend == "claude-code":
        from mallcop.llm.claude_code import ClaudeCodeClient
        return ClaudeCodeClient(model=model)
    elif backend == "managed":
        from mallcop.llm.managed import ManagedClient
        service_url = os.environ.get("MALLCOP_SERVICE_URL")
        service_token = os.environ.get("MALLCOP_SERVICE_TOKEN")
        if not service_url or not service_token:
            pytest.skip("MALLCOP_SERVICE_URL and MALLCOP_SERVICE_TOKEN required for managed backend")
        return ManagedClient(endpoint=service_url, service_token=service_token)
    elif backend == "bedrock":
        from mallcop.llm.bedrock import BedrockClient
        region = os.environ.get("AWS_REGION", "us-east-1")
        return BedrockClient(model=model, region=region)
    elif backend == "openai-compat":
        from mallcop.llm.openai_compat import OpenAICompatClient
        base_url = os.environ.get("OPENAI_BASE_URL")
        api_key = os.environ.get("OPENAI_API_KEY")
        if not base_url:
            pytest.skip("OPENAI_BASE_URL required for openai-compat backend")
        return OpenAICompatClient(endpoint=base_url, api_key=api_key or "")
    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            pytest.skip(
                "ANTHROPIC_API_KEY not set "
                "(use SHAKEDOWN_BACKEND=claude-code for Claude Max)"
            )
        from mallcop.llm import build_llm_client
        return build_llm_client(LLMConfig(provider="anthropic", api_key=api_key))


@pytest.fixture
def shakedown_llm():
    """LLM client for shakedown tests."""
    return _build_llm_client()


@pytest.fixture
def shakedown_harness(shakedown_llm):
    """ShakedownHarness configured with the test LLM client."""
    return ShakedownHarness(
        llm=shakedown_llm,
        scenario_dir=SCENARIOS_DIR,
    )


@pytest.fixture
def all_scenarios():
    """Load all scenario YAML files from the scenarios directory."""
    if not SCENARIOS_DIR.exists():
        return []
    return load_all_scenarios(SCENARIOS_DIR)


@pytest.fixture(scope="session")
def judge_llm():
    """Separate LLM client for judge evaluation — always sonnet, not instrumented."""
    backend = os.environ.get("JUDGE_BACKEND", os.environ.get("SHAKEDOWN_BACKEND", "api"))
    return _build_llm_client(backend=backend, model="sonnet")


@pytest.fixture(scope="session")
def judge_evaluator(judge_llm):
    """JudgeEvaluator using a dedicated LLM judge."""
    return JudgeEvaluator(judge_llm=judge_llm, judge_model="sonnet")


@pytest.fixture(scope="session")
def run_recorder():
    """Records per-scenario grades to a JSONL file under runs/."""
    return RunRecorder()


def pytest_collection_modifyitems(config, items):
    """Add 'shakedown' mark to tests in the shakedown directory."""
    for item in items:
        if "shakedown" in str(item.fspath):
            item.add_marker(pytest.mark.shakedown)
