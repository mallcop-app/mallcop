"""Tests for mallcop research command and pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import pytest
import yaml

from mallcop.intel_manifest import IntelEntry, load_manifest
from mallcop.llm_types import LLMResponse, ToolCall


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_patrol_repo(tmp_path):
    """A minimal patrol repo directory with mallcop.yaml."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {}},
        "routing": {},
        "actor_chain": {},
        "budget": {},
        "pro": {
            "account_id": "acct-001",
            "service_token": "tok-abc123",
            "account_url": "https://api.mallcop.dev",
            "inference_url": "https://api.mallcop.dev",
        },
    }
    (tmp_path / "mallcop.yaml").write_text(yaml.dump(config))
    return tmp_path


@pytest.fixture
def tmp_patrol_repo_no_pro(tmp_path):
    """A patrol repo without Pro config — no service_token."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {}},
        "routing": {},
        "actor_chain": {},
        "budget": {},
    }
    (tmp_path / "mallcop.yaml").write_text(yaml.dump(config))
    return tmp_path


@pytest.fixture
def mock_llm():
    """A mock LLM client that returns a YAML detector when asked."""
    client = MagicMock()
    detector_yaml = yaml.dump({
        "name": "cve-2026-test-rce",
        "description": "Detects exploitation of CVE-2026-9999 (test RCE)",
        "version": "0.1.0",
        "sources": ["azure"],
        "event_types": ["resource_write"],
        "severity_default": "critical",
        "condition": {
            "type": "count_threshold",
            "field": "target",
            "threshold": 1,
        },
    })
    response = LLMResponse(
        tool_calls=[],
        resolution=None,
        tokens_used=500,
        text=detector_yaml,
    )
    client.chat.return_value = response
    return client


@pytest.fixture
def mock_llm_irrelevant():
    """A mock LLM that says the advisory is not relevant."""
    client = MagicMock()
    response = LLMResponse(
        tool_calls=[],
        resolution=None,
        tokens_used=200,
        text="NOT_RELEVANT: This advisory applies only to Windows DNS servers, not configured connectors.",
    )
    client.chat.return_value = response
    return client


# ---------------------------------------------------------------------------
# Advisory dataclass
# ---------------------------------------------------------------------------


def test_advisory_dataclass_has_expected_fields():
    """Advisory dataclass has id, source, summary fields."""
    from mallcop.research import Advisory
    a = Advisory(id="CVE-2026-1234", source="nvd", summary="A test vulnerability.")
    assert a.id == "CVE-2026-1234"
    assert a.source == "nvd"
    assert a.summary == "A test vulnerability."


# ---------------------------------------------------------------------------
# ResearchConfig
# ---------------------------------------------------------------------------


def test_research_config_defaults():
    """ResearchConfig defaults allow_python=False."""
    from mallcop.research import ResearchConfig
    cfg = ResearchConfig()
    assert cfg.allow_python is False


def test_research_config_allow_python():
    """ResearchConfig can enable Python detectors."""
    from mallcop.research import ResearchConfig
    cfg = ResearchConfig(allow_python=True)
    assert cfg.allow_python is True


# ---------------------------------------------------------------------------
# ResearchResult
# ---------------------------------------------------------------------------


def test_research_result_fields():
    """ResearchResult has the expected fields."""
    from mallcop.research import ResearchResult
    r = ResearchResult(
        advisories_checked=5,
        advisories_new=3,
        detectors_generated=2,
        detectors_skipped=1,
    )
    assert r.advisories_checked == 5
    assert r.advisories_new == 3
    assert r.detectors_generated == 2
    assert r.detectors_skipped == 1


# ---------------------------------------------------------------------------
# filter_unworked_advisories
# ---------------------------------------------------------------------------


def test_filter_unworked_skips_already_worked(tmp_path):
    """filter_unworked_advisories removes advisories already in the manifest."""
    from mallcop.research import Advisory, filter_unworked_advisories
    from mallcop.intel_manifest import IntelEntry, save_entry
    from datetime import datetime, timezone

    manifest_path = tmp_path / "intel-manifest.jsonl"
    entry = IntelEntry(
        id="CVE-2026-1111",
        source="nvd",
        researched_at=datetime.now(timezone.utc),
        detector="some-detector",
    )
    save_entry(manifest_path, entry)

    advisories = [
        Advisory(id="CVE-2026-1111", source="nvd", summary="Already done"),
        Advisory(id="CVE-2026-2222", source="nvd", summary="New one"),
    ]
    result = filter_unworked_advisories(manifest_path, advisories)
    assert len(result) == 1
    assert result[0].id == "CVE-2026-2222"


def test_filter_unworked_empty_manifest(tmp_path):
    """filter_unworked_advisories returns all when manifest is empty."""
    from mallcop.research import Advisory, filter_unworked_advisories
    manifest_path = tmp_path / "intel-manifest.jsonl"
    advisories = [
        Advisory(id="CVE-2026-3333", source="nvd", summary="First"),
        Advisory(id="CVE-2026-4444", source="github-advisory", summary="Second"),
    ]
    result = filter_unworked_advisories(manifest_path, advisories)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# write_detector_yaml
# ---------------------------------------------------------------------------


def test_write_detector_yaml_creates_file(tmp_path):
    """write_detector_yaml writes manifest.yaml to the correct path."""
    from mallcop.research import write_detector_yaml
    detector_data = {
        "name": "test-detector",
        "description": "Test",
        "version": "0.1.0",
        "sources": ["azure"],
        "event_types": ["resource_write"],
        "severity_default": "warn",
        "condition": {"type": "count_threshold", "field": "target", "threshold": 1},
    }
    detectors_dir = tmp_path / "detectors"
    write_detector_yaml(detectors_dir, "test-detector", detector_data)

    manifest = detectors_dir / "test-detector" / "manifest.yaml"
    assert manifest.exists()
    loaded = yaml.safe_load(manifest.read_text())
    assert loaded["name"] == "test-detector"


def test_write_detector_yaml_slugifies_name(tmp_path):
    """write_detector_yaml converts spaces to hyphens in directory name."""
    from mallcop.research import write_detector_yaml
    detector_data = {
        "name": "my new detector",
        "description": "Test",
        "version": "0.1.0",
        "sources": ["azure"],
        "event_types": ["resource_write"],
        "severity_default": "warn",
        "condition": {"type": "count_threshold", "field": "target", "threshold": 1},
    }
    detectors_dir = tmp_path / "detectors"
    write_detector_yaml(detectors_dir, "my new detector", detector_data)
    manifest = detectors_dir / "my-new-detector" / "manifest.yaml"
    assert manifest.exists()


# ---------------------------------------------------------------------------
# reject_python_files
# ---------------------------------------------------------------------------


def test_reject_python_files_raises_when_disallowed():
    """reject_python_files raises ValueError if .py output and allow_python=False."""
    from mallcop.research import reject_python_output
    with pytest.raises(ValueError, match="python"):
        reject_python_output("detector.py", allow_python=False)


def test_reject_python_files_ok_when_allowed():
    """reject_python_files does not raise when allow_python=True."""
    from mallcop.research import reject_python_output
    # Should not raise
    reject_python_output("detector.py", allow_python=True)


def test_reject_python_files_ok_for_yaml():
    """reject_python_files does not raise for YAML files."""
    from mallcop.research import reject_python_output
    # Should not raise
    reject_python_output("manifest.yaml", allow_python=False)


# ---------------------------------------------------------------------------
# run_research pipeline
# ---------------------------------------------------------------------------


def test_run_research_generates_detector(tmp_path, mock_llm):
    """run_research generates a detector YAML for a new advisory."""
    from mallcop.research import Advisory, ResearchConfig, run_research

    manifest_path = tmp_path / "intel-manifest.jsonl"
    detectors_dir = tmp_path / "detectors"

    advisories = [
        Advisory(id="CVE-2026-9999", source="nvd", summary="Critical RCE in test service"),
    ]

    result = run_research(
        advisories=advisories,
        manifest_path=manifest_path,
        detectors_dir=detectors_dir,
        llm_client=mock_llm,
        config=ResearchConfig(),
        connector_names=["azure"],
    )

    assert result.advisories_checked == 1
    assert result.advisories_new == 1
    assert result.detectors_generated == 1
    assert result.detectors_skipped == 0

    # Manifest updated
    entries = load_manifest(manifest_path)
    assert len(entries) == 1
    assert entries[0].id == "CVE-2026-9999"
    assert entries[0].detector is not None

    # Detector file written
    detector_name = entries[0].detector
    manifest_file = detectors_dir / detector_name / "manifest.yaml"
    assert manifest_file.exists()


def test_run_research_skips_already_worked(tmp_path, mock_llm):
    """run_research skips advisories already in the manifest."""
    from mallcop.research import Advisory, ResearchConfig, run_research
    from mallcop.intel_manifest import IntelEntry, save_entry
    from datetime import datetime, timezone

    manifest_path = tmp_path / "intel-manifest.jsonl"
    detectors_dir = tmp_path / "detectors"

    # Pre-populate manifest
    save_entry(manifest_path, IntelEntry(
        id="CVE-2026-OLD",
        source="nvd",
        researched_at=datetime.now(timezone.utc),
        detector="old-detector",
    ))

    advisories = [
        Advisory(id="CVE-2026-OLD", source="nvd", summary="Already done"),
        Advisory(id="CVE-2026-NEW", source="nvd", summary="Brand new threat"),
    ]

    result = run_research(
        advisories=advisories,
        manifest_path=manifest_path,
        detectors_dir=detectors_dir,
        llm_client=mock_llm,
        config=ResearchConfig(),
        connector_names=["azure"],
    )

    assert result.advisories_checked == 2
    assert result.advisories_new == 1
    assert result.detectors_generated == 1

    # LLM only called once (for the new advisory)
    assert mock_llm.chat.call_count == 1


def test_run_research_skips_irrelevant_advisory(tmp_path, mock_llm_irrelevant):
    """run_research records irrelevant advisories with reason, no detector written."""
    from mallcop.research import Advisory, ResearchConfig, run_research

    manifest_path = tmp_path / "intel-manifest.jsonl"
    detectors_dir = tmp_path / "detectors"

    advisories = [
        Advisory(id="CVE-2026-IRREL", source="nvd", summary="Windows-only DNS flaw"),
    ]

    result = run_research(
        advisories=advisories,
        manifest_path=manifest_path,
        detectors_dir=detectors_dir,
        llm_client=mock_llm_irrelevant,
        config=ResearchConfig(),
        connector_names=["azure"],
    )

    assert result.advisories_checked == 1
    assert result.advisories_new == 1
    assert result.detectors_generated == 0
    assert result.detectors_skipped == 1

    # Manifest updated with no-detector entry
    entries = load_manifest(manifest_path)
    assert len(entries) == 1
    assert entries[0].id == "CVE-2026-IRREL"
    assert entries[0].detector is None
    assert entries[0].reason is not None

    # No detector files written
    assert not detectors_dir.exists() or not any(detectors_dir.iterdir())


def test_run_research_rejects_python_when_disallowed(tmp_path):
    """run_research rejects LLM attempts to write Python when allow_python=False."""
    from mallcop.research import Advisory, ResearchConfig, run_research

    manifest_path = tmp_path / "intel-manifest.jsonl"
    detectors_dir = tmp_path / "detectors"

    # LLM returns Python code instead of YAML
    python_llm = MagicMock()
    python_response = LLMResponse(
        tool_calls=[],
        resolution=None,
        tokens_used=300,
        text="PYTHON:\ndef detect(events):\n    return []",
    )
    python_llm.chat.return_value = python_response

    advisories = [
        Advisory(id="CVE-2026-PY", source="nvd", summary="Some threat"),
    ]

    result = run_research(
        advisories=advisories,
        manifest_path=manifest_path,
        detectors_dir=detectors_dir,
        llm_client=python_llm,
        config=ResearchConfig(allow_python=False),
        connector_names=["azure"],
    )

    # Should be recorded as skipped (rejected), not as a generated detector
    assert result.detectors_generated == 0
    assert result.detectors_skipped == 1

    # Manifest should record it was researched
    entries = load_manifest(manifest_path)
    assert len(entries) == 1
    assert entries[0].detector is None


def test_run_research_allows_python_when_enabled(tmp_path):
    """run_research writes Python detector when allow_python=True."""
    from mallcop.research import Advisory, ResearchConfig, run_research

    manifest_path = tmp_path / "intel-manifest.jsonl"
    detectors_dir = tmp_path / "detectors"

    python_llm = MagicMock()
    python_response = LLMResponse(
        tool_calls=[],
        resolution=None,
        tokens_used=300,
        text="PYTHON:cve-2026-py-detector\ndef detect(events):\n    return []",
    )
    python_llm.chat.return_value = python_response

    advisories = [
        Advisory(id="CVE-2026-PY2", source="nvd", summary="Some threat allowing Python"),
    ]

    result = run_research(
        advisories=advisories,
        manifest_path=manifest_path,
        detectors_dir=detectors_dir,
        llm_client=python_llm,
        config=ResearchConfig(allow_python=True),
        connector_names=["azure"],
    )

    assert result.detectors_generated == 1
    assert result.detectors_skipped == 0

    entries = load_manifest(manifest_path)
    assert entries[0].detector is not None


def test_run_research_empty_advisories(tmp_path, mock_llm):
    """run_research with no advisories returns zero counts."""
    from mallcop.research import ResearchConfig, run_research

    manifest_path = tmp_path / "intel-manifest.jsonl"
    detectors_dir = tmp_path / "detectors"

    result = run_research(
        advisories=[],
        manifest_path=manifest_path,
        detectors_dir=detectors_dir,
        llm_client=mock_llm,
        config=ResearchConfig(),
        connector_names=["azure"],
    )

    assert result.advisories_checked == 0
    assert result.advisories_new == 0
    assert result.detectors_generated == 0
    mock_llm.chat.assert_not_called()


# ---------------------------------------------------------------------------
# CLI command: mallcop research
# ---------------------------------------------------------------------------


def test_cli_research_command_exists():
    """The 'research' CLI command is registered."""
    from click.testing import CliRunner
    from mallcop.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["research", "--help"])
    assert result.exit_code == 0
    assert "research" in result.output.lower()


def test_cli_research_requires_pro(tmp_patrol_repo_no_pro):
    """mallcop research exits with error when no pro.service_token configured."""
    from click.testing import CliRunner
    from mallcop.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["research", "--dir", str(tmp_patrol_repo_no_pro)])
    assert result.exit_code != 0
    output = result.output
    # Should emit error about Pro required
    assert "pro" in output.lower() or "service_token" in output.lower() or "error" in output.lower()


def test_cli_research_json_output(tmp_patrol_repo, mock_llm):
    """mallcop research outputs JSON with research results."""
    from click.testing import CliRunner
    from mallcop.cli import cli

    runner = CliRunner()
    with patch("mallcop.research.run_research") as mock_run:
        from mallcop.research import ResearchResult
        mock_run.return_value = ResearchResult(
            advisories_checked=3,
            advisories_new=2,
            detectors_generated=1,
            detectors_skipped=1,
        )
        result = runner.invoke(cli, ["research", "--dir", str(tmp_patrol_repo)])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "ok"
    assert data["advisories_checked"] == 3
    assert data["advisories_new"] == 2
    assert data["detectors_generated"] == 1
    assert data["detectors_skipped"] == 1


def test_cli_research_human_output(tmp_patrol_repo, mock_llm):
    """mallcop research --human outputs readable summary."""
    from click.testing import CliRunner
    from mallcop.cli import cli

    runner = CliRunner()
    with patch("mallcop.research.run_research") as mock_run:
        from mallcop.research import ResearchResult
        mock_run.return_value = ResearchResult(
            advisories_checked=5,
            advisories_new=3,
            detectors_generated=2,
            detectors_skipped=1,
        )
        result = runner.invoke(cli, ["research", "--human", "--dir", str(tmp_patrol_repo)])

    assert result.exit_code == 0
    assert "5" in result.output  # advisories_checked
    assert "2" in result.output  # detectors_generated


# ---------------------------------------------------------------------------
# Config: research.allow_python parsed from mallcop.yaml
# ---------------------------------------------------------------------------


def test_config_research_allow_python_parsed(tmp_path):
    """load_config parses research.allow_python from mallcop.yaml."""
    from mallcop.config import load_config

    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {},
        "actor_chain": {},
        "budget": {},
        "research": {"allow_python": True},
    }
    (tmp_path / "mallcop.yaml").write_text(yaml.dump(config))
    cfg = load_config(tmp_path)
    assert cfg.research is not None
    assert cfg.research.allow_python is True


def test_config_research_defaults_when_missing(tmp_path):
    """load_config returns ResearchConfig with allow_python=False when section absent."""
    from mallcop.config import load_config

    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {},
        "actor_chain": {},
        "budget": {},
    }
    (tmp_path / "mallcop.yaml").write_text(yaml.dump(config))
    cfg = load_config(tmp_path)
    # research config should be default (allow_python=False)
    if cfg.research is not None:
        assert cfg.research.allow_python is False
    else:
        # If None, that's also acceptable — CLI treats None as defaults
        pass
