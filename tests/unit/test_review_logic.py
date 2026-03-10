"""Unit tests for review command logic."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.config import MallcopConfig, RouteConfig, BudgetConfig, BaselineConfig
from mallcop.review import _find_post_md, _select_actor_for_review, run_review
from mallcop.schemas import (
    Annotation,
    Baseline,
    Finding,
    FindingStatus,
    Severity,
)

_NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)


def _make_finding(
    fid: str = "f-1",
    severity: Severity = Severity.CRITICAL,
    status: FindingStatus = FindingStatus.OPEN,
    annotations: list[Annotation] | None = None,
) -> Finding:
    return Finding(
        id=fid,
        timestamp=_NOW,
        detector="test-detector",
        event_ids=["e-1"],
        title="Test finding",
        severity=severity,
        status=status,
        annotations=annotations or [],
        metadata={},
    )


def _make_config(
    routing: dict[str, RouteConfig | None] | None = None,
    actor_chain: dict[str, dict[str, Any]] | None = None,
) -> MallcopConfig:
    return MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing=routing or {},
        actor_chain=actor_chain or {},
        budget=BudgetConfig(),
        baseline=BaselineConfig(),
    )


# --- run_review: empty findings ---


@patch("mallcop.review.JsonlStore")
@patch("mallcop.review.load_config")
def test_run_review_empty_findings(mock_load_config, mock_store_cls, tmp_path):
    """run_review returns ok with empty dicts when no open findings."""
    mock_load_config.return_value = _make_config()
    store = MagicMock()
    store.query_findings.return_value = []
    mock_store_cls.return_value = store

    result = run_review(tmp_path)

    assert result["status"] == "ok"
    assert result["findings_by_severity"] == {}
    assert result["post_md"] is None
    assert result["suggested_commands"] == []


# --- _find_post_md: missing POST.md ---


def test_find_post_md_missing_actor(tmp_path):
    """_find_post_md returns None when no POST.md exists anywhere."""
    result = _find_post_md("nonexistent-actor", tmp_path)
    assert result is None


def test_find_post_md_deployment_override(tmp_path):
    """_find_post_md loads from deployment root actors/ when present."""
    actor_dir = tmp_path / "actors" / "triage"
    actor_dir.mkdir(parents=True)
    (actor_dir / "POST.md").write_text("Deploy POST")

    result = _find_post_md("triage", tmp_path)
    assert result == "Deploy POST"


# --- _select_actor_for_review: RouteConfig vs string ---


def test_select_actor_route_config():
    """_select_actor_for_review works with RouteConfig routing format."""
    findings = {"critical": [{"annotations": []}]}
    routing = {"critical": RouteConfig(chain=["triage"], notify=["slack"])}

    actor = _select_actor_for_review(findings, routing)
    assert actor == "triage"


def test_select_actor_string_routing():
    """_select_actor_for_review works with legacy string routing format."""
    findings = {"critical": [{"annotations": []}]}
    routing = {"critical": "triage"}

    actor = _select_actor_for_review(findings, routing)
    assert actor == "triage"


def test_select_actor_no_route_for_severity():
    """_select_actor_for_review returns None when severity has no route."""
    findings = {"critical": [{"annotations": []}]}
    routing = {}  # no route for critical

    actor = _select_actor_for_review(findings, routing)
    assert actor is None


def test_select_actor_follows_chain_when_all_triaged():
    """When all findings are triaged by entry actor, follow routes_to."""
    findings = {
        "critical": [
            {"annotations": [{"actor": "triage"}]},
        ]
    }
    routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
    actor_chain = {
        "triage": {"routes_to": "investigate"},
        "investigate": {},
    }

    actor = _select_actor_for_review(findings, routing, actor_chain)
    assert actor == "investigate"


def test_select_actor_returns_entry_when_not_all_triaged():
    """When some findings lack triage annotation, return entry actor."""
    findings = {
        "critical": [
            {"annotations": [{"actor": "triage"}]},
            {"annotations": []},  # untriaged
        ]
    }
    routing = {"critical": RouteConfig(chain=["triage"], notify=[])}

    actor = _select_actor_for_review(findings, routing)
    assert actor == "triage"


# --- run_review: full integration with mocked store ---


@patch("mallcop.review.JsonlStore")
@patch("mallcop.review.load_config")
def test_run_review_groups_by_severity(mock_load_config, mock_store_cls, tmp_path):
    """run_review groups findings by severity and generates commands."""
    config = _make_config(
        routing={"critical": RouteConfig(chain=["triage"], notify=[])},
        actor_chain={"triage": {}},
    )
    mock_load_config.return_value = config

    crit = _make_finding("f-1", Severity.CRITICAL)
    warn = _make_finding("f-2", Severity.WARN)
    store = MagicMock()
    store.query_findings.return_value = [crit, warn]
    mock_store_cls.return_value = store

    result = run_review(tmp_path)

    assert result["status"] == "ok"
    assert "critical" in result["findings_by_severity"]
    assert "warn" in result["findings_by_severity"]
    assert len(result["suggested_commands"]) == 10  # 5 per finding
