"""Unit tests for investigate command logic."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.config import MallcopConfig, RouteConfig, BudgetConfig, BaselineConfig
from mallcop.investigate import _determine_actor_for_finding, run_investigate
from mallcop.schemas import (
    Annotation,
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)

_NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)


def _make_event(eid: str = "e-1", actor: str = "user@test.com", source: str = "azure") -> Event:
    return Event(
        id=eid,
        timestamp=_NOW,
        ingested_at=_NOW,
        source=source,
        event_type="login",
        actor=actor,
        action="SignIn",
        target="subscription",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _make_finding(
    fid: str = "f-1",
    severity: Severity = Severity.CRITICAL,
    event_ids: list[str] | None = None,
    annotations: list[Annotation] | None = None,
) -> Finding:
    return Finding(
        id=fid,
        timestamp=_NOW,
        detector="test-detector",
        event_ids=event_ids or ["e-1"],
        title="Test finding",
        severity=severity,
        status=FindingStatus.OPEN,
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


def _make_baseline() -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities={"actors": []},
        relationships={},
    )


# --- run_investigate: finding not found ---


@patch("mallcop.investigate.JsonlStore")
@patch("mallcop.investigate.load_config")
def test_run_investigate_finding_not_found(mock_load_config, mock_store_cls, tmp_path):
    """run_investigate returns error when finding ID doesn't exist."""
    mock_load_config.return_value = _make_config()
    store = MagicMock()
    store.query_findings.return_value = []
    mock_store_cls.return_value = store

    result = run_investigate(tmp_path, "nonexistent-id")

    assert result["status"] == "error"
    assert "not found" in result["error"]


# --- run_investigate: empty event_ids ---


@patch("mallcop.investigate.JsonlStore")
@patch("mallcop.investigate.load_config")
def test_run_investigate_empty_event_ids(mock_load_config, mock_store_cls, tmp_path):
    """run_investigate returns ok with empty events when finding has no event_ids."""
    config = _make_config()
    mock_load_config.return_value = config

    finding = _make_finding("f-1", event_ids=[])
    store = MagicMock()
    store.query_findings.return_value = [finding]
    store.query_events.return_value = []
    store.get_baseline.return_value = _make_baseline()
    mock_store_cls.return_value = store

    result = run_investigate(tmp_path, "f-1")

    assert result["status"] == "ok"
    assert result["events"] == []
    assert result["actor_history"] == {}


# --- run_investigate: events matched correctly ---


@patch("mallcop.investigate.JsonlStore")
@patch("mallcop.investigate.load_config")
def test_run_investigate_matches_triggering_events(mock_load_config, mock_store_cls, tmp_path):
    """run_investigate returns only events matching the finding's event_ids."""
    config = _make_config()
    mock_load_config.return_value = config

    finding = _make_finding("f-1", event_ids=["e-1", "e-2"])
    e1 = _make_event("e-1", actor="alice")
    e2 = _make_event("e-2", actor="alice")
    e3 = _make_event("e-3", actor="bob")  # unrelated

    store = MagicMock()
    store.query_findings.return_value = [finding]
    store.query_events.return_value = [e1, e2, e3]
    store.get_baseline.return_value = _make_baseline()
    mock_store_cls.return_value = store

    result = run_investigate(tmp_path, "f-1")

    assert result["status"] == "ok"
    assert len(result["events"]) == 2
    # actor_history includes alice (from triggering events) but not bob
    assert "alice" in result["actor_history"]
    assert "bob" not in result["actor_history"]


# --- _determine_actor_for_finding: missing actor_chain entry ---


def test_determine_actor_no_route():
    """Returns None when routing has no entry for finding's severity."""
    finding = _make_finding(severity=Severity.WARN)
    actor = _determine_actor_for_finding(finding, routing={}, actor_chain={})
    assert actor is None


def test_determine_actor_route_config_entry():
    """Returns entry actor from RouteConfig when finding is untriaged."""
    finding = _make_finding(severity=Severity.CRITICAL)
    routing = {"critical": RouteConfig(chain=["triage"], notify=[])}

    actor = _determine_actor_for_finding(finding, routing, actor_chain={})
    assert actor == "triage"


def test_determine_actor_string_route_backward_compat():
    """Returns actor from legacy string routing format."""
    finding = _make_finding(severity=Severity.CRITICAL)
    routing = {"critical": "triage"}

    actor = _determine_actor_for_finding(finding, routing, actor_chain={})
    assert actor == "triage"


def test_determine_actor_follows_chain_after_triage():
    """After triage annotation, follows routes_to for next actor."""
    triage_ann = Annotation(
        actor="triage", timestamp=_NOW, content="triaged", action="triage", reason=None
    )
    finding = _make_finding(severity=Severity.CRITICAL, annotations=[triage_ann])
    routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
    actor_chain = {
        "triage": {"routes_to": "investigate"},
        "investigate": {},
    }

    actor = _determine_actor_for_finding(finding, routing, actor_chain)
    assert actor == "investigate"


def test_determine_actor_falls_back_to_entry_when_no_routes_to():
    """After triage, falls back to entry actor when no routes_to defined."""
    triage_ann = Annotation(
        actor="triage", timestamp=_NOW, content="triaged", action="triage", reason=None
    )
    finding = _make_finding(severity=Severity.CRITICAL, annotations=[triage_ann])
    routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
    actor_chain = {"triage": {}}  # no routes_to

    actor = _determine_actor_for_finding(finding, routing, actor_chain)
    assert actor == "triage"
