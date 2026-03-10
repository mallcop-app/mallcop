"""Tests for actor chain validation warnings (mallcop-208)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from mallcop.schemas import (
    Annotation,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.review import _select_actor_for_review
from mallcop.investigate import _determine_actor_for_finding
from mallcop.config import RouteConfig


class TestReviewActorChainValidation:
    """_select_actor_for_review should warn on dangling routes_to."""

    def test_valid_routes_to_no_warning(self, caplog):
        """No warning when routes_to points to a valid actor in the chain."""
        findings_by_severity = {
            "critical": [
                {
                    "id": "f1",
                    "annotations": [{"actor": "triage", "text": "ok"}],
                }
            ],
        }
        routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
        actor_chain = {
            "triage": {"routes_to": "investigate"},
            "investigate": {"routes_to": None},
        }

        with caplog.at_level(logging.WARNING, logger="mallcop.review"):
            result = _select_actor_for_review(findings_by_severity, routing, actor_chain)

        assert result == "investigate"
        assert not any("dangling" in r.message.lower() or "not found" in r.message.lower() for r in caplog.records)

    def test_dangling_routes_to_logs_warning(self, caplog):
        """Warning when routes_to references an actor not in actor_chain."""
        findings_by_severity = {
            "critical": [
                {
                    "id": "f1",
                    "annotations": [{"actor": "triage", "text": "ok"}],
                }
            ],
        }
        routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
        actor_chain = {
            "triage": {"routes_to": "nonexistent-actor"},
        }

        with caplog.at_level(logging.WARNING, logger="mallcop.review"):
            result = _select_actor_for_review(findings_by_severity, routing, actor_chain)

        # Should still return the actor (existing behavior), but log a warning
        assert result == "nonexistent-actor"
        assert any("nonexistent-actor" in r.message for r in caplog.records)

    def test_routes_to_none_no_warning(self, caplog):
        """No warning when routes_to is None (end of chain)."""
        findings_by_severity = {
            "critical": [
                {
                    "id": "f1",
                    "annotations": [{"actor": "triage", "text": "ok"}],
                }
            ],
        }
        routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
        actor_chain = {
            "triage": {"routes_to": None},
        }

        with caplog.at_level(logging.WARNING, logger="mallcop.review"):
            result = _select_actor_for_review(findings_by_severity, routing, actor_chain)

        assert result == "triage"
        assert not any("dangling" in r.message.lower() or "not found" in r.message.lower() for r in caplog.records)


class TestInvestigateActorChainValidation:
    """_determine_actor_for_finding should warn on dangling routes_to."""

    def _make_finding(self, annotations=None):
        return Finding(
            id="f1",
            detector="new-actor",
            severity=Severity.CRITICAL,
            title="Test finding",
            event_ids=["e1"],
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            status=FindingStatus.OPEN,
            annotations=annotations or [],
            metadata={},
        )

    def test_valid_routes_to_no_warning(self, caplog):
        """No warning when routes_to points to a valid actor."""
        finding = self._make_finding(
            annotations=[Annotation(
                actor="triage", content="ok",
                timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
                action="annotate", reason=None,
            )]
        )
        routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
        actor_chain = {
            "triage": {"routes_to": "investigate"},
            "investigate": {"routes_to": None},
        }

        with caplog.at_level(logging.WARNING, logger="mallcop.investigate"):
            result = _determine_actor_for_finding(finding, routing, actor_chain)

        assert result == "investigate"
        assert not any("dangling" in r.message.lower() or "not found" in r.message.lower() for r in caplog.records)

    def test_dangling_routes_to_logs_warning(self, caplog):
        """Warning when routes_to references an actor not in actor_chain."""
        finding = self._make_finding(
            annotations=[Annotation(
                actor="triage", content="ok",
                timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
                action="annotate", reason=None,
            )]
        )
        routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
        actor_chain = {
            "triage": {"routes_to": "ghost-actor"},
        }

        with caplog.at_level(logging.WARNING, logger="mallcop.investigate"):
            result = _determine_actor_for_finding(finding, routing, actor_chain)

        assert result == "ghost-actor"
        assert any("ghost-actor" in r.message for r in caplog.records)

    def test_routes_to_none_no_warning(self, caplog):
        """No warning when routes_to is None."""
        finding = self._make_finding(
            annotations=[Annotation(
                actor="triage", content="ok",
                timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
                action="annotate", reason=None,
            )]
        )
        routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
        actor_chain = {
            "triage": {"routes_to": None},
        }

        with caplog.at_level(logging.WARNING, logger="mallcop.investigate"):
            result = _determine_actor_for_finding(finding, routing, actor_chain)

        assert result == "triage"
        assert not any("dangling" in r.message.lower() or "not found" in r.message.lower() for r in caplog.records)

    def test_untriaged_finding_returns_entry_actor_no_warning(self, caplog):
        """Untriaged finding returns entry actor, no chain validation needed."""
        finding = self._make_finding(annotations=[])
        routing = {"critical": RouteConfig(chain=["triage"], notify=[])}
        actor_chain = {
            "triage": {"routes_to": "ghost-actor"},
        }

        with caplog.at_level(logging.WARNING, logger="mallcop.investigate"):
            result = _determine_actor_for_finding(finding, routing, actor_chain)

        assert result == "triage"
        assert not any("ghost-actor" in r.message for r in caplog.records)
