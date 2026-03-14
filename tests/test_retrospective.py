"""Tests for learning mode retrospective analysis."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.baseline import is_learning_mode, retrospective_analysis
from mallcop.schemas import (
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_event(
    eid: str = "evt_001",
    source: str = "azure",
    event_type: str = "new-actor",
    actor: str = "alice",
    timestamp: datetime | None = None,
    daysago: int = 7,
) -> Event:
    ts = timestamp or (datetime.now(timezone.utc) - timedelta(days=daysago))
    return Event(
        id=eid,
        timestamp=ts,
        ingested_at=ts,
        source=source,
        event_type=event_type,
        actor=actor,
        action="login",
        target="/subscriptions/sub-001",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _empty_baseline() -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities={},
        relationships={},
        actor_context={},
    )


# ---------------------------------------------------------------------------
# retrospective_analysis() tests
# ---------------------------------------------------------------------------

class TestRetrospectiveAnalysis:
    def test_returns_empty_list_when_no_suspicious_events(self):
        """Retrospective with benign events returns no findings."""
        events = [_make_event(eid=f"e{i}", daysago=7) for i in range(5)]
        baseline = _empty_baseline()

        # Patch detectors to return nothing
        with patch("mallcop.baseline.run_detect", return_value=[]):
            result = retrospective_analysis("azure", events, baseline)
        assert result == []

    def test_retrospective_runs_detectors_on_learning_period_events(self):
        """Retrospective passes learning-period events to detectors.

        Learning period = [earliest event timestamp, earliest + 14 days].
        Events after the learning window should not be included.
        """
        # Events from 20 days ago: within the learning window (earliest is 20 days ago)
        events_in_window = [_make_event(eid=f"e{i}", daysago=20) for i in range(3)]
        # Events from 3 days ago: AFTER the learning window (cutoff = 20 - 14 = 6 days ago)
        events_outside = [_make_event(eid=f"new{i}", daysago=3) for i in range(2)]
        all_events = events_in_window + events_outside
        baseline = _empty_baseline()

        captured_events: list[list[Event]] = []

        def mock_detect(evts, bl, learning_connectors, **kwargs):
            captured_events.append(evts)
            return []

        with patch("mallcop.baseline.run_detect", side_effect=mock_detect):
            retrospective_analysis("azure", all_events, baseline)

        # Only learning-period events should be passed to detectors
        assert len(captured_events) == 1
        passed_event_ids = {e.id for e in captured_events[0]}
        assert all(e.id in passed_event_ids for e in events_in_window)
        assert not any(e.id in passed_event_ids for e in events_outside)

    def test_retrospective_findings_tagged_with_source(self):
        """Retrospective findings have source=retrospective in metadata."""
        events = [_make_event(eid="e1", daysago=7, event_type="priv-escalation")]
        baseline = _empty_baseline()

        mock_finding = Finding(
            id="fnd_retro",
            timestamp=datetime.now(timezone.utc),
            detector="priv-escalation",
            event_ids=["e1"],
            title="Privilege escalation detected",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )

        with patch("mallcop.baseline.run_detect", return_value=[mock_finding]):
            result = retrospective_analysis("azure", events, baseline)

        assert len(result) == 1
        assert result[0].metadata.get("source") == "retrospective"

    def test_retrospective_runs_detectors_in_non_learning_mode(self):
        """Retrospective passes empty learning_connectors (post-learning)."""
        events = [_make_event(eid="e1", daysago=7)]
        baseline = _empty_baseline()

        captured_kwargs: list[dict] = []

        def mock_detect(evts, bl, learning_connectors, **kwargs):
            captured_kwargs.append({"learning_connectors": learning_connectors})
            return []

        with patch("mallcop.baseline.run_detect", side_effect=mock_detect):
            retrospective_analysis("azure", events, baseline)

        # Retrospective runs with empty learning_connectors — we're past learning mode
        assert captured_kwargs[0]["learning_connectors"] == set()

    def test_retrospective_with_empty_events_returns_empty(self):
        """No events = no retrospective analysis."""
        baseline = _empty_baseline()
        result = retrospective_analysis("azure", [], baseline)
        assert result == []

    def test_retrospective_filters_to_connector_events(self):
        """Retrospective only processes events for the specified connector."""
        azure_events = [_make_event(eid=f"az{i}", source="azure", daysago=7) for i in range(3)]
        github_events = [_make_event(eid=f"gh{i}", source="github", daysago=7) for i in range(2)]
        all_events = azure_events + github_events
        baseline = _empty_baseline()

        captured_events: list[list[Event]] = []

        def mock_detect(evts, bl, learning_connectors, **kwargs):
            captured_events.append(evts)
            return []

        with patch("mallcop.baseline.run_detect", side_effect=mock_detect):
            retrospective_analysis("azure", all_events, baseline)

        passed_event_ids = {e.id for e in captured_events[0]}
        assert all(e.id in passed_event_ids for e in azure_events)
        assert not any(e.id in passed_event_ids for e in github_events)


# ---------------------------------------------------------------------------
# Learning mode transition detection in detect pipeline
# ---------------------------------------------------------------------------

class TestLearningModeTransition:
    def test_no_transition_when_still_learning(self, tmp_path: Path):
        """No retrospective when connector is still in learning mode."""
        from mallcop.cli import _run_detect_pipeline
        from mallcop.store import JsonlStore

        store = JsonlStore(tmp_path)

        # Store events from 3 days ago (within 14-day window = still learning)
        events = [_make_event(eid=f"e{i}", source="azure", daysago=3) for i in range(5)]
        store.append_events(events)

        import yaml
        (tmp_path / "mallcop.yaml").write_text(yaml.dump({
            "secrets": {"backend": "env"},
            "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
            "routing": {},
            "actor_chain": {},
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }))

        with patch("mallcop.cli.retrospective_analysis") as mock_retro:
            mock_retro.return_value = []
            with patch("mallcop.baseline.run_detect", return_value=[]):
                _run_detect_pipeline(tmp_path, store=store)

        # retrospective_analysis should NOT have been called (still in learning mode)
        assert not mock_retro.called

    def test_transition_triggers_retrospective(self, tmp_path: Path):
        """Connector transitioning from learning → normal triggers retrospective."""
        from mallcop.cli import _run_detect_pipeline
        from mallcop.store import JsonlStore
        from mallcop.schemas import Checkpoint

        store = JsonlStore(tmp_path)

        # Store events from 15 days ago (past 14-day window = learning mode ended)
        events = [_make_event(eid=f"e{i}", source="azure", daysago=15) for i in range(5)]
        store.append_events(events)

        # Mark connector as previously in learning mode (previous run was learning)
        store.set_checkpoint(Checkpoint(
            connector="azure:learning_mode_was_active",
            value="true",
            updated_at=datetime.now(timezone.utc),
        ))

        import yaml
        (tmp_path / "mallcop.yaml").write_text(yaml.dump({
            "secrets": {"backend": "env"},
            "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
            "routing": {},
            "actor_chain": {},
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }))

        retrospective_called = []

        with patch("mallcop.cli.retrospective_analysis") as mock_retro:
            mock_retro.return_value = []
            with patch("mallcop.baseline.run_detect", return_value=[]):
                _run_detect_pipeline(tmp_path, store=store)

        # retrospective_analysis should have been called for the azure connector
        assert mock_retro.called
        call_args = mock_retro.call_args
        assert call_args[0][0] == "azure"  # connector name

    def test_retrospective_not_repeated_after_first_run(self, tmp_path: Path):
        """Retrospective runs only once per connector per transition."""
        from mallcop.cli import _run_detect_pipeline
        from mallcop.store import JsonlStore
        from mallcop.schemas import Checkpoint

        store = JsonlStore(tmp_path)

        events = [_make_event(eid=f"e{i}", source="azure", daysago=15) for i in range(5)]
        store.append_events(events)

        # Mark: was in learning mode
        store.set_checkpoint(Checkpoint(
            connector="azure:learning_mode_was_active",
            value="true",
            updated_at=datetime.now(timezone.utc),
        ))
        # Mark: retrospective already done
        store.set_checkpoint(Checkpoint(
            connector="azure:retrospective_done",
            value="true",
            updated_at=datetime.now(timezone.utc),
        ))

        import yaml
        (tmp_path / "mallcop.yaml").write_text(yaml.dump({
            "secrets": {"backend": "env"},
            "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
            "routing": {},
            "actor_chain": {},
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }))

        with patch("mallcop.cli.retrospective_analysis") as mock_retro:
            mock_retro.return_value = []
            with patch("mallcop.baseline.run_detect", return_value=[]):
                _run_detect_pipeline(tmp_path, store=store)

        # Should NOT run again
        assert not mock_retro.called
