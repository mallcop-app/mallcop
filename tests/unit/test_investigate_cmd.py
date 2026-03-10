"""Tests for mallcop investigate command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from mallcop.schemas import (
    Annotation,
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.investigate import run_investigate


def _make_config(
    tmp_path: Path,
    routing: dict[str, str | None] | None = None,
    actor_chain: dict[str, dict[str, Any]] | None = None,
) -> None:
    if routing is None:
        routing = {
            "info": None,
            "warn": "triage",
            "critical": "triage",
        }
    if actor_chain is None:
        actor_chain = {
            "triage": {"routes_to": "notify-teams"},
            "notify-teams": {"routes_to": None},
        }
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": routing,
        "actor_chain": actor_chain,
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(tmp_path / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


def _make_finding(
    id: str,
    severity: Severity = Severity.WARN,
    status: FindingStatus = FindingStatus.OPEN,
    annotations: list[Annotation] | None = None,
    event_ids: list[str] | None = None,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new_actor",
        event_ids=event_ids or ["evt_001"],
        title=title,
        severity=severity,
        status=status,
        annotations=annotations or [],
        metadata={},
    )


def _make_event(
    id: str,
    actor: str = "user@example.com",
    source: str = "azure",
) -> Event:
    return Event(
        id=id,
        timestamp=datetime(2026, 3, 6, 11, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        source=source,
        event_type="login",
        actor=actor,
        action="login",
        target="portal",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _setup_actor_post_md(tmp_path: Path, actor_name: str, content: str) -> None:
    actor_dir = tmp_path / "actors" / actor_name
    actor_dir.mkdir(parents=True, exist_ok=True)
    (actor_dir / "POST.md").write_text(content)


def _write_findings(tmp_path: Path, findings: list[Finding]) -> None:
    with open(tmp_path / "findings.jsonl", "w") as f:
        for fnd in findings:
            f.write(fnd.to_json() + "\n")


def _write_events(tmp_path: Path, events: list[Event]) -> None:
    events_dir = tmp_path / "events"
    events_dir.mkdir(parents=True, exist_ok=True)
    with open(events_dir / "azure-2026-03.jsonl", "w") as f:
        for evt in events:
            f.write(evt.to_json() + "\n")


def _write_baseline(tmp_path: Path, baseline: Baseline) -> None:
    with open(tmp_path / "baseline.json", "w") as f:
        json.dump(baseline.to_dict(), f)


class TestInvestigateLoadsContext:
    def test_loads_finding_detail(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        finding = _make_finding("fnd_abc", title="Suspicious login")
        _write_findings(tmp_path, [finding])

        result = run_investigate(tmp_path, "fnd_abc")

        assert result["finding"]["id"] == "fnd_abc"
        assert result["finding"]["title"] == "Suspicious login"

    def test_finding_not_found(self, tmp_path: Path) -> None:
        _make_config(tmp_path)

        result = run_investigate(tmp_path, "fnd_nonexistent")

        assert result["status"] == "error"
        assert "not found" in result["error"]

    def test_loads_triggering_events(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        events = [
            _make_event("evt_001", actor="admin@corp.com"),
            _make_event("evt_002", actor="admin@corp.com"),
            _make_event("evt_003", actor="other@corp.com"),
        ]
        finding = _make_finding(
            "fnd_abc", event_ids=["evt_001", "evt_002"]
        )
        _write_findings(tmp_path, [finding])
        _write_events(tmp_path, events)

        result = run_investigate(tmp_path, "fnd_abc")

        event_ids = [e["id"] for e in result["events"]]
        assert "evt_001" in event_ids
        assert "evt_002" in event_ids
        assert "evt_003" not in event_ids

    def test_loads_baseline_for_involved_actors(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        events = [_make_event("evt_001", actor="admin@corp.com")]
        finding = _make_finding("fnd_abc", event_ids=["evt_001"])
        _write_findings(tmp_path, [finding])
        _write_events(tmp_path, events)

        baseline = Baseline(
            frequency_tables={"azure:login:admin@corp.com": 42},
            known_entities={"actors": ["admin@corp.com"], "sources": ["azure"]},
            relationships={"admin@corp.com": ["portal"]},
        )
        _write_baseline(tmp_path, baseline)

        result = run_investigate(tmp_path, "fnd_abc")

        assert "baseline" in result
        assert "admin@corp.com" in result["baseline"]["actors"]

    def test_loads_existing_annotations(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        annotations = [
            Annotation(
                actor="triage",
                timestamp=datetime(2026, 3, 6, 13, 0, 0, tzinfo=timezone.utc),
                content="Unknown actor. Escalated.",
                action="escalated",
                reason="Not in baseline",
            ),
        ]
        finding = _make_finding("fnd_abc", annotations=annotations)
        _write_findings(tmp_path, [finding])

        result = run_investigate(tmp_path, "fnd_abc")

        assert len(result["finding"]["annotations"]) == 1
        assert result["finding"]["annotations"][0]["content"] == "Unknown actor. Escalated."


class TestInvestigatePostMdSelection:
    def test_untriaged_finding_gets_triage_post_md(self, tmp_path: Path) -> None:
        _make_config(tmp_path, routing={"warn": "triage", "critical": "triage"})
        _setup_actor_post_md(tmp_path, "triage", "# Triage POST")
        finding = _make_finding("fnd_abc", severity=Severity.WARN)
        _write_findings(tmp_path, [finding])

        result = run_investigate(tmp_path, "fnd_abc")

        assert result["post_md"] == "# Triage POST"
        assert result["post_md_source"] == "triage"

    def test_triaged_finding_gets_next_actor_post_md(self, tmp_path: Path) -> None:
        _make_config(
            tmp_path,
            routing={"warn": "triage"},
            actor_chain={
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": None},
            },
        )
        _setup_actor_post_md(tmp_path, "triage", "# Triage POST")
        _setup_actor_post_md(tmp_path, "investigate", "# Investigate POST")

        annotations = [
            Annotation(
                actor="triage",
                timestamp=datetime(2026, 3, 6, 13, 0, 0, tzinfo=timezone.utc),
                content="Escalated for deeper investigation.",
                action="escalated",
                reason="Uncertain",
            ),
        ]
        finding = _make_finding("fnd_abc", severity=Severity.WARN, annotations=annotations)
        _write_findings(tmp_path, [finding])

        result = run_investigate(tmp_path, "fnd_abc")

        assert result["post_md"] == "# Investigate POST"
        assert result["post_md_source"] == "investigate"

    def test_fallback_to_builtin_post_md(self, tmp_path: Path) -> None:
        _make_config(tmp_path, routing={"warn": "triage"})
        finding = _make_finding("fnd_abc", severity=Severity.WARN)
        _write_findings(tmp_path, [finding])

        result = run_investigate(tmp_path, "fnd_abc")

        assert result["post_md"] is not None
        assert "Triage Agent" in result["post_md"]

    def test_no_routing_returns_none_post_md(self, tmp_path: Path) -> None:
        _make_config(tmp_path, routing={"info": None, "warn": None, "critical": None})
        finding = _make_finding("fnd_abc", severity=Severity.WARN)
        _write_findings(tmp_path, [finding])

        result = run_investigate(tmp_path, "fnd_abc")

        assert result["post_md"] is None

    def test_missing_post_md_falls_back_gracefully(self, tmp_path: Path) -> None:
        """When routing points to an actor with no POST.md, investigate
        does not crash and returns None for post_md."""
        _make_config(
            tmp_path,
            routing={"warn": "nonexistent_actor"},
            actor_chain={"nonexistent_actor": {"routes_to": None}},
        )
        finding = _make_finding("fnd_abc", severity=Severity.WARN)
        _write_findings(tmp_path, [finding])

        result = run_investigate(tmp_path, "fnd_abc")

        assert result["status"] == "ok"
        assert result["post_md"] is None
        assert result["finding"]["id"] == "fnd_abc"

    def test_escalated_finding_loads_builtin_investigate_post_md(self, tmp_path: Path) -> None:
        """When finding has been triaged and actor_chain routes to investigate,
        the built-in investigate POST.md is loaded."""
        _make_config(
            tmp_path,
            routing={"warn": "triage"},
            actor_chain={
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": None},
            },
        )
        # No deployment POST.md -- relies on built-in
        annotations = [
            Annotation(
                actor="triage",
                timestamp=datetime(2026, 3, 6, 13, 0, 0, tzinfo=timezone.utc),
                content="Escalated for deeper investigation.",
                action="escalated",
                reason="Uncertain",
            ),
        ]
        finding = _make_finding("fnd_abc", severity=Severity.WARN, annotations=annotations)
        _write_findings(tmp_path, [finding])

        result = run_investigate(tmp_path, "fnd_abc")

        assert result["post_md"] is not None
        assert result["post_md_source"] == "investigate"


class TestInvestigateActorHistory:
    def test_includes_actor_event_history(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        events = [
            _make_event("evt_001", actor="admin@corp.com"),
            _make_event("evt_002", actor="admin@corp.com"),
            _make_event("evt_003", actor="other@corp.com"),
        ]
        finding = _make_finding("fnd_abc", event_ids=["evt_001"])
        _write_findings(tmp_path, [finding])
        _write_events(tmp_path, events)

        result = run_investigate(tmp_path, "fnd_abc")

        actor_events = result["actor_history"]
        assert "admin@corp.com" in actor_events
        assert len(actor_events["admin@corp.com"]) == 2
