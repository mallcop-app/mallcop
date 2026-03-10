"""Tests for mallcop review command."""

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
from mallcop.review import run_review


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


class TestReviewGroupsBySeverity:
    def test_groups_findings_by_severity(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        findings = [
            _make_finding("fnd_001", severity=Severity.WARN, title="Warn 1"),
            _make_finding("fnd_002", severity=Severity.CRITICAL, title="Critical 1"),
            _make_finding("fnd_003", severity=Severity.WARN, title="Warn 2"),
            _make_finding("fnd_004", severity=Severity.INFO, title="Info 1"),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        groups = result["findings_by_severity"]
        assert "critical" in groups
        assert "warn" in groups
        assert "info" in groups
        assert len(groups["critical"]) == 1
        assert len(groups["warn"]) == 2
        assert len(groups["info"]) == 1

    def test_critical_listed_first(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        findings = [
            _make_finding("fnd_001", severity=Severity.WARN),
            _make_finding("fnd_002", severity=Severity.CRITICAL),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        severity_order = list(result["findings_by_severity"].keys())
        crit_idx = severity_order.index("critical")
        warn_idx = severity_order.index("warn")
        assert crit_idx < warn_idx

    def test_only_open_findings_included(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        findings = [
            _make_finding("fnd_001", status=FindingStatus.OPEN),
            _make_finding("fnd_002", status=FindingStatus.RESOLVED),
            _make_finding("fnd_003", status=FindingStatus.ACKED),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        all_ids = []
        for group in result["findings_by_severity"].values():
            all_ids.extend(f["id"] for f in group)
        assert all_ids == ["fnd_001"]


class TestReviewPostMdSelection:
    def test_selects_post_md_from_routing_config(self, tmp_path: Path) -> None:
        _make_config(tmp_path, routing={"warn": "triage", "critical": "triage"})
        _setup_actor_post_md(tmp_path, "triage", "# Triage POST")
        findings = [
            _make_finding("fnd_001", severity=Severity.CRITICAL),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        assert result["post_md"] == "# Triage POST"
        assert result["post_md_source"] == "triage"

    def test_selects_post_md_for_highest_severity(self, tmp_path: Path) -> None:
        _make_config(
            tmp_path,
            routing={"warn": "triage", "critical": "investigate"},
        )
        _setup_actor_post_md(tmp_path, "triage", "# Triage POST")
        _setup_actor_post_md(tmp_path, "investigate", "# Investigate POST")
        findings = [
            _make_finding("fnd_001", severity=Severity.WARN),
            _make_finding("fnd_002", severity=Severity.CRITICAL),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        assert result["post_md"] == "# Investigate POST"
        assert result["post_md_source"] == "investigate"

    def test_no_post_md_when_no_routing(self, tmp_path: Path) -> None:
        _make_config(tmp_path, routing={"info": None, "warn": None, "critical": None})
        findings = [
            _make_finding("fnd_001", severity=Severity.WARN),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        assert result["post_md"] is None
        assert result["post_md_source"] is None

    def test_fallback_to_builtin_post_md(self, tmp_path: Path) -> None:
        _make_config(tmp_path, routing={"warn": "triage", "critical": "triage"})
        findings = [
            _make_finding("fnd_001", severity=Severity.WARN),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        assert result["post_md"] is not None
        assert "Triage Agent" in result["post_md"]
        assert result["post_md_source"] == "triage"

    def test_no_findings_returns_empty(self, tmp_path: Path) -> None:
        _make_config(tmp_path)

        result = run_review(tmp_path)

        assert result["findings_by_severity"] == {}
        assert result["post_md"] is None
        assert result["suggested_commands"] == []


class TestReviewSuggestedCommands:
    def test_generates_commands_with_finding_ids(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        findings = [
            _make_finding("fnd_abc", severity=Severity.WARN, event_ids=["evt_001"]),
        ]
        _write_findings(tmp_path, findings)
        _write_events(tmp_path, [_make_event("evt_001", actor="admin@corp.com")])

        result = run_review(tmp_path)

        cmds = result["suggested_commands"]
        assert any("investigate fnd_abc" in c for c in cmds)
        assert any("finding fnd_abc" in c for c in cmds)
        assert any("events --finding fnd_abc" in c for c in cmds)

    def test_commands_include_annotate_and_ack(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        findings = [
            _make_finding("fnd_xyz", severity=Severity.CRITICAL),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        cmds = result["suggested_commands"]
        assert any("annotate fnd_xyz" in c for c in cmds)
        assert any("ack fnd_xyz" in c for c in cmds)

    def test_commands_for_multiple_findings(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        findings = [
            _make_finding("fnd_001", severity=Severity.WARN),
            _make_finding("fnd_002", severity=Severity.CRITICAL),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        cmds = result["suggested_commands"]
        assert any("investigate fnd_001" in c for c in cmds)
        assert any("investigate fnd_002" in c for c in cmds)


class TestReviewPostMdSelectionByState:
    """POST.md selection considers finding annotation state, not just routing."""

    def test_critical_triaged_findings_load_investigate_post_md(self, tmp_path: Path) -> None:
        """When highest-severity (CRITICAL) findings have triage annotations,
        review should load the next actor's POST.md (investigate), not triage."""
        _make_config(
            tmp_path,
            routing={"warn": "triage", "critical": "triage"},
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
                content="Unknown actor, not in baseline. Escalated.",
                action="escalated",
                reason="Not in baseline",
            ),
        ]
        findings = [
            _make_finding("fnd_001", severity=Severity.CRITICAL, annotations=annotations),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        assert result["post_md"] == "# Investigate POST"
        assert result["post_md_source"] == "investigate"

    def test_warn_untriaged_findings_load_triage_post_md(self, tmp_path: Path) -> None:
        """When highest-severity findings (WARN) have no annotations,
        review should load the entry actor's POST.md (triage)."""
        _make_config(
            tmp_path,
            routing={"warn": "triage", "critical": "triage"},
            actor_chain={
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": None},
            },
        )
        _setup_actor_post_md(tmp_path, "triage", "# Triage POST")
        _setup_actor_post_md(tmp_path, "investigate", "# Investigate POST")

        findings = [
            _make_finding("fnd_001", severity=Severity.WARN),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        assert result["post_md"] == "# Triage POST"
        assert result["post_md_source"] == "triage"

    def test_mixed_annotations_uses_majority_state(self, tmp_path: Path) -> None:
        """When some findings in the highest-severity group are triaged and
        some are not, review should load POST.md for the untriaged state
        (triage) since there's still work to do at that level."""
        _make_config(
            tmp_path,
            routing={"critical": "triage"},
            actor_chain={
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": None},
            },
        )
        _setup_actor_post_md(tmp_path, "triage", "# Triage POST")
        _setup_actor_post_md(tmp_path, "investigate", "# Investigate POST")

        triaged = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 6, 13, 0, 0, tzinfo=timezone.utc),
            content="Escalated.",
            action="escalated",
            reason="Uncertain",
        )
        findings = [
            _make_finding("fnd_001", severity=Severity.CRITICAL, annotations=[triaged]),
            _make_finding("fnd_002", severity=Severity.CRITICAL),  # untriaged
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        # Some findings still need triage, so triage POST.md is appropriate
        assert result["post_md"] == "# Triage POST"
        assert result["post_md_source"] == "triage"

    def test_all_triaged_escalated_loads_investigate(self, tmp_path: Path) -> None:
        """When ALL findings in the highest-severity group have triage annotations,
        review loads the investigate POST.md."""
        _make_config(
            tmp_path,
            routing={"critical": "triage"},
            actor_chain={
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": None},
            },
        )
        _setup_actor_post_md(tmp_path, "triage", "# Triage POST")
        _setup_actor_post_md(tmp_path, "investigate", "# Investigate POST")

        triaged = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 6, 13, 0, 0, tzinfo=timezone.utc),
            content="Escalated.",
            action="escalated",
            reason="Uncertain",
        )
        findings = [
            _make_finding("fnd_001", severity=Severity.CRITICAL, annotations=[triaged]),
            _make_finding("fnd_002", severity=Severity.CRITICAL, annotations=[triaged]),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        assert result["post_md"] == "# Investigate POST"
        assert result["post_md_source"] == "investigate"

    def test_missing_post_md_falls_back_gracefully(self, tmp_path: Path) -> None:
        """When routing points to an actor that has no POST.md, review
        does not crash and returns None for post_md."""
        _make_config(
            tmp_path,
            routing={"critical": "nonexistent_actor"},
        )
        findings = [
            _make_finding("fnd_001", severity=Severity.CRITICAL),
        ]
        _write_findings(tmp_path, findings)

        result = run_review(tmp_path)

        assert result["post_md"] is None
        assert result["post_md_source"] is None
        # Findings still present despite missing POST.md
        assert "critical" in result["findings_by_severity"]

    def test_builtin_investigate_post_md_exists(self, tmp_path: Path) -> None:
        """The built-in investigate actor directory has a POST.md that can
        be loaded as a fallback."""
        from mallcop.review import _find_post_md

        # No deployment POST.md -- should find the built-in
        post_md = _find_post_md("investigate", tmp_path)

        assert post_md is not None
        assert len(post_md) > 0
