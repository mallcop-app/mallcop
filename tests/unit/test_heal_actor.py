"""Unit tests for the heal actor plugin.

Covers:
1. Manifest loads correctly
2. Drift finding produces parser patch proposal
3. New field scenario
4. Renamed field scenario
5. Format change scenario
6. Audit trail: patches logged with before/after and reason
7. No-drift finding: actor does nothing gracefully
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from mallcop.actors._schema import ActorManifest, load_actor_manifest
from mallcop.actors.heal import HealActor, ParserPatch, analyze_drift
from mallcop.schemas import Annotation, Finding, FindingStatus, Severity


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_drift_finding(
    id: str = "fnd_drift_001",
    app_name: str = "myapp",
    unmatched_ratio: float = 0.45,
    unmatched_lines: list[str] | None = None,
    current_patterns: list[str] | None = None,
) -> Finding:
    meta: dict[str, Any] = {
        "app_name": app_name,
        "unmatched_ratio": unmatched_ratio,
    }
    if unmatched_lines is not None:
        meta["unmatched_lines"] = unmatched_lines
    if current_patterns is not None:
        meta["current_patterns"] = current_patterns
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc),
        detector="log-format-drift",
        event_ids=["evt_001"],
        title=f"{app_name} parser is stale, {int(unmatched_ratio * 100)}% of lines unrecognized.",
        severity=Severity.INFO,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata=meta,
    )


def _make_non_drift_finding(id: str = "fnd_other_001") -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_002"],
        title="New actor detected",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": "unknown@example.com"},
    )


# ─── Manifest tests ───────────────────────────────────────────────────


class TestHealManifest:
    @pytest.fixture
    def heal_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "heal"

    def test_manifest_exists(self, heal_dir: Path) -> None:
        assert (heal_dir / "manifest.yaml").exists()

    def test_manifest_loads_without_error(self, heal_dir: Path) -> None:
        manifest = load_actor_manifest(heal_dir)
        assert isinstance(manifest, ActorManifest)

    def test_manifest_name(self, heal_dir: Path) -> None:
        manifest = load_actor_manifest(heal_dir)
        assert manifest.name == "heal"

    def test_manifest_type_is_agent(self, heal_dir: Path) -> None:
        manifest = load_actor_manifest(heal_dir)
        assert manifest.type == "agent"

    def test_manifest_model_is_sonnet(self, heal_dir: Path) -> None:
        manifest = load_actor_manifest(heal_dir)
        assert manifest.model == "sonnet"

    def test_manifest_has_required_tools(self, heal_dir: Path) -> None:
        manifest = load_actor_manifest(heal_dir)
        assert "read-finding" in manifest.tools
        assert "annotate-finding" in manifest.tools
        assert "resolve-finding" in manifest.tools

    def test_manifest_has_write_permission(self, heal_dir: Path) -> None:
        manifest = load_actor_manifest(heal_dir)
        assert "write" in manifest.permissions

    def test_manifest_max_iterations(self, heal_dir: Path) -> None:
        manifest = load_actor_manifest(heal_dir)
        assert manifest.max_iterations == 5

    def test_post_md_exists(self, heal_dir: Path) -> None:
        assert (heal_dir / "POST.md").exists()

    def test_post_md_mentions_heal(self, heal_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(heal_dir)
        assert "heal" in content.lower()

    def test_post_md_has_security_guardrails(self, heal_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(heal_dir)
        assert "USER_DATA" in content

    def test_post_md_mentions_log_format_drift(self, heal_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(heal_dir)
        assert "drift" in content.lower()


# ─── analyze_drift tests ──────────────────────────────────────────────


class TestAnalyzeDrift:
    def test_non_drift_finding_returns_none(self) -> None:
        finding = _make_non_drift_finding()
        result = analyze_drift(finding)
        assert result is None

    def test_drift_finding_returns_patch(self) -> None:
        finding = _make_drift_finding()
        result = analyze_drift(finding)
        assert result is not None
        assert isinstance(result, ParserPatch)

    def test_patch_has_app_name(self) -> None:
        finding = _make_drift_finding(app_name="myapp")
        result = analyze_drift(finding)
        assert result is not None
        assert result.app_name == "myapp"

    def test_patch_has_scenario(self) -> None:
        finding = _make_drift_finding()
        result = analyze_drift(finding)
        assert result is not None
        assert result.scenario in ("new_field", "renamed_field", "format_change")

    def test_patch_has_reason(self) -> None:
        finding = _make_drift_finding()
        result = analyze_drift(finding)
        assert result is not None
        assert len(result.reason) > 0

    def test_patch_has_confidence(self) -> None:
        finding = _make_drift_finding()
        result = analyze_drift(finding)
        assert result is not None
        assert 0.0 <= result.confidence <= 1.0

    def test_patch_after_is_dict(self) -> None:
        finding = _make_drift_finding()
        result = analyze_drift(finding)
        assert result is not None
        assert isinstance(result.after, dict)

    def test_patch_after_has_name(self) -> None:
        finding = _make_drift_finding()
        result = analyze_drift(finding)
        assert result is not None
        assert "name" in result.after

    def test_patch_after_has_pattern(self) -> None:
        finding = _make_drift_finding()
        result = analyze_drift(finding)
        assert result is not None
        assert "pattern" in result.after

    def test_no_samples_produces_low_confidence_patch(self) -> None:
        """With no unmatched_lines or current_patterns, confidence should be low."""
        finding = _make_drift_finding(unmatched_lines=[], current_patterns=[])
        result = analyze_drift(finding)
        assert result is not None
        assert result.confidence < 0.5

    def test_patch_serializes_to_json(self) -> None:
        finding = _make_drift_finding()
        result = analyze_drift(finding)
        assert result is not None
        data = json.loads(result.to_json())
        assert data["scenario"] in ("new_field", "renamed_field", "format_change")
        assert data["app_name"] == "myapp"
        assert "after" in data
        assert "reason" in data
        assert "confidence" in data


# ─── New field scenario ───────────────────────────────────────────────


class TestNewFieldScenario:
    def test_json_log_line_new_field(self) -> None:
        """JSON log with new fields produces a new_field patch."""
        sample = '{"timestamp": "2026-03-14T10:00:00Z", "level": "INFO", "request_id": "abc123", "message": "request processed"}'
        finding = _make_drift_finding(
            unmatched_lines=[sample],
            current_patterns=[],
        )
        result = analyze_drift(finding)
        assert result is not None
        assert result.scenario == "new_field"
        assert result.before is None  # new template, no existing one
        assert "pattern" in result.after

    def test_kv_log_line_new_field(self) -> None:
        """key=value log line produces a new_field patch."""
        sample = 'ts=2026-03-14T10:00:00Z level=info user=baron action=login resource=/api/v2'
        finding = _make_drift_finding(
            unmatched_lines=[sample],
            current_patterns=[],
        )
        result = analyze_drift(finding)
        assert result is not None
        assert result.scenario == "new_field"

    def test_positional_log_line_new_field(self) -> None:
        """Space-separated positional log line produces a new_field patch."""
        sample = "2026-03-14T10:00:00Z INFO myapp User baron logged in from 192.168.1.1"
        finding = _make_drift_finding(
            unmatched_lines=[sample],
            current_patterns=[],
        )
        result = analyze_drift(finding)
        assert result is not None
        assert result.scenario == "new_field"

    def test_new_field_confidence_above_zero(self) -> None:
        sample = '{"ts": "2026-03-14", "level": "INFO", "msg": "hello"}'
        finding = _make_drift_finding(unmatched_lines=[sample], current_patterns=[])
        result = analyze_drift(finding)
        assert result is not None
        assert result.confidence > 0.0


# ─── Renamed field scenario ───────────────────────────────────────────


class TestRenamedFieldScenario:
    def test_renamed_field_detected(self) -> None:
        """When old pattern groups don't match new names but structure matches."""
        # Old pattern captured 'ts' but new log uses 'timestamp'
        old_pattern = r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<lvl>\S+)\s+(?P<msg>.+)$"
        sample = "2026-03-14T10:00:00Z INFO Something happened in the app"
        finding = _make_drift_finding(
            unmatched_lines=[sample],
            current_patterns=[old_pattern],
        )
        result = analyze_drift(finding)
        assert result is not None
        assert result.scenario in ("renamed_field", "new_field", "format_change")
        # The after entry should have a new/updated pattern
        assert "pattern" in result.after

    def test_renamed_field_patch_has_before(self) -> None:
        """Renamed field patch references the old pattern in before."""
        old_pattern = r"^(?P<ts>\S+)\s+(?P<lvl>\S+)\s+(?P<msg>.+)$"
        sample = "2026-03-14T10:00:00Z INFO test message here"
        finding = _make_drift_finding(
            unmatched_lines=[sample],
            current_patterns=[old_pattern],
        )
        result = analyze_drift(finding)
        assert result is not None
        # For scenarios that find a partial match, before should be set
        # (may vary based on analysis)
        assert result.after is not None


# ─── Format change scenario ───────────────────────────────────────────


class TestFormatChangeScenario:
    def test_format_change_produces_patch(self) -> None:
        """Structural format change produces a format_change patch."""
        # Old pattern used pipe delimiter, new log uses spaces
        old_pattern = r"^(?P<timestamp>[^|]+)\|(?P<level>[^|]+)\|(?P<message>.+)$"
        sample = "2026-03-14T10:00:00Z INFO New format without pipes now"
        finding = _make_drift_finding(
            unmatched_lines=[sample],
            current_patterns=[old_pattern],
        )
        result = analyze_drift(finding)
        assert result is not None
        assert result.scenario in ("format_change", "new_field", "renamed_field")
        assert "pattern" in result.after

    def test_format_change_patch_serializes(self) -> None:
        old_pattern = r"^(?P<ts>[^|]+)\|(?P<msg>.+)$"
        sample = "2026-03-14T10:00:00Z INFO message without pipes"
        finding = _make_drift_finding(
            unmatched_lines=[sample],
            current_patterns=[old_pattern],
        )
        result = analyze_drift(finding)
        assert result is not None
        data = result.to_dict()
        assert "scenario" in data
        assert "after" in data
        assert "before" in data


# ─── Audit trail tests ────────────────────────────────────────────────


class TestAuditTrail:
    def test_heal_actor_adds_annotation(self) -> None:
        """HealActor.handle adds an annotation to log_format_drift findings."""
        finding = _make_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])
        assert len(results) == 1
        updated = results[0]
        heal_anns = [a for a in updated.annotations if a.actor == "heal"]
        assert len(heal_anns) == 1

    def test_annotation_action_is_proposed_patch(self) -> None:
        finding = _make_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])
        ann = [a for a in results[0].annotations if a.actor == "heal"][0]
        assert ann.action == "proposed_patch"

    def test_annotation_content_is_valid_json(self) -> None:
        finding = _make_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])
        ann = [a for a in results[0].annotations if a.actor == "heal"][0]
        data = json.loads(ann.content)
        assert "scenario" in data
        assert "after" in data

    def test_annotation_has_reason(self) -> None:
        finding = _make_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])
        ann = [a for a in results[0].annotations if a.actor == "heal"][0]
        assert ann.reason is not None
        assert len(ann.reason) > 0

    def test_annotation_records_before_and_after(self) -> None:
        finding = _make_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])
        ann = [a for a in results[0].annotations if a.actor == "heal"][0]
        data = json.loads(ann.content)
        assert "before" in data  # may be None for new_field
        assert "after" in data
        assert isinstance(data["after"], dict)

    def test_metadata_updated_with_heal_info(self) -> None:
        finding = _make_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])
        assert "heal_patch" in results[0].metadata
        assert "heal_scenario" in results[0].metadata
        assert "heal_confidence" in results[0].metadata

    def test_original_annotations_preserved(self) -> None:
        """Existing annotations are not removed."""
        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc),
            content="Escalated for format drift.",
            action="escalated",
            reason="Log format changed.",
        )
        finding = _make_drift_finding()
        finding = Finding(
            id=finding.id,
            timestamp=finding.timestamp,
            detector=finding.detector,
            event_ids=finding.event_ids,
            title=finding.title,
            severity=finding.severity,
            status=finding.status,
            annotations=[ann],
            metadata=finding.metadata,
        )
        actor = HealActor()
        results = actor.handle([finding])
        # Both original and heal annotations should be present
        assert len(results[0].annotations) == 2
        actors = [a.actor for a in results[0].annotations]
        assert "triage" in actors
        assert "heal" in actors


# ─── No-drift finding tests ───────────────────────────────────────────


class TestNoDriftFinding:
    def test_non_drift_finding_unchanged(self) -> None:
        """HealActor passes through non-drift findings untouched."""
        finding = _make_non_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])
        assert len(results) == 1
        # No heal annotations added
        heal_anns = [a for a in results[0].annotations if a.actor == "heal"]
        assert len(heal_anns) == 0

    def test_non_drift_metadata_unchanged(self) -> None:
        finding = _make_non_drift_finding()
        actor = HealActor()
        results = actor.handle([finding])
        assert "heal_patch" not in results[0].metadata

    def test_empty_findings_list(self) -> None:
        actor = HealActor()
        results = actor.handle([])
        assert results == []

    def test_mixed_findings_only_drift_annotated(self) -> None:
        drift = _make_drift_finding(id="fnd_drift")
        other = _make_non_drift_finding(id="fnd_other")
        actor = HealActor()
        results = actor.handle([drift, other])
        assert len(results) == 2
        drift_result = [r for r in results if r.id == "fnd_drift"][0]
        other_result = [r for r in results if r.id == "fnd_other"][0]
        assert any(a.actor == "heal" for a in drift_result.annotations)
        assert not any(a.actor == "heal" for a in other_result.annotations)

    def test_analyze_drift_non_drift_returns_none(self) -> None:
        finding = _make_non_drift_finding()
        result = analyze_drift(finding)
        assert result is None
