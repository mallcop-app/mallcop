"""Tests for investigate actor manifest and annotate-finding actor_name fix.

Covers:
1. Investigate manifest loads and validates correctly
2. annotate-finding uses context.actor_name instead of hardcoded "agent"
3. ToolContext.actor_name defaults to "agent" for backward compatibility
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from mallcop.actors._schema import load_actor_manifest
from mallcop.tools import ToolContext


class TestInvestigateManifest:
    """The built-in investigate actor has a valid manifest.yaml."""

    def test_manifest_loads_and_validates(self) -> None:
        """investigate/manifest.yaml loads via load_actor_manifest without error."""
        investigate_dir = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "investigate"
        manifest = load_actor_manifest(investigate_dir)

        assert manifest.name == "investigate"
        assert manifest.type == "agent"
        assert manifest.model == "sonnet"

    def test_manifest_has_correct_permissions(self) -> None:
        """investigate actor has read and write permissions."""
        investigate_dir = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "investigate"
        manifest = load_actor_manifest(investigate_dir)

        assert "read" in manifest.permissions
        assert "write" in manifest.permissions

    def test_manifest_routes_to_notify_teams(self) -> None:
        """investigate actor routes_to notify-teams on escalation."""
        investigate_dir = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "investigate"
        manifest = load_actor_manifest(investigate_dir)

        assert manifest.routes_to == "notify-teams"


class TestAnnotateUsesActorName:
    """annotate-finding uses context.actor_name, not hardcoded 'agent'."""

    def test_annotate_uses_context_actor_name(self) -> None:
        """When context.actor_name is set, annotation uses that name."""
        from datetime import datetime, timezone

        from mallcop.schemas import Finding, FindingStatus, Severity
        from mallcop.tools.findings import annotate_finding

        finding = Finding(
            id="fnd-1",
            timestamp=datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc),
            detector="new-actor",
            severity=Severity.WARN,
            title="Test",
            event_ids=["evt-1"],
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )
        store = MagicMock()
        store.query_findings.return_value = [finding]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock(), actor_name="investigate")

        annotate_finding(ctx, finding_id="fnd-1", text="Deep analysis")

        call_kwargs = store.update_finding.call_args
        annotations = call_kwargs[1]["annotations"]
        assert annotations[0].actor == "investigate"

    def test_default_actor_name_is_agent(self) -> None:
        """ToolContext without explicit actor_name defaults to 'agent'."""
        ctx = ToolContext(store=MagicMock(), connectors={}, config=MagicMock())
        assert ctx.actor_name == "agent"
