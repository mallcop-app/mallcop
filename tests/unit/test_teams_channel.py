"""Tests for Teams channel actor: manifest, digest formatting, webhook delivery."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest
import yaml

from mallcop.actors._schema import ActorManifest, load_actor_manifest
from mallcop.schemas import Finding, Severity, FindingStatus, Annotation


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
    title: str = "Test finding",
    annotations: list[Annotation] | None = None,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001"],
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=annotations or [],
        metadata={},
    )


# ─── Manifest loading and validation ─────────────────────────────────


class TestTeamsManifest:
    @pytest.fixture
    def teams_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "notify_teams"

    def test_manifest_exists(self, teams_dir: Path) -> None:
        assert (teams_dir / "manifest.yaml").exists()

    def test_manifest_loads_without_error(self, teams_dir: Path) -> None:
        manifest = load_actor_manifest(teams_dir)
        assert isinstance(manifest, ActorManifest)

    def test_manifest_name(self, teams_dir: Path) -> None:
        manifest = load_actor_manifest(teams_dir)
        assert manifest.name == "notify-teams"

    def test_manifest_type_is_channel(self, teams_dir: Path) -> None:
        manifest = load_actor_manifest(teams_dir)
        assert manifest.type == "channel"

    def test_manifest_has_no_model(self, teams_dir: Path) -> None:
        manifest = load_actor_manifest(teams_dir)
        assert manifest.model is None

    def test_manifest_config_has_webhook_url(self, teams_dir: Path) -> None:
        manifest = load_actor_manifest(teams_dir)
        assert "webhook_url" in manifest.config
        assert manifest.config["webhook_url"] == "${TEAMS_WEBHOOK_URL}"


# ─── POST.md ──────────────────────────────────────────────────────────


class TestTeamsPostMd:
    @pytest.fixture
    def teams_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "notify_teams"

    def test_post_md_exists(self, teams_dir: Path) -> None:
        assert (teams_dir / "POST.md").exists()

    def test_post_md_loads(self, teams_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(teams_dir)
        assert isinstance(content, str)
        assert len(content) > 0


# ─── Digest formatting ───────────────────────────────────────────────


class TestTeamsDigestFormat:
    def test_format_single_finding(self) -> None:
        from mallcop.actors.notify_teams.channel import format_digest
        findings = [_make_finding()]
        result = format_digest(findings)
        assert isinstance(result, dict)
        # Must contain the finding title somewhere in the message body
        body_str = json.dumps(result)
        assert "Test finding" in body_str

    def test_format_multiple_findings(self) -> None:
        from mallcop.actors.notify_teams.channel import format_digest
        findings = [
            _make_finding(id="fnd_001", title="First finding", severity=Severity.CRITICAL),
            _make_finding(id="fnd_002", title="Second finding", severity=Severity.WARN),
            _make_finding(id="fnd_003", title="Third finding", severity=Severity.INFO),
        ]
        result = format_digest(findings)
        body_str = json.dumps(result)
        assert "First finding" in body_str
        assert "Second finding" in body_str
        assert "Third finding" in body_str

    def test_format_groups_by_severity(self) -> None:
        from mallcop.actors.notify_teams.channel import format_digest
        findings = [
            _make_finding(id="fnd_001", title="Critical one", severity=Severity.CRITICAL),
            _make_finding(id="fnd_002", title="Warning one", severity=Severity.WARN),
        ]
        result = format_digest(findings)
        body_str = json.dumps(result).lower()
        # Critical should appear before warn in the output
        crit_pos = body_str.index("critical")
        warn_pos = body_str.index("warn")
        assert crit_pos < warn_pos

    def test_format_includes_annotations(self) -> None:
        from mallcop.actors.notify_teams.channel import format_digest
        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 6, 12, 5, 0, tzinfo=timezone.utc),
            content="Checked baseline, unknown actor",
            action="escalated",
            reason="Uncertain",
        )
        findings = [_make_finding(annotations=[ann])]
        result = format_digest(findings)
        body_str = json.dumps(result)
        assert "Checked baseline" in body_str

    def test_format_empty_findings(self) -> None:
        from mallcop.actors.notify_teams.channel import format_digest
        result = format_digest([])
        assert isinstance(result, dict)

    def test_format_returns_valid_json_structure(self) -> None:
        from mallcop.actors.notify_teams.channel import format_digest
        findings = [_make_finding()]
        result = format_digest(findings)
        # Must be serializable to JSON
        serialized = json.dumps(result)
        assert len(serialized) > 0


# ─── Webhook delivery ────────────────────────────────────────────────


class TestTeamsWebhookDelivery:
    def test_post_to_webhook_success(self) -> None:
        from mallcop.actors.notify_teams.channel import deliver_digest
        findings = [_make_finding()]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "1"

        with patch("mallcop.actors.notify_base.requests.post", return_value=mock_response) as mock_post:
            result = deliver_digest(findings, "https://example.com/webhook")
            assert result.success is True
            mock_post.assert_called_once()
            # Verify the URL
            call_args = mock_post.call_args
            assert call_args[0][0] == "https://example.com/webhook"

    def test_post_to_webhook_http_error(self) -> None:
        from mallcop.actors.notify_teams.channel import deliver_digest
        findings = [_make_finding()]

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.raise_for_status.side_effect = Exception("500 Server Error")

        with patch("mallcop.actors.notify_base.requests.post", return_value=mock_response) as mock_post:
            result = deliver_digest(findings, "https://example.com/webhook")
            assert result.success is False
            assert result.error is not None

    def test_post_to_webhook_connection_error(self) -> None:
        from mallcop.actors.notify_teams.channel import deliver_digest
        import requests as req
        findings = [_make_finding()]

        with patch("mallcop.actors.notify_base.requests.post", side_effect=req.ConnectionError("Connection refused")):
            result = deliver_digest(findings, "https://example.com/webhook")
            assert result.success is False
            assert result.error is not None

    def test_post_to_webhook_timeout(self) -> None:
        from mallcop.actors.notify_teams.channel import deliver_digest
        import requests as req
        findings = [_make_finding()]

        with patch("mallcop.actors.notify_base.requests.post", side_effect=req.Timeout("Request timed out")):
            result = deliver_digest(findings, "https://example.com/webhook")
            assert result.success is False
            assert "timeout" in result.error.lower() or "timed out" in result.error.lower()
