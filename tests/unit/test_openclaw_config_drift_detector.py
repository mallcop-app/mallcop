"""Tests for openclaw-config-drift detector."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mallcop.schemas import Baseline, Event, Severity


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "openclaw"


def _make_baseline() -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities={},
        relationships={},
    )


def _make_config_event(
    config: dict,
    secrets_found: bool = False,
    override_type: str = "",
) -> Event:
    return Event(
        id="evt_cfgtest001",
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        source="openclaw",
        event_type="config_changed",
        actor="filesystem",
        action="config_changed",
        target="/tmp/test/openclaw.json",
        severity=Severity.WARN,
        metadata={
            "config": config,
            "override_type": override_type,
        },
        raw={"secrets_found": secrets_found},
    )


def _healthy_config() -> dict:
    return {
        "gateway": {
            "auth": {"enabled": True, "method": "token"},
            "mdns": {"enabled": False},
            "guestMode": {"enabled": False, "tools": []},
        }
    }


# ─── auth-disabled ───────────────────────────────────────────────────


class TestOpenClawConfigDriftAuthDisabled:
    def test_auth_disabled_detected(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        config["gateway"]["auth"]["enabled"] = False
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert any(f.metadata["rule"] == "auth-disabled" for f in findings)

    def test_auth_enabled_not_flagged(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()  # auth enabled
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert not any(f.metadata["rule"] == "auth-disabled" for f in findings)

    def test_auth_disabled_severity_critical(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        config["gateway"]["auth"]["enabled"] = False
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        auth_findings = [f for f in findings if f.metadata["rule"] == "auth-disabled"]
        assert len(auth_findings) == 1
        assert auth_findings[0].severity == Severity.CRITICAL


# ─── plaintext-secrets ───────────────────────────────────────────────


class TestOpenClawConfigDriftPlaintextSecrets:
    def test_plaintext_secrets_detected_openai(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        evt = _make_config_event({}, secrets_found=True)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert any(f.metadata["rule"] == "plaintext-secrets" for f in findings)

    def test_plaintext_secrets_detected_aws(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        evt = _make_config_event({}, secrets_found=True)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert any(f.metadata["rule"] == "plaintext-secrets" for f in findings)

    def test_plaintext_secrets_detected_github(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        evt = _make_config_event({}, secrets_found=True)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert any(f.metadata["rule"] == "plaintext-secrets" for f in findings)

    def test_no_secrets_not_flagged(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert not any(f.metadata["rule"] == "plaintext-secrets" for f in findings)


# ─── mdns-enabled ────────────────────────────────────────────────────


class TestOpenClawConfigDriftMdnsEnabled:
    def test_mdns_enabled_detected(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        config["gateway"]["mdns"]["enabled"] = True
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert any(f.metadata["rule"] == "mdns-enabled" for f in findings)

    def test_mdns_disabled_not_flagged(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()  # mdns disabled
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert not any(f.metadata["rule"] == "mdns-enabled" for f in findings)


# ─── guest-mode-tools ────────────────────────────────────────────────


class TestOpenClawConfigDriftGuestModeTools:
    def test_guest_mode_tools_detected(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        config["gateway"]["guestMode"]["tools"] = ["shell_exec", "file_read"]
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert any(f.metadata["rule"] == "guest-mode-tools" for f in findings)

    def test_empty_guest_tools_not_flagged(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()  # empty guest tools list
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert not any(f.metadata["rule"] == "guest-mode-tools" for f in findings)


# ─── shadow-skill-override ───────────────────────────────────────────


class TestOpenClawConfigDriftShadowSkillOverride:
    def test_shadow_skill_override_workspace_overrides_managed(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        evt = _make_config_event(config, override_type="workspace_overrides_managed")

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert any(f.metadata["rule"] == "shadow-skill-override" for f in findings)

    def test_shadow_skill_override_workspace_overrides_bundled(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        evt = _make_config_event(config, override_type="workspace_overrides_bundled")

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert any(f.metadata["rule"] == "shadow-skill-override" for f in findings)

    def test_no_override_not_flagged(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        evt = _make_config_event(config, override_type="")  # no override

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert not any(f.metadata["rule"] == "shadow-skill-override" for f in findings)


# ─── healthy config ──────────────────────────────────────────────────


class TestOpenClawConfigDriftHealthyConfig:
    def test_healthy_config_no_findings(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config = _healthy_config()
        evt = _make_config_event(config)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert findings == []

    def test_config_drift_fixture_triggers_findings(self) -> None:
        """End-to-end: config_drift fixture triggers multiple rules."""
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        config_path = FIXTURES_DIR / "config_drift" / "openclaw.json"
        config = json.loads(config_path.read_text())

        # The fixture contains plaintext secrets — simulate connector setting secrets_found=True.
        evt = _make_config_event(config, secrets_found=True)

        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        rules = {f.metadata["rule"] for f in findings}
        assert "auth-disabled" in rules
        assert "mdns-enabled" in rules
        assert "guest-mode-tools" in rules
        assert "plaintext-secrets" in rules

    def test_wrong_source_ignored(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        evt = Event(
            id="evt_wrongsrc",
            timestamp=datetime.now(timezone.utc),
            ingested_at=datetime.now(timezone.utc),
            source="github",  # wrong source
            event_type="config_changed",
            actor="filesystem",
            action="config_changed",
            target="config",
            severity=Severity.WARN,
            metadata={
                "config": {"gateway": {"auth": {"enabled": False}}},
            },
            raw={"secrets_found": False},
        )
        detector = OpenClawConfigDriftDetector()
        findings = detector.detect([evt], _make_baseline())

        assert findings == []


# ─── relevant sources / event types ──────────────────────────────────


class TestOpenClawConfigDriftRelevance:
    def test_relevant_sources(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        detector = OpenClawConfigDriftDetector()
        assert detector.relevant_sources() == ["openclaw"]

    def test_relevant_event_types(self) -> None:
        from mallcop.detectors.openclaw_config_drift.detector import OpenClawConfigDriftDetector

        detector = OpenClawConfigDriftDetector()
        assert detector.relevant_event_types() == ["config_changed"]
