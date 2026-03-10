"""Tests for priv-escalation detector."""

from datetime import datetime, timezone

import pytest

from mallcop.detectors.priv_escalation.detector import PrivEscalationDetector
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "azure",
    actor: str = "admin@example.com",
    event_type: str = "role_assignment",
    action: str = "create",
    target: str = "/subscriptions/123/roleAssignments/456",
    metadata: dict | None = None,
) -> Event:
    return Event(
        id=id,
        timestamp=_utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=Severity.WARN,
        metadata=metadata or {},
        raw={},
    )


def _make_baseline(known_entities: dict | None = None) -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities=known_entities or {},
        relationships={},
    )


class TestPrivEscalationDetector:
    """Tests for PrivEscalationDetector."""

    # --- Azure: role_assignment with admin grant ---

    def test_fires_on_azure_role_assignment_admin(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="azure",
            event_type="role_assignment",
            actor="attacker@example.com",
            metadata={"role_name": "Owner", "permission_level": "admin"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].detector == "priv-escalation"
        assert findings[0].status == FindingStatus.OPEN
        assert findings[0].event_ids == ["evt_001"]

    def test_fires_on_azure_role_assignment_contributor(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="azure",
            event_type="role_assignment",
            metadata={"role_name": "Contributor", "permission_level": "write"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    # --- GitHub: collaborator_added with admin ---

    def test_fires_on_github_collaborator_added_admin(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="github",
            event_type="collaborator_added",
            actor="hacker",
            target="org/repo",
            metadata={"permission_level": "admin"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "hacker" in findings[0].title

    def test_fires_on_github_permission_change_to_write(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="github",
            event_type="permission_change",
            metadata={"permission_level": "write"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 1

    # --- M365: admin_action ---

    def test_fires_on_m365_admin_action(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="m365",
            event_type="admin_action",
            actor="rogue@corp.com",
            metadata={"role_name": "Global Administrator"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "rogue@corp.com" in findings[0].title

    # --- Does NOT fire on non-elevation event types ---

    def test_ignores_non_elevation_event_type(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            event_type="sign_in",
            metadata={"role_name": "admin"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 0

    # --- Does NOT fire when role/permission is read-only ---

    def test_ignores_reader_role(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            event_type="role_assignment",
            metadata={"role_name": "Reader", "permission_level": "read"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 0

    # --- Baseline exclusion: known role for this actor ---

    def test_does_not_fire_when_role_in_baseline(self) -> None:
        """If the actor+role combo is already in baseline known_entities,
        the detector should NOT fire."""
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="azure",
            event_type="role_assignment",
            actor="admin@example.com",
            metadata={"role_name": "Owner", "permission_level": "admin"},
        )]
        baseline = _make_baseline(known_entities={
            "actor_roles": {
                "admin@example.com": ["Owner"],
            },
        })
        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_fires_when_different_role_in_baseline(self) -> None:
        """If the actor has roles in baseline but NOT this elevated role,
        the detector should fire."""
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="azure",
            event_type="role_assignment",
            actor="admin@example.com",
            metadata={"role_name": "Owner", "permission_level": "admin"},
        )]
        baseline = _make_baseline(known_entities={
            "actor_roles": {
                "admin@example.com": ["Reader"],
            },
        })
        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    # --- Multiple events, one finding per actor+role ---

    def test_multiple_events_same_actor_same_role_one_finding(self) -> None:
        detector = PrivEscalationDetector()
        events = [
            _make_event(id="evt_1", actor="attacker@evil.com",
                        event_type="role_assignment",
                        metadata={"role_name": "Owner"}),
            _make_event(id="evt_2", actor="attacker@evil.com",
                        event_type="role_assignment",
                        metadata={"role_name": "Owner"}),
        ]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 1
        assert set(findings[0].event_ids) == {"evt_1", "evt_2"}

    def test_multiple_actors_multiple_findings(self) -> None:
        detector = PrivEscalationDetector()
        events = [
            _make_event(id="evt_1", actor="attacker1@evil.com",
                        event_type="role_assignment",
                        metadata={"role_name": "Owner"}),
            _make_event(id="evt_2", actor="attacker2@evil.com",
                        event_type="admin_action",
                        metadata={"role_name": "Admin"}),
        ]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 2

    # --- Severity is always critical ---

    def test_severity_always_critical(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            event_type="permission_change",
            metadata={"permission_level": "write"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert all(f.severity == Severity.CRITICAL for f in findings)

    # --- No events, no findings ---

    def test_no_events_no_findings(self) -> None:
        detector = PrivEscalationDetector()
        findings = detector.detect([], _make_baseline())
        assert len(findings) == 0

    # --- relevant_sources and relevant_event_types ---

    def test_relevant_sources(self) -> None:
        detector = PrivEscalationDetector()
        sources = detector.relevant_sources()
        assert sources is not None
        assert set(sources) == {"azure", "github", "m365"}

    def test_relevant_event_types(self) -> None:
        detector = PrivEscalationDetector()
        event_types = detector.relevant_event_types()
        assert event_types is not None
        assert set(event_types) == {
            "role_assignment", "collaborator_added",
            "permission_change", "admin_action",
        }

    # --- Elevation detected via event_type alone (no metadata) ---

    def test_fires_on_admin_action_without_metadata(self) -> None:
        """admin_action event type alone implies elevation."""
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="m365",
            event_type="admin_action",
            metadata={},
        )]
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 1

    # --- Baseline suppression with store-populated actor_roles ---

    def test_baseline_suppression_with_store_populated_actor_roles(self) -> None:
        """End-to-end: store.update_baseline() populates actor_roles,
        detector suppresses known role assignments."""
        from pathlib import Path
        import tempfile
        from mallcop.store import JsonlStore

        with tempfile.TemporaryDirectory() as tmp:
            store = JsonlStore(Path(tmp))

            # First: learning period events establish baseline
            learning_events = [
                _make_event(
                    id="evt_learn_1",
                    source="azure",
                    event_type="role_assignment",
                    actor="admin@example.com",
                    metadata={"role_name": "Owner", "permission_level": "admin"},
                ),
                _make_event(
                    id="evt_learn_2",
                    source="github",
                    event_type="collaborator_added",
                    actor="dev@example.com",
                    metadata={"permission_level": "write"},
                ),
            ]
            store.append_events(learning_events)
            store.update_baseline(learning_events)
            baseline = store.get_baseline()

            # Verify actor_roles were populated
            actor_roles = baseline.known_entities.get("actor_roles", {})
            assert "admin@example.com" in actor_roles
            assert "Owner" in actor_roles["admin@example.com"]

            # Now: same role assignment again should be suppressed
            detector = PrivEscalationDetector()
            repeat_events = [
                _make_event(
                    id="evt_repeat",
                    source="azure",
                    event_type="role_assignment",
                    actor="admin@example.com",
                    metadata={"role_name": "Owner", "permission_level": "admin"},
                ),
            ]
            findings = detector.detect(repeat_events, baseline)
            assert len(findings) == 0, (
                "Known role assignment should be suppressed by baseline"
            )

            # But a NEW role for the same actor should still fire
            new_role_events = [
                _make_event(
                    id="evt_new_role",
                    source="azure",
                    event_type="role_assignment",
                    actor="admin@example.com",
                    metadata={"role_name": "Contributor", "permission_level": "write"},
                ),
            ]
            findings = detector.detect(new_role_events, baseline)
            assert len(findings) == 1, (
                "New role for known actor should still fire"
            )

    # --- Title includes relevant info ---

    def test_title_includes_actor_and_source(self) -> None:
        detector = PrivEscalationDetector()
        events = [_make_event(
            source="github",
            event_type="collaborator_added",
            actor="hacker@evil.com",
            metadata={"permission_level": "admin"},
        )]
        findings = detector.detect(events, _make_baseline())

        assert "hacker@evil.com" in findings[0].title
        assert "github" in findings[0].title
