"""Tests for new-external-access detector."""

from datetime import datetime, timezone

import pytest

from mallcop.detectors.new_external_access.detector import NewExternalAccessDetector
from mallcop.schemas import Baseline, Event, Finding, Severity, FindingStatus


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "github",
    event_type: str = "collaborator_added",
    actor: str = "admin@example.com",
    action: str = "create",
    target: str = "repo/my-repo",
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


def _make_baseline(actors: list[str] | None = None) -> Baseline:
    known = {}
    if actors is not None:
        known["actors"] = actors
    return Baseline(
        frequency_tables={},
        known_entities=known,
        relationships={},
    )


class TestNewExternalAccessDetector:
    """Tests for NewExternalAccessDetector."""

    # --- GitHub: non-org collaborator added ---

    def test_fires_on_github_outside_collaborator(self) -> None:
        """GitHub collaborator_added with member_type=outside fires."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            source="github",
            event_type="collaborator_added",
            actor="org-admin",
            target="repo/my-repo",
            metadata={"member_type": "outside"},
        )]
        baseline = _make_baseline(actors=["org-admin"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert findings[0].detector == "new-external-access"
        assert findings[0].severity == Severity.WARN
        assert findings[0].status == FindingStatus.OPEN
        assert findings[0].event_ids == ["evt_001"]

    def test_does_not_fire_on_github_member_collaborator(self) -> None:
        """GitHub collaborator_added with member_type=member does NOT fire."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            source="github",
            event_type="collaborator_added",
            actor="org-admin",
            target="repo/my-repo",
            metadata={"member_type": "member"},
        )]
        baseline = _make_baseline(actors=["org-admin"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_fires_on_github_collaborator_no_member_type(self) -> None:
        """GitHub collaborator_added with no member_type defaults to external (safe default)."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            source="github",
            event_type="collaborator_added",
            actor="org-admin",
            target="repo/my-repo",
            metadata={},
        )]
        baseline = _make_baseline(actors=["org-admin"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    # --- M365: guest invited ---

    def test_fires_on_m365_guest_invited(self) -> None:
        """M365 guest_invited event fires (always external by definition)."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            id="evt_002",
            source="m365",
            event_type="guest_invited",
            actor="admin@contoso.com",
            target="guest@external.com",
            metadata={"user_type": "Guest"},
        )]
        baseline = _make_baseline(actors=["admin@contoso.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert "guest" in findings[0].title.lower() or "external" in findings[0].title.lower()

    # --- M365: oauth consent ---

    def test_fires_on_m365_oauth_consent(self) -> None:
        """M365 oauth_consent event fires (external app granted access)."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            id="evt_003",
            source="m365",
            event_type="oauth_consent",
            actor="admin@contoso.com",
            target="third-party-app",
            metadata={},
        )]
        baseline = _make_baseline(actors=["admin@contoso.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    # --- M365/SharePoint: external sharing ---

    def test_fires_on_sharepoint_external_sharing(self) -> None:
        """SharePoint sharing with external target fires."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            id="evt_004",
            source="m365",
            event_type="sharepoint_sharing",
            actor="admin@contoso.com",
            target="external-user@other.com",
            metadata={"sharing_type": "external"},
        )]
        baseline = _make_baseline(actors=["admin@contoso.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    def test_does_not_fire_on_sharepoint_internal_sharing(self) -> None:
        """SharePoint sharing with internal target does NOT fire."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            id="evt_005",
            source="m365",
            event_type="sharepoint_sharing",
            actor="admin@contoso.com",
            target="colleague@contoso.com",
            metadata={"sharing_type": "internal"},
        )]
        baseline = _make_baseline(actors=["admin@contoso.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    # --- Still fires even if actor is known in baseline ---

    def test_fires_even_when_granting_actor_is_known(self) -> None:
        """The detector fires on access grants TO external entities,
        regardless of whether the granting actor is known."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            source="github",
            event_type="collaborator_added",
            actor="well-known-admin",
            target="repo/project",
            metadata={"member_type": "outside"},
        )]
        baseline = _make_baseline(actors=["well-known-admin"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    def test_fires_even_when_external_actor_is_known_in_baseline(self) -> None:
        """Even if a known external actor is in the baseline, access grant still fires.
        This is about the access grant event, not the actor being unknown."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            source="m365",
            event_type="guest_invited",
            actor="admin@contoso.com",
            target="known-external@partner.com",
            metadata={"user_type": "Guest"},
        )]
        baseline = _make_baseline(actors=["admin@contoso.com", "known-external@partner.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    # --- Irrelevant events are ignored ---

    def test_ignores_irrelevant_event_types(self) -> None:
        """Events with non-access-grant types are ignored."""
        detector = NewExternalAccessDetector()
        events = [
            _make_event(source="github", event_type="push", actor="dev@example.com"),
            _make_event(source="m365", event_type="sign_in", actor="user@contoso.com"),
            _make_event(source="azure", event_type="role_assignment", actor="admin@azure.com"),
        ]
        baseline = _make_baseline(actors=[])

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_ignores_irrelevant_sources(self) -> None:
        """Events from non-github/m365 sources are ignored even with matching event_type."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            source="azure",
            event_type="collaborator_added",
            metadata={"member_type": "outside"},
        )]
        baseline = _make_baseline(actors=[])

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    # --- Multiple events produce separate findings ---

    def test_multiple_external_access_events_produce_multiple_findings(self) -> None:
        """Each external access event produces its own finding."""
        detector = NewExternalAccessDetector()
        events = [
            _make_event(
                id="evt_1",
                source="github",
                event_type="collaborator_added",
                metadata={"member_type": "outside"},
            ),
            _make_event(
                id="evt_2",
                source="m365",
                event_type="guest_invited",
                metadata={"user_type": "Guest"},
            ),
        ]
        baseline = _make_baseline(actors=[])

        findings = detector.detect(events, baseline)

        assert len(findings) == 2

    # --- No events, no findings ---

    def test_no_events_no_findings(self) -> None:
        """Empty event list produces no findings."""
        detector = NewExternalAccessDetector()
        findings = detector.detect([], _make_baseline(actors=[]))
        assert len(findings) == 0

    # --- Interface methods ---

    def test_relevant_sources(self) -> None:
        """Detector only handles github and m365 sources."""
        detector = NewExternalAccessDetector()
        sources = detector.relevant_sources()
        assert sources is not None
        assert set(sources) == {"github", "m365"}

    def test_relevant_event_types(self) -> None:
        """Detector handles specific access-grant event types."""
        detector = NewExternalAccessDetector()
        types = detector.relevant_event_types()
        assert types is not None
        assert set(types) == {
            "collaborator_added",
            "guest_invited",
            "oauth_consent",
            "sharepoint_sharing",
        }

    # --- Finding metadata ---

    def test_finding_metadata_includes_source_and_event_type(self) -> None:
        """Finding metadata includes source and event_type for downstream actors."""
        detector = NewExternalAccessDetector()
        events = [_make_event(
            source="github",
            event_type="collaborator_added",
            actor="admin",
            target="repo/x",
            metadata={"member_type": "outside"},
        )]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert findings[0].metadata["source"] == "github"
        assert findings[0].metadata["event_type"] == "collaborator_added"
