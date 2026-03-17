"""Tests for container-probing detector."""

from datetime import datetime, timezone

import pytest

from mallcop.detectors.container_probing.detector import ContainerProbingDetector
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "container_logs",
    timestamp: datetime | None = None,
    actor: str = "10.0.0.5",
    event_type: str = "http_request",
    action: str = "request",
    target: str = "web-app:8080",
    metadata: dict | None = None,
) -> Event:
    return Event(
        id=id,
        timestamp=timestamp or _utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=Severity.INFO,
        metadata=metadata or {},
        raw={},
    )


def _make_baseline(
    frequency_tables: dict | None = None,
    known_entities: dict | None = None,
) -> Baseline:
    return Baseline(
        frequency_tables=frequency_tables or {},
        known_entities=known_entities or {},
        relationships={},
    )


class TestUnusualHttpMethods:
    def test_flags_propfind(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "PROPFIND", "path": "/"})]
        findings = detector.detect(events, _make_baseline())
        assert len(findings) == 1
        assert "PROPFIND" in findings[0].title
        assert findings[0].metadata["reason"] == "unusual_method"

    def test_flags_connect(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "CONNECT", "path": "/"})]
        findings = detector.detect(events, _make_baseline())
        assert any(f.metadata["reason"] == "unusual_method" for f in findings)

    def test_allows_normal_get(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/index.html"})]
        findings = detector.detect(events, _make_baseline())
        method_findings = [f for f in findings if f.metadata.get("reason") == "unusual_method"]
        assert len(method_findings) == 0

    def test_allows_normal_post(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "POST", "path": "/api/data"})]
        findings = detector.detect(events, _make_baseline())
        method_findings = [f for f in findings if f.metadata.get("reason") == "unusual_method"]
        assert len(method_findings) == 0

    def test_case_insensitive_method(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "get", "path": "/"})]
        findings = detector.detect(events, _make_baseline())
        method_findings = [f for f in findings if f.metadata.get("reason") == "unusual_method"]
        assert len(method_findings) == 0


class TestPathTraversal:
    def test_flags_dotdot_slash(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/../../etc/passwd"})]
        findings = detector.detect(events, _make_baseline())
        traversal = [f for f in findings if f.metadata.get("reason") == "path_traversal"]
        assert len(traversal) == 1

    def test_flags_encoded_traversal(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/%2e%2e/%2e%2e/etc/shadow"})]
        findings = detector.detect(events, _make_baseline())
        traversal = [f for f in findings if f.metadata.get("reason") == "path_traversal"]
        assert len(traversal) == 1

    def test_normal_path_no_finding(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/api/v1/users"})]
        findings = detector.detect(events, _make_baseline())
        traversal = [f for f in findings if f.metadata.get("reason") == "path_traversal"]
        assert len(traversal) == 0


class TestAttackPatterns:
    def test_flags_sql_injection(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/search?q=1 UNION SELECT * FROM users"})]
        findings = detector.detect(events, _make_baseline())
        attack = [f for f in findings if f.metadata.get("reason") == "attack_pattern"]
        assert len(attack) == 1

    def test_flags_xxe_pattern(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "POST", "path": "/api/xml?payload=<!ENTITY xxe SYSTEM>"})]
        findings = detector.detect(events, _make_baseline())
        attack = [f for f in findings if f.metadata.get("reason") == "attack_pattern"]
        assert len(attack) == 1

    def test_flags_etc_passwd(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/etc/passwd"})]
        findings = detector.detect(events, _make_baseline())
        attack = [f for f in findings if f.metadata.get("reason") == "attack_pattern"]
        assert len(attack) == 1

    def test_flags_dotenv_probe(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/.env"})]
        findings = detector.detect(events, _make_baseline())
        attack = [f for f in findings if f.metadata.get("reason") == "attack_pattern"]
        assert len(attack) == 1

    def test_flags_git_exposure(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/.git/config"})]
        findings = detector.detect(events, _make_baseline())
        attack = [f for f in findings if f.metadata.get("reason") == "attack_pattern"]
        assert len(attack) == 1

    def test_flags_actuator_probe(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/actuator/env"})]
        findings = detector.detect(events, _make_baseline())
        attack = [f for f in findings if f.metadata.get("reason") == "attack_pattern"]
        assert len(attack) == 1

    def test_clean_path_no_finding(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/api/v1/health"})]
        findings = detector.detect(events, _make_baseline())
        attack = [f for f in findings if f.metadata.get("reason") == "attack_pattern"]
        assert len(attack) == 0


class TestRateAnomaly:
    def test_flags_high_rate(self) -> None:
        detector = ContainerProbingDetector(rate_ratio=2.0, min_baseline_count=5)
        events = [
            _make_event(id=f"evt_{i}", metadata={"method": "GET", "path": "/"})
            for i in range(20)
        ]
        baseline = _make_baseline(frequency_tables={"container_logs:http_request:10.0.0.5": 5})
        findings = detector.detect(events, baseline)
        rate_findings = [f for f in findings if f.metadata.get("reason") == "rate_anomaly"]
        assert len(rate_findings) == 1
        assert rate_findings[0].metadata["current_count"] == 20

    def test_no_rate_finding_under_threshold(self) -> None:
        detector = ContainerProbingDetector(rate_ratio=3.0, min_baseline_count=5)
        events = [
            _make_event(id=f"evt_{i}", metadata={"method": "GET", "path": "/"})
            for i in range(10)
        ]
        baseline = _make_baseline(frequency_tables={"container_logs:http_request:10.0.0.5": 5})
        findings = detector.detect(events, baseline)
        rate_findings = [f for f in findings if f.metadata.get("reason") == "rate_anomaly"]
        assert len(rate_findings) == 0

    def test_skips_low_baseline(self) -> None:
        detector = ContainerProbingDetector(rate_ratio=2.0, min_baseline_count=5)
        events = [
            _make_event(id=f"evt_{i}", metadata={"method": "GET", "path": "/"})
            for i in range(20)
        ]
        baseline = _make_baseline(frequency_tables={"container_logs:http_request:10.0.0.5": 2})
        findings = detector.detect(events, baseline)
        rate_findings = [f for f in findings if f.metadata.get("reason") == "rate_anomaly"]
        assert len(rate_findings) == 0


class TestDetectorInterface:
    def test_relevant_sources(self) -> None:
        detector = ContainerProbingDetector()
        assert detector.relevant_sources() == ["container_logs"]

    def test_relevant_event_types(self) -> None:
        detector = ContainerProbingDetector()
        assert detector.relevant_event_types() == ["http_request", "container_access", "container_log"]

    def test_finding_detector_name(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "PROPFIND", "path": "/"})]
        findings = detector.detect(events, _make_baseline())
        assert findings[0].detector == "container-probing"

    def test_finding_status_is_open(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "PROPFIND", "path": "/"})]
        findings = detector.detect(events, _make_baseline())
        assert findings[0].status == FindingStatus.OPEN

    def test_finding_severity_is_warn(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "PROPFIND", "path": "/"})]
        findings = detector.detect(events, _make_baseline())
        assert findings[0].severity == Severity.WARN

    def test_no_events_no_findings(self) -> None:
        detector = ContainerProbingDetector()
        findings = detector.detect([], _make_baseline())
        assert len(findings) == 0

    def test_no_metadata_no_crash(self) -> None:
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={})]
        findings = detector.detect(events, _make_baseline())
        # No method or path means no pattern-based findings
        method_findings = [f for f in findings if f.metadata.get("reason") in ("unusual_method", "path_traversal", "attack_pattern")]
        assert len(method_findings) == 0

    def test_multiple_findings_per_event(self) -> None:
        """An event with both traversal and attack pattern gets multiple findings."""
        detector = ContainerProbingDetector()
        events = [_make_event(metadata={"method": "GET", "path": "/../../etc/passwd"})]
        findings = detector.detect(events, _make_baseline())
        reasons = {f.metadata["reason"] for f in findings}
        assert "path_traversal" in reasons
        assert "attack_pattern" in reasons
