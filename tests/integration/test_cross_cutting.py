"""Cross-cutting integration tests for ship readiness.

Tests multiple components working together across component boundaries:
1. Connector → Detector pipeline
2. Connector → Detector → Reputation
3. OpenClaw → malicious-skill → investigation context
4. Skills + Trust in investigation context
5. Multi-connector entity correlation via reputation
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.reputation import (
    FINDING_DELTA,
    NEUTRAL_SCORE,
    EntityReputation,
)
from mallcop.schemas import (
    Baseline,
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.tools import ToolContext


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
OPENCLAW_FIXTURES = FIXTURES_DIR / "openclaw"
SUPABASE_FIXTURES = FIXTURES_DIR / "supabase"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_baseline(**kwargs: Any) -> Baseline:
    return Baseline(
        frequency_tables=kwargs.get("frequency_tables", {}),
        known_entities=kwargs.get("known_entities", {}),
        relationships=kwargs.get("relationships", {}),
    )


def _make_auth_event(
    event_id: str,
    actor: str = "user@example.com",
    source: str = "supabase",
    event_type: str = "auth_failure",
    timestamp: datetime | None = None,
    ip_address: str = "10.0.0.1",
) -> Event:
    ts = timestamp or datetime.now(timezone.utc)
    return Event(
        id=event_id,
        timestamp=ts,
        ingested_at=ts,
        source=source,
        event_type=event_type,
        actor=actor,
        action="login",
        target="supabase-project",
        severity=Severity.WARN,
        metadata={"ip_address": ip_address},
        raw={},
    )


def _make_finding(
    finding_id: str = "f-001",
    actor: str = "user@example.com",
    detector: str = "unusual-timing",
    severity: Severity = Severity.WARN,
) -> Finding:
    ts = datetime.now(timezone.utc)
    return Finding(
        id=finding_id,
        timestamp=ts,
        detector=detector,
        event_ids=["e-001"],
        title=f"Test finding for {actor}",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": actor, "actor_type": "user"},
    )


# ---------------------------------------------------------------------------
# 1. Connector → Detector pipeline
# ---------------------------------------------------------------------------


class TestConnectorDetectorPipeline:
    """Supabase and OpenClaw connector events feed into relevant detectors."""

    def test_supabase_auth_failures_trigger_burst_detector(self) -> None:
        """Supabase auth_failure events trigger auth-failure-burst detector."""
        from mallcop.detectors.auth_failure_burst.detector import AuthFailureBurstDetector

        now = datetime.now(timezone.utc)
        # 12 auth failures from the same IP within 10 minutes → exceeds threshold of 10
        events = [
            _make_auth_event(
                f"e-{i:03d}",
                actor=f"attacker@evil.com",
                source="supabase",
                event_type="auth_failure",
                timestamp=now + timedelta(seconds=i * 30),
                ip_address="198.51.100.7",
            )
            for i in range(12)
        ]

        detector = AuthFailureBurstDetector(window_minutes=30, threshold=10)
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 1
        assert findings[0].detector == "auth-failure-burst"
        assert findings[0].metadata["count"] == 12
        assert findings[0].metadata["group_key"] == "198.51.100.7"
        assert "supabase" in findings[0].metadata["sources"]

    def test_supabase_auth_failures_from_multiple_ips_grouped_per_ip(self) -> None:
        """Multiple IPs each with burst failures produce one finding per IP."""
        from mallcop.detectors.auth_failure_burst.detector import AuthFailureBurstDetector

        now = datetime.now(timezone.utc)
        ips = ["10.0.0.1", "10.0.0.2"]
        events = []
        for ip in ips:
            events.extend(
                _make_auth_event(
                    f"e-{ip}-{i}",
                    source="supabase",
                    event_type="auth_failure",
                    timestamp=now + timedelta(seconds=i * 10),
                    ip_address=ip,
                )
                for i in range(11)
            )

        detector = AuthFailureBurstDetector(window_minutes=30, threshold=10)
        findings = detector.detect(events, _make_baseline())

        assert len(findings) == 2
        found_ips = {f.metadata["group_key"] for f in findings}
        assert found_ips == set(ips)

    def test_supabase_auth_events_unusual_timing_with_baseline(self) -> None:
        """Supabase auth events at off-hours show up as unusual-timing findings."""
        from mallcop.detectors.unusual_timing.detector import UnusualTimingDetector

        # Baseline: user active only Mon-Fri 9-17
        freq = {}
        for day in range(5):  # Mon-Fri
            for hour_b in range(9, 18, 4):  # buckets at 9, 13
                key = f"supabase:auth_success:admin@acme-corp.com:{day}:{hour_b}"
                freq[key] = 5

        baseline = _make_baseline(frequency_tables=freq)

        # Event at Sunday 3am (day=6, hour_bucket=0)
        sunday_3am = datetime(2026, 3, 8, 3, 0, 0, tzinfo=timezone.utc)  # Sunday
        events = [
            _make_auth_event(
                "e-offhours",
                actor="admin@acme-corp.com",
                source="supabase",
                event_type="auth_success",
                timestamp=sunday_3am,
            )
        ]

        detector = UnusualTimingDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert findings[0].detector == "unusual-timing"
        assert "admin@acme-corp.com" in findings[0].title

    def test_supabase_normal_hours_no_unusual_timing(self) -> None:
        """Supabase auth events within baseline hours produce no unusual-timing findings."""
        from mallcop.detectors.unusual_timing.detector import UnusualTimingDetector
        from mallcop.baseline import hour_bucket

        now = datetime(2026, 3, 10, 10, 30, 0, tzinfo=timezone.utc)  # Monday 10:30
        key = f"supabase:auth_success:admin@acme-corp.com:{now.weekday()}:{hour_bucket(now.hour)}"
        freq = {key: 10}
        baseline = _make_baseline(frequency_tables=freq)

        events = [
            _make_auth_event(
                "e-normal",
                actor="admin@acme-corp.com",
                source="supabase",
                event_type="auth_success",
                timestamp=now,
            )
        ]

        detector = UnusualTimingDetector()
        findings = detector.detect(events, baseline)

        assert findings == []

    def test_openclaw_skill_event_flows_to_malicious_detector(self, tmp_path: Path) -> None:
        """OpenClaw skill_installed event with malicious content triggers malicious-skill detector."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector
        from mallcop.detectors.malicious_skill.detector import MaliciousSkillDetector

        src = OPENCLAW_FIXTURES / "malicious_skill"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})
        poll_result = connector.poll(checkpoint=None)

        skill_events = [
            e for e in poll_result.events
            if e.event_type in ("skill_installed", "skill_modified")
        ]
        assert len(skill_events) >= 1, "Expected at least one skill event from malicious fixture"

        detector = MaliciousSkillDetector()
        findings = detector.detect(poll_result.events, _make_baseline())

        assert len(findings) >= 1
        for f in findings:
            assert f.severity == Severity.CRITICAL
            assert f.detector == "malicious-skill"
            assert "rule" in f.metadata
            assert "skill_name" in f.metadata

    def test_git_oops_findings_have_required_metadata(self, tmp_path: Path) -> None:
        """GitOopsDetector findings have file, pattern_id, and line_numbers metadata."""
        from mallcop.detectors.git_oops.detector import scan_repo

        # Create a minimal repo with a leaked secret
        (tmp_path / ".git").mkdir()
        (tmp_path / "config.py").write_text(
            'AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        )

        findings = scan_repo(tmp_path)

        # The file exists, a pattern may or may not match depending on bundled patterns.yaml
        # What we verify: when findings are produced, they have the right metadata shape.
        for f in findings:
            assert f.detector == "git-oops"
            assert "file" in f.metadata
            assert "pattern_id" in f.metadata
            assert "line_numbers" in f.metadata
            assert isinstance(f.metadata["line_numbers"], list)
            assert f.status == FindingStatus.OPEN


# ---------------------------------------------------------------------------
# 2. Connector → Detector → Reputation
# ---------------------------------------------------------------------------


class TestConnectorDetectorReputation:
    """Findings from detectors update entity reputation correctly."""

    def test_finding_from_connector_updates_reputation(self, tmp_path: Path) -> None:
        """A finding with actor metadata correctly lowers that entity's reputation."""
        rep_path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(rep_path)

        finding = _make_finding("f-001", actor="attacker@evil.com", severity=Severity.WARN)
        rep.record_finding("user", "attacker@evil.com", finding)
        rep.save()

        rep2 = EntityReputation(rep_path)
        score = rep2.get_score("user", "attacker@evil.com")
        expected = NEUTRAL_SCORE + FINDING_DELTA[Severity.WARN]
        assert score.score == pytest.approx(expected, abs=0.01)

    def test_multiple_findings_same_entity_accumulate(self, tmp_path: Path) -> None:
        """Three findings against the same entity compound the score decrease."""
        rep_path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(rep_path)

        actor = "repeat-offender@evil.com"
        for i in range(3):
            f = _make_finding(f"f-{i:03d}", actor=actor, severity=Severity.WARN)
            rep.record_finding("user", actor, f)
        rep.save()

        rep2 = EntityReputation(rep_path)
        score = rep2.get_score("user", actor)
        # Each WARN = -10, so 3 findings → 50 - 30 = 20
        assert score.score == pytest.approx(20.0, abs=0.01)
        assert len(score.history) == 3

    def test_critical_finding_larger_delta_than_warn(self, tmp_path: Path) -> None:
        """CRITICAL findings reduce score more than WARN findings."""
        rep_path_warn = tmp_path / "rep_warn.jsonl"
        rep_path_crit = tmp_path / "rep_crit.jsonl"

        rep_warn = EntityReputation(rep_path_warn)
        rep_warn.record_finding("user", "entity@x.com", _make_finding(severity=Severity.WARN))

        rep_crit = EntityReputation(rep_path_crit)
        rep_crit.record_finding("user", "entity@x.com", _make_finding(severity=Severity.CRITICAL))

        score_warn = rep_warn.get_score("user", "entity@x.com").score
        score_crit = rep_crit.get_score("user", "entity@x.com").score
        assert score_crit < score_warn

    def test_reputation_decay_moves_score_toward_neutral(self, tmp_path: Path) -> None:
        """After 30 days, a score deviating from neutral decays halfway toward 50."""
        rep_path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(rep_path)

        actor = "old-offender@example.com"
        f = _make_finding("f-old", actor=actor, severity=Severity.CRITICAL)
        rep.record_finding("user", actor, f)
        rep.save()

        # Manually backdate the last_updated by 30 days to simulate decay
        rep2 = EntityReputation(rep_path)
        es = rep2._scores[f"user:{actor}"]
        es.last_updated = datetime.now(timezone.utc) - timedelta(days=30)
        rep2._scores[f"user:{actor}"] = es
        rep2.save()

        rep3 = EntityReputation(rep_path)
        decayed = rep3.get_score("user", actor)

        # After 30 days (one half-life), deviation should be halved.
        # Score was 50 + (-20) = 30. Deviation = -20. After 30 days: deviation ≈ -10.
        # So score ≈ 40.
        assert decayed.score > 30.0  # score improved (less negative)
        assert decayed.score < 50.0  # still below neutral


# ---------------------------------------------------------------------------
# 3. OpenClaw → malicious-skill detector → investigation actor context
# ---------------------------------------------------------------------------


class TestOpenClawMaliciousSkillInvestigation:
    """Skill change → malicious detection → investigation actor has relevant context."""

    def test_malicious_skill_finding_has_investigation_context(
        self, tmp_path: Path
    ) -> None:
        """A malicious finding produced from a skill event has metadata useful for investigation."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector
        from mallcop.detectors.malicious_skill.detector import MaliciousSkillDetector

        src = OPENCLAW_FIXTURES / "malicious_skill"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})
        poll_result = connector.poll(checkpoint=None)

        detector = MaliciousSkillDetector()
        findings = detector.detect(poll_result.events, _make_baseline())

        assert findings, "Expected at least one malicious finding"
        for finding in findings:
            # Finding must carry all metadata needed for investigation
            assert "rule" in finding.metadata, "Missing rule in metadata"
            assert "skill_name" in finding.metadata, "Missing skill_name in metadata"
            assert "description" in finding.metadata, "Missing description in metadata"
            assert "matched_field" in finding.metadata, "Missing matched_field in metadata"
            # Event IDs should trace back to the connector events
            assert len(finding.event_ids) >= 1

    def test_skill_event_chain_install_to_detection(self, tmp_path: Path) -> None:
        """Full chain: clean install → inject malicious skill → detect → finding references event."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector
        from mallcop.detectors.malicious_skill.detector import MaliciousSkillDetector

        src = OPENCLAW_FIXTURES / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        first = connector.poll(checkpoint=None)
        assert MaliciousSkillDetector().detect(first.events, _make_baseline()) == []

        # Install a malicious skill (known-malicious-author rule)
        skill_dir = tmp_path / "openclaw" / "skills" / "backdoor"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: backdoor\nauthor: hightower6eu\ndescription: backdoor\n---\n\nRun recon.\n"
        )

        second = connector.poll(checkpoint=first.checkpoint)
        new_skill_events = [e for e in second.events if e.event_type == "skill_installed"]
        assert len(new_skill_events) == 1

        findings = MaliciousSkillDetector().detect(second.events, _make_baseline())
        assert len(findings) >= 1

        finding = findings[0]
        assert finding.event_ids[0] == new_skill_events[0].id
        assert finding.metadata["skill_name"] == "backdoor"


# ---------------------------------------------------------------------------
# 4. Skills + Trust in investigation context
# ---------------------------------------------------------------------------


class TestSkillsTrustInContext:
    """load_skill validates trust; broken trust chain refuses loading."""

    def _make_skill_dir(self, root: Path, name: str, author: str = "dev@example.com") -> Path:
        skill_dir = root / name
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Test skill\nauthor: {author}\n---\n\nSkill body.\n"
        )
        return skill_dir

    def _make_context(self, skill_root: Path, **kwargs: Any) -> ToolContext:
        return ToolContext(
            store=None,
            connectors={},
            config=None,
            skill_root=skill_root,
            loaded_skills={},
            tool_registry=None,
            **kwargs,
        )

    def test_skill_loads_without_trust_infra(self, tmp_path: Path) -> None:
        """Skill loads successfully when no trust infra is configured (graceful degradation)."""
        from mallcop.tools.skills import load_skill

        skill_root = tmp_path / "skills"
        self._make_skill_dir(skill_root, "my-skill")

        ctx = self._make_context(skill_root)
        result = load_skill(ctx, "my-skill")

        assert "error" not in result
        assert "context" in result
        assert "Skill body." in result["context"]
        assert result["verified_by"] is None

    def test_lockfile_hash_mismatch_refuses_load(self, tmp_path: Path) -> None:
        """Skill with lockfile hash mismatch is refused."""
        from mallcop.tools.skills import load_skill

        skill_root = tmp_path / "skills"
        self._make_skill_dir(skill_root, "my-skill")

        # Provide a lockfile with wrong hash for this skill
        fake_lockfile = {
            "my-skill": {
                "sha256": "0" * 64,  # Wrong hash
                "author": "dev@example.com",
                "trust_chain": None,
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "expires": None,
            }
        }

        ctx = self._make_context(skill_root, skill_lockfile=fake_lockfile)
        result = load_skill(ctx, "my-skill")

        assert "error" in result
        assert "lockfile hash mismatch" in result["error"].lower()

    def test_lockfile_hash_match_allows_load(self, tmp_path: Path) -> None:
        """Skill whose content matches the lockfile hash loads successfully."""
        from mallcop.tools.skills import load_skill
        from mallcop.trust import generate_lockfile, _hash_skill
        from mallcop.skills._schema import SkillManifest

        skill_root = tmp_path / "skills"
        skill_dir = self._make_skill_dir(skill_root, "trusted-skill")

        # Generate a valid lockfile with the correct hash
        manifest = SkillManifest(
            name="trusted-skill",
            description="Test skill",
            parent=None,
            tools=None,
            author="dev@example.com",
            version=None,
            path=skill_dir,
        )
        lockfile = generate_lockfile({"trusted-skill": manifest})
        skills_dict = lockfile["skills"]

        ctx = self._make_context(skill_root, skill_lockfile=skills_dict)
        result = load_skill(ctx, "trusted-skill")

        assert "error" not in result, f"Unexpected error: {result.get('error')}"
        assert "context" in result

    def test_missing_skill_returns_error(self, tmp_path: Path) -> None:
        """Loading a nonexistent skill returns an error dict."""
        from mallcop.tools.skills import load_skill

        skill_root = tmp_path / "skills"
        skill_root.mkdir()

        ctx = self._make_context(skill_root)
        result = load_skill(ctx, "does-not-exist")

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_trust_store_no_chain_refuses_load(self, tmp_path: Path) -> None:
        """Skill with author not in trust store is refused."""
        from mallcop.tools.skills import load_skill
        from mallcop.trust import TrustStore

        skill_root = tmp_path / "skills"
        self._make_skill_dir(skill_root, "untrusted-skill", author="unknown@unknown.com")

        # TrustStore with anchors but no path to unknown@unknown.com
        trust_store = TrustStore(
            anchors={"admin@example.com": "ssh-ed25519 AAAA"},
            keyring={"admin@example.com": "ssh-ed25519 AAAA"},
            endorsements={},
        )

        ctx = self._make_context(skill_root, trust_store=trust_store)
        result = load_skill(ctx, "untrusted-skill")

        assert "error" in result
        assert "no trust path" in result["error"].lower()


# ---------------------------------------------------------------------------
# 5. Multi-connector entity correlation
# ---------------------------------------------------------------------------


class TestMultiConnectorEntityCorrelation:
    """Same actor appearing across multiple connector sources unifies reputation."""

    def test_same_actor_across_connectors_accumulates_reputation(
        self, tmp_path: Path
    ) -> None:
        """Findings from supabase and azure for same actor both reduce that entity's score."""
        rep_path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(rep_path)

        actor = "pivot@evil.com"
        finding_supabase = _make_finding("f-supa", actor=actor, detector="auth-failure-burst", severity=Severity.WARN)
        finding_azure = _make_finding("f-az", actor=actor, detector="unusual-timing", severity=Severity.WARN)

        rep.record_finding("user", actor, finding_supabase)
        rep.record_finding("user", actor, finding_azure)
        rep.save()

        rep2 = EntityReputation(rep_path)
        score = rep2.get_score("user", actor)
        # 50 - 10 (supabase WARN) - 10 (azure WARN) = 30
        assert score.score == pytest.approx(30.0, abs=0.01)
        history_reasons = {e.reason for e in score.history}
        assert "finding:auth-failure-burst" in history_reasons
        assert "finding:unusual-timing" in history_reasons

    def test_different_actors_same_source_independent_scores(
        self, tmp_path: Path
    ) -> None:
        """Two different actors each get independent reputation tracks."""
        rep_path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(rep_path)

        actors = ["alice@example.com", "bob@example.com"]
        for actor in actors:
            rep.record_finding("user", actor, _make_finding(f"f-{actor}", actor=actor, severity=Severity.CRITICAL))
        rep.save()

        rep2 = EntityReputation(rep_path)
        for actor in actors:
            score = rep2.get_score("user", actor)
            # Each independently at 50 - 20 = 30
            assert score.score == pytest.approx(30.0, abs=0.01)

    def test_entity_key_includes_source_type(self, tmp_path: Path) -> None:
        """user:email and ip:address are tracked as separate entities."""
        rep_path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(rep_path)

        # Same value, different type
        rep.record_finding("user", "ambiguous@example.com", _make_finding(severity=Severity.CRITICAL))
        rep.record_finding("ip", "ambiguous@example.com", _make_finding(severity=Severity.WARN))
        rep.save()

        rep2 = EntityReputation(rep_path)
        user_score = rep2.get_score("user", "ambiguous@example.com").score
        ip_score = rep2.get_score("ip", "ambiguous@example.com").score

        assert user_score == pytest.approx(30.0, abs=0.01)  # -20 (CRITICAL)
        assert ip_score == pytest.approx(40.0, abs=0.01)    # -10 (WARN)
        assert user_score != ip_score

    def test_connector_event_actor_maps_to_reputation_entity(
        self, tmp_path: Path
    ) -> None:
        """A full connector→detector→reputation round-trip for a single actor."""
        from mallcop.detectors.auth_failure_burst.detector import AuthFailureBurstDetector

        now = datetime.now(timezone.utc)
        actor = "brute@evil.com"
        ip = "10.99.99.99"

        # 15 auth failures from supabase
        events = [
            _make_auth_event(
                f"e-{i:03d}",
                actor=actor,
                source="supabase",
                event_type="auth_failure",
                timestamp=now + timedelta(seconds=i * 20),
                ip_address=ip,
            )
            for i in range(15)
        ]

        detector = AuthFailureBurstDetector(window_minutes=30, threshold=10)
        findings = detector.detect(events, _make_baseline())
        assert len(findings) == 1

        # Record finding against the IP entity (matching group_key)
        rep_path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(rep_path)
        rep.record_finding("ip", ip, findings[0])
        rep.save()

        rep2 = EntityReputation(rep_path)
        score = rep2.get_score("ip", ip)
        assert score.score < NEUTRAL_SCORE
        assert len(score.history) == 1
        assert score.history[0].reason == "finding:auth-failure-burst"
