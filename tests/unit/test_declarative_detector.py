"""Tests for DeclarativeDetector: interprets YAML detection rules at runtime."""

from __future__ import annotations

import textwrap
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from mallcop.schemas import Baseline, Event, Finding, Severity


def _make_event(
    *,
    event_type: str = "http_request",
    actor: str = "user1",
    target: str = "/api/v1/docs",
    source: str = "container-logs",
    timestamp: datetime | None = None,
    metadata: dict | None = None,
    action: str = "request",
    severity: Severity = Severity.INFO,
) -> Event:
    ts = timestamp or datetime.now(timezone.utc)
    return Event(
        id=f"evt_{uuid.uuid4().hex[:8]}",
        timestamp=ts,
        ingested_at=ts,
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=severity,
        metadata=metadata or {},
        raw={},
    )


def _empty_baseline() -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities={},
        relationships={},
    )


# ---------------------------------------------------------------------------
# count_threshold condition
# ---------------------------------------------------------------------------

class TestCountThreshold:
    def _make_rule(self, *, threshold: int = 3, window_minutes: int = 5,
                   group_by: list[str] | None = None) -> dict:
        return {
            "name": "test-count",
            "description": "Test count threshold",
            "event_type": "auth_failure",
            "condition": {
                "type": "count_threshold",
                "group_by": group_by or ["actor"],
                "window_minutes": window_minutes,
                "threshold": threshold,
            },
            "severity": "critical",
        }

    def test_fires_at_threshold(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(threshold=3, window_minutes=5))
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_type="auth_failure", actor="attacker",
                        timestamp=now - timedelta(minutes=i))
            for i in range(3)
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].detector == "test-count"
        assert len(findings[0].event_ids) == 3

    def test_does_not_fire_below_threshold(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(threshold=5, window_minutes=5))
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_type="auth_failure", actor="attacker",
                        timestamp=now - timedelta(minutes=i))
            for i in range(4)
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 0

    def test_groups_by_field(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(threshold=2, window_minutes=5,
                                                   group_by=["actor"]))
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_type="auth_failure", actor="alice", timestamp=now),
            _make_event(event_type="auth_failure", actor="alice",
                        timestamp=now - timedelta(minutes=1)),
            _make_event(event_type="auth_failure", actor="bob", timestamp=now),
        ]
        findings = det.detect(events, _empty_baseline())
        # Only alice hits threshold of 2; bob has 1
        assert len(findings) == 1
        assert "alice" in findings[0].title

    def test_groups_by_metadata_field(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(
            threshold=2, window_minutes=5,
            group_by=["metadata.ip_address"],
        ))
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_type="auth_failure",
                        metadata={"ip_address": "1.2.3.4"}, timestamp=now),
            _make_event(event_type="auth_failure",
                        metadata={"ip_address": "1.2.3.4"},
                        timestamp=now - timedelta(minutes=1)),
            _make_event(event_type="auth_failure",
                        metadata={"ip_address": "5.6.7.8"}, timestamp=now),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 1

    def test_window_excludes_old_events(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(threshold=2, window_minutes=5))
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_type="auth_failure", actor="attacker", timestamp=now),
            _make_event(event_type="auth_failure", actor="attacker",
                        timestamp=now - timedelta(minutes=10)),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 0

    def test_filters_by_event_type(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(threshold=2, window_minutes=5))
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_type="auth_failure", actor="attacker", timestamp=now),
            _make_event(event_type="http_request", actor="attacker",
                        timestamp=now - timedelta(minutes=1)),
            _make_event(event_type="auth_failure", actor="attacker",
                        timestamp=now - timedelta(minutes=2)),
        ]
        findings = det.detect(events, _empty_baseline())
        # Only 2 auth_failure events, threshold is 2 → fires
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# new_value condition
# ---------------------------------------------------------------------------

class TestNewValue:
    def _make_rule(self, *, field: str = "target") -> dict:
        return {
            "name": "test-new-value",
            "description": "Test new value",
            "event_type": "http_request",
            "condition": {
                "type": "new_value",
                "field": field,
            },
            "severity": "warn",
        }

    def test_fires_on_unknown_value(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(field="target"))
        baseline = Baseline(
            frequency_tables={},
            known_entities={"targets": ["/api/v1/docs", "/api/v1/users"]},
            relationships={},
        )
        events = [
            _make_event(event_type="http_request", target="/admin/secret"),
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARN
        assert "/admin/secret" in findings[0].title

    def test_does_not_fire_on_known_value(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(field="target"))
        baseline = Baseline(
            frequency_tables={},
            known_entities={"targets": ["/api/v1/docs"]},
            relationships={},
        )
        events = [
            _make_event(event_type="http_request", target="/api/v1/docs"),
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 0

    def test_fires_on_unknown_actor(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(field="actor"))
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["alice", "bob"]},
            relationships={},
        )
        events = [
            _make_event(event_type="http_request", actor="eve"),
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 1

    def test_empty_baseline_fires(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(field="target"))
        findings = det.detect(
            [_make_event(event_type="http_request", target="/foo")],
            _empty_baseline(),
        )
        assert len(findings) == 1

    def test_deduplicates_new_values(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(field="target"))
        events = [
            _make_event(event_type="http_request", target="/new-path"),
            _make_event(event_type="http_request", target="/new-path"),
        ]
        findings = det.detect(events, _empty_baseline())
        # One finding for the new value, not two
        assert len(findings) == 1
        assert len(findings[0].event_ids) == 2

    def test_metadata_field(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        rule = {
            "name": "test-new-ua",
            "description": "New user agent",
            "event_type": "http_request",
            "condition": {
                "type": "new_value",
                "field": "metadata.user_agent",
            },
            "severity": "info",
        }
        det = DeclarativeDetector(rule)
        baseline = Baseline(
            frequency_tables={},
            known_entities={"user_agents": ["Mozilla/5.0"]},
            relationships={},
        )
        events = [
            _make_event(event_type="http_request",
                        metadata={"user_agent": "evil-bot/1.0"}),
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# volume_ratio condition
# ---------------------------------------------------------------------------

class TestVolumeRatio:
    def _make_rule(self, *, ratio: float = 3.0,
                   filter_: dict | None = None) -> dict:
        cond: dict = {
            "type": "volume_ratio",
            "ratio": ratio,
        }
        if filter_ is not None:
            cond["filter"] = filter_
        return {
            "name": "test-volume-ratio",
            "description": "Test volume ratio",
            "event_type": "http_request",
            "condition": cond,
            "severity": "warn",
        }

    def test_fires_when_ratio_exceeded(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(ratio=3.0))
        baseline = Baseline(
            frequency_tables={"container-logs:http_request:user1": 10},
            known_entities={},
            relationships={},
        )
        # 31 events = ratio 3.1 > 3.0
        events = [
            _make_event(event_type="http_request")
            for _ in range(31)
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARN

    def test_does_not_fire_below_ratio(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(ratio=3.0))
        baseline = Baseline(
            frequency_tables={"container-logs:http_request:user1": 10},
            known_entities={},
            relationships={},
        )
        events = [
            _make_event(event_type="http_request")
            for _ in range(29)
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 0

    def test_fires_with_filter(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(
            ratio=2.0, filter_={"status": "5xx"}))
        baseline = Baseline(
            frequency_tables={"container-logs:http_request:user1": 10},
            known_entities={},
            relationships={},
        )
        # 10 events with status 5xx + 50 events without → only 10 match filter
        # But we need more than 2.0x baseline (10) → need >20
        events = [
            _make_event(event_type="http_request",
                        metadata={"status": "5xx"})
            for _ in range(21)
        ] + [
            _make_event(event_type="http_request",
                        metadata={"status": "200"})
            for _ in range(50)
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 1

    def test_zero_baseline_fires(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(ratio=2.0))
        baseline = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
        )
        events = [_make_event(event_type="http_request")]
        findings = det.detect(events, baseline)
        # Zero baseline → any events should fire
        assert len(findings) == 1

    def test_sums_baseline_across_actors(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(ratio=3.0))
        # Two actors contribute 5 each → baseline total = 10
        baseline = Baseline(
            frequency_tables={
                "container-logs:http_request:alice": 5,
                "container-logs:http_request:bob": 5,
            },
            known_entities={},
            relationships={},
        )
        # 31 events = ratio 3.1 > 3.0 against baseline of 10
        events = [
            _make_event(event_type="http_request")
            for _ in range(31)
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 1

    def test_sums_baseline_across_sources_and_actors(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(ratio=2.0))
        # Multiple sources and actors sum to 20
        baseline = Baseline(
            frequency_tables={
                "container-logs:http_request:alice": 5,
                "container-logs:http_request:bob": 5,
                "nginx:http_request:alice": 7,
                "nginx:http_request:carol": 3,
                # Different event_type — should NOT be counted
                "container-logs:auth_failure:alice": 100,
            },
            known_entities={},
            relationships={},
        )
        # 41 events = ratio 2.05 > 2.0 against baseline of 20
        events = [
            _make_event(event_type="http_request")
            for _ in range(41)
        ]
        findings = det.detect(events, baseline)
        assert len(findings) == 1

    def test_ignores_other_event_types_in_baseline(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(ratio=2.0))
        # Only auth_failure in baseline, no http_request → baseline is 0
        baseline = Baseline(
            frequency_tables={
                "container-logs:auth_failure:alice": 100,
            },
            known_entities={},
            relationships={},
        )
        events = [_make_event(event_type="http_request")]
        findings = det.detect(events, baseline)
        # Zero baseline for http_request → fires on any events
        assert len(findings) == 1
        assert "no baseline" in findings[0].title


# ---------------------------------------------------------------------------
# regex_match condition
# ---------------------------------------------------------------------------

class TestRegexMatch:
    def _make_rule(self, *, field: str = "target",
                   pattern: str = r"/admin/.*") -> dict:
        return {
            "name": "test-regex",
            "description": "Test regex match",
            "event_type": "http_request",
            "condition": {
                "type": "regex_match",
                "field": field,
                "pattern": pattern,
            },
            "severity": "critical",
        }

    def test_fires_on_match(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(pattern=r"/admin/.*"))
        events = [
            _make_event(event_type="http_request", target="/admin/users"),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_does_not_fire_on_non_match(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(pattern=r"/admin/.*"))
        events = [
            _make_event(event_type="http_request", target="/api/v1/docs"),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 0

    def test_matches_metadata_field(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(
            field="metadata.user_agent", pattern=r".*sqlmap.*"))
        events = [
            _make_event(event_type="http_request",
                        metadata={"user_agent": "sqlmap/1.5"}),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 1

    def test_each_matching_event_gets_own_finding(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(pattern=r"/admin/.*"))
        events = [
            _make_event(event_type="http_request", target="/admin/a"),
            _make_event(event_type="http_request", target="/admin/b"),
            _make_event(event_type="http_request", target="/api/ok"),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Interface compliance
# ---------------------------------------------------------------------------

class TestInterface:
    def test_relevant_sources_returns_none(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        rule = {
            "name": "test",
            "description": "Test",
            "event_type": "http_request",
            "condition": {"type": "regex_match", "field": "target",
                          "pattern": ".*"},
            "severity": "info",
        }
        det = DeclarativeDetector(rule)
        assert det.relevant_sources() is None

    def test_relevant_event_types_returns_configured(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        rule = {
            "name": "test",
            "description": "Test",
            "event_type": "auth_failure",
            "condition": {"type": "regex_match", "field": "target",
                          "pattern": ".*"},
            "severity": "info",
        }
        det = DeclarativeDetector(rule)
        assert det.relevant_event_types() == ["auth_failure"]

    def test_unknown_condition_type_raises(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        rule = {
            "name": "test",
            "description": "Test",
            "event_type": "http_request",
            "condition": {"type": "unknown_type"},
            "severity": "info",
        }
        det = DeclarativeDetector(rule)
        with pytest.raises(ValueError, match="Unknown condition type"):
            det.detect([_make_event()], _empty_baseline())


# ---------------------------------------------------------------------------
# Loading from YAML file
# ---------------------------------------------------------------------------

class TestLoadFromYaml:
    def test_load_detectors_from_yaml(self, tmp_path: Path) -> None:
        from mallcop.detectors.declarative import load_declarative_detectors

        yaml_content = {
            "app": "testapp",
            "version": 1,
            "detectors": [
                {
                    "name": "test-count",
                    "description": "Count test",
                    "event_type": "auth_failure",
                    "condition": {
                        "type": "count_threshold",
                        "group_by": ["actor"],
                        "window_minutes": 5,
                        "threshold": 3,
                    },
                    "severity": "critical",
                },
                {
                    "name": "test-regex",
                    "description": "Regex test",
                    "event_type": "http_request",
                    "condition": {
                        "type": "regex_match",
                        "field": "target",
                        "pattern": "/admin/.*",
                    },
                    "severity": "warn",
                },
            ],
        }
        yaml_path = tmp_path / "detectors.yaml"
        yaml_path.write_text(yaml.dump(yaml_content))

        detectors = load_declarative_detectors(yaml_path)
        assert len(detectors) == 2
        assert detectors[0].relevant_event_types() == ["auth_failure"]
        assert detectors[1].relevant_event_types() == ["http_request"]

    def test_load_empty_detectors_list(self, tmp_path: Path) -> None:
        from mallcop.detectors.declarative import load_declarative_detectors

        yaml_content = {"app": "testapp", "version": 1, "detectors": []}
        yaml_path = tmp_path / "detectors.yaml"
        yaml_path.write_text(yaml.dump(yaml_content))

        detectors = load_declarative_detectors(yaml_path)
        assert detectors == []


# ---------------------------------------------------------------------------
# ReDoS protection: declarative detector regex_match (ak1n.1.7)
# ---------------------------------------------------------------------------


class TestDeclarativeDetectorReDoSProtection:
    """regex_match conditions must be guarded with a timeout.

    LLM-generated detector rules may produce regex patterns vulnerable to
    catastrophic backtracking. A TimeoutError from the regex engine must be
    caught and treated as no-match, not a process hang.
    """

    def _make_detector(self, pattern: str) -> "DeclarativeDetector":
        from mallcop.detectors.declarative import DeclarativeDetector
        return DeclarativeDetector({
            "name": "test-regex",
            "description": "Test",
            "event_type": "http_request",
            "condition": {
                "type": "regex_match",
                "field": "actor",
                "pattern": pattern,
            },
            "severity": "warn",
        })

    def _make_event(self, actor: str) -> "Event":
        from mallcop.schemas import Event, Severity
        from datetime import datetime, timezone
        return Event(
            id="evt_001",
            timestamp=datetime(2026, 3, 10, tzinfo=timezone.utc),
            ingested_at=datetime(2026, 3, 10, tzinfo=timezone.utc),
            source="test",
            event_type="http_request",
            actor=actor,
            action="GET",
            target="/path",
            severity=Severity.INFO,
            metadata={},
            raw={},
        )

    def _make_baseline(self) -> "Baseline":
        from mallcop.schemas import Baseline
        return Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
        )

    def test_normal_regex_match_works(self):
        """Sanity: a safe pattern matches correctly."""
        detector = self._make_detector(r"admin")
        baseline = self._make_baseline()
        findings = detector.detect([self._make_event("admin_user")], baseline)
        assert len(findings) == 1

    def test_regex_timeout_skips_event(self):
        """When regex times out, the event is skipped, not a crash."""
        from unittest.mock import patch
        detector = self._make_detector(r".+")
        baseline = self._make_baseline()

        def timeout_search(pattern, text, **kwargs):
            raise TimeoutError("catastrophic backtracking")

        with patch("mallcop.detectors.declarative._safe_regex_search", side_effect=timeout_search):
            findings = detector.detect([self._make_event("someactor")], baseline)

        assert findings == []

    def test_uses_regex_library_for_compilation(self):
        """_regex_pattern must be a regex.Pattern, not a stdlib re.Pattern."""
        import regex
        detector = self._make_detector(r"\w+")
        assert isinstance(detector._regex_pattern, regex.Pattern)


# ---------------------------------------------------------------------------
# regex pre-compile correctness (bead 2.21)
# ---------------------------------------------------------------------------


class TestRegexPreCompile:
    """Regex pattern should be compiled once at __init__, not on every detect() call."""

    def _make_regex_rule(self, pattern: str = r"admin|root") -> dict:
        return {
            "name": "test-regex-precompile",
            "description": "Test regex pre-compile",
            "event_type": "http_request",
            "condition": {
                "type": "regex_match",
                "field": "actor",
                "pattern": pattern,
            },
            "severity": "warn",
        }

    def test_regex_pattern_compiled_at_init(self) -> None:
        """_regex_pattern is a compiled pattern after __init__."""
        import regex
        from mallcop.detectors.declarative import DeclarativeDetector
        det = DeclarativeDetector(self._make_regex_rule())
        assert isinstance(det._regex_pattern, regex.Pattern)
        assert det._regex_pattern.pattern == r"admin|root"

    def test_non_regex_condition_has_no_precompiled_pattern(self) -> None:
        """Detectors with non-regex conditions have _regex_pattern = None."""
        from mallcop.detectors.declarative import DeclarativeDetector
        rule = {
            "name": "test-count-no-regex",
            "description": "Count threshold",
            "event_type": "auth_failure",
            "condition": {"type": "count_threshold", "group_by": ["actor"],
                          "window_minutes": 5, "threshold": 3},
            "severity": "critical",
        }
        det = DeclarativeDetector(rule)
        assert det._regex_pattern is None

    def test_detect_uses_precompiled_pattern_not_fresh_compile(self) -> None:
        """detect() uses self._regex_pattern (no re-compile on each call)."""
        import regex
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_regex_rule())
        original_pattern = det._regex_pattern

        events = [_make_event(event_type="http_request", actor="admin")]

        # Run detect twice; the same pattern object should be reused
        det.detect(events, _empty_baseline())
        assert det._regex_pattern is original_pattern

    def test_regex_matches_correct_events(self) -> None:
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_regex_rule(pattern=r"^attacker"))
        events = [
            _make_event(event_type="http_request", actor="attacker1"),
            _make_event(event_type="http_request", actor="legitimate_user"),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert "attacker1" in findings[0].title


# ---------------------------------------------------------------------------
# count_threshold sliding window correctness (bead 2.22)
# ---------------------------------------------------------------------------


class TestCountThresholdSlidingWindow:
    """best_right must be recorded so window_events slice is correct."""

    def _make_rule(self, threshold: int = 3, window_minutes: int = 5) -> dict:
        return {
            "name": "test-window-correctness",
            "description": "Window correctness",
            "event_type": "auth_failure",
            "condition": {
                "type": "count_threshold",
                "group_by": ["actor"],
                "window_minutes": window_minutes,
                "threshold": threshold,
            },
            "severity": "warn",
        }

    def test_window_events_are_all_within_time_window(self) -> None:
        """All event_ids in the finding must be within window_minutes of each other."""
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(threshold=3, window_minutes=5))
        now = datetime.now(timezone.utc)

        # 5 events: first 2 are outside the 5-min window relative to the last 3
        events = [
            _make_event(event_type="auth_failure", actor="bob",
                        timestamp=now - timedelta(minutes=20)),
            _make_event(event_type="auth_failure", actor="bob",
                        timestamp=now - timedelta(minutes=15)),
            _make_event(event_type="auth_failure", actor="bob",
                        timestamp=now - timedelta(minutes=4)),
            _make_event(event_type="auth_failure", actor="bob",
                        timestamp=now - timedelta(minutes=3)),
            _make_event(event_type="auth_failure", actor="bob",
                        timestamp=now - timedelta(minutes=2)),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert len(findings[0].event_ids) == 3
        in_window_ids = {events[2].id, events[3].id, events[4].id}
        assert set(findings[0].event_ids) == in_window_ids

    def test_best_window_selected_when_two_candidate_windows(self) -> None:
        """When multiple windows exist, the largest is selected."""
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(threshold=2, window_minutes=5))
        now = datetime.now(timezone.utc)

        # First cluster: 2 events (t-20 and t-16)
        # Second cluster: 3 events (t-3, t-2, t-1) — bigger window wins
        events = [
            _make_event(event_type="auth_failure", actor="eve",
                        timestamp=now - timedelta(minutes=20)),
            _make_event(event_type="auth_failure", actor="eve",
                        timestamp=now - timedelta(minutes=16)),
            _make_event(event_type="auth_failure", actor="eve",
                        timestamp=now - timedelta(minutes=3)),
            _make_event(event_type="auth_failure", actor="eve",
                        timestamp=now - timedelta(minutes=2)),
            _make_event(event_type="auth_failure", actor="eve",
                        timestamp=now - timedelta(minutes=1)),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert len(findings[0].event_ids) == 3
        best_ids = {events[2].id, events[3].id, events[4].id}
        assert set(findings[0].event_ids) == best_ids

    def test_stale_best_start_bug_repro(self) -> None:
        """Regression: window_events slice uses best_right, not stale best_start+best_count."""
        from mallcop.detectors.declarative import DeclarativeDetector

        det = DeclarativeDetector(self._make_rule(threshold=3, window_minutes=5))
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_type="auth_failure", actor="carol",
                        timestamp=now - timedelta(minutes=10)),
            _make_event(event_type="auth_failure", actor="carol",
                        timestamp=now - timedelta(minutes=9)),
            _make_event(event_type="auth_failure", actor="carol",
                        timestamp=now - timedelta(minutes=4)),
            _make_event(event_type="auth_failure", actor="carol",
                        timestamp=now - timedelta(minutes=3)),
            _make_event(event_type="auth_failure", actor="carol",
                        timestamp=now - timedelta(minutes=2)),
        ]
        findings = det.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert len(findings[0].event_ids) == 3
        expected = {events[2].id, events[3].id, events[4].id}
        assert set(findings[0].event_ids) == expected
