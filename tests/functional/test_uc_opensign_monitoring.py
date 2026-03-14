"""UC-2: OpenSign container log monitoring.

Baron tells the agent to set up OpenSign monitoring. Agent runs
`mallcop discover-app opensign` which samples container logs. Agent
analyzes the samples, generates parser + detector bundle. On next
`mallcop watch`, the container-logs connector polls OpenSign stdout,
the generated parser filters noise and extracts security-relevant
events, the generated detectors fire on anomalies, and triage
investigates.

We mock:
  - Container-logs connector (synthetic log lines -- no live API calls)
  - LLM client (deterministic triage decisions)

We verify:
  - Parser correctly filters noise lines (routine HTTP requests)
  - Parser extracts security-relevant events (auth failures)
  - Noise summary event is emitted with correct counts
  - App-specific declarative detectors fire on test anomalies
  - Full pipeline: raw log_line events -> parser transforms -> detect -> findings
  - Artifact verification passes for generated parser + detector YAML
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.app_integration import apply_parsers, load_app_detectors
from mallcop.cli import cli
from mallcop.detect import run_detect
from mallcop.parsers.runtime import ParserRuntime, load_parser
from mallcop.schemas import (
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore
from mallcop.verify import verify_app_artifacts


# --- Fixtures: OpenSign log lines ---

_NOW = datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc)

# Routine HTTP request logs (noise -- should be filtered)
_NOISE_LINES = [
    f'[{(_NOW - timedelta(minutes=10)).isoformat()}] "GET /api/documents HTTP/1.1" 200 4523',
    f'[{(_NOW - timedelta(minutes=9)).isoformat()}] "GET /api/documents/123 HTTP/1.1" 200 1287',
    f'[{(_NOW - timedelta(minutes=8)).isoformat()}] "POST /api/documents HTTP/1.1" 201 892',
    f'[{(_NOW - timedelta(minutes=7)).isoformat()}] "GET /api/health HTTP/1.1" 200 23',
    f'[{(_NOW - timedelta(minutes=6)).isoformat()}] "GET /api/documents HTTP/1.1" 200 4410',
    f'[{(_NOW - timedelta(minutes=5)).isoformat()}] "PUT /api/documents/456 HTTP/1.1" 200 1100',
    f'[{(_NOW - timedelta(minutes=4)).isoformat()}] "GET /static/bundle.js HTTP/1.1" 200 85000',
    f'[{(_NOW - timedelta(minutes=3)).isoformat()}] "GET /api/users/me HTTP/1.1" 200 350',
]

# Auth failure logs (security-relevant -- should become Events)
_AUTH_FAILURE_LINES = [
    f'[{(_NOW - timedelta(minutes=2, seconds=50)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=2, seconds=40)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=2, seconds=30)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=2, seconds=20)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=2, seconds=10)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=2)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=1, seconds=50)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=1, seconds=40)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=1, seconds=30)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=1, seconds=20)).isoformat()}] AUTH FAILED: user=admin ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=1, seconds=10)).isoformat()}] AUTH FAILED: user=root ip=198.51.100.42',
    f'[{(_NOW - timedelta(minutes=1)).isoformat()}] AUTH FAILED: user=root ip=198.51.100.42',
]

# Unmatched lines (unknown format)
_UNMATCHED_LINES = [
    "DEBUG: internal cache refreshed",
]

ALL_LOG_LINES = _NOISE_LINES + _AUTH_FAILURE_LINES + _UNMATCHED_LINES


# --- Helpers ---


def _opensign_parser_yaml() -> dict[str, Any]:
    """Parser manifest matching the design doc example."""
    return {
        "app": "opensign",
        "version": 1,
        "generated_at": "2026-03-07T12:00:00Z",
        "generated_by": "claude-sonnet-4-5",
        "templates": [
            {
                "name": "http_request",
                "pattern": r'^\[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^ ]+) HTTP/[\d.]+" (?P<status>\d+) (?P<bytes>\d+)',
                "classification": "routine",
                "event_mapping": {
                    "event_type": "http_request",
                    "actor": "",
                    "action": "{method}",
                    "target": "{path}",
                    "severity": "info",
                },
                "noise_filter": True,
            },
            {
                "name": "auth_failure",
                "pattern": r'^\[(?P<timestamp>[^\]]+)\] AUTH FAILED: user=(?P<user>[^ ]+) ip=(?P<ip>[^ ]+)',
                "classification": "security",
                "event_mapping": {
                    "event_type": "auth_failure",
                    "actor": "{user}",
                    "action": "login_failed",
                    "target": "opensign",
                    "severity": "warn",
                    "metadata": {
                        "ip_address": "{ip}",
                    },
                },
                "noise_filter": False,
            },
        ],
        "noise_summary": True,
        "unmatched_threshold": 0.3,
    }


def _opensign_detectors_yaml() -> dict[str, Any]:
    """Detector rules matching the design doc example."""
    return {
        "app": "opensign",
        "version": 1,
        "generated_at": "2026-03-07T12:00:00Z",
        "detectors": [
            {
                "name": "opensign-auth-brute-force",
                "description": "Burst of auth failures from same IP within 5 minutes",
                "event_type": "auth_failure",
                "condition": {
                    "type": "count_threshold",
                    "group_by": ["metadata.ip_address"],
                    "window_minutes": 5,
                    "threshold": 10,
                },
                "severity": "critical",
            },
            {
                "name": "opensign-unusual-endpoint",
                "description": "Request to path not seen in baseline",
                "event_type": "http_request",
                "condition": {
                    "type": "new_value",
                    "field": "target",
                },
                "severity": "warn",
            },
        ],
    }


def _write_app_artifacts(root: Path) -> None:
    """Write parser.yaml and detectors.yaml to apps/opensign/."""
    app_dir = root / "apps" / "opensign"
    app_dir.mkdir(parents=True, exist_ok=True)

    with open(app_dir / "parser.yaml", "w") as f:
        yaml.dump(_opensign_parser_yaml(), f, default_flow_style=False, sort_keys=False)

    with open(app_dir / "detectors.yaml", "w") as f:
        yaml.dump(_opensign_detectors_yaml(), f, default_flow_style=False, sort_keys=False)


def _make_config_yaml(root: Path) -> None:
    """Write mallcop.yaml with container-logs connector for opensign."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {
            "container-logs": {
                "subscription_id": "test-sub-id",
                "resource_group": "acme-rg",
                "apps": [
                    {"name": "opensign", "container": "opensign"},
                ],
            },
        },
        "routing": {
            "critical": "triage",
            "warn": "triage",
            "info": None,
        },
        "actor_chain": {"triage": {"routes_to": "notify-teams"}},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
        "squelch": 0,  # disabled: functional tests are not testing squelch gating
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _empty_baseline(**overrides: Any) -> Baseline:
    """Create an empty Baseline with all required fields."""
    defaults: dict[str, Any] = {
        "frequency_tables": {},
        "known_entities": {"actors": [], "targets": [], "ips": []},
        "relationships": {},
    }
    defaults.update(overrides)
    return Baseline(**defaults)


def _make_raw_log_events(lines: list[str], app_name: str = "opensign") -> list[Event]:
    """Simulate what the container-logs connector produces: raw log_line events."""
    now = datetime.now(timezone.utc)
    events: list[Event] = []
    for i, line in enumerate(lines):
        events.append(Event(
            id=f"evt_cl_{app_name}_{i:04d}",
            timestamp=now,
            ingested_at=now,
            source="container-logs",
            event_type="log_line",
            actor=app_name,
            action="log",
            target="opensign",
            severity=Severity.INFO,
            metadata={"app": app_name, "line_number": i + 1},
            raw={"line": line},
        ))
    return events


# --- Phase 1: Parser correctly filters noise and extracts security events ---


class TestParserFiltersAndExtracts:
    """Parser transforms raw log lines into structured events."""

    def test_noise_lines_are_counted_not_stored(self, tmp_path: Path) -> None:
        """Routine HTTP request lines are noise-filtered: counted but not emitted as Events."""
        _write_app_artifacts(tmp_path)
        manifest = load_parser(tmp_path / "apps" / "opensign" / "parser.yaml")
        runtime = ParserRuntime(manifest=manifest, source="container-logs", app_name="opensign")

        result = runtime.parse(_NOISE_LINES)

        # All 8 noise lines matched the http_request template
        assert result.noise_counts.get("http_request") == 8
        # No events emitted (all noise-filtered)
        assert len(result.events) == 0

    def test_auth_failures_become_structured_events(self, tmp_path: Path) -> None:
        """Auth failure lines become structured Events with correct fields."""
        _write_app_artifacts(tmp_path)
        manifest = load_parser(tmp_path / "apps" / "opensign" / "parser.yaml")
        runtime = ParserRuntime(manifest=manifest, source="container-logs", app_name="opensign")

        result = runtime.parse(_AUTH_FAILURE_LINES)

        # All 12 auth failure lines become events (not noise-filtered)
        assert len(result.events) == 12

        # Check first event structure
        evt = result.events[0]
        assert evt.event_type == "auth_failure"
        assert evt.actor == "admin"
        assert evt.action == "login_failed"
        assert evt.target == "opensign"
        assert evt.severity == Severity.WARN
        assert evt.metadata["ip_address"] == "198.51.100.42"
        assert evt.metadata["app"] == "opensign"
        assert evt.metadata["template"] == "auth_failure"
        assert evt.source == "container-logs"

    def test_mixed_lines_produce_correct_counts(self, tmp_path: Path) -> None:
        """Mixed log lines: noise filtered, security events emitted, unmatched counted."""
        _write_app_artifacts(tmp_path)
        manifest = load_parser(tmp_path / "apps" / "opensign" / "parser.yaml")
        runtime = ParserRuntime(manifest=manifest, source="container-logs", app_name="opensign")

        result = runtime.parse(ALL_LOG_LINES)

        # 12 auth failures -> events, 8 HTTP requests -> noise, 1 unmatched
        assert len(result.events) == 12
        assert result.noise_counts.get("http_request") == 8
        assert result.unmatched_count == 1

        # Total lines: 21 (8 noise + 12 security + 1 unmatched)
        # Unmatched ratio: 1/21 < 0.3 -> no format drift
        assert not result.format_drift
        assert result.unmatched_ratio < 0.3

    def test_noise_summary_event_emitted(self, tmp_path: Path) -> None:
        """Parser emits a noise_summary Event with template counts."""
        _write_app_artifacts(tmp_path)
        manifest = load_parser(tmp_path / "apps" / "opensign" / "parser.yaml")
        runtime = ParserRuntime(manifest=manifest, source="container-logs", app_name="opensign")

        result = runtime.parse(ALL_LOG_LINES)

        assert result.summary_event is not None
        summary = result.summary_event
        assert summary.event_type == "noise_summary"
        assert summary.source == "container-logs"
        assert summary.metadata["app"] == "opensign"
        assert summary.metadata["template_counts"]["http_request"] == 8
        assert summary.metadata["unmatched_count"] == 1
        assert summary.metadata["total_lines"] == 21

    def test_format_drift_detected_when_unmatched_ratio_high(self, tmp_path: Path) -> None:
        """If >30% of lines are unmatched, format_drift is set."""
        _write_app_artifacts(tmp_path)
        manifest = load_parser(tmp_path / "apps" / "opensign" / "parser.yaml")
        runtime = ParserRuntime(manifest=manifest, source="container-logs", app_name="opensign")

        # Feed lines that won't match any template
        garbage = [f"UNKNOWN LOG FORMAT {i}" for i in range(10)]
        result = runtime.parse(garbage)

        assert result.format_drift is True
        assert result.unmatched_ratio == 1.0
        assert result.unmatched_count == 10


# --- Phase 2: apply_parsers integration ---


class TestApplyParsersIntegration:
    """apply_parsers transforms raw container-logs events using parser.yaml."""

    def test_raw_events_transformed_to_structured(self, tmp_path: Path) -> None:
        """Raw log_line events for opensign are replaced with parsed events."""
        _write_app_artifacts(tmp_path)
        raw_events = _make_raw_log_events(ALL_LOG_LINES)

        parsed = apply_parsers(raw_events, tmp_path, app_names=["opensign"])

        # Should have: 12 auth_failure events + 1 noise_summary = 13
        auth_events = [e for e in parsed if e.event_type == "auth_failure"]
        summary_events = [e for e in parsed if e.event_type == "noise_summary"]
        assert len(auth_events) == 12
        assert len(summary_events) == 1
        # Original raw log_line events should be gone
        log_line_events = [e for e in parsed if e.event_type == "log_line"]
        assert len(log_line_events) == 0

    def test_events_without_parser_pass_through(self, tmp_path: Path) -> None:
        """Events from apps without parser.yaml pass through unchanged."""
        # No app artifacts written -- no parser.yaml
        raw_events = _make_raw_log_events(ALL_LOG_LINES)
        parsed = apply_parsers(raw_events, tmp_path, app_names=["opensign"])

        # All events pass through unchanged
        assert len(parsed) == len(raw_events)
        assert all(e.event_type == "log_line" for e in parsed)

    def test_non_container_logs_events_unaffected(self, tmp_path: Path) -> None:
        """Events from non-container-logs sources pass through regardless."""
        _write_app_artifacts(tmp_path)

        azure_event = Event(
            id="evt_azure_001",
            timestamp=datetime.now(timezone.utc),
            ingested_at=datetime.now(timezone.utc),
            source="azure",
            event_type="role_assignment",
            actor="admin-user",
            action="assign",
            target="/subscriptions/abc",
            severity=Severity.WARN,
            metadata={},
            raw={"test": True},
        )

        parsed = apply_parsers([azure_event], tmp_path, app_names=["opensign"])
        assert len(parsed) == 1
        assert parsed[0].source == "azure"
        assert parsed[0].event_type == "role_assignment"


# --- Phase 3: Declarative detectors fire on parsed events ---


class TestDeclarativeDetectorsFire:
    """App-specific declarative detectors fire on security anomalies."""

    def test_auth_brute_force_fires_on_burst(self, tmp_path: Path) -> None:
        """opensign-auth-brute-force fires when 10+ auth failures from same IP in 5 min."""
        _write_app_artifacts(tmp_path)
        manifest = load_parser(tmp_path / "apps" / "opensign" / "parser.yaml")
        runtime = ParserRuntime(manifest=manifest, source="container-logs", app_name="opensign")
        result = runtime.parse(_AUTH_FAILURE_LINES)

        detectors = load_app_detectors(tmp_path, app_names=["opensign"])
        assert len(detectors) == 2

        brute_force = [d for d in detectors if d._name == "opensign-auth-brute-force"]
        assert len(brute_force) == 1

        baseline = _empty_baseline()

        findings = brute_force[0].detect(result.events, baseline)

        # 12 auth failures from 198.51.100.42 within ~2 minutes -> fires (threshold 10)
        assert len(findings) == 1
        fnd = findings[0]
        assert fnd.detector == "opensign-auth-brute-force"
        assert fnd.severity == Severity.CRITICAL
        assert "198.51.100.42" in fnd.title
        assert "12 events" in fnd.title

    def test_auth_brute_force_does_not_fire_below_threshold(self, tmp_path: Path) -> None:
        """Below-threshold auth failures do not trigger the detector."""
        _write_app_artifacts(tmp_path)
        manifest = load_parser(tmp_path / "apps" / "opensign" / "parser.yaml")
        runtime = ParserRuntime(manifest=manifest, source="container-logs", app_name="opensign")

        # Only 5 auth failures -- below threshold of 10
        result = runtime.parse(_AUTH_FAILURE_LINES[:5])

        detectors = load_app_detectors(tmp_path, app_names=["opensign"])
        brute_force = [d for d in detectors if d._name == "opensign-auth-brute-force"]

        baseline = _empty_baseline()

        findings = brute_force[0].detect(result.events, baseline)
        assert len(findings) == 0

    def test_unusual_endpoint_fires_on_new_path(self, tmp_path: Path) -> None:
        """opensign-unusual-endpoint fires on paths not in baseline."""
        _write_app_artifacts(tmp_path)

        # Create events with http_request event_type (as if parser produced them
        # with noise_filter=False for unusual paths)
        now = datetime.now(timezone.utc)
        events = [
            Event(
                id="evt_req_001",
                timestamp=now,
                ingested_at=now,
                source="container-logs",
                event_type="http_request",
                actor="opensign",
                action="GET",
                target="/api/admin/config",
                severity=Severity.INFO,
                metadata={"app": "opensign"},
                raw={},
            ),
        ]

        detectors = load_app_detectors(tmp_path, app_names=["opensign"])
        unusual = [d for d in detectors if d._name == "opensign-unusual-endpoint"]
        assert len(unusual) == 1

        baseline = _empty_baseline(
            known_entities={"targets": ["/api/documents", "/api/health"]},
        )

        findings = unusual[0].detect(events, baseline)
        assert len(findings) == 1
        assert findings[0].detector == "opensign-unusual-endpoint"
        assert "/api/admin/config" in findings[0].title

    def test_unusual_endpoint_no_fire_for_known_path(self, tmp_path: Path) -> None:
        """Known paths in baseline do not trigger the unusual-endpoint detector."""
        _write_app_artifacts(tmp_path)

        now = datetime.now(timezone.utc)
        events = [
            Event(
                id="evt_req_002",
                timestamp=now,
                ingested_at=now,
                source="container-logs",
                event_type="http_request",
                actor="opensign",
                action="GET",
                target="/api/documents",
                severity=Severity.INFO,
                metadata={"app": "opensign"},
                raw={},
            ),
        ]

        detectors = load_app_detectors(tmp_path, app_names=["opensign"])
        unusual = [d for d in detectors if d._name == "opensign-unusual-endpoint"]

        baseline = _empty_baseline(
            known_entities={"targets": ["/api/documents", "/api/health"]},
        )

        findings = unusual[0].detect(events, baseline)
        assert len(findings) == 0


# --- Phase 4: Artifact verification ---


class TestArtifactVerification:
    """mallcop verify validates the generated parser + detector YAML."""

    def test_valid_artifacts_pass_verification(self, tmp_path: Path) -> None:
        """Well-formed parser.yaml and detectors.yaml pass verification."""
        _write_app_artifacts(tmp_path)
        app_dir = tmp_path / "apps" / "opensign"

        results = verify_app_artifacts(app_dir)
        assert len(results) >= 2  # parser + detectors

        for r in results:
            assert r.passed, f"{r.plugin_type} verification failed: {r.errors}"


# --- Phase 5: Full pipeline end-to-end ---


class TestFullOpenSignPipeline:
    """Full UC-2 pipeline: raw logs -> parser -> store -> detect -> findings -> triage."""

    def test_full_uc2_pipeline(self, tmp_path: Path) -> None:
        """End-to-end: container log lines -> parser -> detect -> brute force finding -> triage.

        Exercises the full discover-app -> parser-generation -> watch -> detect flow
        using recorded container log fixtures.
        """
        root = tmp_path
        _make_config_yaml(root)
        _write_app_artifacts(root)

        # Step 1: Simulate container-logs connector producing raw log_line events
        raw_events = _make_raw_log_events(ALL_LOG_LINES)

        # Step 2: Apply parser transforms (as scan pipeline does)
        parsed_events = apply_parsers(raw_events, root, app_names=["opensign"])

        # Verify parser output
        auth_events = [e for e in parsed_events if e.event_type == "auth_failure"]
        summary_events = [e for e in parsed_events if e.event_type == "noise_summary"]
        assert len(auth_events) == 12, f"Expected 12 auth_failure events, got {len(auth_events)}"
        assert len(summary_events) == 1

        # Step 3: Store parsed events
        store = JsonlStore(root)
        store.append_events(parsed_events)

        # Step 4: Run detect with app-specific detectors
        all_events = store.query_events()
        baseline = _empty_baseline()

        config_connectors = {
            "container-logs": {
                "subscription_id": "test",
                "resource_group": "test-rg",
                "apps": [{"name": "opensign", "container": "opensign"}],
            },
        }

        findings = run_detect(
            all_events, baseline, learning_connectors=set(),
            root=root, config_connectors=config_connectors,
        )

        # opensign-auth-brute-force should fire (12 failures from same IP)
        brute_findings = [f for f in findings if f.detector == "opensign-auth-brute-force"]
        assert len(brute_findings) >= 1, (
            f"Expected opensign-auth-brute-force finding, got detectors: "
            f"{[f.detector for f in findings]}"
        )

        bf = brute_findings[0]
        assert bf.severity == Severity.CRITICAL
        assert "198.51.100.42" in bf.title

        # Store findings
        store.append_findings(findings)

        # Step 5: Triage resolves the brute force finding
        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            if finding.detector == "opensign-auth-brute-force":
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.ESCALATED,
                        reason=(
                            "Brute force attack detected: 12 auth failures from "
                            "198.51.100.42 targeting admin and root accounts. "
                            "Escalating for immediate action."
                        ),
                    ),
                    tokens_used=800,
                    iterations=2,
                )
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason=f"Resolved: {finding.title}",
                ),
                tokens_used=300,
                iterations=1,
            )

        from mallcop.escalate import run_escalate

        escalate_result = run_escalate(root, actor_runner=mock_triage)
        assert escalate_result["status"] == "ok"
        assert escalate_result["findings_processed"] >= 1

        # Step 6: Verify the finding was escalated (stays OPEN, gets annotation)
        store2 = JsonlStore(root)
        all_findings = store2.query_findings()
        brute_escalated = [
            f for f in all_findings
            if f.detector == "opensign-auth-brute-force"
            and any(a.action == "escalated" for a in f.annotations)
        ]
        assert len(brute_escalated) >= 1, (
            f"Expected escalated opensign-auth-brute-force finding, got: "
            f"{[(f.detector, f.status.value, [a.action for a in f.annotations]) for f in all_findings]}"
        )

        esc_fnd = brute_escalated[0]
        assert esc_fnd.status == FindingStatus.OPEN  # escalated findings stay open
        esc_annotation = [a for a in esc_fnd.annotations if a.action == "escalated"][0]
        assert esc_annotation.actor == "triage"
        assert "brute force" in esc_annotation.content.lower()

    def test_learning_mode_downgrades_app_findings(self, tmp_path: Path) -> None:
        """During learning mode, app detector findings are downgraded to INFO."""
        root = tmp_path
        _make_config_yaml(root)
        _write_app_artifacts(root)

        raw_events = _make_raw_log_events(ALL_LOG_LINES)
        parsed_events = apply_parsers(raw_events, root, app_names=["opensign"])

        store = JsonlStore(root)
        store.append_events(parsed_events)

        all_events = store.query_events()
        baseline = _empty_baseline()

        config_connectors = {
            "container-logs": {
                "subscription_id": "test",
                "resource_group": "test-rg",
                "apps": [{"name": "opensign", "container": "opensign"}],
            },
        }

        # With container-logs in learning mode
        findings = run_detect(
            all_events, baseline,
            learning_connectors={"container-logs"},
            root=root, config_connectors=config_connectors,
        )

        brute_findings = [f for f in findings if f.detector == "opensign-auth-brute-force"]
        assert len(brute_findings) >= 1

        # All findings from container-logs should be downgraded to INFO
        for bf in brute_findings:
            assert bf.severity == Severity.INFO, (
                f"Expected INFO severity in learning mode, got {bf.severity}"
            )

    def test_no_findings_when_logs_are_routine(self, tmp_path: Path) -> None:
        """When all log lines are routine noise, no findings are generated."""
        root = tmp_path
        _make_config_yaml(root)
        _write_app_artifacts(root)

        # Only noise lines -- no security events
        raw_events = _make_raw_log_events(_NOISE_LINES)
        parsed_events = apply_parsers(raw_events, root, app_names=["opensign"])

        store = JsonlStore(root)
        store.append_events(parsed_events)

        all_events = store.query_events()
        baseline = _empty_baseline()

        config_connectors = {
            "container-logs": {
                "subscription_id": "test",
                "resource_group": "test-rg",
                "apps": [{"name": "opensign", "container": "opensign"}],
            },
        }

        findings = run_detect(
            all_events, baseline, learning_connectors=set(),
            root=root, config_connectors=config_connectors,
        )

        # Only noise summary event in store -- no auth failures to trigger detectors
        brute_findings = [f for f in findings if f.detector == "opensign-auth-brute-force"]
        assert len(brute_findings) == 0
