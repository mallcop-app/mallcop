"""Unit tests for the parser runtime: load parser.yaml, apply templates, produce Events."""

from __future__ import annotations

import hashlib
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from mallcop.parsers.runtime import (
    ParserManifest,
    ParserTemplate,
    ParseResult,
    ParserRuntime,
    load_parser,
)
from mallcop.schemas import Event, Severity


# ---------------------------------------------------------------------------
# Fixture parser.yaml content
# ---------------------------------------------------------------------------

FIXTURE_PARSER_YAML = textwrap.dedent("""\
    app: testapp
    version: 1
    generated_at: "2026-03-07T12:00:00Z"
    generated_by: "test"

    templates:
      - name: http_request
        pattern: '^\\[(?P<timestamp>[^\\]]+)\\] "(?P<method>\\w+) (?P<path>[^ ]+) HTTP/[\\d.]+" (?P<status>\\d+) (?P<bytes>\\d+)'
        classification: routine
        event_mapping:
          event_type: "http_request"
          actor: ""
          action: "{method}"
          target: "{path}"
          severity: info
        noise_filter: true

      - name: auth_failure
        pattern: '^\\[(?P<timestamp>[^\\]]+)\\] AUTH FAILED: user=(?P<user>[^ ]+) ip=(?P<ip>[^ ]+)'
        classification: security
        event_mapping:
          event_type: "auth_failure"
          actor: "{user}"
          action: "login_failed"
          target: "testapp"
          severity: warn
          metadata:
            ip_address: "{ip}"
        noise_filter: false

      - name: startup
        pattern: '^\\[(?P<timestamp>[^\\]]+)\\] Server started on port (?P<port>\\d+)'
        classification: operational
        event_mapping:
          event_type: "server_start"
          actor: "testapp"
          action: "start"
          target: "port:{port}"
          severity: info
        noise_filter: true

      - name: db_error
        pattern: '^\\[(?P<timestamp>[^\\]]+)\\] ERROR: database connection failed: (?P<reason>.+)'
        classification: error
        event_mapping:
          event_type: "db_error"
          actor: "testapp"
          action: "db_connection_failed"
          target: "database"
          severity: critical
        noise_filter: false

    noise_summary: true
    unmatched_threshold: 0.3
""")


@pytest.fixture
def parser_yaml_path(tmp_path: Path) -> Path:
    p = tmp_path / "apps" / "testapp" / "parser.yaml"
    p.parent.mkdir(parents=True)
    p.write_text(FIXTURE_PARSER_YAML)
    return p


@pytest.fixture
def manifest(parser_yaml_path: Path) -> ParserManifest:
    return load_parser(parser_yaml_path)


@pytest.fixture
def runtime(manifest: ParserManifest) -> ParserRuntime:
    return ParserRuntime(manifest, source="container-logs", app_name="testapp")


# ---------------------------------------------------------------------------
# load_parser tests
# ---------------------------------------------------------------------------


class TestLoadParser:
    def test_loads_manifest(self, parser_yaml_path: Path) -> None:
        m = load_parser(parser_yaml_path)
        assert m.app == "testapp"
        assert m.version == 1
        assert m.noise_summary is True
        assert m.unmatched_threshold == 0.3
        assert len(m.templates) == 4

    def test_template_fields(self, manifest: ParserManifest) -> None:
        t = manifest.templates[0]
        assert t.name == "http_request"
        assert t.classification == "routine"
        assert t.noise_filter is True
        assert t.event_mapping["event_type"] == "http_request"

    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_parser(tmp_path / "nonexistent.yaml")

    def test_missing_required_field(self, tmp_path: Path) -> None:
        bad = tmp_path / "parser.yaml"
        bad.write_text("app: testapp\nversion: 1\n")
        with pytest.raises((KeyError, ValueError)):
            load_parser(bad)

    def test_invalid_regex(self, tmp_path: Path) -> None:
        bad_yaml = textwrap.dedent("""\
            app: testapp
            version: 1
            generated_at: "2026-03-07T12:00:00Z"
            generated_by: "test"
            templates:
              - name: bad
                pattern: '[invalid('
                classification: routine
                event_mapping:
                  event_type: test
                  actor: ""
                  action: test
                  target: test
                  severity: info
                noise_filter: true
            noise_summary: true
            unmatched_threshold: 0.3
        """)
        p = tmp_path / "parser.yaml"
        p.write_text(bad_yaml)
        with pytest.raises(ValueError, match="regex"):
            load_parser(p)


# ---------------------------------------------------------------------------
# ParserRuntime — template matching
# ---------------------------------------------------------------------------


class TestParserRuntimeMatching:
    def test_routine_noise_filtered(self, runtime: ParserRuntime) -> None:
        lines = ['[2026-03-07T10:00:00Z] "GET /index.html HTTP/1.1" 200 1234']
        result = runtime.parse(lines)
        # noise_filter=true → no events, but counted
        assert len(result.events) == 0
        assert result.noise_counts["http_request"] == 1

    def test_security_creates_event(self, runtime: ParserRuntime) -> None:
        lines = ["[2026-03-07T10:00:00Z] AUTH FAILED: user=admin ip=10.0.0.1"]
        result = runtime.parse(lines)
        assert len(result.events) == 1
        evt = result.events[0]
        assert evt.event_type == "auth_failure"
        assert evt.actor == "admin"
        assert evt.action == "login_failed"
        assert evt.target == "testapp"
        assert evt.severity == Severity.WARN
        assert evt.metadata["ip_address"] == "10.0.0.1"
        assert evt.source == "container-logs"

    def test_operational_noise_filtered(self, runtime: ParserRuntime) -> None:
        lines = ["[2026-03-07T10:00:00Z] Server started on port 8080"]
        result = runtime.parse(lines)
        assert len(result.events) == 0
        assert result.noise_counts["startup"] == 1

    def test_error_creates_event(self, runtime: ParserRuntime) -> None:
        lines = [
            "[2026-03-07T10:00:00Z] ERROR: database connection failed: timeout after 30s"
        ]
        result = runtime.parse(lines)
        assert len(result.events) == 1
        evt = result.events[0]
        assert evt.event_type == "db_error"
        assert evt.severity == Severity.CRITICAL
        assert evt.action == "db_connection_failed"

    def test_unmatched_counted(self, runtime: ParserRuntime) -> None:
        lines = ["some random log line that matches nothing"]
        result = runtime.parse(lines)
        assert len(result.events) == 0
        assert result.unmatched_count == 1

    def test_first_match_wins(self, runtime: ParserRuntime) -> None:
        # If a line could match multiple templates, first one wins
        lines = ['[2026-03-07T10:00:00Z] "POST /api/login HTTP/1.1" 401 0']
        result = runtime.parse(lines)
        # Matches http_request (first template), not auth_failure
        assert result.noise_counts.get("http_request", 0) == 1
        assert len(result.events) == 0


# ---------------------------------------------------------------------------
# ParserRuntime — batch processing
# ---------------------------------------------------------------------------


class TestParserRuntimeBatch:
    def test_mixed_batch(self, runtime: ParserRuntime) -> None:
        lines = [
            '[2026-03-07T10:00:00Z] "GET /index.html HTTP/1.1" 200 1234',
            '[2026-03-07T10:00:01Z] "GET /style.css HTTP/1.1" 200 5678',
            "[2026-03-07T10:00:02Z] AUTH FAILED: user=admin ip=10.0.0.1",
            "some unmatched line",
            "[2026-03-07T10:00:03Z] Server started on port 8080",
            "[2026-03-07T10:00:04Z] ERROR: database connection failed: disk full",
        ]
        result = runtime.parse(lines)

        # 2 non-noise events: auth_failure + db_error
        assert len(result.events) == 2
        assert result.events[0].event_type == "auth_failure"
        assert result.events[1].event_type == "db_error"

        # noise counts
        assert result.noise_counts["http_request"] == 2
        assert result.noise_counts["startup"] == 1

        # unmatched
        assert result.unmatched_count == 1

    def test_empty_lines_skipped(self, runtime: ParserRuntime) -> None:
        lines = ["", "  ", "\t"]
        result = runtime.parse(lines)
        assert len(result.events) == 0
        assert result.unmatched_count == 0

    def test_empty_batch(self, runtime: ParserRuntime) -> None:
        result = runtime.parse([])
        assert len(result.events) == 0
        assert result.unmatched_count == 0
        assert not result.noise_counts


# ---------------------------------------------------------------------------
# ParserRuntime — noise summary event
# ---------------------------------------------------------------------------


class TestParserRuntimeNoiseSummary:
    def test_noise_summary_emitted(self, runtime: ParserRuntime) -> None:
        lines = [
            '[2026-03-07T10:00:00Z] "GET /index.html HTTP/1.1" 200 1234',
            '[2026-03-07T10:00:01Z] "POST /api HTTP/1.1" 201 100',
            "[2026-03-07T10:00:02Z] Server started on port 8080",
        ]
        result = runtime.parse(lines)
        summary = result.summary_event
        assert summary is not None
        assert summary.event_type == "noise_summary"
        assert summary.source == "container-logs"
        assert summary.metadata["app"] == "testapp"
        assert summary.metadata["template_counts"]["http_request"] == 2
        assert summary.metadata["template_counts"]["startup"] == 1
        assert summary.metadata["unmatched_count"] == 0
        assert summary.metadata["total_lines"] == 3

    def test_no_summary_when_disabled(self, manifest: ParserManifest) -> None:
        manifest.noise_summary = False
        rt = ParserRuntime(manifest, source="container-logs", app_name="testapp")
        lines = ['[2026-03-07T10:00:00Z] "GET / HTTP/1.1" 200 100']
        result = rt.parse(lines)
        assert result.summary_event is None

    def test_no_summary_for_empty_batch(self, runtime: ParserRuntime) -> None:
        result = runtime.parse([])
        assert result.summary_event is None


# ---------------------------------------------------------------------------
# ParserRuntime — unmatched threshold / format-drift flag
# ---------------------------------------------------------------------------


class TestParserRuntimeFormatDrift:
    def test_drift_flag_when_above_threshold(self, runtime: ParserRuntime) -> None:
        # 4 lines, 2 unmatched = 50% > 30% threshold
        lines = [
            '[2026-03-07T10:00:00Z] "GET / HTTP/1.1" 200 100',
            "unmatched line 1",
            "unmatched line 2",
            "[2026-03-07T10:00:01Z] Server started on port 8080",
        ]
        result = runtime.parse(lines)
        assert result.format_drift is True
        assert result.unmatched_ratio > 0.3

    def test_no_drift_when_below_threshold(self, runtime: ParserRuntime) -> None:
        # 10 matched, 1 unmatched = 9% < 30%
        lines = [
            f'[2026-03-07T10:00:{i:02d}Z] "GET /{i} HTTP/1.1" 200 100'
            for i in range(10)
        ]
        lines.append("one unmatched")
        result = runtime.parse(lines)
        assert result.format_drift is False

    def test_no_drift_for_empty_batch(self, runtime: ParserRuntime) -> None:
        result = runtime.parse([])
        assert result.format_drift is False


# ---------------------------------------------------------------------------
# ParserRuntime — Event field mapping
# ---------------------------------------------------------------------------


class TestParserRuntimeEventFields:
    def test_event_id_is_deterministic(self, runtime: ParserRuntime) -> None:
        lines = ["[2026-03-07T10:00:00Z] AUTH FAILED: user=bob ip=1.2.3.4"]
        r1 = runtime.parse(lines)
        r2 = runtime.parse(lines)
        assert r1.events[0].id == r2.events[0].id

    def test_event_has_raw(self, runtime: ParserRuntime) -> None:
        lines = ["[2026-03-07T10:00:00Z] AUTH FAILED: user=bob ip=1.2.3.4"]
        result = runtime.parse(lines)
        evt = result.events[0]
        assert "line" in evt.raw
        assert "AUTH FAILED" in evt.raw["line"]

    def test_event_timestamp_from_regex(self, runtime: ParserRuntime) -> None:
        lines = ["[2026-03-07T10:00:00Z] AUTH FAILED: user=bob ip=1.2.3.4"]
        result = runtime.parse(lines)
        evt = result.events[0]
        assert evt.timestamp == datetime(2026, 3, 7, 10, 0, 0, tzinfo=timezone.utc)

    def test_event_metadata_mapping(self, runtime: ParserRuntime) -> None:
        lines = ["[2026-03-07T10:00:00Z] AUTH FAILED: user=alice ip=192.168.1.1"]
        result = runtime.parse(lines)
        evt = result.events[0]
        assert evt.metadata["ip_address"] == "192.168.1.1"
        assert evt.metadata["app"] == "testapp"
        assert evt.metadata["template"] == "auth_failure"

    def test_severity_mapping(self, runtime: ParserRuntime) -> None:
        lines = [
            "[2026-03-07T10:00:00Z] AUTH FAILED: user=bob ip=1.2.3.4",
            "[2026-03-07T10:00:01Z] ERROR: database connection failed: oops",
        ]
        result = runtime.parse(lines)
        assert result.events[0].severity == Severity.WARN
        assert result.events[1].severity == Severity.CRITICAL

    def test_empty_actor_defaults_to_app(self, runtime: ParserRuntime) -> None:
        # http_request has actor: "" — but it's noise_filter=true so won't produce event
        # Create a template with empty actor and noise_filter=false
        manifest = ParserManifest(
            app="testapp",
            version=1,
            generated_at="2026-03-07T12:00:00Z",
            generated_by="test",
            templates=[
                ParserTemplate(
                    name="test",
                    pattern=r"^HELLO (?P<target>\w+)",
                    classification="routine",
                    event_mapping={
                        "event_type": "greeting",
                        "actor": "",
                        "action": "greet",
                        "target": "{target}",
                        "severity": "info",
                    },
                    noise_filter=False,
                ),
            ],
            noise_summary=False,
            unmatched_threshold=0.3,
        )
        rt = ParserRuntime(manifest, source="test", app_name="testapp")
        result = rt.parse(["HELLO world"])
        assert result.events[0].actor == "testapp"
