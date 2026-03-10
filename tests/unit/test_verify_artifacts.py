"""Tests for mallcop verify — parser.yaml and detectors.yaml artifact validation."""

import yaml
import pytest
from pathlib import Path

from mallcop.verify import verify_app_artifacts, VerifyResult


def _valid_parser_yaml() -> dict:
    return {
        "app": "testapp",
        "version": 1,
        "generated_at": "2026-03-07T12:00:00Z",
        "generated_by": "claude-sonnet-4-5",
        "templates": [
            {
                "name": "http_request",
                "pattern": r'^\[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^ ]+)"',
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
                "pattern": r"^\[(?P<timestamp>[^\]]+)\] AUTH FAILED: user=(?P<user>[^ ]+)",
                "classification": "security",
                "event_mapping": {
                    "event_type": "auth_failure",
                    "actor": "{user}",
                    "action": "login_failed",
                    "target": "testapp",
                    "severity": "warn",
                },
                "noise_filter": False,
            },
        ],
        "noise_summary": True,
        "unmatched_threshold": 0.3,
    }


def _valid_detectors_yaml() -> dict:
    return {
        "app": "testapp",
        "version": 1,
        "generated_at": "2026-03-07T12:00:00Z",
        "detectors": [
            {
                "name": "testapp-auth-brute-force",
                "description": "Burst of auth failures",
                "event_type": "auth_failure",
                "condition": {
                    "type": "count_threshold",
                    "group_by": ["actor"],
                    "window_minutes": 5,
                    "threshold": 10,
                },
                "severity": "critical",
            },
            {
                "name": "testapp-unusual-endpoint",
                "description": "New path not in baseline",
                "event_type": "http_request",
                "condition": {
                    "type": "new_value",
                    "field": "target",
                },
                "severity": "warn",
            },
        ],
    }


def _write_app(app_dir: Path, parser: dict | None = None, detectors: dict | None = None) -> None:
    app_dir.mkdir(parents=True, exist_ok=True)
    if parser is not None:
        (app_dir / "parser.yaml").write_text(yaml.dump(parser))
    if detectors is not None:
        (app_dir / "detectors.yaml").write_text(yaml.dump(detectors))


class TestVerifyParserYaml:
    def test_valid_parser_passes(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        _write_app(app_dir, parser=_valid_parser_yaml())
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert parser_result.passed, f"Expected pass, got errors: {parser_result.errors}"

    def test_missing_app_field(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        del parser["app"]
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("app" in e.lower() for e in parser_result.errors)

    def test_missing_version(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        del parser["version"]
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("version" in e.lower() for e in parser_result.errors)

    def test_missing_templates(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        del parser["templates"]
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("templates" in e.lower() for e in parser_result.errors)

    def test_empty_templates(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        parser["templates"] = []
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("templates" in e.lower() for e in parser_result.errors)

    def test_template_missing_name(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        del parser["templates"][0]["name"]
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("name" in e.lower() for e in parser_result.errors)

    def test_template_missing_pattern(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        del parser["templates"][0]["pattern"]
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("pattern" in e.lower() for e in parser_result.errors)

    def test_invalid_regex_fails(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        parser["templates"][0]["pattern"] = r"[invalid(("
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("regex" in e.lower() or "pattern" in e.lower() for e in parser_result.errors)

    def test_template_missing_classification(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        del parser["templates"][0]["classification"]
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("classification" in e.lower() for e in parser_result.errors)

    def test_invalid_classification(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        parser["templates"][0]["classification"] = "bogus"
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("classification" in e.lower() for e in parser_result.errors)

    def test_template_missing_event_mapping(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        del parser["templates"][0]["event_mapping"]
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("event_mapping" in e.lower() for e in parser_result.errors)

    def test_event_mapping_missing_event_type(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        del parser["templates"][0]["event_mapping"]["event_type"]
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("event_type" in e.lower() for e in parser_result.errors)

    def test_event_mapping_invalid_severity(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        parser["templates"][0]["event_mapping"]["severity"] = "extreme"
        _write_app(app_dir, parser=parser)
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        assert not parser_result.passed
        assert any("severity" in e.lower() for e in parser_result.errors)

    def test_no_parser_yaml_skipped(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        _write_app(app_dir, detectors=_valid_detectors_yaml())
        results = verify_app_artifacts(app_dir)
        # Should still work — parser is optional if not present
        parser_results = [r for r in results if r.plugin_type == "parser"]
        assert len(parser_results) == 0


class TestVerifyDetectorsYaml:
    def test_valid_detectors_passes(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        _write_app(app_dir, detectors=_valid_detectors_yaml())
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert det_result.passed, f"Expected pass, got errors: {det_result.errors}"

    def test_missing_app_field(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        del detectors["app"]
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("app" in e.lower() for e in det_result.errors)

    def test_missing_detectors_list(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        del detectors["detectors"]
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("detectors" in e.lower() for e in det_result.errors)

    def test_detector_missing_name(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        del detectors["detectors"][0]["name"]
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("name" in e.lower() for e in det_result.errors)

    def test_detector_missing_event_type(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        del detectors["detectors"][0]["event_type"]
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("event_type" in e.lower() for e in det_result.errors)

    def test_detector_missing_condition(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        del detectors["detectors"][0]["condition"]
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("condition" in e.lower() for e in det_result.errors)

    def test_detector_unknown_condition_type(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        detectors["detectors"][0]["condition"]["type"] = "magic_filter"
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("condition type" in e.lower() or "magic_filter" in e for e in det_result.errors)

    def test_detector_invalid_severity(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        detectors["detectors"][0]["severity"] = "extreme"
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("severity" in e.lower() for e in det_result.errors)

    def test_count_threshold_missing_required_fields(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        # count_threshold requires window_minutes and threshold
        detectors["detectors"][0]["condition"] = {"type": "count_threshold"}
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("window_minutes" in e or "threshold" in e for e in det_result.errors)

    def test_new_value_missing_field(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        detectors["detectors"][1]["condition"] = {"type": "new_value"}
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("field" in e.lower() for e in det_result.errors)

    def test_volume_ratio_missing_ratio(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        detectors["detectors"][0]["condition"] = {"type": "volume_ratio"}
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("ratio" in e.lower() for e in det_result.errors)

    def test_regex_match_missing_fields(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        detectors = _valid_detectors_yaml()
        detectors["detectors"][0]["condition"] = {"type": "regex_match"}
        _write_app(app_dir, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not det_result.passed
        assert any("field" in e.lower() or "pattern" in e.lower() for e in det_result.errors)

    def test_no_detectors_yaml_skipped(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        _write_app(app_dir, parser=_valid_parser_yaml())
        results = verify_app_artifacts(app_dir)
        det_results = [r for r in results if r.plugin_type == "detectors"]
        assert len(det_results) == 0


class TestCrossValidation:
    def test_detector_references_parser_event_type(self, tmp_path: Path) -> None:
        """Detectors referencing event_types not in parser should warn."""
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        detectors = _valid_detectors_yaml()
        # Add a detector that references an event_type not in parser
        detectors["detectors"].append({
            "name": "testapp-ghost-detector",
            "description": "References nonexistent event type",
            "event_type": "nonexistent_event",
            "condition": {"type": "new_value", "field": "actor"},
            "severity": "warn",
        })
        _write_app(app_dir, parser=parser, detectors=detectors)
        results = verify_app_artifacts(app_dir)
        # Cross-validation warnings should be present
        all_warnings = []
        for r in results:
            all_warnings.extend(r.warnings)
        assert any("nonexistent_event" in w for w in all_warnings)

    def test_matching_event_types_no_warning(self, tmp_path: Path) -> None:
        """When all detector event_types match parser event_types, no warnings."""
        app_dir = tmp_path / "apps" / "testapp"
        _write_app(app_dir, parser=_valid_parser_yaml(), detectors=_valid_detectors_yaml())
        results = verify_app_artifacts(app_dir)
        all_warnings = []
        for r in results:
            all_warnings.extend(r.warnings)
        cross_warnings = [w for w in all_warnings if "event_type" in w.lower()]
        assert len(cross_warnings) == 0


class TestVerifyBothArtifacts:
    def test_both_valid(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        _write_app(app_dir, parser=_valid_parser_yaml(), detectors=_valid_detectors_yaml())
        results = verify_app_artifacts(app_dir)
        assert all(r.passed for r in results), f"Failures: {[r.errors for r in results if not r.passed]}"

    def test_invalid_parser_valid_detectors(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        parser = _valid_parser_yaml()
        parser["templates"][0]["pattern"] = r"[invalid(("
        _write_app(app_dir, parser=parser, detectors=_valid_detectors_yaml())
        results = verify_app_artifacts(app_dir)
        parser_result = [r for r in results if r.plugin_type == "parser"][0]
        det_result = [r for r in results if r.plugin_type == "detectors"][0]
        assert not parser_result.passed
        assert det_result.passed

    def test_empty_app_dir(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "apps" / "testapp"
        app_dir.mkdir(parents=True)
        results = verify_app_artifacts(app_dir)
        assert len(results) == 0
