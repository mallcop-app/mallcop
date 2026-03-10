"""Tests for mallcop watch command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest
import yaml

from mallcop.schemas import Finding, Severity, FindingStatus


# ─── Helpers ────────────────────────────────────────────────────────


def _write_config(root: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {"warn": "triage", "critical": "triage", "info": None},
        "actor_chain": {"triage": {"routes_to": None}},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


# ─── Watch: pipeline orchestration ──────────────────────────────


class TestWatchPipeline:
    def test_calls_scan_detect_escalate_in_order(self, tmp_path: Path) -> None:
        """watch calls scan, detect, escalate in sequence."""
        from mallcop.watch import run_watch

        call_order: list[str] = []

        def mock_scan(root: Path) -> dict[str, Any]:
            call_order.append("scan")
            return {"status": "ok", "total_events_ingested": 0, "connectors": {}}

        def mock_detect(root: Path) -> dict[str, Any]:
            call_order.append("detect")
            return {"status": "ok", "findings_count": 0, "summary": {}, "learning_connectors": []}

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            call_order.append("escalate")
            return {
                "status": "ok",
                "findings_processed": 0,
                "circuit_breaker_triggered": False,
                "budget_exhausted": False,
                "tokens_used": 0,
            }

        result = run_watch(
            tmp_path,
            scan_fn=mock_scan,
            detect_fn=mock_detect,
            escalate_fn=mock_escalate,
            dry_run=False,
        )

        assert call_order == ["scan", "detect", "escalate"]
        assert result["status"] == "ok"

    def test_dry_run_skips_escalate(self, tmp_path: Path) -> None:
        """watch --dry-run runs scan + detect but skips escalate."""
        from mallcop.watch import run_watch

        call_order: list[str] = []

        def mock_scan(root: Path) -> dict[str, Any]:
            call_order.append("scan")
            return {"status": "ok", "total_events_ingested": 5, "connectors": {}}

        def mock_detect(root: Path) -> dict[str, Any]:
            call_order.append("detect")
            return {"status": "ok", "findings_count": 2, "summary": {}, "learning_connectors": []}

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            call_order.append("escalate")
            return {
                "status": "ok",
                "findings_processed": 2,
                "circuit_breaker_triggered": False,
                "budget_exhausted": False,
                "tokens_used": 0,
            }

        result = run_watch(
            tmp_path,
            scan_fn=mock_scan,
            detect_fn=mock_detect,
            escalate_fn=mock_escalate,
            dry_run=True,
        )

        assert "scan" in call_order
        assert "detect" in call_order
        assert "escalate" not in call_order
        assert result["dry_run"] is True

    def test_fail_fast_on_scan_failure(self, tmp_path: Path) -> None:
        """If scan fails, detect and escalate don't run."""
        from mallcop.watch import run_watch

        call_order: list[str] = []

        def mock_scan(root: Path) -> dict[str, Any]:
            call_order.append("scan")
            raise RuntimeError("Scan failed")

        def mock_detect(root: Path) -> dict[str, Any]:
            call_order.append("detect")
            return {"status": "ok", "findings_count": 0, "summary": {}, "learning_connectors": []}

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            call_order.append("escalate")
            return {
                "status": "ok",
                "findings_processed": 0,
                "circuit_breaker_triggered": False,
                "budget_exhausted": False,
                "tokens_used": 0,
            }

        result = run_watch(
            tmp_path,
            scan_fn=mock_scan,
            detect_fn=mock_detect,
            escalate_fn=mock_escalate,
            dry_run=False,
        )

        assert call_order == ["scan"]
        assert result["status"] == "error"

    def test_fail_fast_on_detect_failure(self, tmp_path: Path) -> None:
        """If detect fails, escalate doesn't run."""
        from mallcop.watch import run_watch

        call_order: list[str] = []

        def mock_scan(root: Path) -> dict[str, Any]:
            call_order.append("scan")
            return {"status": "ok", "total_events_ingested": 5, "connectors": {}}

        def mock_detect(root: Path) -> dict[str, Any]:
            call_order.append("detect")
            raise RuntimeError("Detect failed")

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            call_order.append("escalate")
            return {
                "status": "ok",
                "findings_processed": 0,
                "circuit_breaker_triggered": False,
                "budget_exhausted": False,
                "tokens_used": 0,
            }

        result = run_watch(
            tmp_path,
            scan_fn=mock_scan,
            detect_fn=mock_detect,
            escalate_fn=mock_escalate,
            dry_run=False,
        )

        assert call_order == ["scan", "detect"]
        assert result["status"] == "error"

    def test_returns_combined_result(self, tmp_path: Path) -> None:
        """watch returns a combined result with scan, detect, escalate summaries."""
        from mallcop.watch import run_watch

        def mock_scan(root: Path) -> dict[str, Any]:
            return {"status": "ok", "total_events_ingested": 10, "connectors": {"azure": {"events_ingested": 10}}}

        def mock_detect(root: Path) -> dict[str, Any]:
            return {"status": "ok", "findings_count": 3, "summary": {"new-actor": {"warn": 3}}, "learning_connectors": []}

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            return {
                "status": "ok",
                "findings_processed": 3,
                "circuit_breaker_triggered": False,
                "budget_exhausted": False,
                "tokens_used": 1500,
            }

        result = run_watch(
            tmp_path,
            scan_fn=mock_scan,
            detect_fn=mock_detect,
            escalate_fn=mock_escalate,
            dry_run=False,
        )

        assert result["status"] == "ok"
        assert "scan" in result
        assert "detect" in result
        assert "escalate" in result
