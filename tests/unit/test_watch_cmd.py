"""Tests for mallcop watch command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock, call

import pytest
import yaml

from mallcop.config import ProConfig
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
                "donuts_used": 0,
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
                "donuts_used": 0,
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
                "donuts_used": 0,
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
                "donuts_used": 0,
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
                "donuts_used": 1500,
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


# ─── Watch: Pro usage reporting ──────────────────────────────────────────────


class TestWatchProUsageReporting:
    """Tests for ProClient.record_usage() integration after escalate."""

    def _make_fns(self, tokens_used: int = 1500) -> tuple:
        def mock_scan(root: Path) -> dict[str, Any]:
            return {"status": "ok", "total_events_ingested": 5, "connectors": {}}

        def mock_detect(root: Path) -> dict[str, Any]:
            return {"status": "ok", "findings_count": 2, "summary": {}, "learning_connectors": []}

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            return {
                "status": "ok",
                "findings_processed": 2,
                "circuit_breaker_triggered": False,
                "budget_exhausted": False,
                "donuts_used": tokens_used,
            }

        return mock_scan, mock_detect, mock_escalate

    def test_pro_config_calls_record_usage(self, tmp_path: Path) -> None:
        """watch with pro config calls ProClient.record_usage after escalate."""
        from mallcop.watch import run_watch

        pro_config = ProConfig(
            account_id="acct-123",
            service_token="tok-abc",
            account_url="https://api.mallcop.app",
            inference_url="",
        )
        mock_scan, mock_detect, mock_escalate = self._make_fns(tokens_used=1500)

        mock_client = MagicMock()
        mock_client.record_usage.return_value = {"recorded": True}

        with patch("mallcop.watch.ProClient", return_value=mock_client) as MockProClient:
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=False,
                pro_config=pro_config,
            )

        assert result["status"] == "ok"
        MockProClient.assert_called_once_with("https://api.mallcop.app")
        mock_client.record_usage.assert_called_once_with(
            account_id="acct-123",
            model="managed",
            input_tokens=1500,
            output_tokens=0,
            service_token="tok-abc",
        )

    def test_byok_config_does_not_call_record_usage(self, tmp_path: Path) -> None:
        """watch without pro config does NOT call ProClient.record_usage."""
        from mallcop.watch import run_watch

        mock_scan, mock_detect, mock_escalate = self._make_fns(tokens_used=500)

        with patch("mallcop.watch.ProClient") as MockProClient:
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=False,
                pro_config=None,
            )

        assert result["status"] == "ok"
        MockProClient.assert_not_called()

    def test_record_usage_failure_does_not_fail_watch(self, tmp_path: Path) -> None:
        """record_usage failure is logged as warning; watch still returns ok."""
        from mallcop.watch import run_watch

        pro_config = ProConfig(
            account_id="acct-123",
            service_token="tok-abc",
            account_url="https://api.mallcop.app",
            inference_url="",
        )
        mock_scan, mock_detect, mock_escalate = self._make_fns(tokens_used=800)

        mock_client = MagicMock()
        mock_client.record_usage.side_effect = RuntimeError("service unavailable")

        with patch("mallcop.watch.ProClient", return_value=mock_client):
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=False,
                pro_config=pro_config,
            )

        assert result["status"] == "ok"
        mock_client.record_usage.assert_called_once()

    def test_no_tokens_skips_record_usage(self, tmp_path: Path) -> None:
        """If escalate used 0 tokens, record_usage is still called (0 tokens is valid)."""
        from mallcop.watch import run_watch

        pro_config = ProConfig(
            account_id="acct-123",
            service_token="tok-abc",
            account_url="https://api.mallcop.app",
            inference_url="",
        )
        mock_scan, mock_detect, mock_escalate = self._make_fns(tokens_used=0)

        mock_client = MagicMock()
        mock_client.record_usage.return_value = {"recorded": True}

        with patch("mallcop.watch.ProClient", return_value=mock_client):
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=False,
                pro_config=pro_config,
            )

        assert result["status"] == "ok"
        mock_client.record_usage.assert_called_once()

    def test_dry_run_does_not_call_record_usage(self, tmp_path: Path) -> None:
        """dry_run skips escalate, so record_usage is also not called."""
        from mallcop.watch import run_watch

        pro_config = ProConfig(
            account_id="acct-123",
            service_token="tok-abc",
            account_url="https://api.mallcop.app",
            inference_url="",
        )
        mock_scan, mock_detect, mock_escalate = self._make_fns(tokens_used=1000)

        with patch("mallcop.watch.ProClient") as MockProClient:
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=True,
                pro_config=pro_config,
            )

        assert result["dry_run"] is True
        MockProClient.assert_not_called()


# ─── Watch: pro_config partial state ─────────────────────────────────────────
# mallcop-ak1n.5.5: partial pro_config, escalate failure, missing tokens_used


class TestWatchProConfigPartialState:
    """5.5: pro_config partial state coverage."""

    def _make_fns(self, tokens_used: int = 500) -> tuple:
        def mock_scan(root: Path) -> dict[str, Any]:
            return {"status": "ok", "total_events_ingested": 1, "connectors": {}}

        def mock_detect(root: Path) -> dict[str, Any]:
            return {"status": "ok", "findings_count": 1, "summary": {}, "learning_connectors": []}

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            return {
                "status": "ok",
                "findings_processed": 1,
                "circuit_breaker_triggered": False,
                "budget_exhausted": False,
                "donuts_used": tokens_used,
            }

        return mock_scan, mock_detect, mock_escalate

    def test_pro_config_missing_service_token_skips_record_usage(self, tmp_path: Path) -> None:
        """ProConfig with account_id but no service_token must NOT call record_usage."""
        from mallcop.watch import run_watch

        pro_config = ProConfig(
            account_id="acct-123",
            service_token="",  # missing
            account_url="https://api.mallcop.app",
            inference_url="",
        )
        mock_scan, mock_detect, mock_escalate = self._make_fns()

        with patch("mallcop.watch.ProClient") as MockProClient:
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=False,
                pro_config=pro_config,
            )

        assert result["status"] == "ok"
        MockProClient.assert_not_called()

    def test_pro_config_missing_account_id_skips_record_usage(self, tmp_path: Path) -> None:
        """ProConfig with service_token but no account_id must NOT call record_usage."""
        from mallcop.watch import run_watch

        pro_config = ProConfig(
            account_id="",  # missing
            service_token="tok-abc",
            account_url="https://api.mallcop.app",
            inference_url="",
        )
        mock_scan, mock_detect, mock_escalate = self._make_fns()

        with patch("mallcop.watch.ProClient") as MockProClient:
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=False,
                pro_config=pro_config,
            )

        assert result["status"] == "ok"
        MockProClient.assert_not_called()

    def test_escalate_failure_skips_record_usage(self, tmp_path: Path) -> None:
        """When escalate raises, run_watch returns early — record_usage must NOT be called."""
        from mallcop.watch import run_watch

        pro_config = ProConfig(
            account_id="acct-123",
            service_token="tok-abc",
            account_url="https://api.mallcop.app",
            inference_url="",
        )

        def mock_scan(root: Path) -> dict[str, Any]:
            return {"status": "ok", "total_events_ingested": 1, "connectors": {}}

        def mock_detect(root: Path) -> dict[str, Any]:
            return {"status": "ok", "findings_count": 1, "summary": {}, "learning_connectors": []}

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("escalate exploded")

        with patch("mallcop.watch.ProClient") as MockProClient:
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=False,
                pro_config=pro_config,
            )

        assert result["status"] == "error"
        MockProClient.assert_not_called()

    def test_missing_tokens_used_in_result_defaults_to_zero(self, tmp_path: Path) -> None:
        """If escalate result has no 'donuts_used' key, watch uses 0 and does not crash."""
        from mallcop.watch import run_watch

        pro_config = ProConfig(
            account_id="acct-123",
            service_token="tok-abc",
            account_url="https://api.mallcop.app",
            inference_url="",
        )

        def mock_scan(root: Path) -> dict[str, Any]:
            return {"status": "ok", "total_events_ingested": 0, "connectors": {}}

        def mock_detect(root: Path) -> dict[str, Any]:
            return {"status": "ok", "findings_count": 0, "summary": {}, "learning_connectors": []}

        def mock_escalate(root: Path, **kwargs: Any) -> dict[str, Any]:
            # Note: no 'donuts_used' key
            return {"status": "ok", "findings_processed": 0}

        mock_client = MagicMock()
        mock_client.record_usage.return_value = {"recorded": True}

        with patch("mallcop.watch.ProClient", return_value=mock_client):
            result = run_watch(
                tmp_path,
                scan_fn=mock_scan,
                detect_fn=mock_detect,
                escalate_fn=mock_escalate,
                dry_run=False,
                pro_config=pro_config,
            )

        assert result["status"] == "ok"
        mock_client.record_usage.assert_called_once()
        call_kwargs = mock_client.record_usage.call_args
        assert call_kwargs[1]["input_tokens"] == 0
