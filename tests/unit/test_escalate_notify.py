"""Tests for email notification wiring in run_escalate()."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import BatchResult, RunResult
from mallcop.config import (
    BudgetConfig,
    MallcopConfig,
    NotifyConfig,
    ProConfig,
    RouteConfig,
)
from mallcop.schemas import Annotation, Finding, FindingStatus, Severity


def _make_finding(
    id: str = "f-1",
    severity: Severity = Severity.WARN,
    detector: str = "test-detector",
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        detector=detector,
        event_ids=["e-1"],
        title=f"Test finding {id}",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_config(
    pro: ProConfig | None = None,
    notify: NotifyConfig | None = None,
    routing: dict | None = None,
) -> MallcopConfig:
    return MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing=routing or {"warn": RouteConfig(chain=["test-actor"], notify=[])},
        actor_chain={},
        budget=BudgetConfig(),
        pro=pro,
        notify=notify or NotifyConfig(),
        squelch=0,
    )


def _actor_escalates(finding, **kwargs) -> RunResult:
    """Actor runner that always escalates."""
    return RunResult(
        resolution=ActorResolution(
            finding_id=finding.id,
            action=ResolutionAction.ESCALATED,
            reason="Actor cannot resolve",
            confidence=0.8,
        ),
        tokens_used=100,
        iterations=1,
    )


def _actor_resolves(finding, **kwargs) -> RunResult:
    """Actor runner that always resolves."""
    return RunResult(
        resolution=ActorResolution(
            finding_id=finding.id,
            action=ResolutionAction.RESOLVED,
            reason="Fixed it",
            confidence=0.9,
        ),
        tokens_used=100,
        iterations=1,
    )


@pytest.fixture
def tmp_repo(tmp_path):
    """Create a minimal mallcop repo with config."""
    mallcop_dir = tmp_path / ".mallcop"
    mallcop_dir.mkdir()
    config_file = tmp_path / "mallcop.yaml"
    config_file.write_text(
        "secrets:\n  backend: env\nconnectors: {}\nrouting:\n  warn:\n    chain: [test-actor]\n    notify: []\nactor_chain: {}\n"
    )
    # Empty findings and costs files
    (mallcop_dir / "findings.jsonl").write_text("")
    (mallcop_dir / "costs.jsonl").write_text("")
    return tmp_path


class TestNotifyNoProConfig:
    """When pro config is absent, notify is never attempted."""

    def test_no_pro_config_skips_notify(self, tmp_repo):
        from mallcop.escalate import run_escalate
        from mallcop.store import JsonlStore

        store = JsonlStore(tmp_repo)
        f = _make_finding()
        store.append_findings([f])

        config = _make_config(pro=None, notify=NotifyConfig(email=True))

        with patch("mallcop.escalate.load_config", return_value=config), \
             patch("mallcop.pro.requests.post") as mock_post:
            run_escalate(tmp_repo, actor_runner=_actor_escalates, store=store)
            mock_post.assert_not_called()


class TestNotifyDisabled:
    """When notify.email is False, no notification fires."""

    def test_notify_disabled_skips(self, tmp_repo):
        from mallcop.escalate import run_escalate
        from mallcop.store import JsonlStore

        store = JsonlStore(tmp_repo)
        f = _make_finding()
        store.append_findings([f])

        pro = ProConfig(account_id="acct-1", service_token="tok-1")
        config = _make_config(pro=pro, notify=NotifyConfig(email=False))

        with patch("mallcop.escalate.load_config", return_value=config), \
             patch("mallcop.pro.requests.post") as mock_post:
            run_escalate(tmp_repo, actor_runner=_actor_escalates, store=store)
            mock_post.assert_not_called()


class TestNotifyHealFailed:
    """When actor escalates (heal failed), notify fires."""

    def test_heal_failed_fires_notify(self, tmp_repo):
        from mallcop.escalate import run_escalate
        from mallcop.store import JsonlStore

        store = JsonlStore(tmp_repo)
        f = _make_finding()
        store.append_findings([f])

        pro = ProConfig(account_id="acct-1", service_token="tok-1")
        config = _make_config(pro=pro, notify=NotifyConfig(email=True))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "sent"}

        with patch("mallcop.escalate.load_config", return_value=config), \
             patch("mallcop.pro.requests.post", return_value=mock_resp) as mock_post:
            run_escalate(tmp_repo, actor_runner=_actor_escalates, store=store)
            # notify should have been called
            assert mock_post.call_count >= 1
            # Find the notify call (POST to /notify)
            notify_calls = [c for c in mock_post.call_args_list if "/notify" in str(c)]
            assert len(notify_calls) == 1
            _, kwargs = notify_calls[0]
            assert kwargs["json"]["trigger"] == "heal_failed"


class TestNotifyEmailNotVerified:
    """When server returns 403 (email not verified), escalation result is unchanged."""

    def test_email_not_verified_warns(self, tmp_repo):
        from mallcop.escalate import run_escalate
        from mallcop.store import JsonlStore

        store = JsonlStore(tmp_repo)
        f = _make_finding()
        store.append_findings([f])

        pro = ProConfig(account_id="acct-1", service_token="tok-1")
        config = _make_config(pro=pro, notify=NotifyConfig(email=True))

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"detail": "email_not_verified"}
        mock_resp.text = '{"detail": "email_not_verified"}'

        with patch("mallcop.escalate.load_config", return_value=config), \
             patch("mallcop.pro.requests.post", return_value=mock_resp):
            # Should not raise
            result = run_escalate(tmp_repo, actor_runner=_actor_escalates, store=store)
            assert result["status"] == "ok"


class TestNotifyRateLimited:
    """When server returns 429 (rate limited), escalation result is unchanged."""

    def test_rate_limited_logs_info(self, tmp_repo):
        from mallcop.escalate import run_escalate
        from mallcop.store import JsonlStore

        store = JsonlStore(tmp_repo)
        f = _make_finding()
        store.append_findings([f])

        pro = ProConfig(account_id="acct-1", service_token="tok-1")
        config = _make_config(pro=pro, notify=NotifyConfig(email=True))

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.json.return_value = {"detail": "rate_limited", "retry_after": 300}
        mock_resp.text = '{"detail": "rate_limited", "retry_after": 300}'

        with patch("mallcop.escalate.load_config", return_value=config), \
             patch("mallcop.pro.requests.post", return_value=mock_resp):
            result = run_escalate(tmp_repo, actor_runner=_actor_escalates, store=store)
            assert result["status"] == "ok"


class TestNotifyResolved:
    """When all findings are resolved, no notification fires."""

    def test_all_resolved_no_notify(self, tmp_repo):
        from mallcop.escalate import run_escalate
        from mallcop.store import JsonlStore

        store = JsonlStore(tmp_repo)
        f = _make_finding()
        store.append_findings([f])

        pro = ProConfig(account_id="acct-1", service_token="tok-1")
        config = _make_config(pro=pro, notify=NotifyConfig(email=True))

        with patch("mallcop.escalate.load_config", return_value=config), \
             patch("mallcop.pro.requests.post") as mock_post:
            run_escalate(tmp_repo, actor_runner=_actor_resolves, store=store)
            # No notify call since everything resolved
            notify_calls = [c for c in mock_post.call_args_list if "/notify" in str(c)]
            assert len(notify_calls) == 0


class TestNotifyMinSeverity:
    """min_severity filter excludes low-severity findings."""

    def test_info_findings_filtered_by_warn_min(self, tmp_repo):
        from mallcop.escalate import run_escalate
        from mallcop.store import JsonlStore

        store = JsonlStore(tmp_repo)
        f = _make_finding(severity=Severity.INFO)
        store.append_findings([f])

        pro = ProConfig(account_id="acct-1", service_token="tok-1")
        config = _make_config(
            pro=pro,
            notify=NotifyConfig(email=True, min_severity="warn"),
            routing={"info": RouteConfig(chain=["test-actor"], notify=[])},
        )

        with patch("mallcop.escalate.load_config", return_value=config), \
             patch("mallcop.pro.requests.post") as mock_post:
            run_escalate(tmp_repo, actor_runner=_actor_escalates, store=store)
            notify_calls = [c for c in mock_post.call_args_list if "/notify" in str(c)]
            assert len(notify_calls) == 0
