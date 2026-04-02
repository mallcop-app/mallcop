"""Tests for mallcop.notify — watch-cycle channel dispatch via /v1/notify."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest

from mallcop.config import RouteConfig
from mallcop.schemas import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id: str = "f-1",
    severity: Severity = Severity.CRITICAL,
    title: str = "Test finding",
    detector: str = "test-detector",
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        detector=detector,
        event_ids=["e-1"],
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_routing(notify_channels: list[str]) -> dict[str, RouteConfig | None]:
    return {
        "critical": RouteConfig(chain=[], notify=notify_channels),
        "warn": RouteConfig(chain=[], notify=notify_channels),
        "info": RouteConfig(chain=[], notify=notify_channels),
    }


def _make_managed_client(summary_text: str = "Finding summary text") -> MagicMock:
    """Return a mock ManagedClient whose chat() returns a text summary."""
    mock_resp = MagicMock()
    mock_resp.tool_calls = []
    mock_resp.raw_resolution = None
    mock_resp.tokens_used = 50
    # Simulate text content via the LLMResponse text attribute
    mock_client = MagicMock()
    mock_client.chat.return_value = mock_resp
    # We'll use a different approach: the notify module calls a helper that
    # calls managed_client.chat() and extracts text. We mock the full response.
    mock_client._summary_text = summary_text
    return mock_client


# ---------------------------------------------------------------------------
# Test 1: notify dispatched for critical finding matching routing config
# ---------------------------------------------------------------------------


class TestNotifyDispatchedForCritical:
    """Critical finding with notify channels → POST /v1/notify called."""

    def test_notify_dispatched_for_critical_matching_channel(self):
        from mallcop.notify import dispatch_notify

        findings = [_make_finding(severity=Severity.CRITICAL)]
        routing = _make_routing(["ops"])

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "sent"}

        mock_balance_resp = MagicMock()
        mock_balance_resp.status_code = 200
        mock_balance_resp.json.return_value = {"balance": 1000}

        mock_client = MagicMock()
        mock_client.chat.return_value = MagicMock(tool_calls=[], tokens_used=10)

        with patch("mallcop.notify.requests.get", return_value=mock_balance_resp), \
             patch("mallcop.notify.requests.post", return_value=mock_resp) as mock_post:
            result = dispatch_notify(
                findings=findings,
                routing=routing,
                managed_client=mock_client,
                api_base_url="https://api.mallcop.app",
                api_key="mallcop-sk-test",
            )

        # POST /v1/notify must have been called
        assert mock_post.called
        call_url = mock_post.call_args[0][0]
        assert "/v1/notify" in call_url
        assert result["dispatched"] == 1


# ---------------------------------------------------------------------------
# Test 2: notify suppressed for info finding when balance=0
# ---------------------------------------------------------------------------


class TestNotifySuppressedInfoWhenBalanceZero:
    """Info finding with balance=0 → POST /v1/notify NOT called."""

    def test_info_suppressed_when_balance_zero(self):
        from mallcop.notify import dispatch_notify

        findings = [_make_finding(severity=Severity.INFO)]
        routing = _make_routing(["ops"])

        mock_balance_resp = MagicMock()
        mock_balance_resp.status_code = 200
        mock_balance_resp.json.return_value = {"balance": 0}

        mock_client = MagicMock()

        with patch("mallcop.notify.requests.get", return_value=mock_balance_resp), \
             patch("mallcop.notify.requests.post") as mock_post:
            result = dispatch_notify(
                findings=findings,
                routing=routing,
                managed_client=mock_client,
                api_base_url="https://api.mallcop.app",
                api_key="mallcop-sk-test",
            )

        mock_post.assert_not_called()
        assert result["dispatched"] == 0
        assert result["suppressed"] == 1


# ---------------------------------------------------------------------------
# Test 3: notify sent for critical finding with balance=0 using summary=null
# ---------------------------------------------------------------------------


class TestNotifyCriticalWithBalanceZeroSummaryNull:
    """Critical finding with balance=0 → POST /v1/notify called with summary=null."""

    def test_critical_sent_with_null_summary_when_balance_zero(self):
        from mallcop.notify import dispatch_notify

        findings = [_make_finding(severity=Severity.CRITICAL)]
        routing = _make_routing(["ops"])

        mock_balance_resp = MagicMock()
        mock_balance_resp.status_code = 200
        mock_balance_resp.json.return_value = {"balance": 0}

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "sent"}

        mock_client = MagicMock()

        with patch("mallcop.notify.requests.get", return_value=mock_balance_resp), \
             patch("mallcop.notify.requests.post", return_value=mock_resp) as mock_post:
            result = dispatch_notify(
                findings=findings,
                routing=routing,
                managed_client=mock_client,
                api_base_url="https://api.mallcop.app",
                api_key="mallcop-sk-test",
            )

        # notify must be called for critical even with zero balance
        assert mock_post.called
        # summary in payload must be null/None
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs.get("json", {})
        assert payload.get("summary") is None
        assert result["dispatched"] == 1
        # managed_client.chat must NOT have been called (no summary generation)
        mock_client.chat.assert_not_called()


# ---------------------------------------------------------------------------
# Test 4: balance check called before summary generation
# ---------------------------------------------------------------------------


class TestBalanceCheckedBeforeSummary:
    """Balance check must happen before ManagedClient.chat() is called."""

    def test_balance_checked_before_summary_generation(self):
        from mallcop.notify import dispatch_notify

        findings = [_make_finding(severity=Severity.WARN)]
        routing = _make_routing(["ops"])

        call_order = []

        mock_balance_resp = MagicMock()
        mock_balance_resp.status_code = 200
        mock_balance_resp.json.return_value = {"balance": 500}

        mock_notify_resp = MagicMock()
        mock_notify_resp.status_code = 200
        mock_notify_resp.json.return_value = {"status": "sent"}

        mock_client = MagicMock()

        def balance_get(url, **kwargs):
            call_order.append("balance_check")
            return mock_balance_resp

        def chat_call(*args, **kwargs):
            call_order.append("summary_generation")
            resp = MagicMock()
            resp.tool_calls = []
            resp.tokens_used = 10
            return resp

        mock_client.chat.side_effect = chat_call

        with patch("mallcop.notify.requests.get", side_effect=balance_get), \
             patch("mallcop.notify.requests.post", return_value=mock_notify_resp):
            dispatch_notify(
                findings=findings,
                routing=routing,
                managed_client=mock_client,
                api_base_url="https://api.mallcop.app",
                api_key="mallcop-sk-test",
            )

        assert "balance_check" in call_order
        if "summary_generation" in call_order:
            assert call_order.index("balance_check") < call_order.index("summary_generation")


# ---------------------------------------------------------------------------
# Test 5: low-balance warning threshold computed correctly
# ---------------------------------------------------------------------------


class TestLowBalanceWarningThreshold:
    """Low-balance warning fires when balance < LOW_BALANCE_THRESHOLD."""

    def test_low_balance_threshold_computed(self):
        from mallcop.notify import LOW_BALANCE_THRESHOLD, compute_low_balance_warning

        # Threshold is a positive integer
        assert isinstance(LOW_BALANCE_THRESHOLD, int)
        assert LOW_BALANCE_THRESHOLD > 0

        # Below threshold: warning is True
        assert compute_low_balance_warning(balance=LOW_BALANCE_THRESHOLD - 1) is True

        # At or above threshold: warning is False
        assert compute_low_balance_warning(balance=LOW_BALANCE_THRESHOLD) is False
        assert compute_low_balance_warning(balance=LOW_BALANCE_THRESHOLD + 100) is False

        # Zero balance: warning is True
        assert compute_low_balance_warning(balance=0) is True


# ---------------------------------------------------------------------------
# Test 6: notify not sent when no notify channels configured
# ---------------------------------------------------------------------------


class TestNotifyNotSentWithNoChannels:
    """When routing has no notify channels, POST /v1/notify is never called."""

    def test_no_channels_no_notify(self):
        from mallcop.notify import dispatch_notify

        findings = [_make_finding(severity=Severity.CRITICAL)]
        # All severities have empty notify channel lists
        routing = {
            "critical": RouteConfig(chain=["actor"], notify=[]),
            "warn": RouteConfig(chain=["actor"], notify=[]),
            "info": RouteConfig(chain=["actor"], notify=[]),
        }

        mock_client = MagicMock()

        with patch("mallcop.notify.requests.get") as mock_get, \
             patch("mallcop.notify.requests.post") as mock_post:
            result = dispatch_notify(
                findings=findings,
                routing=routing,
                managed_client=mock_client,
                api_base_url="https://api.mallcop.app",
                api_key="mallcop-sk-test",
            )

        mock_post.assert_not_called()
        # Balance check should also be skipped — no point checking if no channels
        mock_get.assert_not_called()
        assert result["dispatched"] == 0
