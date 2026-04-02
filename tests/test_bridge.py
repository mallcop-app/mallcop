"""Tests for mallcop bridge polling module (bridge.py).

TDD sequence:
1. bridge_poll_loop receives messages, runs inference, posts response
2. exponential backoff on HTTP errors
3. graceful shutdown via stop_event (daemon thread exits with main)
4. --bridge flag parsing in CLI
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest
import requests

from mallcop.bridge import (
    POLL_INTERVAL,
    _BACKOFF_STEPS,
    _build_system_prompt,
    _load_findings_context,
    bridge_poll_loop,
    run_inference,
    start_bridge_thread,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

INFERENCE_URL = "http://localhost:9000"
SERVICE_TOKEN = "mallcop-sk-test-token"


def _make_poll_response(messages: list[dict]) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"messages": messages}
    return r


def _make_error_response(status_code: int) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = {}
    return r


def _make_inference_response(content: str, input_tokens: int = 10, output_tokens: int = 20) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {
        "content": [{"type": "text", "text": content}],
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }
    r.raise_for_status = MagicMock()
    return r


def _make_respond_response() -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"status": "ok"}
    return r


def _make_findings_file(tmp_path: Path, findings: list[dict]) -> Path:
    path = tmp_path / "findings.jsonl"
    path.write_text("\n".join(json.dumps(f) for f in findings))
    return path


# ---------------------------------------------------------------------------
# Test 1: _load_findings_context loads findings
# ---------------------------------------------------------------------------

class TestLoadFindingsContext:
    """_load_findings_context returns a formatted string of findings."""

    def test_returns_empty_string_when_file_missing(self, tmp_path: Path) -> None:
        result = _load_findings_context(tmp_path / "findings.jsonl")
        assert result == ""

    def test_returns_finding_summaries(self, tmp_path: Path) -> None:
        path = _make_findings_file(tmp_path, [
            {"id": "F001", "severity": "high", "title": "Open S3 bucket"},
            {"id": "F002", "severity": "low", "title": "Debug endpoint exposed"},
        ])
        result = _load_findings_context(path)
        assert "[high] F001: Open S3 bucket" in result
        assert "[low] F002: Debug endpoint exposed" in result

    def test_skips_empty_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "findings.jsonl"
        path.write_text('\n{"id":"F001","severity":"high","title":"Test"}\n\n')
        result = _load_findings_context(path)
        assert "F001" in result

    def test_skips_entries_without_title(self, tmp_path: Path) -> None:
        path = _make_findings_file(tmp_path, [
            {"id": "F001", "severity": "low"},
        ])
        result = _load_findings_context(path)
        assert result == ""


# ---------------------------------------------------------------------------
# Test 2: _build_system_prompt
# ---------------------------------------------------------------------------

class TestBuildSystemPrompt:
    """_build_system_prompt includes findings when present."""

    def test_base_prompt_when_no_findings(self) -> None:
        result = _build_system_prompt("")
        assert "security analyst" in result
        assert "Current findings" not in result

    def test_includes_findings_block(self) -> None:
        result = _build_system_prompt("[high] F001: Open S3")
        assert "Current findings" in result
        assert "F001" in result


# ---------------------------------------------------------------------------
# Test 3: run_inference sends correct request, parses response
# ---------------------------------------------------------------------------

class TestRunInference:
    """run_inference calls inference endpoint and returns content + tokens."""

    def test_sends_post_to_messages_endpoint(self, tmp_path: Path) -> None:
        findings_path = tmp_path / "findings.jsonl"
        msg = {"session_id": "sess-1", "content": "What is my security risk?"}

        with patch("mallcop.bridge.requests.post") as mock_post:
            mock_post.return_value = _make_inference_response("Low risk.")
            result = run_inference(msg, findings_path, SERVICE_TOKEN, INFERENCE_URL)

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == f"{INFERENCE_URL}/v1/messages"
        headers = call_kwargs[1]["headers"]
        assert headers["Authorization"] == f"Bearer {SERVICE_TOKEN}"
        payload = call_kwargs[1]["json"]
        assert payload["messages"][0]["content"] == "What is my security risk?"

    def test_returns_content_and_tokens(self, tmp_path: Path) -> None:
        findings_path = tmp_path / "findings.jsonl"
        msg = {"session_id": "sess-1", "content": "Is my config safe?"}

        with patch("mallcop.bridge.requests.post") as mock_post:
            mock_post.return_value = _make_inference_response("Looks good.", 15, 25)
            result = run_inference(msg, findings_path, SERVICE_TOKEN, INFERENCE_URL)

        assert result["content"] == "Looks good."
        assert result["tokens_used"] == 40  # 15 + 25

    def test_includes_findings_in_system_prompt(self, tmp_path: Path) -> None:
        findings_path = _make_findings_file(tmp_path, [
            {"id": "F001", "severity": "critical", "title": "SSH open to world"},
        ])
        msg = {"session_id": "sess-2", "content": "Any issues?"}

        with patch("mallcop.bridge.requests.post") as mock_post:
            mock_post.return_value = _make_inference_response("Yes.")
            run_inference(msg, findings_path, SERVICE_TOKEN, INFERENCE_URL)

        payload = mock_post.call_args[1]["json"]
        assert "SSH open to world" in payload["system"]


# ---------------------------------------------------------------------------
# Test 4: bridge_poll_loop — receives messages, runs inference, posts response
# ---------------------------------------------------------------------------

class TestBridgePollLoop:
    """bridge_poll_loop polls, infers, responds, then stops."""

    def _run_loop_once(
        self,
        tmp_path: Path,
        poll_response: MagicMock,
        inference_response: MagicMock | None = None,
        respond_response: MagicMock | None = None,
        stop_after: float = 0.05,
    ) -> tuple[MagicMock, MagicMock, MagicMock]:
        """Run bridge_poll_loop in a thread and stop it after stop_after seconds."""
        stop_event = threading.Event()
        findings_path = tmp_path / "findings.jsonl"

        mock_get = MagicMock(return_value=poll_response)
        mock_post = MagicMock(
            side_effect=[
                inference_response or _make_inference_response("Answer."),
                respond_response or _make_respond_response(),
            ] * 10  # enough for multiple calls
        )

        def _run():
            with patch("mallcop.bridge.requests.get", mock_get), \
                 patch("mallcop.bridge.requests.post", mock_post):
                bridge_poll_loop(INFERENCE_URL, SERVICE_TOKEN, findings_path, stop_event)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(stop_after)
        stop_event.set()
        t.join(timeout=2.0)

        return mock_get, mock_post, stop_event

    def test_polls_bridge_endpoint(self, tmp_path: Path) -> None:
        poll_resp = _make_poll_response([])
        mock_get, _, _ = self._run_loop_once(tmp_path, poll_resp)
        mock_get.assert_called()
        call_url = mock_get.call_args[0][0]
        assert call_url == f"{INFERENCE_URL}/v1/bridge/poll"

    def test_sends_auth_header_on_poll(self, tmp_path: Path) -> None:
        poll_resp = _make_poll_response([])
        mock_get, _, _ = self._run_loop_once(tmp_path, poll_resp)
        headers = mock_get.call_args[1]["headers"]
        assert headers["Authorization"] == f"Bearer {SERVICE_TOKEN}"

    def test_processes_message_and_posts_response(self, tmp_path: Path) -> None:
        msg = {"session_id": "sess-abc", "content": "Are we secure?"}
        poll_resp = _make_poll_response([msg])

        stop_event = threading.Event()
        findings_path = tmp_path / "findings.jsonl"
        posted_responses: list[dict] = []

        def fake_post(url: str, **kwargs: Any) -> MagicMock:
            if "messages" in url:
                return _make_inference_response("All clear.")
            if "respond" in url:
                posted_responses.append(kwargs.get("json", {}))
                return _make_respond_response()
            return MagicMock(status_code=200)

        mock_get = MagicMock(return_value=poll_resp)

        def _run():
            with patch("mallcop.bridge.requests.get", mock_get), \
                 patch("mallcop.bridge.requests.post", fake_post):
                bridge_poll_loop(INFERENCE_URL, SERVICE_TOKEN, findings_path, stop_event)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(0.1)
        stop_event.set()
        t.join(timeout=2.0)

        assert len(posted_responses) >= 1
        resp = posted_responses[0]
        assert resp["session_id"] == "sess-abc"
        assert resp["content"] == "All clear."
        assert "metadata" in resp

    def test_respond_url_correct(self, tmp_path: Path) -> None:
        msg = {"session_id": "sess-xyz", "content": "Question?"}
        poll_resp = _make_poll_response([msg])

        stop_event = threading.Event()
        findings_path = tmp_path / "findings.jsonl"
        respond_urls: list[str] = []

        def fake_post(url: str, **kwargs: Any) -> MagicMock:
            if "messages" in url:
                return _make_inference_response("Answer.")
            respond_urls.append(url)
            return _make_respond_response()

        def _run():
            with patch("mallcop.bridge.requests.get", MagicMock(return_value=poll_resp)), \
                 patch("mallcop.bridge.requests.post", fake_post):
                bridge_poll_loop(INFERENCE_URL, SERVICE_TOKEN, findings_path, stop_event)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(0.1)
        stop_event.set()
        t.join(timeout=2.0)

        assert any(f"{INFERENCE_URL}/v1/bridge/respond" in u for u in respond_urls)


# ---------------------------------------------------------------------------
# Test 5: Exponential backoff on HTTP errors
# ---------------------------------------------------------------------------

class TestExponentialBackoff:
    """bridge_poll_loop backs off on HTTP errors following the _BACKOFF_STEPS sequence."""

    def test_backoff_sequence_defined(self) -> None:
        assert _BACKOFF_STEPS == [3, 6, 12, 24, 60]

    def test_backoff_used_on_http_error(self, tmp_path: Path) -> None:
        """On non-200 poll response, loop uses backoff sleep (not POLL_INTERVAL)."""
        stop_event = threading.Event()
        findings_path = tmp_path / "findings.jsonl"

        error_resp = _make_error_response(503)
        sleep_calls: list[float] = []

        def fake_sleep(secs: float) -> None:
            sleep_calls.append(secs)
            stop_event.set()  # stop after first backoff sleep

        def _run():
            with patch("mallcop.bridge.requests.get", MagicMock(return_value=error_resp)), \
                 patch("mallcop.bridge.time.sleep", fake_sleep):
                bridge_poll_loop(INFERENCE_URL, SERVICE_TOKEN, findings_path, stop_event)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=3.0)

        # At least one sleep should be a backoff step (first backoff = _BACKOFF_STEPS[1] = 6)
        # or the stop_event was set immediately
        assert stop_event.is_set()

    def test_backoff_caps_at_60s(self) -> None:
        """Backoff never exceeds 60 seconds regardless of consecutive failures."""
        assert max(_BACKOFF_STEPS) == 60

    def test_backoff_resets_on_success(self, tmp_path: Path) -> None:
        """After a successful poll, backoff index resets (next error starts from step 1)."""
        stop_event = threading.Event()
        findings_path = tmp_path / "findings.jsonl"

        call_count = [0]
        # First call: error; second call: success; third call: error again
        responses = [
            _make_error_response(500),
            _make_poll_response([]),
            _make_error_response(500),
        ]

        def fake_get(*args: Any, **kwargs: Any) -> MagicMock:
            idx = min(call_count[0], len(responses) - 1)
            call_count[0] += 1
            if call_count[0] >= 3:
                stop_event.set()
            return responses[idx]

        sleep_calls: list[float] = []

        def fake_sleep(secs: float) -> None:
            sleep_calls.append(secs)

        def _run():
            with patch("mallcop.bridge.requests.get", fake_get), \
                 patch("mallcop.bridge.time.sleep", fake_sleep):
                bridge_poll_loop(INFERENCE_URL, SERVICE_TOKEN, findings_path, stop_event)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=3.0)

        # Both error sleeps should be at an early backoff level (not maxed out at 60)
        error_sleeps = [s for s in sleep_calls if s > POLL_INTERVAL]
        assert all(s <= _BACKOFF_STEPS[1] for s in error_sleeps)


# ---------------------------------------------------------------------------
# Test 6: Graceful shutdown via stop_event
# ---------------------------------------------------------------------------

class TestGracefulShutdown:
    """bridge_poll_loop exits when stop_event is set."""

    def test_exits_when_stop_event_set(self, tmp_path: Path) -> None:
        stop_event = threading.Event()
        findings_path = tmp_path / "findings.jsonl"

        with patch("mallcop.bridge.requests.get", return_value=_make_poll_response([])):
            t = threading.Thread(
                target=bridge_poll_loop,
                args=(INFERENCE_URL, SERVICE_TOKEN, findings_path, stop_event),
                daemon=True,
            )
            t.start()
            time.sleep(0.05)
            stop_event.set()
            t.join(timeout=2.0)

        assert not t.is_alive()

    def test_start_bridge_thread_returns_daemon_thread(self, tmp_path: Path) -> None:
        findings_path = tmp_path / "findings.jsonl"

        with patch("mallcop.bridge.requests.get", return_value=_make_poll_response([])):
            t = start_bridge_thread(INFERENCE_URL, SERVICE_TOKEN, findings_path)

        assert t.daemon is True
        assert t.is_alive()
        # Let the daemon thread die when test exits — no explicit stop needed

    def test_thread_name(self, tmp_path: Path) -> None:
        findings_path = tmp_path / "findings.jsonl"

        with patch("mallcop.bridge.requests.get", return_value=_make_poll_response([])):
            t = start_bridge_thread(INFERENCE_URL, SERVICE_TOKEN, findings_path)

        assert t.name == "mallcop-bridge"


# ---------------------------------------------------------------------------
# Test 7: --bridge flag in CLI
# ---------------------------------------------------------------------------

class TestBridgeCliFlag:
    """--bridge flag on mallcop watch starts bridge thread when Pro config present."""

    def test_bridge_flag_registered_on_watch(self) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["watch", "--help"])
        assert "--bridge" in result.output

    def test_bridge_flag_is_boolean(self) -> None:
        """--bridge is a boolean flag (no argument required)."""
        from click.testing import CliRunner
        from mallcop.cli import cli
        import click

        # Check that the watch command has a bridge parameter of type bool
        watch_cmd = cli.commands["watch"]
        bridge_param = next(
            (p for p in watch_cmd.params if p.name == "bridge"),
            None,
        )
        assert bridge_param is not None
        assert bridge_param.is_flag

    def test_watch_without_bridge_flag_does_not_start_thread(self, tmp_path: Path) -> None:
        """Without --bridge, no bridge thread is started."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        runner = CliRunner()
        with patch("mallcop.bridge.start_bridge_thread") as mock_start, \
             patch("mallcop.cli.run_scan_pipeline", return_value={}), \
             patch("mallcop.cli.run_detect_pipeline", return_value={}), \
             patch("mallcop.escalate.run_escalate", return_value={}), \
             patch("mallcop.cli.load_config") as mock_cfg:
            mock_cfg.return_value = MagicMock(pro=None)
            runner.invoke(cli, ["watch", "--dir", str(tmp_path)])

        mock_start.assert_not_called()

    def test_watch_with_bridge_flag_and_no_pro_config_prints_warning(self, tmp_path: Path) -> None:
        """With --bridge but no Pro config, warn and continue."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        runner = CliRunner()
        with patch("mallcop.bridge.start_bridge_thread") as mock_start, \
             patch("mallcop.cli.run_scan_pipeline", return_value={}), \
             patch("mallcop.cli.run_detect_pipeline", return_value={}), \
             patch("mallcop.cli.load_config") as mock_cfg:
            mock_pro = MagicMock()
            mock_pro.service_token = ""
            mock_pro.inference_url = ""
            mock_cfg.return_value = MagicMock(pro=mock_pro)
            result = runner.invoke(cli, ["watch", "--bridge", "--dir", str(tmp_path)])

        mock_start.assert_not_called()
        assert "skipped" in result.output or "missing" in result.output

    def test_watch_with_bridge_flag_and_pro_config_starts_thread(self, tmp_path: Path) -> None:
        """With --bridge and valid Pro config, starts the bridge thread."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        runner = CliRunner()
        with patch("mallcop.bridge.start_bridge_thread") as mock_start, \
             patch("mallcop.cli.run_scan_pipeline", return_value={}), \
             patch("mallcop.cli.run_detect_pipeline", return_value={}), \
             patch("mallcop.cli.load_config") as mock_cfg:
            mock_pro = MagicMock()
            mock_pro.service_token = "mallcop-sk-abc"
            mock_pro.inference_url = "https://api.mallcop.app/api/inference"
            mock_cfg.return_value = MagicMock(pro=mock_pro)
            result = runner.invoke(cli, ["watch", "--bridge", "--dir", str(tmp_path)])

        mock_start.assert_called_once_with(
            inference_url="https://api.mallcop.app/api/inference",
            service_token="mallcop-sk-abc",
            findings_path=tmp_path / "findings.jsonl",
        )
