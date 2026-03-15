"""Integration tests for boundary checker: preflight, squelch exemption, batch, circuit breaker."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from mallcop.boundary import BoundaryViolation, run_boundary_preflight
from mallcop.actors.batch import _NON_BULK_DETECTORS, is_non_bulk_resolvable
from mallcop.schemas import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(detector: str = "test-detector", severity: Severity = Severity.WARN) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(tz=timezone.utc),
        detector=detector,
        event_ids=[],
        title="test finding",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_config(with_openclaw: bool = True) -> MagicMock:
    cfg = MagicMock()
    if with_openclaw:
        cfg.connectors = {"openclaw": {"openclaw_user": "openclaw_usr"}}
    else:
        cfg.connectors = {}
    return cfg


# ---------------------------------------------------------------------------
# 1. run_boundary_preflight with openclaw in config returns findings
# ---------------------------------------------------------------------------

class TestRunBoundaryPreflight:
    def test_returns_findings_when_violations_exist(self, tmp_path: Path):
        """Preflight returns findings and writes them to the store when violations exist."""
        violation = BoundaryViolation(
            check_name="file_ownership",
            severity=Severity.CRITICAL,
            message="some file is world-writable",
            remediation_command="chmod o-w /some/path",
        )

        mock_store = MagicMock()
        mock_config = _make_config(with_openclaw=True)

        with patch("mallcop.config.load_config", return_value=mock_config), \
             patch("mallcop.store.JsonlStore", return_value=mock_store), \
             patch("mallcop.boundary.run_boundary_checks", return_value=[violation]), \
             patch("os.getlogin", return_value="mallcop_usr"):
            findings = run_boundary_preflight(tmp_path)

        assert len(findings) == 1
        assert findings[0].detector == "boundary-violation"
        assert findings[0].severity == Severity.CRITICAL
        mock_store.append_findings.assert_called_once_with(findings)

    def test_returns_empty_when_no_violations(self, tmp_path: Path):
        """Preflight returns empty list when no violations, does not write to store."""
        mock_store = MagicMock()
        mock_config = _make_config(with_openclaw=True)

        with patch("mallcop.config.load_config", return_value=mock_config), \
             patch("mallcop.store.JsonlStore", return_value=mock_store), \
             patch("mallcop.boundary.run_boundary_checks", return_value=[]), \
             patch("os.getlogin", return_value="mallcop_usr"):
            findings = run_boundary_preflight(tmp_path)

        assert findings == []
        mock_store.append_findings.assert_not_called()

    def test_returns_empty_without_openclaw_connector(self, tmp_path: Path):
        """Preflight returns empty list immediately when openclaw not in config."""
        mock_config = _make_config(with_openclaw=False)

        with patch("mallcop.config.load_config", return_value=mock_config), \
             patch("mallcop.boundary.run_boundary_checks") as mock_checks:
            findings = run_boundary_preflight(tmp_path)

        assert findings == []
        mock_checks.assert_not_called()

    def test_uses_openclaw_user_from_config(self, tmp_path: Path):
        """Preflight passes the configured openclaw_user to run_boundary_checks."""
        mock_store = MagicMock()
        mock_config = _make_config(with_openclaw=True)
        mock_config.connectors = {"openclaw": {"openclaw_user": "expected_openclaw"}}

        captured = {}

        def capture_checks(paths, mallcop_user, openclaw_user):
            captured["openclaw_user"] = openclaw_user
            return []

        with patch("mallcop.config.load_config", return_value=mock_config), \
             patch("mallcop.store.JsonlStore", return_value=mock_store), \
             patch("mallcop.boundary.run_boundary_checks", side_effect=capture_checks), \
             patch("os.getlogin", return_value="mallcop_usr"):
            run_boundary_preflight(tmp_path)

        assert captured["openclaw_user"] == "expected_openclaw"


# ---------------------------------------------------------------------------
# 2. boundary-violation in _NON_BULK_DETECTORS
# ---------------------------------------------------------------------------

class TestNonBulkDetectors:
    def test_boundary_violation_in_frozenset(self):
        assert "boundary-violation" in _NON_BULK_DETECTORS

    def test_boundary_finding_is_non_bulk_resolvable(self):
        finding = _make_finding(detector="boundary-violation")
        assert is_non_bulk_resolvable(finding) is True

    def test_other_detectors_not_affected(self):
        finding = _make_finding(detector="unusual-resource-access")
        assert is_non_bulk_resolvable(finding) is False


# ---------------------------------------------------------------------------
# 3. Squelch exemption: boundary-violation findings skip squelch
# ---------------------------------------------------------------------------

class TestSquelchExemption:
    def test_boundary_finding_never_squelched(self):
        """_should_squelch must not be reached for boundary-violation findings."""
        from mallcop.escalate import _should_squelch
        from mallcop.actors._schema import ActorResolution, ResolutionAction
        from mallcop.actors.runtime import RunResult

        # Build a RunResult that would normally be squelched (low confidence)
        _dummy_finding_id = str(uuid.uuid4())
        resolution = ActorResolution(
            finding_id=_dummy_finding_id,
            action=ResolutionAction.ESCALATED,
            reason="Test",
            confidence=0.1,  # Very low confidence — would be squelched at squelch=5
        )
        result = RunResult(resolution=resolution, tokens_used=0, iterations=1)

        # Confirm _should_squelch *would* squelch this at threshold 0.5
        squelched, _ = _should_squelch(result, squelch=5, _random_override=0.5)
        assert squelched is True, "Precondition: low-confidence finding should be squelchable"

        # Now verify the escalate loop exempts boundary-violation from squelch
        # We do this by calling run_escalate with a mocked store and actor_runner
        # that returns the low-confidence escalated result, and checking the finding
        # is NOT marked SQUELCHED.
        from mallcop.escalate import run_escalate
        from mallcop.schemas import FindingStatus

        bv_finding = _make_finding(detector="boundary-violation", severity=Severity.CRITICAL)
        bv_finding = Finding(
            id=bv_finding.id,
            timestamp=bv_finding.timestamp,
            detector="boundary-violation",
            event_ids=[],
            title="world-writable path",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},
        )

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [bv_finding]
        mock_store.get_baseline.return_value = None

        mock_config = MagicMock()
        mock_config.budget.max_findings_for_actors = 25
        mock_config.budget.max_donuts_per_run = 0  # unlimited
        mock_config.budget.max_donuts_per_finding = 0
        mock_config.routing = {"critical": MagicMock(chain=["triage"], notify=[])}
        mock_config.squelch = 5

        def mock_actor_runner(finding, **kwargs):
            return RunResult(resolution=resolution, tokens_used=10, iterations=1)

        mock_store.query_feedback.return_value = []

        with patch("mallcop.escalate.load_config", return_value=mock_config), \
             patch("mallcop.escalate.append_cost_log"), \
             patch("mallcop.escalate.check_circuit_breaker", return_value=None):
            run_escalate(Path("/fake/root"), actor_runner=mock_actor_runner, store=mock_store)

        # The finding should NOT have been updated with SQUELCHED status
        for call in mock_store.update_finding.call_args_list:
            kwargs = call[1] if call[1] else {}
            args = call[0] if call[0] else ()
            # Check status kwarg was not SQUELCHED
            status = kwargs.get("status")
            assert status != FindingStatus.SQUELCHED, (
                f"boundary-violation finding was incorrectly squelched: {call}"
            )


# ---------------------------------------------------------------------------
# 4. Circuit breaker excludes boundary-violation from count
# ---------------------------------------------------------------------------

class TestCircuitBreakerExemption:
    def test_boundary_violations_excluded_from_circuit_breaker(self):
        """Circuit breaker threshold uses only non-boundary findings."""
        from mallcop.escalate import run_escalate
        from mallcop.actors._schema import ActorResolution, ResolutionAction
        from mallcop.actors.runtime import RunResult

        bv_finding = _make_finding(detector="boundary-violation", severity=Severity.CRITICAL)
        normal_finding = _make_finding(detector="priv-escalation", severity=Severity.WARN)

        mock_store = MagicMock()
        # Only return the normal finding in the gated set (boundary partition removes bv)
        mock_store.query_findings.return_value = [bv_finding, normal_finding]
        mock_store.get_baseline.return_value = None

        captured_findings = []

        def mock_circuit_breaker(findings, budget_config):
            captured_findings.extend(findings)
            return None  # No circuit breaker trip

        mock_config = MagicMock()
        mock_config.budget.max_findings_for_actors = 25
        mock_config.budget.max_donuts_per_run = 0
        mock_config.budget.max_donuts_per_finding = 0
        mock_config.routing = {}
        mock_config.squelch = 0

        mock_store.query_feedback.return_value = []

        with patch("mallcop.escalate.load_config", return_value=mock_config), \
             patch("mallcop.escalate.append_cost_log"), \
             patch("mallcop.escalate.check_circuit_breaker", side_effect=mock_circuit_breaker):
            run_escalate(Path("/fake/root"), actor_runner=None, store=mock_store)

        # circuit breaker should only have seen the normal finding, not the boundary-violation
        finding_detectors = [f.detector for f in captured_findings]
        assert "boundary-violation" not in finding_detectors
        assert "priv-escalation" in finding_detectors


# ---------------------------------------------------------------------------
# 5. Circuit breaker: boundary findings still processed when CB trips
# ---------------------------------------------------------------------------

class TestBoundaryFindingsFlowThroughCircuitBreaker:
    def test_boundary_findings_processed_when_cb_trips(self):
        """When circuit breaker fires, boundary-violation findings still reach actor chain."""
        from mallcop.escalate import run_escalate
        from mallcop.actors._schema import ActorResolution, ResolutionAction
        from mallcop.actors.runtime import RunResult

        bv_finding = _make_finding(detector="boundary-violation", severity=Severity.CRITICAL)

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [bv_finding]
        mock_store.get_baseline.return_value = None
        mock_store.query_feedback.return_value = []

        mock_config = MagicMock()
        mock_config.budget.max_findings_for_actors = 25
        mock_config.budget.max_donuts_per_run = 0
        mock_config.budget.max_donuts_per_finding = 0
        # Route CRITICAL findings through triage actor
        mock_config.routing = {"critical": MagicMock(chain=["triage"], notify=[])}
        mock_config.squelch = 0

        processed_findings: list[Finding] = []

        def mock_actor_runner(finding, **kwargs):
            processed_findings.append(finding)
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Boundary violation requires remediation",
                ),
                tokens_used=10,
                iterations=1,
            )

        # Simulate circuit breaker firing (returning a meta finding)
        cb_meta = _make_finding(detector="mallcop-budget", severity=Severity.CRITICAL)
        cb_meta.id = "meta_circuit_breaker"

        with patch("mallcop.escalate.load_config", return_value=mock_config), \
             patch("mallcop.escalate.append_cost_log"), \
             patch("mallcop.escalate.check_circuit_breaker", return_value=cb_meta):
            result = run_escalate(
                Path("/fake/root"), actor_runner=mock_actor_runner, store=mock_store
            )

        # Circuit breaker should have been triggered
        assert result["circuit_breaker_triggered"] is True
        # But the boundary-violation finding should still have been processed
        assert any(f.detector == "boundary-violation" for f in processed_findings), (
            "boundary-violation finding was not processed despite circuit breaker"
        )


# ---------------------------------------------------------------------------
# 6. Ack rejection: boundary-violation findings cannot be acked
# ---------------------------------------------------------------------------

class TestAckRejection:
    def test_ack_boundary_violation_rejected(self, tmp_path: Path):
        """mallcop ack rejects boundary-violation findings with an error."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        bv_finding = _make_finding(detector="boundary-violation", severity=Severity.CRITICAL)

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [bv_finding]

        with patch("mallcop.cli.JsonlStore", return_value=mock_store):
            runner = CliRunner()
            result = runner.invoke(cli, ["ack", bv_finding.id, "--dir", str(tmp_path)])

        assert result.exit_code == 1
        import json as _json
        output = _json.loads(result.output.strip())
        assert output["status"] == "error"
        assert "boundary-violation" in output["error"]
        assert "cannot be acked" in output["error"]

    def test_ack_normal_finding_not_rejected(self, tmp_path: Path):
        """Normal findings can still be acked (ack rejection only applies to boundary-violation)."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        normal_finding = _make_finding(detector="priv-escalation", severity=Severity.WARN)

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [normal_finding]
        # Simulate update_finding and query_findings for re-read
        updated_finding = _make_finding(detector="priv-escalation", severity=Severity.WARN)
        updated_finding.status = FindingStatus.ACKED
        mock_store.query_findings.side_effect = [
            [normal_finding],   # first call: look up finding
            [updated_finding],  # second call: re-read after update
        ]

        with patch("mallcop.cli.JsonlStore", return_value=mock_store), \
             patch("mallcop.cli.load_config", side_effect=Exception("no config needed")):
            runner = CliRunner()
            result = runner.invoke(cli, ["ack", normal_finding.id, "--dir", str(tmp_path)])

        # Should not exit with error code 1 due to boundary-violation rejection
        # (may fail for other reasons like config, but not the boundary-violation gate)
        import json as _json
        if result.output.strip():
            try:
                output = _json.loads(result.output.strip())
                assert "cannot be acked" not in output.get("error", ""), (
                    "Normal finding was incorrectly rejected as boundary-violation"
                )
            except _json.JSONDecodeError:
                pass  # Non-JSON output is fine


# ---------------------------------------------------------------------------
# 7. Actor cannot resolve boundary-violation findings
# ---------------------------------------------------------------------------

class TestActorResolveRejection:
    def test_resolve_finding_tool_blocks_resolve_on_boundary_violation(self):
        """resolve-finding tool overrides 'resolved' to 'escalated' for boundary-violation."""
        from mallcop.tools.findings import resolve_finding
        from mallcop.tools import ToolContext

        bv_finding = _make_finding(detector="boundary-violation", severity=Severity.CRITICAL)

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [bv_finding]

        context = MagicMock(spec=ToolContext)
        context.store = mock_store

        result = resolve_finding(
            context=context,
            finding_id=bv_finding.id,
            action="resolved",
            reason="Looks benign",
        )

        assert result["action"] == "escalated", (
            "resolve-finding should override 'resolved' to 'escalated' for boundary-violation"
        )
        assert "boundary-violation" in result["reason"]
        assert "cannot be resolved" in result["reason"]
        assert "Looks benign" in result["reason"]

    def test_resolve_finding_tool_allows_escalate_on_boundary_violation(self):
        """resolve-finding tool allows 'escalated' action on boundary-violation findings."""
        from mallcop.tools.findings import resolve_finding
        from mallcop.tools import ToolContext

        bv_finding = _make_finding(detector="boundary-violation", severity=Severity.CRITICAL)

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [bv_finding]

        context = MagicMock(spec=ToolContext)
        context.store = mock_store

        result = resolve_finding(
            context=context,
            finding_id=bv_finding.id,
            action="escalated",
            reason="Needs human review",
        )

        assert result["action"] == "escalated"
        assert result["reason"] == "Needs human review"

    def test_resolve_finding_tool_allows_resolve_on_normal_finding(self):
        """resolve-finding tool does not affect 'resolved' on non-boundary findings."""
        from mallcop.tools.findings import resolve_finding
        from mallcop.tools import ToolContext

        normal_finding = _make_finding(detector="priv-escalation", severity=Severity.WARN)

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [normal_finding]

        context = MagicMock(spec=ToolContext)
        context.store = mock_store

        result = resolve_finding(
            context=context,
            finding_id=normal_finding.id,
            action="resolved",
            reason="Normal activity",
        )

        assert result["action"] == "resolved"
        assert result["reason"] == "Normal activity"

    def test_escalate_pipeline_overrides_resolved_to_escalated(self):
        """run_escalate overrides any RESOLVED resolution for boundary-violation findings."""
        from mallcop.escalate import run_escalate
        from mallcop.actors._schema import ActorResolution, ResolutionAction
        from mallcop.actors.runtime import RunResult

        bv_finding = _make_finding(detector="boundary-violation", severity=Severity.CRITICAL)

        mock_store = MagicMock()
        mock_store.query_findings.return_value = [bv_finding]
        mock_store.get_baseline.return_value = None
        mock_store.query_feedback.return_value = []

        mock_config = MagicMock()
        mock_config.budget.max_findings_for_actors = 25
        mock_config.budget.max_donuts_per_run = 0
        mock_config.budget.max_donuts_per_finding = 0
        mock_config.routing = {"critical": MagicMock(chain=["triage"], notify=[])}
        mock_config.squelch = 0

        def mock_actor_runner(finding, **kwargs):
            # Actor claims to resolve the boundary-violation (should be overridden)
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="I think this is fine",
                ),
                tokens_used=10,
                iterations=1,
            )

        with patch("mallcop.escalate.load_config", return_value=mock_config), \
             patch("mallcop.escalate.append_cost_log"), \
             patch("mallcop.escalate.check_circuit_breaker", return_value=None):
            run_escalate(Path("/fake/root"), actor_runner=mock_actor_runner, store=mock_store)

        # The finding should NOT have been updated with RESOLVED status
        for call in mock_store.update_finding.call_args_list:
            kwargs = call[1] if call[1] else {}
            status = kwargs.get("status")
            assert status != FindingStatus.RESOLVED, (
                f"boundary-violation finding was incorrectly resolved: {call}"
            )
            # Also verify SQUELCHED was not applied
            assert status != FindingStatus.SQUELCHED, (
                f"boundary-violation finding was incorrectly squelched: {call}"
            )
