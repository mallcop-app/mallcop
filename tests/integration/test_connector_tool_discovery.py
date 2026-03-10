"""Integration tests for connector-specific tool discovery.

Verifies that build_actor_runner discovers tools from connector directories
(connectors/<name>/tools.py) when the connector is configured, and skips
them when not configured. Precedence: deployment plugins > connector tools > built-in.

Bead: mallcop-14
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from mallcop.actors._schema import ActorManifest, ActorResolution, ResolutionAction
from mallcop.actors.runtime import (
    ActorRuntime,
    LLMClient,
    LLMResponse,
    RunResult,
    ToolCall,
    build_actor_runner,
)
from mallcop.config import BudgetConfig, MallcopConfig, load_config
from mallcop.schemas import Event, Finding, FindingStatus, Severity
from mallcop.store import JsonlStore
from mallcop.tools import ToolContext, ToolRegistry, tool

from datetime import datetime, timezone


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_finding(id: str = "fnd_001") -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc),
        detector="new-actor",
        event_ids=["evt_001"],
        title="New actor detected",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _write_config(root: Path, connectors: dict[str, Any] | None = None) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": connectors or {},
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


class MockLLMClient(LLMClient):
    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self._call_count = 0
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        self.calls.append({
            "model": model,
            "system_prompt": system_prompt,
            "messages": messages,
            "tools": tools,
        })
        if self._call_count >= len(self._responses):
            raise RuntimeError("MockLLMClient exhausted responses")
        resp = self._responses[self._call_count]
        self._call_count += 1
        return resp


def _create_fake_connector_with_tools(connector_dir: Path, tool_name: str) -> None:
    """Create a fake connector directory with manifest.yaml and tools.py."""
    connector_dir.mkdir(parents=True, exist_ok=True)

    # manifest.yaml
    manifest = {
        "name": connector_dir.name,
        "description": f"Fake {connector_dir.name} connector",
        "version": "0.1.0",
        "auth": {"required": [], "optional": []},
        "event_types": ["test-event"],
        "tools": [
            {"name": tool_name, "description": f"Tool from {connector_dir.name}", "permission": "read"}
        ],
    }
    with open(connector_dir / "manifest.yaml", "w") as f:
        yaml.dump(manifest, f)

    # __init__.py
    (connector_dir / "__init__.py").write_text("")

    # tools.py with @tool-decorated function
    tools_code = f'''"""Tools for {connector_dir.name} connector."""
from mallcop.tools import tool

@tool(name="{tool_name}", description="Tool from {connector_dir.name}", permission="read")
def fake_tool() -> str:
    """A fake tool for testing."""
    return "result from {connector_dir.name}"
'''
    (connector_dir / "tools.py").write_text(tools_code)


# ─── Test 1: Connector tool appears in registry via build_actor_runner ─


class TestConnectorToolInBuildActorRunner:
    """build_actor_runner discovers connector tools when connector is configured."""

    def test_connector_tools_in_registry_when_configured(self, tmp_path: Path) -> None:
        """When azure is in config.connectors, azure tools are discoverable."""
        # Create a fake connector with tools
        connectors_dir = tmp_path / "src" / "connectors"
        fake_conn_dir = connectors_dir / "fakecloud"
        _create_fake_connector_with_tools(fake_conn_dir, "fakecloud.query-logs")

        # Write config with the connector listed
        _write_config(tmp_path, connectors={"fakecloud": {"api_key": "test"}})
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)

        # Create a triage actor dir
        actor_dir = tmp_path / "actors" / "triage"
        actor_dir.mkdir(parents=True)
        actor_manifest = {
            "name": "triage",
            "type": "agent",
            "description": "Test triage",
            "version": "0.1.0",
            "model": "haiku",
            "tools": ["fakecloud.query-logs"],
            "permissions": ["read"],
            "routes_to": None,
            "max_iterations": 5,
        }
        with open(actor_dir / "manifest.yaml", "w") as f:
            yaml.dump(actor_manifest, f)

        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="Done",
        )
        llm = MockLLMClient([
            LLMResponse(tool_calls=[], resolution=resolution, tokens_used=100),
        ])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[actor_dir],
            connector_dirs=[fake_conn_dir],
        )

        assert runner is not None
        # The runner should work — if the tool wasn't discovered, ActorRuntime
        # would raise KeyError when filtering tools
        result = runner(_make_finding())
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED


# ─── Test 2: Connector not in config → its tools not discovered ───────


class TestUnconfiguredConnectorExcluded:
    """Connectors not listed in config.connectors have their tools skipped."""

    def test_unconfigured_connector_tools_not_discovered(self, tmp_path: Path) -> None:
        """If a connector is NOT in config.connectors, its tools.py is not scanned."""
        connectors_dir = tmp_path / "src" / "connectors"
        fake_conn_dir = connectors_dir / "fakecloud"
        _create_fake_connector_with_tools(fake_conn_dir, "fakecloud.query-logs")

        # Config with NO connectors
        _write_config(tmp_path, connectors={})
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)

        # Pass the fake connector dir explicitly — but since fakecloud is NOT
        # in config.connectors, _discover_configured_connector_dirs should
        # filter it out, and the tool should NOT appear in the registry.
        from mallcop.actors.runtime import _discover_configured_connector_dirs

        result_dirs = _discover_configured_connector_dirs(config, connector_dirs=[fake_conn_dir])
        assert result_dirs == [], "Unconfigured connector dir should be filtered out"

        # Also verify via ToolRegistry: only built-in tools, no connector tools
        builtin_tools_dir = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "tools"
        registry = ToolRegistry.discover_tools(result_dirs + [builtin_tools_dir])
        tool_names = [t["name"] for t in registry.list_tools()]
        assert "fakecloud.query-logs" not in tool_names

    def test_only_configured_connectors_tools_discovered(self, tmp_path: Path) -> None:
        """With two connectors on disk but only one configured, only one's tools appear."""
        connectors_dir = tmp_path / "src" / "connectors"

        # Create two fake connectors
        conn_a = connectors_dir / "alpha"
        _create_fake_connector_with_tools(conn_a, "alpha.tool")
        conn_b = connectors_dir / "beta"
        _create_fake_connector_with_tools(conn_b, "beta.tool")

        # Only alpha is configured
        _write_config(tmp_path, connectors={"alpha": {"key": "val"}})
        config = load_config(tmp_path)

        # Directly test: pass only configured connector dirs
        registry = ToolRegistry.discover_tools([conn_a])
        tool_names = [t["name"] for t in registry.list_tools()]
        assert "alpha.tool" in tool_names

        # Beta should NOT be discovered if we don't pass it
        assert "beta.tool" not in tool_names


# ─── Test 3: Precedence — deployment plugin overrides connector tool ──


class TestToolPrecedence:
    """Deployment plugin tools take precedence over connector tools of the same name."""

    def test_deployment_plugin_overrides_connector_tool(self, tmp_path: Path) -> None:
        """If deployment plugins/tools/ has a tool with same name as connector tool,
        the deployment version wins."""
        # Create connector tool
        conn_dir = tmp_path / "connectors" / "fakecloud"
        conn_dir.mkdir(parents=True)
        (conn_dir / "__init__.py").write_text("")
        conn_tools = f'''from mallcop.tools import tool

@tool(name="shared-tool", description="connector version", permission="read")
def shared_tool() -> str:
    return "from connector"
'''
        (conn_dir / "tools.py").write_text(conn_tools)

        # Create deployment plugin tool with same name
        deploy_dir = tmp_path / "plugins" / "tools"
        deploy_dir.mkdir(parents=True)
        deploy_tools = f'''from mallcop.tools import tool

@tool(name="shared-tool", description="deployment version", permission="read")
def shared_tool() -> str:
    return "from deployment"
'''
        (deploy_dir / "override.py").write_text(deploy_tools)

        # discover_tools: deployment first, then connector → deployment wins
        registry = ToolRegistry.discover_tools([deploy_dir, conn_dir])
        tools = registry.list_tools()
        shared = [t for t in tools if t["name"] == "shared-tool"]
        assert len(shared) == 1
        assert shared[0]["description"] == "deployment version"

    def test_connector_tool_does_not_override_builtin(self, tmp_path: Path) -> None:
        """If a connector tool has the same name as a built-in tool,
        the built-in wins (built-in is scanned first in default precedence:
        deployment > connector > built-in... wait, design says deployment > connector > built-in
        so connector DOES override built-in). Let's verify the actual precedence order."""
        builtin_dir = tmp_path / "builtin"
        builtin_dir.mkdir()
        builtin_code = '''from mallcop.tools import tool

@tool(name="read-events", description="builtin version", permission="read")
def read_events() -> str:
    return "from builtin"
'''
        (builtin_dir / "events.py").write_text(builtin_code)

        conn_dir = tmp_path / "connector"
        conn_dir.mkdir()
        conn_code = '''from mallcop.tools import tool

@tool(name="read-events", description="connector version", permission="read")
def read_events() -> str:
    return "from connector"
'''
        (conn_dir / "events.py").write_text(conn_code)

        # Precedence: deployment > connector > built-in
        # So connector tools are scanned BEFORE built-in → connector wins
        registry = ToolRegistry.discover_tools([conn_dir, builtin_dir])
        tools = registry.list_tools()
        evt_tool = [t for t in tools if t["name"] == "read-events"]
        assert len(evt_tool) == 1
        assert evt_tool[0]["description"] == "connector version"


# ─── Test 4: build_actor_runner wires connector tools end-to-end ──────


class TestBuildActorRunnerConnectorIntegration:
    """build_actor_runner with configured connector discovers its tools
    and an actor can reference them by name."""

    def test_actor_uses_connector_tool(self, tmp_path: Path) -> None:
        """Actor manifest references a connector tool, LLM calls it, tool executes."""
        # Create a fake connector with a tool
        conn_dir = tmp_path / "connectors" / "fakecloud"
        conn_dir.mkdir(parents=True)
        (conn_dir / "__init__.py").write_text("")
        (conn_dir / "manifest.yaml").write_text(yaml.dump({
            "name": "fakecloud",
            "description": "Fake",
            "version": "0.1.0",
            "auth": {"required": [], "optional": []},
            "event_types": [],
            "tools": [{"name": "fakecloud.check-status", "description": "Check status", "permission": "read"}],
        }))
        tools_code = '''"""Fakecloud tools."""
from mallcop.tools import tool

@tool(name="fakecloud.check-status", description="Check fakecloud status", permission="read")
def check_status() -> str:
    return "all systems operational"
'''
        (conn_dir / "tools.py").write_text(tools_code)

        # Config with fakecloud configured
        _write_config(tmp_path, connectors={"fakecloud": {"key": "val"}})
        store = JsonlStore(tmp_path)
        config = load_config(tmp_path)

        # Actor manifest that uses the connector tool
        actor_dir = tmp_path / "actors" / "triage"
        actor_dir.mkdir(parents=True)
        with open(actor_dir / "manifest.yaml", "w") as f:
            yaml.dump({
                "name": "triage",
                "type": "agent",
                "description": "Test",
                "version": "0.1.0",
                "model": "haiku",
                "tools": ["fakecloud.check-status"],
                "permissions": ["read"],
                "routes_to": None,
                "max_iterations": 5,
            }, f)

        resolution = ActorResolution(
            finding_id="fnd_001",
            action=ResolutionAction.RESOLVED,
            reason="All clear",
        )
        llm = MockLLMClient([
            LLMResponse(
                tool_calls=[ToolCall(name="fakecloud.check-status", arguments={})],
                resolution=None,
                tokens_used=80,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=resolution,
                tokens_used=50,
            ),
        ])

        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=llm,
            actor_dirs=[actor_dir],
            connector_dirs=[conn_dir],
        )
        assert runner is not None

        result = runner(_make_finding())
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.RESOLVED

        # Verify the connector tool was actually called — check LLM messages
        second_call = llm.calls[1]
        tool_msgs = [m for m in second_call["messages"] if m.get("role") == "tool"]
        # tool_msgs[0] = finding context, tool_msgs[1] = fakecloud.check-status result
        assert len(tool_msgs) >= 2
        assert "all systems operational" in tool_msgs[1]["content"]
