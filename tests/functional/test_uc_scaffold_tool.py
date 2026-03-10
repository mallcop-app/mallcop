"""Functional tests for tool scaffold and verify.

Exercises:
  1. mallcop scaffold tool <name> -> generates plugins/tools/<name>.py
  2. mallcop verify plugins/tools/<name>.py -> validates tool file
  3. mallcop verify --all -> includes tools in plugins/tools/
  4. Scaffold -> verify round-trip passes
  5. Verify catches: missing @tool, bad permission, non-serializable params, bare *args/**kwargs
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from mallcop.cli import cli


class TestScaffoldTool:
    """scaffold tool <name> generates a valid tool file."""

    def test_scaffold_tool_creates_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["scaffold", "tool", "mycheck"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert data["status"] == "ok"
            assert data["plugin_type"] == "tool"
            assert data["name"] == "mycheck"
            assert "plugins/tools/mycheck.py" in data["path"]

            tool_file = Path.cwd() / "plugins" / "tools" / "mycheck.py"
            assert tool_file.exists()

    def test_scaffold_tool_file_structure(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(cli, ["scaffold", "tool", "mycheck"])
            tool_file = Path.cwd() / "plugins" / "tools" / "mycheck.py"
            code = tool_file.read_text()

            # Has @tool decorator
            assert "@tool(" in code
            # Has permission="read"
            assert 'permission="read"' in code
            # Has context: ToolContext as first param
            assert "context: ToolContext" in code
            # Has type-hinted user-facing params
            assert "str" in code or "int" in code
            # Has module docstring
            assert '"""' in code
            # Returns dict
            assert "return {" in code or "return dict" in code or "-> dict" in code

    def test_scaffold_tool_creates_parent_dir(self, tmp_path: Path) -> None:
        """plugins/tools/ directory is created if it doesn't exist."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            assert not (Path.cwd() / "plugins" / "tools").exists()
            runner.invoke(cli, ["scaffold", "tool", "mycheck"])
            assert (Path.cwd() / "plugins" / "tools").is_dir()

    def test_scaffold_tool_duplicate_errors(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result1 = runner.invoke(cli, ["scaffold", "tool", "mycheck"])
            assert result1.exit_code == 0
            result2 = runner.invoke(cli, ["scaffold", "tool", "mycheck"])
            assert result2.exit_code == 1
            data = json.loads(result2.output)
            assert data["status"] == "error"

    def test_scaffold_tool_hyphenated_name(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["scaffold", "tool", "my-check"])
            assert result.exit_code == 0
            tool_file = Path.cwd() / "plugins" / "tools" / "my-check.py"
            assert tool_file.exists()
            code = tool_file.read_text()
            assert "@tool(" in code


class TestScaffoldToolVerifyRoundtrip:
    """scaffold tool -> verify passes without modification."""

    def test_scaffold_then_verify_passes(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(cli, ["scaffold", "tool", "mycheck"])
            result = runner.invoke(cli, ["verify", "plugins/tools/mycheck.py"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert data["status"] == "ok"
            assert data["results"][0]["passed"] is True
            assert data["results"][0]["errors"] == []


class TestVerifyToolValid:
    """verify accepts valid tool files."""

    def test_verify_valid_tool_file(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "good_tool.py"
        tool_file.write_text('''\
"""A good tool."""

from mallcop.tools import ToolContext, tool


@tool(name="good-tool", description="Does good things", permission="read")
def good_tool(context: ToolContext, query: str, limit: int = 10) -> dict:
    """Do good things."""
    return {"result": query}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["results"][0]["passed"] is True

    def test_verify_tool_write_permission(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "write_tool.py"
        tool_file.write_text('''\
"""A write tool."""

from mallcop.tools import ToolContext, tool


@tool(name="write-tool", description="Writes things", permission="write")
def write_tool(context: ToolContext, target: str) -> dict:
    """Write things."""
    return {"written": target}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["results"][0]["passed"] is True

    def test_verify_tool_multiple_tools_in_file(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "multi_tool.py"
        tool_file.write_text('''\
"""Multiple tools in one file."""

from mallcop.tools import ToolContext, tool


@tool(name="tool-a", description="Tool A", permission="read")
def tool_a(context: ToolContext, query: str) -> dict:
    return {}


@tool(name="tool-b", description="Tool B", permission="read")
def tool_b(context: ToolContext, name: str) -> dict:
    return {}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["status"] == "ok"


class TestVerifyToolMissingDecorator:
    """verify catches tool files with no @tool decorator."""

    def test_verify_no_tool_decorator(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "bad_tool.py"
        tool_file.write_text('''\
"""A file with no @tool decorator."""


def not_a_tool(query: str) -> dict:
    return {}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["status"] == "fail"
        assert any("@tool" in e.lower() or "decorator" in e.lower()
                    for e in data["results"][0]["errors"])


class TestVerifyToolBadPermission:
    """verify catches tool with invalid permission value."""

    def test_verify_bad_permission(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "bad_perm.py"
        # Write a file where the @tool decorator would fail at import time
        # because "execute" is not a valid permission. The verify should catch this.
        tool_file.write_text('''\
"""A tool with bad permission."""

from mallcop.tools import ToolContext, tool


@tool(name="bad-perm", description="Bad permission", permission="execute")
def bad_perm(context: ToolContext, query: str) -> dict:
    return {}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["status"] == "fail"
        assert any("permission" in e.lower()
                    for e in data["results"][0]["errors"])


class TestVerifyToolNonSerializableParam:
    """verify catches tool with non-JSON-serializable parameter types."""

    def test_verify_non_serializable_param(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "bad_param.py"
        tool_file.write_text('''\
"""A tool with non-serializable param type."""

from pathlib import Path
from mallcop.tools import ToolContext, tool


@tool(name="bad-param", description="Bad param", permission="read")
def bad_param(context: ToolContext, path: Path) -> dict:
    return {}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["status"] == "fail"
        assert any("serializable" in e.lower() or "type" in e.lower()
                    for e in data["results"][0]["errors"])

    def test_verify_bare_args_rejected(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "bare_args.py"
        tool_file.write_text('''\
"""A tool with bare *args."""

from mallcop.tools import ToolContext, tool


@tool(name="bare-args", description="Bare args", permission="read")
def bare_args(context: ToolContext, *args) -> dict:
    return {}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["status"] == "fail"
        assert any("args" in e.lower() or "kwargs" in e.lower()
                    for e in data["results"][0]["errors"])

    def test_verify_bare_kwargs_rejected(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "bare_kwargs.py"
        tool_file.write_text('''\
"""A tool with bare **kwargs."""

from mallcop.tools import ToolContext, tool


@tool(name="bare-kwargs", description="Bare kwargs", permission="read")
def bare_kwargs(context: ToolContext, **kwargs) -> dict:
    return {}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["status"] == "fail"
        assert any("args" in e.lower() or "kwargs" in e.lower()
                    for e in data["results"][0]["errors"])

    def test_verify_untyped_param_rejected(self, tmp_path: Path) -> None:
        tool_file = tmp_path / "untyped.py"
        tool_file.write_text('''\
"""A tool with untyped user-facing param."""

from mallcop.tools import ToolContext, tool


@tool(name="untyped", description="Untyped param", permission="read")
def untyped(context: ToolContext, query) -> dict:
    return {}
''')
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tool_file)])
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["status"] == "fail"
        assert any("type" in e.lower() for e in data["results"][0]["errors"])


class TestVerifyAllIncludesTools:
    """verify --all discovers and validates tools in plugins/tools/."""

    def test_verify_all_includes_tool_files(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            # Create a connector and a tool
            runner.invoke(cli, ["scaffold", "connector", "cloud1"])
            runner.invoke(cli, ["scaffold", "tool", "mycheck"])

            result = runner.invoke(cli, ["verify", "--all"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert data["status"] == "ok"
            # Should have at least 2 results: 1 connector + 1 tool
            assert len(data["results"]) >= 2
            types = {r["type"] for r in data["results"]}
            assert "tool" in types
            assert "connector" in types

    def test_verify_all_catches_bad_tool(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            # Create a good connector and a bad tool file
            runner.invoke(cli, ["scaffold", "connector", "cloud1"])

            # Write a bad tool file (no @tool decorator)
            tools_dir = Path.cwd() / "plugins" / "tools"
            tools_dir.mkdir(parents=True, exist_ok=True)
            (tools_dir / "bad_tool.py").write_text('''\
"""Bad tool - no decorator."""


def not_a_tool(query: str) -> dict:
    return {}
''')
            result = runner.invoke(cli, ["verify", "--all"])
            assert result.exit_code == 1
            data = json.loads(result.output)
            assert data["status"] == "fail"
