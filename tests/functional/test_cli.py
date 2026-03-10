"""Tests for CLI entrypoint and command stubs."""

from click.testing import CliRunner

from mallcop.cli import cli


EXPECTED_COMMANDS = [
    "init",
    "scan",
    "detect",
    "escalate",
    "watch",
    "review",
    "investigate",
    "report",
    "finding",
    "events",
    "baseline",
    "annotate",
    "ack",
    "status",
    "scaffold",
    "verify",
]


class TestCliHelp:
    def test_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_help_lists_all_commands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        for cmd in EXPECTED_COMMANDS:
            assert cmd in result.output, f"Command '{cmd}' not found in help output"


class TestCliStubs:
    """Each command should exist and exit without crashing."""

    def test_init(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0

    def test_scan(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code == 0

    def test_detect(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["detect"])
        assert result.exit_code == 0

    def test_escalate(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["escalate"])
        assert result.exit_code == 0

    def test_watch(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["watch"])
        assert result.exit_code == 0

    def test_review(self, tmp_path) -> None:
        import yaml
        config = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "budget": {},
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config, f)
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_investigate(self, tmp_path) -> None:
        import yaml
        config = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "budget": {},
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config, f)
        runner = CliRunner()
        # Finding not found returns exit code 1
        result = runner.invoke(cli, ["investigate", "fnd_test", "--dir", str(tmp_path)])
        assert result.exit_code == 1

    def test_report(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report"])
        assert result.exit_code == 0

    def test_finding(self, tmp_path) -> None:
        import yaml
        config = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "budget": {},
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config, f)
        runner = CliRunner()
        # Finding not found returns exit code 1
        result = runner.invoke(cli, ["finding", "fnd_test", "--dir", str(tmp_path)])
        assert result.exit_code == 1

    def test_events(self, tmp_path) -> None:
        import yaml
        config = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "budget": {},
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config, f)
        runner = CliRunner()
        result = runner.invoke(cli, ["events", "--dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_baseline(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["baseline"])
        assert result.exit_code == 0

    def test_annotate(self) -> None:
        runner = CliRunner()
        # annotate is implemented — nonexistent finding returns exit 1
        result = runner.invoke(cli, ["annotate", "fnd_test", "some note"])
        assert result.exit_code == 1

    def test_ack(self) -> None:
        runner = CliRunner()
        # ack now requires a valid finding; nonexistent finding returns exit 1
        result = runner.invoke(cli, ["ack", "fnd_test"])
        assert result.exit_code == 1

    def test_status(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0

    def test_scaffold(self, tmp_path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["scaffold", "connector", "test"])
            assert result.exit_code == 0

    def test_verify_no_args(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["verify"])
        assert result.exit_code == 1  # requires path or --all

    def test_ack_returns_error_for_missing_finding(self) -> None:
        """ack command returns error JSON for nonexistent finding (no longer a stub)."""
        import json

        runner = CliRunner()
        result = runner.invoke(cli, ["ack", "fnd_test"])
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "not found" in data["error"].lower()
