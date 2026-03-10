"""Tests for triage actor plugin: manifest validation, POST.md loading."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mallcop.actors._schema import ActorManifest, load_actor_manifest


# ─── Manifest loading and validation ─────────────────────────────────


class TestTriageManifest:
    @pytest.fixture
    def triage_dir(self) -> Path:
        """Return the path to the built-in triage actor plugin."""
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "triage"

    def test_manifest_exists(self, triage_dir: Path) -> None:
        assert (triage_dir / "manifest.yaml").exists()

    def test_manifest_loads_without_error(self, triage_dir: Path) -> None:
        manifest = load_actor_manifest(triage_dir)
        assert isinstance(manifest, ActorManifest)

    def test_manifest_name(self, triage_dir: Path) -> None:
        manifest = load_actor_manifest(triage_dir)
        assert manifest.name == "triage"

    def test_manifest_type_is_agent(self, triage_dir: Path) -> None:
        manifest = load_actor_manifest(triage_dir)
        assert manifest.type == "agent"

    def test_manifest_model_is_sonnet(self, triage_dir: Path) -> None:
        manifest = load_actor_manifest(triage_dir)
        assert manifest.model == "sonnet"

    def test_manifest_tools(self, triage_dir: Path) -> None:
        manifest = load_actor_manifest(triage_dir)
        expected_tools = ["read-events", "check-baseline", "read-finding", "search-events", "resolve-finding"]
        assert manifest.tools == expected_tools

    def test_manifest_permissions_read_only(self, triage_dir: Path) -> None:
        manifest = load_actor_manifest(triage_dir)
        assert manifest.permissions == ["read"]

    def test_manifest_routes_to(self, triage_dir: Path) -> None:
        manifest = load_actor_manifest(triage_dir)
        assert manifest.routes_to == "investigate"

    def test_manifest_max_iterations(self, triage_dir: Path) -> None:
        manifest = load_actor_manifest(triage_dir)
        assert manifest.max_iterations == 3


# ─── POST.md loading ─────────────────────────────────────────────────


class TestTriagePostMd:
    @pytest.fixture
    def triage_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "triage"

    def test_post_md_exists(self, triage_dir: Path) -> None:
        assert (triage_dir / "POST.md").exists()

    def test_post_md_loads_as_string(self, triage_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(triage_dir)
        assert isinstance(content, str)
        assert len(content) > 0

    def test_post_md_contains_triage_identity(self, triage_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(triage_dir)
        assert "triage" in content.lower()

    def test_post_md_contains_decision_criteria(self, triage_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(triage_dir)
        assert "baseline" in content.lower()

    def test_post_md_contains_security_guardrails(self, triage_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(triage_dir)
        assert "USER_DATA" in content

    def test_post_md_contains_output_format(self, triage_dir: Path) -> None:
        from mallcop.actors.runtime import load_post_md
        content = load_post_md(triage_dir)
        assert "resolution" in content.lower() or "resolve" in content.lower()
