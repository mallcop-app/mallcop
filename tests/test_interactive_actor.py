"""Validation tests for the interactive actor manifest and system prompt."""

from pathlib import Path

import pytest
import yaml

ACTOR_DIR = Path(__file__).parent.parent / "src" / "mallcop" / "actors" / "interactive"
MANIFEST_PATH = ACTOR_DIR / "manifest.yaml"
POST_PATH = ACTOR_DIR / "POST.md"


class TestInteractiveManifest:
    def setup_method(self):
        with open(MANIFEST_PATH) as f:
            self.manifest = yaml.safe_load(f)

    def test_manifest_exists(self):
        assert MANIFEST_PATH.exists(), "manifest.yaml not found"

    def test_required_field_name(self):
        assert self.manifest.get("name") == "interactive"

    def test_required_field_type(self):
        assert self.manifest.get("type") == "agent"

    def test_required_field_description(self):
        desc = self.manifest.get("description")
        assert desc and len(desc) > 0, "description must not be empty"

    def test_required_field_version(self):
        version = self.manifest.get("version")
        assert version and len(version) > 0, "version must not be empty"

    def test_required_field_model(self):
        assert self.manifest.get("model") == "detective"

    def test_tools_list_present(self):
        tools = self.manifest.get("tools")
        assert isinstance(tools, list), "tools must be a list"
        assert len(tools) > 0, "tools list must not be empty"

    def test_read_tools_present(self):
        tools = self.manifest.get("tools", [])
        expected_read = {
            "read-finding",
            "list-findings",
            "search-findings",
            "read-events",
            "search-events",
            "check-baseline",
            "baseline-stats",
            "read-config",
        }
        for t in expected_read:
            assert t in tools, f"expected tool '{t}' not in manifest tools"

    def test_write_tools_present(self):
        tools = self.manifest.get("tools", [])
        assert "annotate-finding" in tools
        assert "escalate-to-investigator" in tools

    def test_no_routes_to(self):
        # Interactive actor must NOT have routes_to (chat does not auto-chain)
        assert "routes_to" not in self.manifest, (
            "interactive actor must not have routes_to — chat hands off via tool"
        )

    def test_schema_loadable(self):
        # Verify the manifest loads cleanly via the official schema loader
        from mallcop.actors._schema import load_actor_manifest

        actor = load_actor_manifest(ACTOR_DIR)
        assert actor.name == "interactive"
        assert actor.type == "agent"
        assert actor.model == "detective"
        assert actor.routes_to is None


class TestInteractivePost:
    def setup_method(self):
        self.content = POST_PATH.read_text()

    def test_post_exists(self):
        assert POST_PATH.exists(), "POST.md not found"

    def test_post_non_empty(self):
        assert len(self.content.strip()) > 100, "POST.md must have substantive content"

    def test_contains_list_findings(self):
        assert "list-findings" in self.content

    def test_contains_escalate(self):
        assert "escalate" in self.content.lower()

    def test_contains_annotate(self):
        assert "annotate" in self.content.lower()

    def test_contains_security_section(self):
        assert "UNTRUSTED" in self.content or "untrusted" in self.content.lower()

    def test_anti_hallucination_guidance(self):
        # Must warn against hallucinating finding IDs
        assert "hallucinate" in self.content.lower()

    def test_format_guidance_present(self):
        # Must show format for finding responses
        assert "SEVERITY" in self.content
