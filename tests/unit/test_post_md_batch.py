"""Tests that POST.md files document batch context behavior."""

from pathlib import Path

import pytest

ACTORS_DIR = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors"

# triage POST.md was optimized with live LLMs and intentionally omits
# the batch context section — the prompt works better without it.
ACTOR_DIRS = ["notify_teams", "investigate"]


@pytest.mark.parametrize("actor_name", ACTOR_DIRS)
def test_post_md_contains_batch_context_section(actor_name):
    """Each actor POST.md must have a Batch Context section."""
    post_md = ACTORS_DIR / actor_name / "POST.md"
    assert post_md.exists(), f"POST.md missing for {actor_name}"
    content = post_md.read_text()
    assert "## Batch Context" in content, (
        f"{actor_name}/POST.md missing '## Batch Context' section"
    )


@pytest.mark.parametrize("actor_name", ACTOR_DIRS)
def test_post_md_batch_section_has_key_guidance(actor_name):
    """Batch Context section must explain one-at-a-time processing and consistency."""
    post_md = ACTORS_DIR / actor_name / "POST.md"
    content = post_md.read_text()
    lower = content.lower()
    assert "one finding at a time" in lower, (
        f"{actor_name}/POST.md batch section must mention one-finding-at-a-time processing"
    )
    assert "consistent" in lower, (
        f"{actor_name}/POST.md batch section must mention consistency across findings"
    )
