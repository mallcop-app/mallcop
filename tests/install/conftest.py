"""
Fixtures for installation path tests.

This file is shared between test_clawcop.py (bead mallcop-h4i6) and
test_manual_install.py (bead mallcop-opoq). Add new fixtures here rather
than creating separate conftest.py files.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest


# ---------------------------------------------------------------------------
# Docker availability guard
# ---------------------------------------------------------------------------

def _docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


DOCKER_AVAILABLE = _docker_available()


# ---------------------------------------------------------------------------
# ClawCop container fixture (bead mallcop-h4i6)
# ---------------------------------------------------------------------------

INSTALL_DIR = Path(__file__).parent
# Repo root is two levels up from tests/install/
REPO_ROOT = INSTALL_DIR.parent.parent
CLAWCOP_IMAGE_TAG = "mallcop-clawcop-test:latest"


class ContainerRunResult(NamedTuple):
    stdout: str
    stderr: str
    exit_code: int


class ExecResult(NamedTuple):
    stdout: str
    stderr: str
    exit_code: int


class ClawcopContainer:
    """Thin wrapper that builds an image once and provides run/exec helpers."""

    def __init__(self, image_tag: str) -> None:
        self.image_tag = image_tag
        self._container_id: str | None = None

    def run(self) -> ContainerRunResult:
        """Run the container to completion and return its output."""
        result = subprocess.run(
            [
                "docker", "run",
                "--rm",
                "--name", "mallcop-clawcop-test-run",
                self.image_tag,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return ContainerRunResult(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
        )

    def run_detached(self) -> str:
        """Start the container in detached mode and return the container ID."""
        result = subprocess.run(
            [
                "docker", "run",
                "-d",
                "--name", "mallcop-clawcop-test-detached",
                self.image_tag,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        self._container_id = result.stdout.strip()
        return self._container_id

    def wait(self) -> int:
        """Wait for a detached container to finish and return its exit code."""
        if not self._container_id:
            raise RuntimeError("No detached container running.")
        result = subprocess.run(
            ["docker", "wait", self._container_id],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return int(result.stdout.strip())

    def exec(self, command: str) -> ExecResult:
        """Execute a shell command in the running or stopped container (via a fresh run)."""
        result = subprocess.run(
            [
                "docker", "run",
                "--rm",
                "--entrypoint", "/bin/bash",
                self.image_tag,
                "-c", command,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return ExecResult(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
        )


@pytest.fixture
def minimal_mallcop_config() -> str:
    """Minimal mallcop.yaml YAML string for a single GitHub connector (bead mallcop-opoq)."""
    return """\
secrets:
  backend: env
connectors:
  github:
    token: ${GITHUB_TOKEN}
    org: test-org
routing: {}
actor_chain: {}
budget:
  max_findings_for_actors: 5
  max_tokens_per_run: 10000
  max_tokens_per_finding: 2000
"""


@pytest.fixture(scope="module")
def clawcop_container():
    """
    Build the ClawCop test Docker image once per module and return a
    ClawcopContainer helper.

    Skips automatically if Docker is not available on the host.
    """
    if not DOCKER_AVAILABLE:
        pytest.skip("Docker not available — skipping install_prerelease tests")

    dockerfile = INSTALL_DIR / "Dockerfile.clawcop-test"
    if not dockerfile.exists():
        pytest.skip(f"Dockerfile not found: {dockerfile}")

    # Build image using repo root as context so the Dockerfile can COPY src/
    build_result = subprocess.run(
        [
            "docker", "build",
            "-f", str(dockerfile),
            "-t", CLAWCOP_IMAGE_TAG,
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if build_result.returncode != 0:
        pytest.fail(
            f"Docker build failed:\n{build_result.stdout}\n{build_result.stderr}"
        )

    return ClawcopContainer(CLAWCOP_IMAGE_TAG)


# ---------------------------------------------------------------------------
# Manual install fixtures (bead mallcop-opoq)
# ---------------------------------------------------------------------------
# Add fixtures for test_manual_install.py here when bead mallcop-opoq is worked.
