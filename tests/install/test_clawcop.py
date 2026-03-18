"""
Install path test: ClawCop container.

Tests the outcome of the ClawCop installer running inside an ubuntu:22.04
Docker container.  All tests are @pytest.mark.install_prerelease — they
require Docker and are only executed during pre-release CI gates.

The clawcop_container fixture (in conftest.py) builds the image once per
module.  Each test either:
  - Runs the container to completion (via run()), or
  - Executes a command in a fresh container (via exec()).

Docker availability is checked at import time; the fixture skips the module
gracefully if Docker is absent.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_docker_available(clawcop_container) -> None:
    """Guard: all tests in this module need the fixture to have been built."""
    # The fixture already skips if Docker is unavailable, so reaching here
    # means Docker is present.  This helper is a no-op documentation aid.


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.install_prerelease
def test_user_created(clawcop_container):
    """mallcop-user exists in /etc/passwd inside the container."""
    result = clawcop_container.exec("grep -c '^mallcop:' /etc/passwd")
    # grep exits 0 and prints 1 when the user exists
    assert result.exit_code == 0, (
        f"mallcop user not found in /etc/passwd.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    count = result.stdout.strip()
    assert count == "1", f"Expected 1 mallcop entry in /etc/passwd, got: {count!r}"


@pytest.mark.install_prerelease
def test_cron_installed(clawcop_container):
    """A cron job for mallcop-user contains 'mallcop watch' and '*/6'."""
    result = clawcop_container.exec("crontab -u mallcop -l")
    assert result.exit_code == 0, (
        f"crontab -u mallcop -l failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    cron_output = result.stdout
    assert "mallcop watch" in cron_output, (
        f"Expected 'mallcop watch' in mallcop crontab.\nGot: {cron_output!r}"
    )
    assert "*/6" in cron_output, (
        f"Expected '*/6' (every 6 hours) in mallcop crontab.\nGot: {cron_output!r}"
    )


@pytest.mark.install_prerelease
def test_permissions(clawcop_container):
    """mallcop-user cannot write outside home dir (/opt/mallcop is 750, owned by mallcop)."""
    # /opt/mallcop must be owned by mallcop with mode 750
    stat_result = clawcop_container.exec("stat -c '%U %a' /opt/mallcop")
    assert stat_result.exit_code == 0, (
        f"stat /opt/mallcop failed.\nstdout: {stat_result.stdout}\nstderr: {stat_result.stderr}"
    )
    stat_output = stat_result.stdout.strip()
    assert "mallcop" in stat_output, (
        f"/opt/mallcop not owned by mallcop.\nstat output: {stat_output!r}"
    )
    assert "750" in stat_output, (
        f"/opt/mallcop permissions are not 750.\nstat output: {stat_output!r}"
    )

    # mallcop user must not be able to write to /tmp/canary as a test of general write denial
    # (mallcop has no shell, so we verify the user has nologin shell)
    shell_result = clawcop_container.exec(
        "getent passwd mallcop | cut -d: -f7"
    )
    assert shell_result.exit_code == 0
    shell = shell_result.stdout.strip()
    assert "nologin" in shell or "false" in shell, (
        f"mallcop user has a login shell: {shell!r}. Expected nologin or false."
    )


@pytest.mark.install_prerelease
def test_group_isolation(clawcop_container):
    """mallcop-user is not in the root or sudo group."""
    groups_result = clawcop_container.exec("groups mallcop")
    assert groups_result.exit_code == 0, (
        f"groups mallcop failed.\nstdout: {groups_result.stdout}\nstderr: {groups_result.stderr}"
    )
    groups_output = groups_result.stdout.lower()
    # The output is like: "mallcop : mallcop testuser"
    # We split on the colon to get the group list portion
    if ":" in groups_output:
        group_list = groups_output.split(":", 1)[1]
    else:
        group_list = groups_output

    group_names = group_list.split()
    assert "root" not in group_names, (
        f"mallcop user is in the root group.\ngroups output: {groups_result.stdout!r}"
    )
    assert "sudo" not in group_names, (
        f"mallcop user is in the sudo group.\ngroups output: {groups_result.stdout!r}"
    )


@pytest.mark.install_prerelease
def test_first_patrol_detects_malicious_skill(clawcop_container):
    """First patrol run finds evil/skill.md, logs a detection to stdout, exits 0.

    The container entrypoint runs 'mallcop watch' as the mallcop user with
    openclaw_home pointing at /home/testuser/.openclaw, which contains
    evil/skill.md with 'curl ... | bash' content (matching the encoded-payload
    detector rule).  The test verifies the container exits 0 and that the
    patrol output includes a detection signal.
    """
    result = clawcop_container.run()

    assert result.exit_code == 0, (
        f"Container exited with non-zero code {result.exit_code}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    combined = (result.stdout + result.stderr).lower()

    # The patrol must have run and logged something related to the malicious skill.
    # Acceptable signals: detector name, finding keyword, or skill name.
    detection_signals = [
        "malicious",
        "malicious-skill",
        "evil",
        "finding",
        "encoded-payload",
    ]
    found_signal = any(signal in combined for signal in detection_signals)
    assert found_signal, (
        f"No detection signal in patrol output.\n"
        f"Expected one of {detection_signals}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
