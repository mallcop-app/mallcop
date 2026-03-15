"""Tests for boundary checker module (mallcop/openclaw co-residency checks)."""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from mallcop.boundary import (
    BoundaryViolation,
    check_cross_write,
    check_file_ownership,
    check_sudo_access,
    run_boundary_checks,
    violations_to_findings,
)
from mallcop.schemas import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MALLCOP_UID = 1001
OPENCLAW_UID = 1002
OTHER_UID = 1099

MALLCOP_GID = 2001
OPENCLAW_GID = 2002

def _stat(uid=MALLCOP_UID, gid=MALLCOP_GID, mode=0o100750):
    s = MagicMock()
    s.st_uid = uid
    s.st_gid = gid
    s.st_mode = mode
    return s


def _pw(uid):
    return SimpleNamespace(pw_uid=uid)


def _grp(gid, members=None):
    return SimpleNamespace(gr_gid=gid, gr_mem=members or [])


# ---------------------------------------------------------------------------
# check_file_ownership
# ---------------------------------------------------------------------------

class TestCheckFileOwnership:
    def test_all_pass(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(MALLCOP_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=MALLCOP_UID, mode=0o100750)),
        ):
            violations = check_file_ownership([p], "mallcop")
        assert violations == []

    def test_wrong_owner(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(MALLCOP_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=OTHER_UID, mode=0o100750)),
        ):
            violations = check_file_ownership([p], "mallcop")
        assert len(violations) == 1
        v = violations[0]
        assert v.check_name == "file_ownership"
        assert v.severity == Severity.CRITICAL
        assert "chown" in v.remediation_command
        assert str(p) in v.remediation_command

    def test_world_writable(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        # Owned correctly but world-writable
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(MALLCOP_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=MALLCOP_UID, mode=0o100757)),
        ):
            violations = check_file_ownership([p], "mallcop")
        assert len(violations) == 1
        v = violations[0]
        assert v.check_name == "file_ownership"
        assert "chmod" in v.remediation_command

    def test_wrong_owner_and_world_writable(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(MALLCOP_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=OTHER_UID, mode=0o100757)),
        ):
            violations = check_file_ownership([p], "mallcop")
        # Two separate violations (wrong owner + world-writable)
        assert len(violations) == 2


# ---------------------------------------------------------------------------
# check_cross_write
# ---------------------------------------------------------------------------

class TestCheckCrossWrite:
    def test_no_violation_no_group_write(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        # openclaw user is different uid, file not group/world writable
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(OPENCLAW_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=MALLCOP_UID, gid=MALLCOP_GID, mode=0o100750)),
            patch("mallcop.boundary.grp.getgrall", return_value=[
                _grp(MALLCOP_GID, members=["mallcop"]),
            ]),
        ):
            violations = check_cross_write([p], "openclaw")
        assert violations == []

    def test_openclaw_owns_mallcop_path(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(OPENCLAW_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=OPENCLAW_UID, gid=MALLCOP_GID, mode=0o100750)),
            patch("mallcop.boundary.grp.getgrall", return_value=[]),
        ):
            violations = check_cross_write([p], "openclaw")
        assert len(violations) == 1
        assert violations[0].check_name == "cross_write"
        assert violations[0].severity == Severity.CRITICAL

    def test_openclaw_in_group_with_group_writable(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(OPENCLAW_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=MALLCOP_UID, gid=MALLCOP_GID, mode=0o100770)),
            patch("mallcop.boundary.grp.getgrall", return_value=[
                _grp(MALLCOP_GID, members=["mallcop", "openclaw"]),
            ]),
        ):
            violations = check_cross_write([p], "openclaw")
        assert len(violations) == 1
        assert violations[0].check_name == "cross_write"

    def test_openclaw_in_group_no_group_write_ok(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        # openclaw is in the file group but the group bit is NOT set
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(OPENCLAW_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=MALLCOP_UID, gid=MALLCOP_GID, mode=0o100750)),
            patch("mallcop.boundary.grp.getgrall", return_value=[
                _grp(MALLCOP_GID, members=["mallcop", "openclaw"]),
            ]),
        ):
            violations = check_cross_write([p], "openclaw")
        assert violations == []

    def test_world_writable_cross_write(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        with (
            patch("mallcop.boundary.pwd.getpwnam", return_value=_pw(OPENCLAW_UID)),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=MALLCOP_UID, gid=MALLCOP_GID, mode=0o100777)),
            patch("mallcop.boundary.grp.getgrall", return_value=[]),
        ):
            violations = check_cross_write([p], "openclaw")
        assert len(violations) == 1


# ---------------------------------------------------------------------------
# check_sudo_access
# ---------------------------------------------------------------------------

class TestCheckSudoAccess:
    def test_no_sudo_linux(self):
        with (
            patch("mallcop.boundary.sys.platform", "linux"),
            patch("mallcop.boundary.grp.getgrnam", side_effect=KeyError("no sudo group")),
        ):
            violations = check_sudo_access("openclaw")
        assert violations == []

    def test_openclaw_in_sudo_linux(self):
        with (
            patch("mallcop.boundary.sys.platform", "linux"),
            patch("mallcop.boundary.grp.getgrnam", side_effect=lambda name: (
                _grp(27, members=["openclaw"]) if name in ("sudo", "wheel") else (_ for _ in ()).throw(KeyError(name))
            )),
        ):
            violations = check_sudo_access("openclaw")
        assert len(violations) == 1
        v = violations[0]
        assert v.check_name == "sudo_access"
        assert v.severity == Severity.CRITICAL
        assert v.remediation_command == ""

    def test_openclaw_in_wheel_linux(self):
        def side_effect(name):
            if name == "sudo":
                raise KeyError("no sudo")
            if name == "wheel":
                return _grp(10, members=["openclaw"])
            raise KeyError(name)

        with (
            patch("mallcop.boundary.sys.platform", "linux"),
            patch("mallcop.boundary.grp.getgrnam", side_effect=side_effect),
        ):
            violations = check_sudo_access("openclaw")
        assert len(violations) == 1

    def test_no_sudo_macos(self):
        with (
            patch("mallcop.boundary.sys.platform", "darwin"),
            patch("mallcop.boundary.grp.getgrnam", side_effect=KeyError("no admin group")),
        ):
            violations = check_sudo_access("openclaw")
        assert violations == []

    def test_openclaw_in_admin_macos(self):
        with (
            patch("mallcop.boundary.sys.platform", "darwin"),
            patch("mallcop.boundary.grp.getgrnam", return_value=_grp(80, members=["openclaw"])),
        ):
            violations = check_sudo_access("openclaw")
        assert len(violations) == 1

    def test_not_in_sudo_group(self):
        with (
            patch("mallcop.boundary.sys.platform", "linux"),
            patch("mallcop.boundary.grp.getgrnam", return_value=_grp(27, members=["admin"])),
        ):
            violations = check_sudo_access("openclaw")
        assert violations == []


# ---------------------------------------------------------------------------
# run_boundary_checks
# ---------------------------------------------------------------------------

class TestRunBoundaryChecks:
    def test_all_pass(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()

        def getpwnam(name):
            return _pw(MALLCOP_UID) if name == "mallcop" else _pw(OPENCLAW_UID)

        with (
            patch("mallcop.boundary.sys.platform", "linux"),
            patch("mallcop.boundary.pwd.getpwnam", side_effect=getpwnam),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=MALLCOP_UID, gid=MALLCOP_GID, mode=0o100750)),
            patch("mallcop.boundary.grp.getgrall", return_value=[_grp(MALLCOP_GID, members=["mallcop"])]),
            patch("mallcop.boundary.grp.getgrnam", side_effect=KeyError("no sudo")),
        ):
            violations = run_boundary_checks([p], "mallcop", "openclaw")
        assert violations == []

    def test_multiple_violations_combined(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        # world-writable + openclaw in sudo
        with (
            patch("mallcop.boundary.sys.platform", "linux"),
            patch("mallcop.boundary.pwd.getpwnam", side_effect=lambda name: (
                _pw(MALLCOP_UID) if name == "mallcop" else _pw(OPENCLAW_UID)
            )),
            patch("mallcop.boundary.os.stat", return_value=_stat(uid=MALLCOP_UID, gid=MALLCOP_GID, mode=0o100757)),
            patch("mallcop.boundary.grp.getgrall", return_value=[]),
            patch("mallcop.boundary.grp.getgrnam", return_value=_grp(27, members=["openclaw"])),
        ):
            violations = run_boundary_checks([p], "mallcop", "openclaw")
        # world-writable triggers file_ownership + cross_write; sudo triggers sudo_access
        assert len(violations) >= 2

    def test_windows_platform(self, tmp_path):
        p = tmp_path / "data"
        p.mkdir()
        with patch("mallcop.boundary.sys.platform", "win32"):
            violations = run_boundary_checks([p], "mallcop", "openclaw")
        assert len(violations) == 1
        assert violations[0].check_name == "unsupported_platform"
        assert violations[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# violations_to_findings
# ---------------------------------------------------------------------------

class TestViolationsToFindings:
    def test_empty(self):
        findings = violations_to_findings([])
        assert findings == []

    def test_single_violation(self):
        v = BoundaryViolation(
            check_name="file_ownership",
            severity=Severity.CRITICAL,
            message="bad owner",
            remediation_command="chown mallcop /path",
        )
        findings = violations_to_findings([v])
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.detector == "boundary-violation"
        assert f.severity == Severity.CRITICAL
        assert f.status == FindingStatus.OPEN
        assert f.metadata["check_name"] == "file_ownership"
        assert f.metadata["remediation_command"] == "chown mallcop /path"

    def test_multiple_violations_multiple_findings(self):
        violations = [
            BoundaryViolation("file_ownership", Severity.CRITICAL, "msg1", "cmd1"),
            BoundaryViolation("cross_write", Severity.CRITICAL, "msg2", ""),
            BoundaryViolation("sudo_access", Severity.CRITICAL, "msg3", ""),
        ]
        findings = violations_to_findings(violations)
        assert len(findings) == 3
        detectors = {f.detector for f in findings}
        assert detectors == {"boundary-violation"}
        check_names = [f.metadata["check_name"] for f in findings]
        assert check_names == ["file_ownership", "cross_write", "sudo_access"]

    def test_finding_has_unique_ids(self):
        violations = [
            BoundaryViolation("file_ownership", Severity.CRITICAL, "msg1", ""),
            BoundaryViolation("file_ownership", Severity.CRITICAL, "msg2", ""),
        ]
        findings = violations_to_findings(violations)
        ids = [f.id for f in findings]
        assert len(set(ids)) == 2
