"""Platform-aware permission validation for mallcop/openclaw co-residency."""

from __future__ import annotations

import grp
import os
import pwd
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from mallcop.schemas import Finding, FindingStatus, Severity

# Defer config/store imports to avoid circular imports at module load time


@dataclass
class BoundaryViolation:
    check_name: str
    severity: Severity
    message: str
    remediation_command: str


def check_file_ownership(
    mallcop_paths: list[Path], mallcop_user: str
) -> list[BoundaryViolation]:
    """Verify each path is owned by mallcop_user and not world-writable."""
    expected_uid = pwd.getpwnam(mallcop_user).pw_uid
    violations: list[BoundaryViolation] = []

    for path in mallcop_paths:
        st = os.stat(path)

        if st.st_uid != expected_uid:
            violations.append(
                BoundaryViolation(
                    check_name="file_ownership",
                    severity=Severity.CRITICAL,
                    message=(
                        f"{path} is owned by uid {st.st_uid}, expected {expected_uid} ({mallcop_user})"
                    ),
                    remediation_command=f"chown {mallcop_user}:{mallcop_user} {path} && chmod 750 {path}",
                )
            )

        if st.st_mode & 0o002:
            violations.append(
                BoundaryViolation(
                    check_name="file_ownership",
                    severity=Severity.CRITICAL,
                    message=f"{path} is world-writable (mode {oct(st.st_mode)})",
                    remediation_command=f"chmod o-w {path}",
                )
            )

    return violations


def check_cross_write(
    mallcop_paths: list[Path], openclaw_user: str
) -> list[BoundaryViolation]:
    """Verify openclaw_user cannot write to any mallcop path."""
    openclaw_uid = pwd.getpwnam(openclaw_user).pw_uid
    all_groups = grp.getgrall()
    # Build set of gids that openclaw_user belongs to
    openclaw_gids = {
        g.gr_gid for g in all_groups if openclaw_user in g.gr_mem
    }

    violations: list[BoundaryViolation] = []

    for path in mallcop_paths:
        st = os.stat(path)
        can_write = False

        # Owner check
        if st.st_uid == openclaw_uid:
            can_write = True

        # Group-writable and openclaw is in that group
        if not can_write and (st.st_mode & 0o020) and st.st_gid in openclaw_gids:
            can_write = True

        # World-writable
        if not can_write and (st.st_mode & 0o002):
            can_write = True

        if can_write:
            violations.append(
                BoundaryViolation(
                    check_name="cross_write",
                    severity=Severity.CRITICAL,
                    message=(
                        f"{openclaw_user} can write to mallcop path {path}"
                    ),
                    remediation_command="",
                )
            )

    return violations


def check_sudo_access(openclaw_user: str) -> list[BoundaryViolation]:
    """Check whether openclaw_user has privilege-escalation group membership."""
    if sys.platform.startswith("linux"):
        group_names = ["sudo", "wheel"]
    elif sys.platform == "darwin":
        group_names = ["admin"]
    else:
        # Handled by run_boundary_checks; return empty here
        return []

    for group_name in group_names:
        try:
            g = grp.getgrnam(group_name)
            if openclaw_user in g.gr_mem:
                return [
                    BoundaryViolation(
                        check_name="sudo_access",
                        severity=Severity.CRITICAL,
                        message=(
                            f"{openclaw_user} is a member of the '{group_name}' group "
                            f"and may escalate privileges"
                        ),
                        remediation_command="",
                    )
                ]
        except KeyError:
            continue

    return []


def run_boundary_checks(
    mallcop_paths: list[Path],
    mallcop_user: str,
    openclaw_user: str,
) -> list[BoundaryViolation]:
    """Run all boundary checks and return combined violations."""
    if sys.platform == "win32":
        return [
            BoundaryViolation(
                check_name="unsupported_platform",
                severity=Severity.CRITICAL,
                message="Boundary checks are not supported on Windows",
                remediation_command="",
            )
        ]

    violations: list[BoundaryViolation] = []
    violations.extend(check_file_ownership(mallcop_paths, mallcop_user))
    violations.extend(check_cross_write(mallcop_paths, openclaw_user))
    violations.extend(check_sudo_access(openclaw_user))
    return violations


def run_boundary_preflight(root: Path) -> list[Finding]:
    """Run boundary checks and persist any violations as findings.

    Args:
        root: Deployment repo directory (used for config + store).

    Returns:
        List of boundary-violation Finding objects (empty if openclaw not configured).
    """
    from mallcop.config import load_config
    from mallcop.store import JsonlStore

    config = load_config(root)

    # Only run if openclaw connector is configured
    if "openclaw" not in config.connectors:
        return []

    # Determine mallcop_user: current process user
    try:
        mallcop_user = os.getlogin()
    except OSError:
        mallcop_user = pwd.getpwuid(os.getuid()).pw_name

    # Determine openclaw_user: from connector config or by detecting openclaw_home owner
    openclaw_cfg = config.connectors.get("openclaw", {})
    openclaw_user = openclaw_cfg.get("openclaw_user") if isinstance(openclaw_cfg, dict) else None
    if not openclaw_user:
        openclaw_home = (
            openclaw_cfg.get("home")
            if isinstance(openclaw_cfg, dict)
            else None
        )
        if openclaw_home:
            try:
                st = os.stat(openclaw_home)
                openclaw_user = pwd.getpwuid(st.st_uid).pw_name
            except (OSError, KeyError):
                openclaw_user = mallcop_user  # fallback: same user, checks will be no-ops
        else:
            openclaw_user = mallcop_user  # fallback

    # Gather mallcop paths to check
    import sys as _sys
    mallcop_install_dir = Path(_sys.executable).parent.parent
    mallcop_paths: list[Path] = [
        Path(mallcop_install_dir),
        root,
    ]
    # Add state dir if present in config
    state_dir = root / ".mallcop"
    if state_dir.exists():
        mallcop_paths.append(state_dir)

    violations = run_boundary_checks(mallcop_paths, mallcop_user, openclaw_user)
    findings = violations_to_findings(violations)

    if findings:
        store = JsonlStore(root)
        store.append_findings(findings)

    return findings


def violations_to_findings(violations: list[BoundaryViolation]) -> list[Finding]:
    """Convert BoundaryViolation objects to Finding objects."""
    now = datetime.now(tz=timezone.utc)
    findings: list[Finding] = []

    for v in violations:
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                timestamp=now,
                detector="boundary-violation",
                event_ids=[],
                title=v.message,
                severity=v.severity,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={
                    "check_name": v.check_name,
                    "remediation_command": v.remediation_command,
                },
            )
        )

    return findings
