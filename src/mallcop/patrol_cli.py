"""Patrol CLI: create, list, update, disable, enable, remove, run.

Each command:
- Loads config from mallcop.yaml (or the path in MALLCOP_REPO env var)
- Validates inputs (period format, budget vs global max)
- Uses CrontabBackend for crontab management
- Updates mallcop.yaml patrols section (read-modify-write without clobbering)
- Emits JSON output by default
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from mallcop.crontab import CrontabBackend
from mallcop.patrol import PatrolConfig, period_to_cron
from mallcop.secrets import ConfigError

__all__ = ["patrol"]

# The mallcop binary used when running patrols immediately.
# In production this is /opt/mallcop/venv/bin/mallcop; fall back to sys.executable -m mallcop.
_MALLCOP_BIN = "/opt/mallcop/venv/bin/mallcop"


def _get_repo_root() -> Path:
    """Return the deployment repo root (cwd or MALLCOP_REPO env var)."""
    env_root = os.environ.get("MALLCOP_REPO")
    return Path(env_root) if env_root else Path.cwd()


def _load_raw_config(root: Path) -> dict[str, Any]:
    config_path = root / "mallcop.yaml"
    if not config_path.exists():
        return {}
    with open(config_path) as f:
        data = yaml.safe_load(f)
    return data or {}


def _save_raw_config(root: Path, data: dict[str, Any]) -> None:
    config_path = root / "mallcop.yaml"
    with open(config_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def _get_max_donuts(config: dict[str, Any]) -> int:
    budget = config.get("budget") or {}
    return int(budget.get("max_donuts_per_run", budget.get("max_tokens_per_run", 50000)))


def _emit(data: dict[str, Any]) -> None:
    click.echo(json.dumps(data))


def _error(message: str) -> None:
    _emit({"status": "error", "error": message})


def _patrol_command_for(patrol_cfg: dict[str, Any]) -> str:
    """Return 'research' or 'watch' based on patrol config."""
    return "research" if patrol_cfg.get("research") else "watch"


def _cron_schedule_for(every: str) -> str:
    """Convert period string to cron expression, raising ConfigError on failure."""
    return period_to_cron(every)


@click.group()
def patrol() -> None:
    """Manage scheduled patrols (cron-based watch/research runs)."""


# ─── patrol create ──────────────────────────────────────────────────


@patrol.command("create")
@click.argument("name")
@click.option("--every", required=True, help="Period: 15m, 1h, 6h, 1d, 1w, 1mo")
@click.option("--budget", default=0, type=int, help="Max donuts for this patrol (0=no actors)")
@click.option("--chain", default=None, help="Comma-separated actor chain override")
@click.option("--notify", default=None, help="Comma-separated notification channels")
@click.option("--research", "is_research", is_flag=True, help="Run mallcop research instead of watch")
@click.option("--no-git", "no_git", is_flag=True, help="Disable git wrapper in cron entry")
def patrol_create(
    name: str,
    every: str,
    budget: int,
    chain: str | None,
    notify: str | None,
    is_research: bool,
    no_git: bool,
) -> None:
    """Create a new scheduled patrol."""
    root = _get_repo_root()
    config = _load_raw_config(root)

    # Validate period
    try:
        cron_schedule = _cron_schedule_for(every)
    except ConfigError as e:
        _error(str(e))
        raise SystemExit(1)

    # Validate budget
    max_donuts = _get_max_donuts(config)
    if budget > max_donuts:
        _error(
            f"Patrol budget ({budget}) exceeds max_donuts_per_run ({max_donuts}). "
            f"Reduce the patrol budget or raise max_donuts_per_run in the budget section."
        )
        raise SystemExit(1)

    # Check for duplicate within this repo's config.
    # Stale crontab entries from other (deleted) repos are overwritten silently.
    patrols = config.get("patrols") or {}
    backend = CrontabBackend(repo_path=root)
    if name in patrols:
        _error(f"Patrol '{name}' already exists. Use 'patrol update' to change it.")
        raise SystemExit(1)

    with_git = not no_git

    # Write crontab entry
    command = "research" if is_research else "watch"
    backend.write_entry(name=name, schedule=cron_schedule, command=command, with_git=with_git)

    # Update config
    patrol_entry: dict[str, Any] = {"every": every}
    if budget:
        patrol_entry["budget"] = budget
    if chain:
        patrol_entry["chain"] = [c.strip() for c in chain.split(",")]
    if notify:
        patrol_entry["notify"] = [n.strip() for n in notify.split(",")]
    if is_research:
        patrol_entry["research"] = True
    if not with_git:
        patrol_entry["with_git"] = False

    if "patrols" not in config or config["patrols"] is None:
        config["patrols"] = {}
    config["patrols"][name] = patrol_entry
    _save_raw_config(root, config)

    _emit({
        "status": "ok",
        "name": name,
        "schedule": cron_schedule,
        "every": every,
        "command": command,
        "with_git": with_git,
    })


# ─── patrol list ────────────────────────────────────────────────────


@patrol.command("list")
@click.option("--json", "output_json", is_flag=True, default=True, hidden=True)
def patrol_list(output_json: bool) -> None:
    """List all configured patrols with their schedules and status."""
    root = _get_repo_root()
    config = _load_raw_config(root)
    backend = CrontabBackend(repo_path=root)

    patrols_cfg = config.get("patrols") or {}
    crontab_entries = {e.name: e for e in backend.read_entries()}

    result: list[dict[str, Any]] = []
    for patrol_name, patrol_cfg in patrols_cfg.items():
        if not isinstance(patrol_cfg, dict):
            continue
        every = patrol_cfg.get("every", "")
        try:
            schedule = _cron_schedule_for(every) if every else ""
        except ConfigError:
            schedule = ""

        in_crontab = patrol_name in crontab_entries
        enabled = in_crontab and patrol_cfg.get("enabled", True) is not False

        entry: dict[str, Any] = {
            "name": patrol_name,
            "every": every,
            "schedule": schedule,
            "enabled": enabled,
            "research": bool(patrol_cfg.get("research", False)),
        }
        if patrol_cfg.get("budget"):
            entry["budget"] = patrol_cfg["budget"]
        if patrol_cfg.get("chain"):
            entry["chain"] = patrol_cfg["chain"]
        if patrol_cfg.get("notify"):
            entry["notify"] = patrol_cfg["notify"]
        result.append(entry)

    _emit({"status": "ok", "patrols": result})


# ─── patrol update ──────────────────────────────────────────────────


@patrol.command("update")
@click.argument("name")
@click.option("--every", required=True, help="New period: 15m, 1h, 6h, 1d, 1w, 1mo")
def patrol_update(name: str, every: str) -> None:
    """Update the schedule for an existing patrol."""
    root = _get_repo_root()
    config = _load_raw_config(root)

    patrols_cfg = config.get("patrols") or {}
    if name not in patrols_cfg:
        _error(f"Patrol '{name}' not found. Use 'patrol create' to add it.")
        raise SystemExit(1)

    try:
        cron_schedule = _cron_schedule_for(every)
    except ConfigError as e:
        _error(str(e))
        raise SystemExit(1)

    patrol_cfg = patrols_cfg[name]
    if not isinstance(patrol_cfg, dict):
        patrol_cfg = {}

    with_git = patrol_cfg.get("with_git", True)
    is_research = patrol_cfg.get("research", False)
    command = "research" if is_research else "watch"

    backend = CrontabBackend(repo_path=root)
    # write_entry replaces the existing entry atomically
    backend.write_entry(name=name, schedule=cron_schedule, command=command, with_git=with_git)

    # Update config
    patrol_cfg["every"] = every
    config["patrols"][name] = patrol_cfg
    _save_raw_config(root, config)

    _emit({"status": "ok", "name": name, "schedule": cron_schedule, "every": every})


# ─── patrol disable ─────────────────────────────────────────────────


@patrol.command("disable")
@click.argument("name")
def patrol_disable(name: str) -> None:
    """Disable a patrol (removes crontab entry, keeps config)."""
    root = _get_repo_root()
    config = _load_raw_config(root)

    patrols_cfg = config.get("patrols") or {}
    if name not in patrols_cfg:
        _error(f"Patrol '{name}' not found.")
        raise SystemExit(1)

    backend = CrontabBackend(repo_path=root)
    backend.remove_entry(name)

    # Mark disabled in config
    patrol_cfg = patrols_cfg[name]
    if isinstance(patrol_cfg, dict):
        patrol_cfg["enabled"] = False
    else:
        config["patrols"][name] = {"enabled": False}
    _save_raw_config(root, config)

    _emit({"status": "ok", "name": name, "enabled": False})


# ─── patrol enable ──────────────────────────────────────────────────


@patrol.command("enable")
@click.argument("name")
def patrol_enable(name: str) -> None:
    """Enable a patrol (re-creates crontab entry from config)."""
    root = _get_repo_root()
    config = _load_raw_config(root)

    patrols_cfg = config.get("patrols") or {}
    if name not in patrols_cfg:
        _error(f"Patrol '{name}' not found.")
        raise SystemExit(1)

    patrol_cfg = patrols_cfg[name]
    if not isinstance(patrol_cfg, dict):
        _error(f"Patrol '{name}' config is malformed.")
        raise SystemExit(1)

    every = patrol_cfg.get("every", "")
    if not every:
        _error(f"Patrol '{name}' has no 'every' field — cannot re-enable.")
        raise SystemExit(1)

    try:
        cron_schedule = _cron_schedule_for(every)
    except ConfigError as e:
        _error(str(e))
        raise SystemExit(1)

    with_git = patrol_cfg.get("with_git", True)
    is_research = patrol_cfg.get("research", False)
    command = "research" if is_research else "watch"

    backend = CrontabBackend(repo_path=root)
    backend.write_entry(name=name, schedule=cron_schedule, command=command, with_git=with_git)

    # Clear disabled flag
    patrol_cfg.pop("enabled", None)
    config["patrols"][name] = patrol_cfg
    _save_raw_config(root, config)

    _emit({"status": "ok", "name": name, "enabled": True, "schedule": cron_schedule})


# ─── patrol remove ──────────────────────────────────────────────────


@patrol.command("remove")
@click.argument("name")
def patrol_remove(name: str) -> None:
    """Remove a patrol (removes crontab entry and config)."""
    root = _get_repo_root()
    config = _load_raw_config(root)

    patrols_cfg = config.get("patrols") or {}
    if name not in patrols_cfg:
        _error(f"Patrol '{name}' not found.")
        raise SystemExit(1)

    backend = CrontabBackend(repo_path=root)
    backend.remove_entry(name)

    del config["patrols"][name]
    if not config["patrols"]:
        del config["patrols"]
    _save_raw_config(root, config)

    _emit({"status": "ok", "name": name, "removed": True})


# ─── patrol run ─────────────────────────────────────────────────────


@patrol.command("run")
@click.argument("name")
def patrol_run(name: str) -> None:
    """Run a patrol immediately (does not wait for cron)."""
    root = _get_repo_root()
    config = _load_raw_config(root)

    patrols_cfg = config.get("patrols") or {}
    if name not in patrols_cfg:
        _error(f"Patrol '{name}' not found.")
        raise SystemExit(1)

    patrol_cfg = patrols_cfg[name]
    if not isinstance(patrol_cfg, dict):
        _error(f"Patrol '{name}' config is malformed.")
        raise SystemExit(1)

    command = _patrol_command_for(patrol_cfg)

    # Resolve the mallcop binary: prefer the installed path, fall back to the
    # mallcop console script in the same venv as sys.executable.
    mallcop_bin: str | None = None
    if Path(_MALLCOP_BIN).exists():
        mallcop_bin = _MALLCOP_BIN
    else:
        # Try the mallcop binary next to sys.executable (same venv)
        candidate = Path(sys.executable).parent / "mallcop"
        if candidate.exists():
            mallcop_bin = str(candidate)

    if mallcop_bin is None:
        _error(
            f"Could not locate the mallcop binary. "
            f"Expected {_MALLCOP_BIN} or alongside {sys.executable}."
        )
        raise SystemExit(1)

    cmd = [mallcop_bin, command, "--dir", str(root)]

    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        stderr_text = proc.stderr.decode(errors="replace")
        _error(f"Patrol '{name}' run failed (exit {proc.returncode}): {stderr_text}")
        raise SystemExit(1)

    _emit({"status": "ok", "name": name, "command": command, "exit_code": 0})
