"""mallcop discover: repo content detection and discovery.json writer.

Inspects a repo for signals that map to connector types, probes credential
availability, and writes .mallcop/discovery.json.

This is the bridge between what the repo contains and what the dashboard
needs to render the coverage view.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from mallcop.__init__ import __version__


# ---------------------------------------------------------------------------
# Connector catalog
# ---------------------------------------------------------------------------

# Connector metadata keyed by connector type (matches manifest name field).
# display_name and description are dashboard-facing strings.
# category groups connectors for the coverage view.
# credential_help is a list of per-secret metadata objects.

_CONNECTOR_CATALOG: dict[str, dict[str, Any]] = {
    "dependency-scan": {
        "display_name": "Dependency Scanning",
        "description": "Checks package dependencies for known vulnerabilities.",
        "category": "code",
        "credential_help": [],
    },
    "aws": {
        "display_name": "AWS",
        "description": "CloudTrail events, IAM configuration, S3 bucket policies.",
        "category": "cloud",
        "credential_help": [
            {
                "name": "AWS_ACCESS_KEY_ID",
                "description": "AWS access key for read-only scanning.",
                "how_to_get": (
                    "Go to IAM > Users > Security Credentials > Create Access Key. "
                    "Use a dedicated read-only user."
                ),
                "permissions_needed": "SecurityAudit policy (read-only)",
                "help_url": (
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                    "id_credentials_access-keys.html"
                ),
            },
            {
                "name": "AWS_SECRET_ACCESS_KEY",
                "description": "AWS secret key paired with the access key above.",
                "how_to_get": (
                    "Provided when you create the access key. Store it securely."
                ),
                "permissions_needed": "Same user as AWS_ACCESS_KEY_ID",
                "help_url": (
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                    "id_credentials_access-keys.html"
                ),
            },
            {
                "name": "AWS_REGION",
                "description": "Primary AWS region to scan.",
                "how_to_get": "Your default region, e.g., us-east-1.",
                "permissions_needed": "None (region identifier only)",
                "help_url": None,
            },
        ],
    },
    "azure": {
        "display_name": "Azure",
        "description": "Activity log, resource configuration, identity security.",
        "category": "cloud",
        "credential_help": [
            {
                "name": "AZURE_CLIENT_ID",
                "description": "Azure AD application (client) ID.",
                "how_to_get": (
                    "Azure Portal > App Registrations > Your App > Overview > "
                    "Application (client) ID."
                ),
                "permissions_needed": "Reader role on the subscription",
                "help_url": (
                    "https://learn.microsoft.com/en-us/azure/active-directory/develop/"
                    "quickstart-register-app"
                ),
            },
            {
                "name": "AZURE_CLIENT_SECRET",
                "description": "Azure AD application secret.",
                "how_to_get": (
                    "Azure Portal > App Registrations > Your App > Certificates & secrets > "
                    "New client secret."
                ),
                "permissions_needed": "Same app registration as AZURE_CLIENT_ID",
                "help_url": (
                    "https://learn.microsoft.com/en-us/azure/active-directory/develop/"
                    "quickstart-register-app"
                ),
            },
            {
                "name": "AZURE_TENANT_ID",
                "description": "Azure AD tenant (directory) ID.",
                "how_to_get": "Azure Portal > Azure Active Directory > Overview > Tenant ID.",
                "permissions_needed": "None (tenant identifier only)",
                "help_url": None,
            },
            {
                "name": "AZURE_SUBSCRIPTION_ID",
                "description": "Azure subscription to scan.",
                "how_to_get": "Azure Portal > Subscriptions > Your Subscription > Overview.",
                "permissions_needed": "None (subscription identifier only)",
                "help_url": None,
            },
        ],
    },
    "auth-provider": {
        "display_name": "Auth Provider",
        "description": "Authentication provider audit logs — Supabase Auth, Auth0, Okta, Clerk.",
        "category": "identity",
        "credential_help": [
            {
                "name": "SUPABASE_PROJECT_URL",
                "description": "Supabase project URL (if using Supabase Auth).",
                "how_to_get": "Supabase Dashboard > Project Settings > API > Project URL.",
                "permissions_needed": "Service role access",
                "help_url": "https://supabase.com/docs/guides/api",
            },
            {
                "name": "SUPABASE_SERVICE_ROLE_KEY",
                "description": "Supabase service role key (if using Supabase Auth).",
                "how_to_get": "Supabase Dashboard > Project Settings > API > service_role key.",
                "permissions_needed": "Service role",
                "help_url": "https://supabase.com/docs/guides/api",
            },
        ],
    },
    "ci-pipeline": {
        "display_name": "CI Pipeline",
        "description": "GitHub Actions, GitLab CI, CircleCI — workflow runs, secret access, permissions.",
        "category": "code",
        "credential_help": [
            {
                "name": "GITHUB_TOKEN",
                "description": "GitHub personal access token or GitHub App token.",
                "how_to_get": (
                    "GitHub > Settings > Developer settings > Personal access tokens > "
                    "Generate new token. Requires repo and read:org scopes."
                ),
                "permissions_needed": "repo, read:org",
                "help_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token",
            },
        ],
    },
    "container-scan": {
        "display_name": "Container Scan",
        "description": "Docker image vulnerabilities, base image currency, runtime configuration.",
        "category": "infra",
        "credential_help": [
            {
                "name": "AZURE_CLIENT_ID",
                "description": "Azure AD application (client) ID.",
                "how_to_get": "Azure Portal > App Registrations > Your App > Overview.",
                "permissions_needed": "Reader role on the subscription",
                "help_url": None,
            },
            {
                "name": "AZURE_CLIENT_SECRET",
                "description": "Azure AD application secret.",
                "how_to_get": "Azure Portal > App Registrations > Your App > Certificates & secrets.",
                "permissions_needed": "Same app registration as AZURE_CLIENT_ID",
                "help_url": None,
            },
            {
                "name": "AZURE_TENANT_ID",
                "description": "Azure AD tenant (directory) ID.",
                "how_to_get": "Azure Portal > Azure Active Directory > Overview > Tenant ID.",
                "permissions_needed": "None (tenant identifier only)",
                "help_url": None,
            },
        ],
    },
    "m365": {
        "display_name": "Microsoft 365",
        "description": "Azure AD, Exchange, SharePoint, DLP audit events.",
        "category": "identity",
        "credential_help": [
            {
                "name": "M365_TENANT_ID",
                "description": "Microsoft 365 tenant ID.",
                "how_to_get": "Azure Portal > Azure Active Directory > Overview > Tenant ID.",
                "permissions_needed": "None (tenant identifier only)",
                "help_url": None,
            },
            {
                "name": "M365_CLIENT_ID",
                "description": "Azure AD application (client) ID.",
                "how_to_get": "Azure Portal > App Registrations > Your App > Overview.",
                "permissions_needed": "ActivityFeed.Read, ActivityFeed.ReadDlp",
                "help_url": None,
            },
            {
                "name": "M365_CLIENT_SECRET",
                "description": "Azure AD application secret.",
                "how_to_get": "Azure Portal > App Registrations > Your App > Certificates & secrets.",
                "permissions_needed": "Same app registration as M365_CLIENT_ID",
                "help_url": None,
            },
        ],
    },
    "openclaw": {
        "display_name": "OpenClaw",
        "description": "AI agent skill integrity, behavior monitoring, gateway security.",
        "category": "infra",
        "credential_help": [],
    },
    "supabase": {
        "display_name": "Supabase",
        "description": "Auth audit logs, project config changes, edge function monitoring.",
        "category": "cloud",
        "credential_help": [
            {
                "name": "SUPABASE_PROJECT_URL",
                "description": "Supabase project URL.",
                "how_to_get": "Supabase Dashboard > Project Settings > API > Project URL.",
                "permissions_needed": "Service role access",
                "help_url": "https://supabase.com/docs/guides/api",
            },
            {
                "name": "SUPABASE_SERVICE_ROLE_KEY",
                "description": "Supabase service role key (has full DB access — keep secret).",
                "how_to_get": "Supabase Dashboard > Project Settings > API > service_role key.",
                "permissions_needed": "Service role",
                "help_url": "https://supabase.com/docs/guides/api",
            },
            {
                "name": "SUPABASE_PROJECT_REF",
                "description": "Supabase project reference ID.",
                "how_to_get": "Supabase Dashboard > Project Settings > General > Reference ID.",
                "permissions_needed": "None (identifier only)",
                "help_url": None,
            },
        ],
    },
    "deployment": {
        "display_name": "Deployment",
        "description": "Deployment platform audit — Vercel, Netlify, Railway deployment events and access.",
        "category": "infra",
        "credential_help": [
            {
                "name": "VERCEL_TOKEN",
                "description": "Vercel API token.",
                "how_to_get": (
                    "Vercel Dashboard > Account Settings > Tokens > Create. "
                    "Use read-only scope if available."
                ),
                "permissions_needed": "Read access to deployments and team audit",
                "help_url": "https://vercel.com/docs/rest-api#authentication",
            },
        ],
    },
    "database": {
        "display_name": "Database",
        "description": "Database access patterns, connection string hygiene, ORM configuration.",
        "category": "infra",
        "credential_help": [],
    },
    "secrets": {
        "display_name": "Secrets",
        "description": "Secret and credential hygiene — API keys, tokens, and passwords in source or env.",
        "category": "code",
        "credential_help": [],
    },
}


# ---------------------------------------------------------------------------
# Repo content detection
# ---------------------------------------------------------------------------


def _read_requirements_txt(repo_dir: Path) -> list[str]:
    """Parse requirements.txt into a list of package names (lowercased)."""
    req_file = repo_dir / "requirements.txt"
    if not req_file.exists():
        return []
    packages = []
    for line in req_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip version specifiers: boto3==1.34.0 -> boto3
        name = re.split(r"[>=<!@\[]", line)[0].strip().lower()
        if name:
            packages.append(name)
    return packages


def _read_package_json(repo_dir: Path) -> dict[str, list[str]]:
    """Parse package.json and return {'deps': [...], 'dev': [...]} of package names (lowercased)."""
    pkg_file = repo_dir / "package.json"
    if not pkg_file.exists():
        return {"deps": [], "dev": []}
    try:
        data = json.loads(pkg_file.read_text())
    except (json.JSONDecodeError, OSError):
        return {"deps": [], "dev": []}
    deps = list((data.get("dependencies") or {}).keys())
    dev = list((data.get("devDependencies") or {}).keys())
    return {"deps": [d.lower() for d in deps], "dev": [d.lower() for d in dev]}


def _read_pipfile(repo_dir: Path) -> list[str]:
    """Parse Pipfile for package names."""
    pipfile = repo_dir / "Pipfile"
    if not pipfile.exists():
        return []
    try:
        data = yaml.safe_load(pipfile.read_text())
    except Exception:
        return []
    packages = list((data.get("packages") or {}).keys())
    dev = list((data.get("dev-packages") or {}).keys())
    return [p.lower() for p in packages + dev]


def detect_repo_signals(repo_dir: Path) -> dict[str, list[str]]:
    """Scan repo for detection signals.

    Returns a mapping of connector_type -> list of signal strings describing
    what was found. Empty list means the connector was not detected.
    """
    signals: dict[str, list[str]] = {}

    # ---- Python dependency files ----
    py_packages: list[str] = []
    if (repo_dir / "requirements.txt").exists():
        py_packages = _read_requirements_txt(repo_dir)
        if py_packages:
            signals.setdefault("dependency-scan", []).append(
                f"requirements.txt ({len(py_packages)} packages)"
            )
    if (repo_dir / "Pipfile").exists():
        pip_pkgs = _read_pipfile(repo_dir)
        if pip_pkgs:
            signals.setdefault("dependency-scan", []).append(
                f"Pipfile ({len(pip_pkgs)} packages)"
            )
        py_packages = list(set(py_packages + pip_pkgs))
    if (repo_dir / "poetry.lock").exists():
        signals.setdefault("dependency-scan", []).append("poetry.lock")

    # ---- Node dependency files ----
    node_pkgs: dict[str, list[str]] = {"deps": [], "dev": []}
    if (repo_dir / "package.json").exists():
        node_pkgs = _read_package_json(repo_dir)
        all_node = node_pkgs["deps"] + node_pkgs["dev"]
        signals.setdefault("dependency-scan", []).append(
            f"package.json ({len(all_node)} packages)"
        )

    # ---- Go / Rust ----
    if (repo_dir / "go.mod").exists():
        signals.setdefault("dependency-scan", []).append("go.mod")
    if (repo_dir / "Cargo.toml").exists():
        signals.setdefault("dependency-scan", []).append("Cargo.toml")

    # ---- AWS detection ----
    # Python: boto3 or botocore in requirements
    if "boto3" in py_packages or "botocore" in py_packages:
        signals.setdefault("aws", []).append("boto3 in requirements.txt")
    # Node: @aws-sdk/* packages
    node_all = node_pkgs["deps"] + node_pkgs["dev"]
    aws_node_pkgs = [p for p in node_all if p.startswith("@aws-sdk/") or p == "aws-sdk"]
    if aws_node_pkgs:
        signals.setdefault("aws", []).append(
            f"{aws_node_pkgs[0]} in package.json"
        )
    # .env.example or .env with AWS_REGION
    for env_file in [".env.example", ".env.sample", ".env"]:
        env_path = repo_dir / env_file
        if env_path.exists():
            content = env_path.read_text(errors="replace")
            if "AWS_" in content:
                signals.setdefault("aws", []).append(
                    f"AWS_ variables in {env_file}"
                )
                break

    # ---- Azure detection ----
    azure_node_pkgs = [p for p in node_all if p.startswith("@azure/") or p.startswith("azure-")]
    if azure_node_pkgs:
        signals.setdefault("azure", []).append(f"{azure_node_pkgs[0]} in package.json")
    azure_py_pkgs = [p for p in py_packages if p.startswith("azure-")]
    if azure_py_pkgs:
        signals.setdefault("azure", []).append(f"{azure_py_pkgs[0]} in requirements.txt")
    if (repo_dir / ".azure").is_dir():
        signals.setdefault("azure", []).append(".azure/ directory")

    # ---- Auth provider detection ----
    supabase_node = [p for p in node_all if "@supabase" in p]
    if supabase_node:
        signals.setdefault("auth-provider", []).append(f"{supabase_node[0]} in package.json")
    if (repo_dir / "supabase").is_dir() and (repo_dir / "supabase" / "config.toml").exists():
        signals.setdefault("auth-provider", []).append("supabase/config.toml")

    # ---- CI pipeline detection (GitHub Actions) ----
    workflows_dir = repo_dir / ".github" / "workflows"
    if workflows_dir.is_dir():
        yml_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
        if yml_files:
            signals.setdefault("ci-pipeline", []).append(
                f".github/workflows/ ({len(yml_files)} workflow files)"
            )

    # ---- Container scan detection ----
    container_signals = []
    if (repo_dir / "Dockerfile").exists():
        container_signals.append("Dockerfile")
    if (repo_dir / "docker-compose.yml").exists():
        container_signals.append("docker-compose.yml")
    if (repo_dir / "docker-compose.yaml").exists():
        container_signals.append("docker-compose.yaml")
    if container_signals:
        signals.setdefault("container-scan", []).append(", ".join(container_signals))

    # ---- Deployment platform detection ----
    deployment_signals = []
    if (repo_dir / "vercel.json").exists():
        deployment_signals.append("vercel.json")
    if (repo_dir / ".vercel").is_dir():
        deployment_signals.append(".vercel/")
    if (repo_dir / "netlify.toml").exists():
        deployment_signals.append("netlify.toml")
    if (repo_dir / ".netlify").is_dir():
        deployment_signals.append(".netlify/")
    if (repo_dir / "railway.toml").exists():
        deployment_signals.append("railway.toml")
    if deployment_signals:
        signals.setdefault("deployment", []).append(", ".join(deployment_signals))

    # ---- Database detection ----
    # ORM / schema files: Prisma, Drizzle, SQLAlchemy, Alembic
    db_signals = []
    if (repo_dir / "prisma" / "schema.prisma").exists():
        db_signals.append("prisma/schema.prisma")
    if (repo_dir / "drizzle.config.ts").exists() or (repo_dir / "drizzle.config.js").exists():
        db_signals.append("drizzle.config")
    if "sqlalchemy" in py_packages or "alembic" in py_packages:
        db_signals.append("sqlalchemy/alembic in requirements.txt")
    # Connection string env vars
    for env_file in [".env.example", ".env.sample", ".env"]:
        env_path = repo_dir / env_file
        if env_path.exists():
            content = env_path.read_text(errors="replace")
            if "DATABASE_URL" in content or "DB_URL" in content or "POSTGRES" in content:
                db_signals.append(f"database URL in {env_file}")
                break
    if db_signals:
        signals.setdefault("database", []).append(", ".join(db_signals))

    # ---- OpenClaw detection ----
    openclaw_home = Path.home() / ".openclaw"
    if openclaw_home.is_dir():
        signals.setdefault("openclaw", []).append("~/.openclaw found")

    # ---- Secrets detection ----
    # Always active: source scan runs against any repo.
    signals.setdefault("secrets", []).append("source scan")

    return signals


# ---------------------------------------------------------------------------
# Credential probing
# ---------------------------------------------------------------------------

# Map connector type -> env var name prefixes to check.
# These are derived from the manifest auth.required fields with the convention
# used by EnvSecretProvider: {CONNECTOR_NAME_UPPER}_{KEY_UPPER}
_CONNECTOR_ENV_VARS: dict[str, list[str]] = {
    "dependency-scan": [],
    "aws": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
    "azure": ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID"],
    "auth-provider": ["SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY"],
    "ci-pipeline": ["GITHUB_TOKEN"],
    "container-scan": ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
    "deployment": ["VERCEL_TOKEN"],
    "database": [],
    "secrets": [],
    "m365": ["M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET"],
    "openclaw": [],  # no credentials required
}

# Env vars that are required (missing means status = detected, not active)
_CONNECTOR_REQUIRED_ENV_VARS: dict[str, list[str]] = {
    "dependency-scan": [],
    "aws": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
    "azure": ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
    "auth-provider": ["SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY"],
    "ci-pipeline": ["GITHUB_TOKEN"],
    "container-scan": ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
    "deployment": ["VERCEL_TOKEN"],
    "database": [],
    "secrets": [],
    "m365": ["M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET"],
    "openclaw": [],
}

# Connectors that are active even without credentials (no external auth needed)
_NO_CREDENTIAL_CONNECTORS: frozenset[str] = frozenset(["dependency-scan", "database", "secrets", "openclaw"])


def probe_credentials(
    connector_type: str, env: dict[str, str] | None = None
) -> dict[str, str]:
    """Check which env vars are present/missing for a connector.

    Returns a dict of env_var_name -> status ("present" | "missing").
    Uses os.environ when env is None.
    """
    if env is None:
        env = dict(os.environ)
    all_vars = _CONNECTOR_ENV_VARS.get(connector_type, [])
    result: dict[str, str] = {}
    for var in all_vars:
        result[var] = "present" if var in env and env[var] else "missing"
    return result


def connector_status(
    connector_type: str,
    detection_signals: list[str],
    secrets_status: dict[str, str],
) -> str:
    """Derive connector status from detection signals and credential status.

    Rules:
    - No-credential connectors: active if detected or no detection needed.
    - Connectors with required creds and detection signals but missing creds: detected.
    - Connectors with all required creds present: active (if detected or always-on).
    - Connectors with no detection signals and no creds: available.
    """
    if connector_type in _NO_CREDENTIAL_CONNECTORS:
        return "active" if detection_signals else "available"

    required = _CONNECTOR_REQUIRED_ENV_VARS.get(connector_type, [])
    missing_required = [v for v in required if secrets_status.get(v) == "missing"]

    if detection_signals:
        if not required or not missing_required:
            # Detected and credentials present (or no creds needed)
            return "active"
        else:
            # Detected but missing required credentials
            return "detected"
    else:
        # No detection signals
        if not required or not missing_required:
            # No signals, but credentials are present — connector is available and configured
            return "active"
        else:
            # No signals, credentials missing — connector is available (can be manually enabled)
            return "available"


# ---------------------------------------------------------------------------
# Repo identification
# ---------------------------------------------------------------------------


def get_repo_name(repo_dir: Path) -> str:
    """Extract owner/repo from git remote origin URL, or fall back to dir name."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            # Parse github.com/owner/repo from HTTPS or SSH URL
            # https://github.com/owner/repo.git
            # git@github.com:owner/repo.git
            match = re.search(r"github\.com[:/]([^/]+)/([^/.]+)(?:\.git)?$", url)
            if match:
                return f"{match.group(1)}/{match.group(2)}"
            # Try parsing other remote formats: last two path components
            parts = re.split(r"[/:]", url.rstrip("/").rstrip(".git"))
            if len(parts) >= 2:
                return f"{parts[-2]}/{parts[-1].replace('.git', '')}"
    except Exception:
        pass
    return repo_dir.name


# ---------------------------------------------------------------------------
# Main discover() function
# ---------------------------------------------------------------------------


def discover(
    repo_dir: Path,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect a repo and return a discovery report (the discovery.json structure).

    Args:
        repo_dir: Path to the repo root to inspect.
        env: Environment variables to use for credential probing. Defaults to os.environ.

    Returns:
        A dict matching the discovery.json schema (schema_version 1.0).
    """
    if env is None:
        env = dict(os.environ)

    repo_name = get_repo_name(repo_dir)
    detected_signals = detect_repo_signals(repo_dir)

    # All known connector types in display order
    all_connector_types = list(_CONNECTOR_CATALOG.keys())

    connectors_output: list[dict[str, Any]] = []
    for connector_type in all_connector_types:
        catalog_entry = _CONNECTOR_CATALOG[connector_type]
        signals = detected_signals.get(connector_type, [])
        secrets_st = probe_credentials(connector_type, env)
        status = connector_status(connector_type, signals, secrets_st)

        # Filter secrets_status to only required vars when no signals (available connector)
        if not signals and status == "available":
            # For available connectors, still show the status but it reflects env
            pass

        # Credential help from catalog (always present, even if no signals)
        secrets_required = catalog_entry.get("credential_help", [])

        connector_entry: dict[str, Any] = {
            "type": connector_type,
            "status": status,
            "category": catalog_entry["category"],
            "display_name": catalog_entry["display_name"],
            "description": catalog_entry["description"],
            "detection_signals": signals,
            "secrets_required": secrets_required,
            "secrets_status": secrets_st,
            "last_run": None,
            "last_run_result": None,
            "finding_count": 0,
        }
        connectors_output.append(connector_entry)

    # Coverage calculation
    active_count = sum(1 for c in connectors_output if c["status"] == "active")
    detected_count = sum(1 for c in connectors_output if c["status"] == "detected")
    available_count = sum(1 for c in connectors_output if c["status"] == "available")
    total_possible = len(connectors_output)
    percentage = round((active_count / total_possible) * 100) if total_possible > 0 else 0

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cli_version": __version__,
        "repo": repo_name,
        "coverage": {
            "percentage": percentage,
            "active_count": active_count,
            "detected_count": detected_count,
            "available_count": available_count,
            "total_possible": total_possible,
        },
        "connectors": connectors_output,
    }


def write_discovery_json(repo_dir: Path, discovery_data: dict[str, Any]) -> Path:
    """Write discovery data to .mallcop/discovery.json in the repo directory."""
    import logging
    mallcop_dir = repo_dir / ".mallcop"
    mallcop_dir.mkdir(parents=True, exist_ok=True)
    discovery_path = mallcop_dir / "discovery.json"
    try:
        discovery_path.write_text(json.dumps(discovery_data, indent=2))
    except OSError as exc:
        logging.warning("Could not write discovery.json: %s", exc)
    return discovery_path
