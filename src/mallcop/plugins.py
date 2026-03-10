"""Plugin discovery: scan directories for plugin subdirectories with manifest.yaml."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mallcop.connectors._base import ConnectorBase

_PLUGIN_CATEGORIES = {
    "connectors": "connector",
    "detectors": "detector",
    "actors": "actor",
}


@dataclass
class PluginInfo:
    name: str
    plugin_type: str
    path: Path


def discover_plugins(
    search_paths: list[Path],
) -> dict[str, dict[str, PluginInfo]]:
    """Scan search paths for plugins. Earlier paths take priority (first wins).

    Each search path is expected to contain subdirectories named
    'connectors/', 'detectors/', and/or 'actors/', each containing
    plugin directories with manifest.yaml files.

    Resolution order: first occurrence of a plugin name wins.
    """
    result: dict[str, dict[str, PluginInfo]] = {
        "connectors": {},
        "detectors": {},
        "actors": {},
    }

    for search_path in search_paths:
        if not search_path.exists() or not search_path.is_dir():
            continue

        for category_dir, plugin_type in _PLUGIN_CATEGORIES.items():
            category_path = search_path / category_dir
            if not category_path.exists() or not category_path.is_dir():
                continue

            for entry in sorted(category_path.iterdir()):
                # Skip non-directories and private files/dirs (starting with _)
                if not entry.is_dir() or entry.name.startswith("_"):
                    continue

                manifest_path = entry / "manifest.yaml"
                if not manifest_path.exists():
                    continue

                try:
                    with open(manifest_path) as f:
                        data = yaml.safe_load(f)
                    plugin_name = data.get("name", "")
                    if not plugin_name:
                        continue
                except Exception:
                    continue

                # First wins: skip if already discovered
                if plugin_name not in result[category_dir]:
                    result[category_dir][plugin_name] = PluginInfo(
                        name=plugin_name,
                        plugin_type=plugin_type,
                        path=entry,
                    )

    return result


# Map plugin_type to (module filename, base class import path)
_PLUGIN_MODULE_MAP: dict[str, tuple[str, str, str]] = {
    "connector": ("connector.py", "mallcop.connectors._base", "ConnectorBase"),
    "detector": ("detector.py", "mallcop.detectors._base", "DetectorBase"),
    "actor": ("actor.py", "mallcop.actors._base", "ActorBase"),
}


def load_plugin_class(info: PluginInfo) -> type | None:
    """Import the plugin module and return the first subclass of the base class.

    Convention: connectors have connector.py, detectors have detector.py, etc.
    The first class that is a subclass of the appropriate base (ConnectorBase,
    DetectorBase, ActorBase) is returned.

    For built-in plugins (inside the mallcop package), uses the standard
    dotted import path so classes are identity-compatible with direct imports.

    Returns None if the module file doesn't exist or no matching class is found.
    """
    entry = _PLUGIN_MODULE_MAP.get(info.plugin_type)
    if entry is None:
        return None

    module_file, base_module_path, base_class_name = entry
    module_stem = Path(module_file).stem  # "connector" from "connector.py"
    module_path = info.path / module_file
    if not module_path.exists():
        return None

    # Import the base class
    base_mod = importlib.import_module(base_module_path)
    base_cls = getattr(base_mod, base_class_name)

    # Determine if this is a built-in plugin (inside the mallcop package)
    package_root = Path(__file__).parent
    try:
        info.path.relative_to(package_root)
        is_builtin = True
    except ValueError:
        is_builtin = False

    if is_builtin:
        # Use standard dotted import: mallcop.connectors.azure.connector
        rel = info.path.relative_to(package_root)
        dotted = "mallcop." + ".".join(rel.parts) + "." + module_stem
        mod = importlib.import_module(dotted)
    else:
        # External plugin: load from file
        spec = importlib.util.spec_from_file_location(
            f"mallcop._plugins.{info.plugin_type}.{info.name}",
            module_path,
        )
        if spec is None or spec.loader is None:
            return None

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

    # Find the first concrete subclass of the base
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if issubclass(obj, base_cls) and obj is not base_cls:
            return obj

    return None


def get_search_paths(cwd: Path | None = None) -> list[Path]:
    """Build plugin search paths: deployment repo plugins/ -> built-in package."""
    if cwd is None:
        cwd = Path.cwd()
    paths: list[Path] = []
    deploy_plugins = cwd / "plugins"
    if deploy_plugins.exists():
        paths.append(deploy_plugins)
    paths.append(Path(__file__).parent)
    return paths


def instantiate_connector(name: str) -> ConnectorBase | None:
    """Discover and instantiate a connector plugin by name."""
    search_paths = get_search_paths()
    plugins = discover_plugins(search_paths)
    info = plugins["connectors"].get(name)
    if info is None:
        return None
    cls = load_plugin_class(info)
    if cls is None:
        return None
    return cls()
