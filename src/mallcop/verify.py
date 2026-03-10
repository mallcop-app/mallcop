"""Plugin verification: validate manifest, base class, and contracts."""

from __future__ import annotations

import importlib.util
import inspect
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mallcop.connectors._base import ConnectorBase
from mallcop.detectors._base import DetectorBase
from mallcop.actors._base import ActorBase


@dataclass
class VerifyResult:
    plugin_name: str
    plugin_type: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0


_BASE_CLASSES = {
    "connector": ConnectorBase,
    "detector": DetectorBase,
    "actor": ActorBase,
}

_MODULE_NAMES = {
    "connector": "connector",
    "detector": "detector",
}


def verify_plugin(plugin_dir: Path, plugin_type: str) -> VerifyResult:
    """Validate a plugin directory against its contracts."""
    result = VerifyResult(
        plugin_name=plugin_dir.name,
        plugin_type=plugin_type,
    )

    # 1. Check manifest exists
    manifest_path = plugin_dir / "manifest.yaml"
    if not manifest_path.exists():
        result.errors.append("Missing manifest.yaml")
        return result

    # 2. Load and validate manifest
    try:
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
    except Exception as e:
        result.errors.append(f"Failed to parse manifest.yaml: {e}")
        return result

    if not isinstance(manifest, dict):
        result.errors.append("manifest.yaml is not a valid YAML mapping")
        return result

    # Dispatch to type-specific validation
    if plugin_type == "connector":
        _verify_connector(plugin_dir, manifest, result)
    elif plugin_type == "detector":
        _verify_detector(plugin_dir, manifest, result)
    elif plugin_type == "actor":
        _verify_actor(plugin_dir, manifest, result)
    else:
        result.errors.append(f"Unknown plugin_type '{plugin_type}'")

    return result


def _verify_manifest_common(manifest: dict, result: VerifyResult) -> bool:
    """Validate fields common to all manifests. Returns False if fatal."""
    ok = True
    if not manifest.get("name"):
        result.errors.append("Manifest 'name' is empty or missing")
        ok = False
    if "version" not in manifest:
        result.errors.append("Manifest missing 'version'")
        ok = False
    if "description" not in manifest:
        result.errors.append("Manifest missing 'description'")
        ok = False
    return ok


def _load_module(plugin_dir: Path, module_name: str) -> Any:
    """Dynamically load a Python module from plugin directory."""
    module_path = plugin_dir / f"{module_name}.py"
    if not module_path.exists():
        return None

    spec = importlib.util.spec_from_file_location(
        f"mallcop_plugin_{plugin_dir.name}_{module_name}",
        module_path,
    )
    if spec is None or spec.loader is None:
        return None

    module = importlib.util.module_from_spec(spec)
    # Add parent to sys.path temporarily so relative imports work
    parent = str(plugin_dir.parent)
    added = parent not in sys.path
    if added:
        sys.path.insert(0, parent)
    try:
        spec.loader.exec_module(module)
    finally:
        if added and parent in sys.path:
            sys.path.remove(parent)

    return module


def _find_subclass(module: Any, base_class: type) -> type | None:
    """Find a class in module that is a subclass of base_class (not base_class itself)."""
    for name, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, base_class) and obj is not base_class:
            return obj
    return None


def _verify_connector(plugin_dir: Path, manifest: dict, result: VerifyResult) -> None:
    if not _verify_manifest_common(manifest, result):
        return

    # Connector-specific manifest fields
    if "event_types" not in manifest:
        result.errors.append("Connector manifest missing 'event_types'")
        return
    if not manifest.get("event_types"):
        result.errors.append("Connector manifest 'event_types' must not be empty")
        return
    if "auth" not in manifest:
        result.errors.append("Connector manifest missing 'auth'")
        return

    # Load module and check base class
    module = _load_module(plugin_dir, "connector")
    if module is None:
        result.errors.append("Missing connector.py module")
        return

    cls = _find_subclass(module, ConnectorBase)
    if cls is None:
        result.errors.append(
            "No class found implementing ConnectorBase in connector.py"
        )
        return

    # Contract test: event_types match
    try:
        instance = cls()
        code_event_types = sorted(instance.event_types())
        manifest_event_types = sorted(manifest["event_types"])
        if code_event_types != manifest_event_types:
            result.errors.append(
                f"event_types mismatch: manifest declares {manifest_event_types}, "
                f"code returns {code_event_types}"
            )
    except Exception as e:
        result.errors.append(f"Failed to instantiate connector: {e}")


def _verify_detector(plugin_dir: Path, manifest: dict, result: VerifyResult) -> None:
    from mallcop.schemas import Severity

    if not _verify_manifest_common(manifest, result):
        return

    # Detector-specific manifest fields
    if "sources" not in manifest:
        result.errors.append("Detector manifest missing 'sources'")
        return
    if "event_types" not in manifest:
        result.errors.append("Detector manifest missing 'event_types'")
        return
    if "severity_default" not in manifest:
        result.errors.append("Detector manifest missing 'severity_default'")
        return

    valid_severities = {s.value for s in Severity}
    if manifest["severity_default"] not in valid_severities:
        result.errors.append(
            f"Invalid severity_default '{manifest['severity_default']}', "
            f"must be one of {valid_severities}"
        )
        return

    # Load module and check base class
    module = _load_module(plugin_dir, "detector")
    if module is None:
        result.errors.append("Missing detector.py module")
        return

    cls = _find_subclass(module, DetectorBase)
    if cls is None:
        result.errors.append(
            "No class found implementing DetectorBase in detector.py"
        )
        return

    # Contract test: sources match
    manifest_sources = manifest.get("sources")
    if isinstance(manifest_sources, list):
        try:
            instance = cls()
            code_sources = instance.relevant_sources()
            if code_sources is None:
                result.errors.append(
                    f"sources mismatch: manifest declares {manifest_sources}, "
                    f"code returns None (all sources)"
                )
            elif sorted(code_sources) != sorted(manifest_sources):
                result.errors.append(
                    f"sources mismatch: manifest declares {sorted(manifest_sources)}, "
                    f"code returns {sorted(code_sources)}"
                )
        except Exception as e:
            result.errors.append(f"Failed to instantiate detector: {e}")


def _verify_actor(plugin_dir: Path, manifest: dict, result: VerifyResult) -> None:
    if not _verify_manifest_common(manifest, result):
        return

    # Actor-specific manifest fields
    if "type" not in manifest:
        result.errors.append("Actor manifest missing 'type'")
        return

    valid_types = {"agent", "channel"}
    if manifest["type"] not in valid_types:
        result.errors.append(
            f"Invalid actor type '{manifest['type']}', must be one of {valid_types}"
        )
        return

    if manifest["type"] == "agent" and not manifest.get("model"):
        result.errors.append("Agent-type actors must specify a 'model'")
        return

    # Check POST.md exists
    post_md = plugin_dir / "POST.md"
    if not post_md.exists():
        result.errors.append("Missing POST.md")


# --- Tool file verification ---

_VALID_PERMISSIONS = {"read", "write"}

# JSON-serializable types that tool params may use
_SERIALIZABLE_TYPES = {
    str, int, float, bool, list, dict, type(None),
}
_SERIALIZABLE_TYPE_NAMES = {
    "str", "int", "float", "bool", "list", "dict", "None", "NoneType",
    "Any",  # typing.Any is acceptable
}


def verify_tool_file(tool_path: Path) -> VerifyResult:
    """Validate a .py tool file: @tool decorator, permissions, param types."""
    result = VerifyResult(
        plugin_name=tool_path.stem,
        plugin_type="tool",
    )

    if not tool_path.exists():
        result.errors.append(f"File not found: {tool_path}")
        return result

    # Try to load the module
    module = None
    try:
        module = _load_module(tool_path.parent, tool_path.stem)
    except Exception as e:
        err_str = str(e).lower()
        if "permission" in err_str:
            result.errors.append(f"Invalid tool permission: {e}")
        else:
            result.errors.append(f"Failed to load tool file: {e}")
        return result

    if module is None:
        result.errors.append(f"Failed to load tool file: {tool_path}")
        return result

    # Find all @tool-decorated functions
    tool_fns = []
    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if callable(obj) and hasattr(obj, "_tool_meta"):
            tool_fns.append(obj)

    if not tool_fns:
        result.errors.append(
            "No @tool-decorated functions found. "
            "Tool files must contain at least one function with the @tool decorator."
        )
        return result

    # Validate each tool function
    for fn in tool_fns:
        meta = fn._tool_meta
        tool_name = meta.name

        # Permission check
        if meta.permission not in _VALID_PERMISSIONS:
            result.errors.append(
                f"Tool '{tool_name}': invalid permission '{meta.permission}', "
                f"must be one of {_VALID_PERMISSIONS}"
            )

        # Inspect the original function signature
        inner = getattr(fn, "__wrapped__", fn)
        sig = inspect.signature(inner)
        hints = inner.__annotations__ if hasattr(inner, "__annotations__") else {}

        for param_name, param in sig.parameters.items():
            if param_name in ("context", "return"):
                continue

            # Reject *args and **kwargs
            if param.kind == inspect.Parameter.VAR_POSITIONAL:
                result.errors.append(
                    f"Tool '{tool_name}': bare *args not allowed "
                    f"(parameter '{param_name}')"
                )
                continue
            if param.kind == inspect.Parameter.VAR_KEYWORD:
                result.errors.append(
                    f"Tool '{tool_name}': bare **kwargs not allowed "
                    f"(parameter '{param_name}')"
                )
                continue

            # Check type hint exists
            if param_name not in hints:
                result.errors.append(
                    f"Tool '{tool_name}': parameter '{param_name}' "
                    f"has no type hint. All user-facing params must be typed."
                )
                continue

            # Check type hint is JSON-serializable
            type_hint = hints[param_name]
            type_name = getattr(type_hint, "__name__", str(type_hint))
            # Handle Optional, Union, etc — extract the base name
            if type_name.startswith("typing."):
                type_name = type_name.replace("typing.", "")
            # For union types like str | None, check each component
            origin = getattr(type_hint, "__origin__", None)
            if origin is not None:
                # It's a generic like list[str], dict[str, Any], Optional[str], etc.
                # The base (list, dict) is serializable — accept it
                base_name = getattr(origin, "__name__", str(origin))
                if base_name not in _SERIALIZABLE_TYPE_NAMES and base_name not in ("Union", "Optional"):
                    result.errors.append(
                        f"Tool '{tool_name}': parameter '{param_name}' "
                        f"type '{type_name}' is not JSON-serializable. "
                        f"Use str, int, float, bool, list, dict, or None."
                    )
            elif type_hint not in _SERIALIZABLE_TYPES and type_name not in _SERIALIZABLE_TYPE_NAMES:
                result.errors.append(
                    f"Tool '{tool_name}': parameter '{param_name}' "
                    f"type '{type_name}' is not JSON-serializable. "
                    f"Use str, int, float, bool, list, dict, or None."
                )

    return result


# --- App artifact verification (parser.yaml + detectors.yaml) ---

_VALID_CLASSIFICATIONS = {"routine", "operational", "error", "security", "unknown"}
_VALID_SEVERITIES = {"info", "warn", "critical"}
_VALID_CONDITION_TYPES = {"count_threshold", "new_value", "volume_ratio", "regex_match"}

# Required fields per condition type
_CONDITION_REQUIRED: dict[str, list[str]] = {
    "count_threshold": ["window_minutes", "threshold"],
    "new_value": ["field"],
    "volume_ratio": ["ratio"],
    "regex_match": ["field", "pattern"],
}


def _verify_parser_yaml(path: Path) -> VerifyResult:
    """Validate a parser.yaml artifact."""
    result = VerifyResult(plugin_name=path.parent.name, plugin_type="parser")

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        result.errors.append(f"Failed to parse parser.yaml: {e}")
        return result

    if not isinstance(data, dict):
        result.errors.append("parser.yaml is not a valid YAML mapping")
        return result

    # Required top-level fields
    if "app" not in data:
        result.errors.append("parser.yaml missing required field 'app'")
    if "version" not in data:
        result.errors.append("parser.yaml missing required field 'version'")

    if result.errors:
        return result

    # Templates
    templates = data.get("templates")
    if templates is None:
        result.errors.append("parser.yaml missing required field 'templates'")
        return result
    if not isinstance(templates, list) or len(templates) == 0:
        result.errors.append("parser.yaml 'templates' must be a non-empty list")
        return result

    for i, t in enumerate(templates):
        if not isinstance(t, dict):
            result.errors.append(f"Template {i}: must be a mapping")
            continue

        tname = t.get("name", f"template[{i}]")

        # Required template fields
        if "name" not in t:
            result.errors.append(f"Template {i}: missing required field 'name'")
        if "pattern" not in t:
            result.errors.append(f"Template '{tname}': missing required field 'pattern'")
        else:
            # Validate regex
            try:
                re.compile(t["pattern"])
            except re.error as e:
                result.errors.append(
                    f"Template '{tname}': invalid regex pattern: {e}"
                )

        if "classification" not in t:
            result.errors.append(
                f"Template '{tname}': missing required field 'classification'"
            )
        elif t["classification"] not in _VALID_CLASSIFICATIONS:
            result.errors.append(
                f"Template '{tname}': invalid classification '{t['classification']}', "
                f"must be one of {sorted(_VALID_CLASSIFICATIONS)}"
            )

        if "event_mapping" not in t:
            result.errors.append(
                f"Template '{tname}': missing required field 'event_mapping'"
            )
        elif isinstance(t["event_mapping"], dict):
            mapping = t["event_mapping"]
            if "event_type" not in mapping:
                result.errors.append(
                    f"Template '{tname}': event_mapping missing 'event_type'"
                )
            sev = mapping.get("severity")
            if sev is not None and sev not in _VALID_SEVERITIES:
                result.errors.append(
                    f"Template '{tname}': invalid severity '{sev}' in event_mapping, "
                    f"must be one of {sorted(_VALID_SEVERITIES)}"
                )

    return result


def _verify_detectors_yaml(path: Path) -> VerifyResult:
    """Validate a detectors.yaml artifact."""
    result = VerifyResult(plugin_name=path.parent.name, plugin_type="detectors")

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        result.errors.append(f"Failed to parse detectors.yaml: {e}")
        return result

    if not isinstance(data, dict):
        result.errors.append("detectors.yaml is not a valid YAML mapping")
        return result

    if "app" not in data:
        result.errors.append("detectors.yaml missing required field 'app'")

    detectors = data.get("detectors")
    if detectors is None:
        result.errors.append("detectors.yaml missing required field 'detectors'")
        return result

    if not isinstance(detectors, list):
        result.errors.append("detectors.yaml 'detectors' must be a list")
        return result

    for i, d in enumerate(detectors):
        if not isinstance(d, dict):
            result.errors.append(f"Detector {i}: must be a mapping")
            continue

        dname = d.get("name", f"detector[{i}]")

        if "name" not in d:
            result.errors.append(f"Detector {i}: missing required field 'name'")
        if "event_type" not in d:
            result.errors.append(f"Detector '{dname}': missing required field 'event_type'")

        # Severity (required — DeclarativeDetector crashes without it)
        sev = d.get("severity")
        if sev is None:
            result.errors.append(f"Detector '{dname}': missing required field 'severity'")
        elif sev not in _VALID_SEVERITIES:
            result.errors.append(
                f"Detector '{dname}': invalid severity '{sev}', "
                f"must be one of {sorted(_VALID_SEVERITIES)}"
            )

        # Condition
        condition = d.get("condition")
        if condition is None:
            result.errors.append(f"Detector '{dname}': missing required field 'condition'")
            continue

        if not isinstance(condition, dict):
            result.errors.append(f"Detector '{dname}': condition must be a mapping")
            continue

        ctype = condition.get("type")
        if ctype is None:
            result.errors.append(f"Detector '{dname}': condition missing 'type'")
            continue

        if ctype not in _VALID_CONDITION_TYPES:
            result.errors.append(
                f"Detector '{dname}': unknown condition type '{ctype}', "
                f"must be one of {sorted(_VALID_CONDITION_TYPES)}"
            )
            continue

        # Check required fields for this condition type
        required = _CONDITION_REQUIRED.get(ctype, [])
        for req_field in required:
            if req_field not in condition:
                result.errors.append(
                    f"Detector '{dname}': condition type '{ctype}' "
                    f"requires field '{req_field}'"
                )

    return result


def _cross_validate(
    parser_result: VerifyResult | None,
    detectors_result: VerifyResult | None,
    parser_path: Path | None,
    detectors_path: Path | None,
) -> None:
    """Cross-validate detector event_types against parser template event_types."""
    if parser_path is None or detectors_path is None:
        return
    if parser_result is None or detectors_result is None:
        return

    # Extract parser event_types from templates
    try:
        with open(parser_path) as f:
            parser_data = yaml.safe_load(f)
        with open(detectors_path) as f:
            detectors_data = yaml.safe_load(f)
    except Exception:
        return

    if not isinstance(parser_data, dict) or not isinstance(detectors_data, dict):
        return

    parser_event_types: set[str] = set()
    for t in parser_data.get("templates", []):
        if isinstance(t, dict):
            mapping = t.get("event_mapping", {})
            if isinstance(mapping, dict) and "event_type" in mapping:
                parser_event_types.add(mapping["event_type"])

    for d in detectors_data.get("detectors", []):
        if isinstance(d, dict):
            det_event_type = d.get("event_type", "")
            dname = d.get("name", "unknown")
            if det_event_type and det_event_type not in parser_event_types:
                detectors_result.warnings.append(
                    f"Detector '{dname}' references event_type '{det_event_type}' "
                    f"not found in parser templates"
                )


def verify_app_artifacts(app_dir: Path) -> list[VerifyResult]:
    """Validate parser.yaml and detectors.yaml in an app directory.

    Returns a list of VerifyResult (one per artifact found).
    """
    results: list[VerifyResult] = []
    parser_path = app_dir / "parser.yaml"
    detectors_path = app_dir / "detectors.yaml"

    parser_result: VerifyResult | None = None
    detectors_result: VerifyResult | None = None

    if parser_path.exists():
        parser_result = _verify_parser_yaml(parser_path)
        results.append(parser_result)

    if detectors_path.exists():
        detectors_result = _verify_detectors_yaml(detectors_path)
        results.append(detectors_result)

    # Cross-validate if both exist
    if parser_path.exists() and detectors_path.exists():
        _cross_validate(
            parser_result, detectors_result,
            parser_path, detectors_path,
        )

    return results
