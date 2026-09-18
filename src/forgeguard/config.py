from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

VALID_CATEGORIES = {"documentation", "actions", "secrets", "dependencies"}
VALID_THRESHOLDS = {"none", "critical", "high", "medium", "low"}


class ConfigError(ValueError):
    """Raised when a ForgeGuard configuration is invalid."""


@dataclass(frozen=True)
class Config:
    enabled: dict[str, bool] = field(
        default_factory=lambda: {category: True for category in VALID_CATEGORIES}
    )
    ignore: frozenset[str] = frozenset()
    fail_on: str = "none"


def _parse_scalar(value: str, line: int):
    value = value.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.isdigit():
        return int(value)
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if value:
        return value
    raise ConfigError(f"Line {line}: expected a value")


def _parse_simple_yaml(text: str) -> dict:
    """Parse the intentionally small, documented ForgeGuard YAML subset."""
    result: dict = {}
    section: str | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ConfigError(f"Line {number}: use spaces for indentation")
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            key = stripped.split(":", 1)[0].strip()
            if not key or key in result:
                raise ConfigError(f"Line {number}: empty or duplicate key: {key}")
            if stripped.endswith(":"):
                section = stripped[:-1]
                result[section] = [] if section == "ignore" else {}
                continue
            if ":" not in stripped:
                raise ConfigError(f"Line {number}: expected key: value")
            key, value = stripped.split(":", 1)
            result[key.strip()] = _parse_scalar(value, number)
            section = None
        elif indent == 2 and section == "ignore" and stripped.startswith("- "):
            result[section].append(stripped[2:].strip())
        elif indent == 2 and section and isinstance(result[section], dict) and ":" in stripped:
            key, value = stripped.split(":", 1)
            if not key.strip() or key.strip() in result[section]:
                raise ConfigError(f"Line {number}: empty or duplicate key: {key}")
            result[section][key.strip()] = _parse_scalar(value, number)
        else:
            raise ConfigError(f"Line {number}: unsupported indentation or syntax")
    return result


def load_config(path: Path | None, *, required: bool = False) -> Config:
    if path is None or not path.exists():
        if required:
            raise ConfigError(f"Configuration file does not exist: {path}")
        return Config()
    try:
        if path.stat().st_size > 64_000:
            raise ConfigError("Configuration exceeds the 64 KB limit")
        data = _parse_simple_yaml(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise ConfigError(f"Could not read {path}: {error}") from error
    allowed = {"version", "scan", "thresholds", "ignore"}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"Unknown top-level keys: {', '.join(sorted(unknown))}")
    if type(data.get("version")) is not int or data["version"] != 1:
        raise ConfigError("Configuration version must be 1")
    scan = data.get("scan", {})
    if not isinstance(scan, dict):
        raise ConfigError("scan must be a mapping of category names to booleans")
    unknown_categories = set(scan) - VALID_CATEGORIES
    if unknown_categories:
        raise ConfigError(f"Unknown scan categories: {', '.join(sorted(unknown_categories))}")
    if any(not isinstance(value, bool) for value in scan.values()):
        raise ConfigError("Scan category values must be true or false")
    enabled = {category: scan.get(category, True) for category in VALID_CATEGORIES}
    thresholds = data.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ConfigError("thresholds must be a mapping")
    if set(thresholds) - {"fail_on"}:
        raise ConfigError("Only fail_on is supported under thresholds")
    fail_on = thresholds.get("fail_on", "none")
    if not isinstance(fail_on, str) or fail_on not in VALID_THRESHOLDS:
        raise ConfigError(f"Invalid fail_on threshold: {fail_on}")
    ignored = data.get("ignore", [])
    if not isinstance(ignored, list) or any(not str(item).startswith("FG-") for item in ignored):
        raise ConfigError("Every ignored check must be an FG-* check ID")
    return Config(enabled, frozenset(map(str, ignored)), fail_on)
