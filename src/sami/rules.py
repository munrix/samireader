"""Rule packs: every threshold and every name list, outside the code.

Leagues tune thresholds, add known-bad hashes and extend the category lists
without touching Python, and a rule change is then reviewable and versionable
on its own (PLAN §4). A pack loaded with ``--rules`` is layered *over* the
built-in defaults, so an override file only needs to state what it changes.

The shipped defaults are conservative and public, which means they are also
known to anyone who wants to evade them. Leagues that care should keep a
private overlay pack — see ``docs/OPERATIONS.md``.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sami.findings import Severity

DEFAULT_PACK_PATH = Path(__file__).with_name("rules") / "default.json"


class RuleError(Exception):
    """A rule pack could not be loaded or is structurally invalid."""


def _load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]  # noqa: PLC0415 (optional dependency)
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuleError(
                f"{path} is YAML but PyYAML is not installed (pip install 'samireader[yaml]', "
                "or convert the pack to JSON)"
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise RuleError(f"{path}: rule pack must be a mapping at the top level")
    return data


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Overlay wins. Lists replace rather than concatenate, so a league can *shrink* one."""
    merged = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


@dataclass
class RulePack:
    data: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ load

    @classmethod
    def default(cls) -> RulePack:
        return cls(data=_load_mapping(DEFAULT_PACK_PATH), sources=["built-in defaults"])

    @classmethod
    def load(cls, path: str | Path | None) -> RulePack:
        pack = cls.default()
        if path is None:
            return pack
        overlay_path = Path(path)
        if not overlay_path.is_file():
            raise RuleError(f"rule pack not found: {overlay_path}")
        overlay = _load_mapping(overlay_path)
        pack.data = _deep_merge(pack.data, overlay)
        pack.sources.append(str(overlay_path))
        pack.validate()
        return pack

    def validate(self) -> None:
        for rule, value in (self.data.get("severity") or {}).items():
            try:
                Severity(value)
            except ValueError as exc:
                raise RuleError(f"severity override for {rule!r} is not a severity: {value!r}") from exc
        disabled = self.data.get("disabled_rules")
        if disabled is not None and not isinstance(disabled, list):
            raise RuleError("disabled_rules must be a list of rule ids")

    # ------------------------------------------------------------------ read

    @property
    def name(self) -> str:
        return str(self.data.get("name", "unnamed"))

    @property
    def version(self) -> str:
        return str(self.data.get("version", "0"))

    def get(self, path: str, default: Any = None) -> Any:
        """Dotted lookup: ``pack.get("clocks.offset_tolerance_minutes", 3)``."""
        node: Any = self.data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def number(self, path: str, default: float) -> float:
        value = self.get(path, default)
        return float(value) if isinstance(value, (int, float)) else default

    def integer(self, path: str, default: int) -> int:
        value = self.get(path, default)
        return int(value) if isinstance(value, (int, float)) else default

    def strings(self, path: str) -> list[str]:
        value = self.get(path, [])
        return [str(v) for v in value] if isinstance(value, list) else []

    def categories(self, path: str) -> dict[str, list[str]]:
        value = self.get(path, {})
        if not isinstance(value, dict):
            return {}
        return {k: [str(x).lower() for x in v] for k, v in value.items() if isinstance(v, list)}

    def enabled(self, rule: str) -> bool:
        return rule not in set(self.strings("disabled_rules"))

    def severity(self, rule: str, default: Severity) -> Severity:
        override = (self.data.get("severity") or {}).get(rule)
        return Severity(override) if override else default

    def describe(self) -> str:
        return f"{self.name} v{self.version} ({' + '.join(self.sources)})"
