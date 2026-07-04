"""Project config from the `[tool.langdoctor]` table in pyproject.toml.

CLI flags take precedence over config; ignore lists are unioned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .scanner import read_toml


@dataclass
class Settings:
    fail_on: str | None = None
    ignore: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


def load_settings(root) -> Settings:
    root = Path(root)
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return Settings()
    table = (read_toml(pyproject).get("tool", {}) or {}).get("langdoctor", {}) or {}
    return Settings(
        fail_on=table.get("fail-on") or table.get("fail_on"),
        ignore=[str(x) for x in (table.get("ignore") or [])],
        exclude=[str(x) for x in (table.get("exclude") or [])],
    )
