"""Check registry.

Code-pattern checks (LD2xx–LD5xx) register here via @register_check. The
data-driven version check (LD1xx) lives in checks/versions.py and is invoked
directly by the engine — it reads advisories.json rather than being one
function per advisory.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..finding import Finding

if TYPE_CHECKING:
    from ..scanner import Project

CheckFn = Callable[["Project"], "list[Finding]"]


@dataclass(frozen=True)
class RegisteredCheck:
    id: str
    category: str
    severity: str | None
    title: str
    heuristic: bool
    func: CheckFn


CHECK_REGISTRY: dict[str, RegisteredCheck] = {}


def register_check(
    id: str,
    category: str,
    severity: str | None = None,
    title: str = "",
    heuristic: bool = False,
) -> Callable[[CheckFn], CheckFn]:
    def decorator(func: CheckFn) -> CheckFn:
        if id in CHECK_REGISTRY:
            raise ValueError(f"duplicate check id: {id}")
        CHECK_REGISTRY[id] = RegisteredCheck(id, category, severity, title, heuristic, func)
        return func

    return decorator


def all_checks() -> list[RegisteredCheck]:
    return list(CHECK_REGISTRY.values())
