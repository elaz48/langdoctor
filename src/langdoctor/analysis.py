"""Shared source-analysis helpers for code-pattern checks (LD2xx–LD5xx).

Python sources are parsed once with stdlib `ast` and cached on the Project.
A file that fails to parse yields a `tree` of None; checks must tolerate that.
"""

from __future__ import annotations

import ast
import contextlib
from dataclasses import dataclass
from pathlib import Path

from .advisories import normalize_name


@dataclass
class SourceFile:
    path: Path
    rel: str
    text: str
    lines: list[str]
    tree: ast.Module | None


def load_sources(project) -> list[SourceFile]:
    cached = getattr(project, "_ld_sources", None)
    if cached is not None:
        return cached
    sources: list[SourceFile] = []
    for path in getattr(project, "python_files", []):
        text = _read(path)
        try:
            tree: ast.Module | None = ast.parse(text)
        except (SyntaxError, ValueError):
            tree = None
        sources.append(SourceFile(path, _rel(path, project.root), text, text.splitlines(), tree))
    with contextlib.suppress(AttributeError, TypeError):  # pragma: no cover - defensive
        project._ld_sources = sources
    return sources


def read_project_file(project, rel: str) -> str:
    return _read(project.root / rel)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:  # pragma: no cover - defensive
        return str(path)


def callee_name(func: ast.AST) -> str | None:
    """Simple callee name: the attribute tail or the bare Name id."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def find_calls(tree: ast.Module | None, name: str) -> list[ast.Call]:
    if tree is None:
        return []
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and callee_name(n.func) == name]


def call_kwargs(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg}


def import_entries(tree: ast.Module | None) -> list[tuple[str, str, int]]:
    """Return (module, imported_name, lineno). For `import x`, name is ''."""
    out: list[tuple[str, str, int]] = []
    if tree is None:
        return out
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                out.append((mod, alias.name, node.lineno))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, "", node.lineno))
    return out


def project_uses(project, prefix: str) -> bool:
    """True if a dependency or an import top-level starts with `prefix`."""
    prefix_n = normalize_name(prefix)
    for dep in getattr(project, "dependencies", []):
        if normalize_name(dep.name).startswith(prefix_n):
            return True
    for sf in load_sources(project):
        for mod, _, _ in import_entries(sf.tree):
            if normalize_name(mod.split(".")[0]).startswith(prefix_n):
                return True
    return False
