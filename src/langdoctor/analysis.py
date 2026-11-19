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
        except (SyntaxError, ValueError, RecursionError):
            # RecursionError: an expression nested deeper than the parser can
            # follow. Like any other file that does not parse, it is unread.
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


@dataclass(frozen=True)
class _TreeIndex:
    """Everything the checks look up in a file, gathered in ONE walk of its tree.

    Each check used to walk the tree itself (LD302 twelve times, once per chat
    model), which made a scan of a large codebase take most of a minute.
    """

    calls: dict[str, list[ast.Call]]            # callee name -> its calls, in walk order
    imports: list[ast.Import | ast.ImportFrom]  # in walk order
    attributes: list[ast.Attribute]


def _index(tree: ast.Module) -> _TreeIndex:
    index = getattr(tree, "_ld_index", None)
    if index is None:
        calls: dict[str, list[ast.Call]] = {}
        imports: list[ast.Import | ast.ImportFrom] = []
        attributes: list[ast.Attribute] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = callee_name(node.func)
                if name:
                    calls.setdefault(name, []).append(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(node)
            elif isinstance(node, ast.Attribute):
                attributes.append(node)
        index = _TreeIndex(calls, imports, attributes)
        tree._ld_index = index  # cached on the tree: a file is parsed once per scan
    return index


def find_calls(tree: ast.Module | None, name: str) -> list[ast.Call]:
    if tree is None:
        return []
    return list(_index(tree).calls.get(name, ()))


def import_nodes(tree: ast.Module | None) -> list[ast.Import | ast.ImportFrom]:
    return [] if tree is None else _index(tree).imports


def attribute_nodes(tree: ast.Module | None) -> list[ast.Attribute]:
    return [] if tree is None else _index(tree).attributes


def call_kwargs(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg}


def import_entries(tree: ast.Module | None) -> list[tuple[str, str, int]]:
    """Return (module, imported_name, lineno). For `import x`, name is ''."""
    out: list[tuple[str, str, int]] = []
    for node in import_nodes(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                out.append((mod, alias.name, node.lineno))
        else:
            for alias in node.names:
                out.append((alias.name, "", node.lineno))
    return out


def imported_module_names(tree: ast.Module | None) -> set[str]:
    """Names that mean a module everywhere in the file.

    Bound by `import x`, `import x as y` or `import a.b`, and never rebound by
    an assignment, a loop/with target or a function parameter: after
    `import graph; graph = StateGraph(...)` the name is a builder, not a module.
    `from x import y` is left out on purpose: y may be an object, not a module.
    """
    imported: set[str] = set()
    rebound: set[str] = set()
    if tree is None:
        return imported
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            rebound.add(node.id)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
    return imported - rebound


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
