"""Is an advisory's vulnerable API imported anywhere in the project?

An advisory can list `symbols`: the public entry points an application has to
import for the vulnerable code to be in play. That list is data, curated from
the vendor advisory (advisories.json). This module looks for those entry points
in the project's Python sources and reports what it found.

It sees static imports and attribute access through an imported module. It does
not see dynamic imports, a name passed around under another binding, or a
library that reaches the vulnerable code on the application's behalf — which is
why an advisory only lists entry points when the vendor ties the issue to them,
and why the result is worded as a fact ("not imported in 14 files"), never as a
conclusion ("not affected"). It never changes a finding's severity or the exit
code.

Symbol format:
    "pkg.module:Name"  Name imported from pkg.module or one of its submodules,
                       or reached as `<module>.Name`
    "pkg.module"       any import of pkg.module or one of its submodules
"""

from __future__ import annotations

import ast
import contextlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from .analysis import attribute_nodes, import_nodes, load_notebook_sources, load_sources
from .finding import Reachability, Use

_MAX_USES = 25  # enough to act on; a report does not need every call site
# No import path is this deep. Resolving every node of an `a.b.c. ... .z` chain
# all the way down would be quadratic in its length on a crafted file.
_MAX_CHAIN_PARTS = 12


@dataclass
class _FileImports:
    rel: str
    from_imports: tuple[tuple[str, str, int], ...]  # (module, name, line); absolute only
    module_imports: tuple[tuple[str, int], ...]     # `import a.b.c` -> ("a.b.c", line)
    bound: dict[str, tuple[str, ...]]               # local name -> every path an import gave it
    roots: frozenset[str]                           # top-level packages this file imports
    tree: ast.Module
    _attributes: tuple[tuple[str, int], ...] | None = None

    @property
    def attributes(self) -> tuple[tuple[str, int], ...]:
        """`alias.x.y` chains resolved to dotted paths — worked out on first
        use, which only happens for a file that imports a package of interest."""
        if self._attributes is None:
            self._attributes = tuple(
                (dotted, node.lineno)
                for node in attribute_nodes(self.tree)
                for dotted in _dotted(node, self.bound)
            )
        return self._attributes


def assess(project, symbols: Iterable[str]) -> Reachability | None:
    """Search the whole scanned tree for the given entry points.

    The whole tree, not just the manifest's directory: an import found in
    another service errs towards "used", and the wrong "not imported" is the
    direction that would mislead. Returns None when there is nothing to claim:
    no entry points listed, or no Python file that could be read.
    """
    symbols = tuple(symbols)
    if not symbols:
        return None
    files, unparsed = _project_imports(project)
    if not files:
        return None
    uses = sorted(
        {use for file in files for symbol in symbols for use in _uses_in(file, symbol)},
        key=lambda use: (use.file, use.line, use.symbol),
    )
    return Reachability(
        symbols=symbols,
        uses=tuple(uses[:_MAX_USES]),
        files_searched=len(files),
        files_unparsed=unparsed,
        total_uses=len(uses),
    )


def _uses_in(file: _FileImports, symbol: str) -> Iterator[Use]:
    module, _, name = symbol.partition(":")
    if module.split(".")[0] not in file.roots:
        return  # nothing from that package is imported here, so nothing can match
    for imported_from, imported, line in file.from_imports:
        if name:
            # `from pkg.module import *` brings Name in as well
            hit = imported in (name, "*") and _under(imported_from, module)
        else:
            hit = _under(imported_from, module) or _under(f"{imported_from}.{imported}", module)
        if hit:
            yield Use(file.rel, line, symbol)
    if not name:
        for imported, line in file.module_imports:
            if _under(imported, module):
                yield Use(file.rel, line, symbol)
    for dotted, line in file.attributes:
        if name:
            owner, _, attribute = dotted.rpartition(".")
            hit = attribute == name and _under(owner, module)
        else:
            hit = _under(dotted, module)
        if hit:
            yield Use(file.rel, line, symbol)


def _under(candidate: str, module: str) -> bool:
    """candidate is `module` itself or one of its submodules.

    Deliberately one-directional: the PARENT of the declared module does not
    count, so `from langchain_core import load` (the module) is not taken for
    the function `langchain_core.load:load`. advisories.json therefore declares
    the shallowest public path a name can be imported from.
    """
    return candidate == module or candidate.startswith(module + ".")


def _project_imports(project) -> tuple[list[_FileImports], int]:
    cached = getattr(project, "_ld_imports", None)
    if cached is not None:
        return cached
    files: list[_FileImports] = []
    unparsed = 0
    # Notebooks are searched too: a lot of LangChain code lives in them.
    for source in [*load_sources(project), *load_notebook_sources(project)]:
        if source.tree is None:
            unparsed += 1
            continue
        files.append(_file_imports(source.rel, source.tree))
        if source.partial:
            unparsed += 1  # what could be read was searched; the rest is unknown
    result = (files, unparsed)
    with contextlib.suppress(AttributeError, TypeError):  # pragma: no cover - defensive
        project._ld_imports = result
    return result


def _file_imports(rel: str, tree: ast.Module) -> _FileImports:
    from_imports: list[tuple[str, str, int]] = []
    module_imports: list[tuple[str, int]] = []
    # A name can be bound by several imports (in different functions, or
    # re-imported); it stands for all of them, since scopes are not tracked.
    bound: dict[str, tuple[str, ...]] = {}

    def bind(name: str, path: str) -> None:
        if path not in bound.get(name, ()):
            bound[name] = (*bound.get(name, ()), path)

    for node in import_nodes(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue  # a relative import is the project's own code
            for alias in node.names:
                from_imports.append((node.module, alias.name, node.lineno))
                if alias.name != "*":
                    bind(alias.asname or alias.name, f"{node.module}.{alias.name}")
        else:
            for alias in node.names:
                module_imports.append((alias.name, node.lineno))
                if alias.asname:
                    bind(alias.asname, alias.name)
                else:  # `import a.b.c` binds only `a`
                    root = alias.name.split(".")[0]
                    bind(root, root)
    roots = frozenset(
        module.split(".")[0]
        for module in [*(m for m, _, _ in from_imports), *(m for m, _ in module_imports)]
    )
    return _FileImports(rel, tuple(from_imports), tuple(module_imports), bound, roots, tree)


def _dotted(node: ast.Attribute, bound: dict[str, tuple[str, ...]]) -> list[str]:
    """`alias.x.y` -> ["pkg.module.x.y"], one per path `alias` was imported as."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        if len(parts) == _MAX_CHAIN_PARTS:
            return []
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return []
    tail = list(reversed(parts))
    return [".".join([path, *tail]) for path in bound.get(current.id, ())]
