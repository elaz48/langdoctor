"""Jupyter notebooks as Python sources.

A notebook is JSON, and its code cells are the Python. `read_notebook` turns
one into a syntax tree in which every statement carries the number of the line
it occupies in the .ipynb file itself. A finding then points at a line that
exists: an editor can open it, GitHub can annotate it, and an inline
`# langdoctor: ignore` comment on that line is found like in any other file.

That works for the layout Jupyter, VS Code and Colab all write: one JSON string
per source line, each on its own line. A notebook stored any other way (minified,
or a cell's source kept as one long string) cannot be placed line by line, so
it is reported as not read rather than given invented line numbers.

The rule throughout: code that could not be read makes the notebook `partial`.
The reachability search then answers "unknown", never "not imported" — so every
shortcut here has to either read the code or admit that it did not.

Only the hardcoded-secret check and the reachability search read notebooks. The
production-readiness checks do not: a notebook is not deployed code.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass

from .lines import split_lines

# More code than any notebook written by a person holds. Beyond it the rest is
# left unread: a syntax tree costs about a gigabyte per million statements.
MAX_CODE_LINES = 100_000

# Cell magics whose body is certainly not Python. Everything else is read as
# Python — `%%time`, `%%capture`, `%%python`, and any magic not listed here —
# and if such a body does not parse, the notebook is marked partial.
_NON_PYTHON_CELL_MAGICS = {
    "bash", "sh", "shell", "html", "markdown", "javascript", "js", "latex", "svg", "sql",
    "perl", "ruby", "system", "sx", "bigquery",
}
# `%%writefile path`: the body is the file. It is code when the path says so.
_TEXT_FILE_MAGICS = {"writefile", "file"}
# IPython help syntax, a whole line with no spaces: `obj?`, `obj??`, `?obj`.
_HELP_RE = re.compile(r"\?{1,2}[\w.]+|[\w.]+\?{1,2}")
_SOURCE_OPEN = '"source": ['
_SOURCE_EMPTY = '"source": []'
_COMPILE_FLAGS = ast.PyCF_ONLY_AST | ast.PyCF_ALLOW_TOP_LEVEL_AWAIT  # notebooks `await` freely
_PYTHON, _MAYBE_PYTHON, _NOT_PYTHON = "python", "maybe", "skip"


@dataclass(frozen=True)
class Notebook:
    lines: tuple[str, ...]   # code cells only, each line where it sits in the .ipynb file
    tree: ast.Module | None  # None: not a notebook this reader understands
    partial: bool            # some of its code could not be read

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


UNREAD = Notebook((), None, True)


def read_notebook(raw: str) -> Notebook:
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError):  # not JSON, or nested absurdly deep
        return UNREAD
    cells = document.get("cells") if isinstance(document, dict) else None
    if not isinstance(cells, list):  # nbformat 3 keeps cells elsewhere
        return UNREAD

    raw_lines = split_lines(raw)
    virtual = [""] * len(raw_lines)
    body: list[ast.stmt] = []
    partial = False
    cursor = 0
    code_lines = 0
    lost = False  # the layout stopped matching; nothing after this can be placed
    for cell in cells:
        if not isinstance(cell, dict):
            partial = True
            continue
        is_code = cell.get("cell_type") == "code"
        lines = _source_lines(cell.get("source"))
        position = None if lost or lines is None else _locate(raw_lines, lines, cursor)
        if position is None:
            # One failed search is the limit: looking again for every later
            # cell would make a hostile notebook quadratic.
            lost = lost or lines is not None
            partial = partial or (is_code and _has_text(cell.get("source")))
            continue
        start, cursor = position
        code = [line.rstrip("\r\n") for line in lines] if is_code else []
        policy = _cell_policy(code)
        if policy == _NOT_PYTHON or not any(line.strip() for line in code):
            continue
        code_lines += len(code)
        if code_lines > MAX_CODE_LINES:
            partial = True
            break
        virtual[start:start + len(code)] = code
        tree, clean = _parse(code)
        if tree is None:
            partial = partial or policy == _PYTHON
            continue
        partial = partial or not clean
        ast.increment_lineno(tree, start)  # cell line 1 is file line start + 1
        body.extend(tree.body)
    return Notebook(tuple(virtual), ast.Module(body=body, type_ignores=[]), partial)


def _source_lines(source) -> list[str] | None:
    """A cell's source as one string per line, or None if it cannot be placed."""
    if source is None or source == "":
        return []
    if not isinstance(source, list) or not all(isinstance(line, str) for line in source):
        return None  # one long string (or something else): no line per source line
    if any("\n" in line.rstrip("\r\n") for line in source):
        return None
    return source


def _has_text(source) -> bool:
    if isinstance(source, str):
        return bool(source.strip())
    return isinstance(source, list) and any(str(line).strip() for line in source)


def _locate(raw_lines: list[str], lines: list[str], cursor: int) -> tuple[int, int] | None:
    """(index of the cell's first source line, index after its last), searching
    forward from `cursor` for the `"source": [` block that holds exactly these lines."""
    wanted = [{json.dumps(line, ensure_ascii=False), json.dumps(line)} for line in lines]
    for index in range(cursor, len(raw_lines)):
        stripped = raw_lines[index].strip()
        if not lines:
            if stripped.rstrip(",") == _SOURCE_EMPTY:
                return index, index + 1
            continue
        if stripped != _SOURCE_OPEN:
            continue
        first = index + 1
        if first + len(lines) <= len(raw_lines) and all(
            raw_lines[first + offset].strip().rstrip(",") in wanted[offset]
            for offset in range(len(lines))
        ):
            return first, first + len(lines)
    return None


def _cell_policy(code: list[str]) -> str:
    """Is this cell Python? Decided by its cell magic, if it starts with one."""
    first = next((line.strip() for line in code if line.strip()), "")
    if not first.startswith("%%"):
        return _PYTHON
    words = first[2:].split()
    name = words[0] if words else ""
    if name in _NON_PYTHON_CELL_MAGICS:
        return _NOT_PYTHON
    if name == "script":
        interpreter = words[1].rsplit("/", 1)[-1] if len(words) > 1 else ""
        return _PYTHON if interpreter.startswith(("python", "pypy")) else _NOT_PYTHON
    if name in _TEXT_FILE_MAGICS:
        return _PYTHON if words[-1].endswith(".py") else _MAYBE_PYTHON
    return _PYTHON


def _parse(code: list[str]) -> tuple[ast.Module | None, bool]:
    """(tree, clean) for one cell.

    The cell is tried exactly as written first. Only if that fails are the lines
    that look like IPython magics, shell escapes or help requests replaced by
    `pass` — and then every replaced line must come back as a `pass` STATEMENT.
    One that does not was inside a string or a bracket: the rewrite changed what
    the code means, possibly swallowing an import, so the result is not clean.
    """
    tree = _compile(code)
    if tree is not None:
        return tree, True
    rewritten = [_neutralised(line) for line in code]
    changed = {
        n for n, (old, new) in enumerate(zip(code, rewritten, strict=True), start=1) if old != new
    }
    if not changed:
        return None, False
    tree = _compile(rewritten)
    if tree is None:
        return None, False
    statements = {node.lineno for node in ast.walk(tree) if isinstance(node, ast.Pass)}
    return tree, changed <= statements


def _compile(code: list[str]) -> ast.Module | None:
    try:
        return compile("\n".join(code) + "\n", "<cell>", "exec", _COMPILE_FLAGS, True)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # MemoryError is how the parser reports an expression too deep for it.
        return None


def _neutralised(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith(("%", "!")) or _HELP_RE.fullmatch(stripped):
        return line[: len(line) - len(line.lstrip())] + "pass"
    return line
