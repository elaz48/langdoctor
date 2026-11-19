"""Jupyter notebooks as Python sources.

A notebook is where a lot of LangChain code lives. Two things read it: the
hardcoded-secret check and the reachability search. The production-readiness
checks do not — a notebook is not deployed code.
"""

import json

from langdoctor.checks.checkpointer import memory_saver_in_prod
from langdoctor.checks.secrets import hardcoded_secrets
from langdoctor.engine import run_scan
from langdoctor.notebooks import read_notebook
from langdoctor.reachability import assess
from langdoctor.scanner import scan

EVERNOTE = "langchain_community.document_loaders:EverNoteLoader"
FAKE_KEY = "sk-proj-EXAMPLE-NOT-A-REAL-KEY-000000"


def _cell(kind, *lines):
    source = [line + "\n" for line in lines[:-1]] + list(lines[-1:])
    cell = {"cell_type": kind, "metadata": {}, "source": source}
    if kind == "code":
        cell.update(execution_count=None, outputs=[])
    return cell


def _notebook(*cells, **dumps_options):
    document = {"cells": list(cells), "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    options = {"indent": 1, "sort_keys": True, "ensure_ascii": False, **dumps_options}
    return json.dumps(document, **options) + "\n"


def _write(tmp_path, files):
    for name, content in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return scan(tmp_path)


def _line_of(text, needle):
    return next(i for i, line in enumerate(text.splitlines(), start=1) if needle in line)


def test_code_keeps_the_line_numbers_of_the_ipynb_file():
    raw = _notebook(
        _cell("markdown", "# Title", "import nothing_here"),
        _cell("code", "import os", "from langgraph.graph import StateGraph"),
        _cell("code", "graph = StateGraph(dict)"),
    )
    notebook = read_notebook(raw)
    assert notebook.partial is False
    names = {node.lineno: type(node).__name__ for node in notebook.tree.body}
    assert names == {
        _line_of(raw, '"import os'): "Import",
        _line_of(raw, "from langgraph.graph"): "ImportFrom",
        _line_of(raw, "graph = StateGraph"): "Assign",
    }
    # the virtual text holds code only, on the same lines
    lines = notebook.text.splitlines()
    assert lines[_line_of(raw, "graph = StateGraph") - 1] == "graph = StateGraph(dict)"
    assert "nothing_here" not in notebook.text and "Title" not in notebook.text


def test_magics_shell_lines_help_and_top_level_await_do_not_break_a_cell():
    raw = _notebook(
        _cell("code", "%pip install -q langgraph", "!ls -la", "import os  # needed?", "os?"),
        _cell("code", "%%time", "result = await graph.ainvoke({})"),
        _cell("code", "%%bash", "echo from langgraph import nothing"),
        _cell("code", "if True:", "    %matplotlib inline", "    x = 1"),
    )
    notebook = read_notebook(raw)
    assert notebook.partial is False
    kinds = [type(node).__name__ for node in notebook.tree.body]
    assert kinds.count("Import") == 1 and "If" in kinds and "Assign" in kinds
    assert "echo" not in notebook.text  # a %%bash cell is not Python


def test_one_broken_cell_leaves_the_others_readable_but_marks_the_notebook():
    raw = _notebook(
        _cell("code", "def (:"),
        _cell("code", "from langchain_community.document_loaders import EverNoteLoader"),
    )
    notebook = read_notebook(raw)
    assert notebook.partial is True
    assert [type(node).__name__ for node in notebook.tree.body] == ["ImportFrom"]


def test_a_notebook_that_cannot_be_laid_out_is_unread():
    code = _cell("code", "import os", "x = 1")
    for raw in (
        _notebook(code, indent=None),                      # minified: no line per source line
        "{ not json",
        json.dumps({"worksheets": []}),                    # nbformat 3
        "[" * 100_000,                                     # absurdly nested
        _notebook({**code, "source": "import os\nx = 1"}),  # one string holding two lines
    ):
        notebook = read_notebook(raw)
        assert notebook.partial is True and not getattr(notebook.tree, "body", None), raw[:40]


def test_an_empty_or_code_free_notebook_is_fully_read():
    for raw in (_notebook(), _notebook(_cell("markdown", "notes")), _notebook(_cell("code", ""))):
        notebook = read_notebook(raw)
        assert notebook.partial is False and notebook.tree.body == []


def test_a_secret_in_a_notebook_is_reported_on_its_real_line(tmp_path):
    raw = _notebook(
        _cell("markdown", "setup"),
        _cell("code", "import os", f'OPENAI_API_KEY = "{FAKE_KEY}"'),
    )
    project = _write(tmp_path, {"explore.ipynb": raw})
    findings = hardcoded_secrets(project)
    assert [(f.id, f.file, f.line) for f in findings] == [
        ("LD401", "explore.ipynb", _line_of(raw, FAKE_KEY)),
    ]


def test_an_inline_ignore_comment_inside_a_cell_suppresses(tmp_path):
    raw = _notebook(_cell("code", f'KEY = "{FAKE_KEY}"  # langdoctor: ignore=LD401'))
    result = run_scan(_write(tmp_path, {"explore.ipynb": raw}))
    assert [f.id for f in result.findings] == [] and result.suppressed == 1


def test_reachability_reads_notebooks(tmp_path):
    raw = _notebook(
        _cell("code", "%pip install langchain-community"),
        _cell("code", "from langchain_community.document_loaders import EverNoteLoader"),
    )
    project = _write(tmp_path, {"app.py": "import os\n", "notebooks/ingest.ipynb": raw})
    result = assess(project, (EVERNOTE,))
    assert result.reachable is True and result.files_searched == 2
    assert [(use.file, use.line) for use in result.uses] == [
        ("notebooks/ingest.ipynb", _line_of(raw, "EverNoteLoader")),
    ]


def test_reachability_is_conclusive_only_when_every_notebook_was_read(tmp_path):
    readable = _notebook(_cell("code", "import os"))
    project = _write(tmp_path / "a", {"app.py": "import os\n", "ok.ipynb": readable})
    result = assess(project, (EVERNOTE,))
    assert (result.reachable, result.files_searched, result.files_unparsed) == (False, 2, 0)

    project = _write(tmp_path / "b", {
        "app.py": "import os\n",
        "ok.ipynb": readable,
        "half.ipynb": _notebook(_cell("code", "def (:"), _cell("code", "import os")),
        "minified.ipynb": _notebook(_cell("code", "import os"), indent=None),
    })
    result = assess(project, (EVERNOTE,))
    assert (result.reachable, result.files_unparsed) == (None, 2)


def test_production_checks_do_not_read_notebooks(tmp_path):
    raw = _notebook(_cell(
        "code", "from langgraph.checkpoint.memory import MemorySaver", "saver = MemorySaver()",
    ))
    project = _write(tmp_path, {"Dockerfile": "FROM python:3.12\n", "demo.ipynb": raw})
    assert memory_saver_in_prod(project) == []
    assert [f.id for f in run_scan(project).findings] == []


def test_jupyter_checkpoint_copies_are_skipped(tmp_path):
    raw = _notebook(_cell("code", f'KEY = "{FAKE_KEY}"'))
    project = _write(tmp_path, {
        "explore.ipynb": raw,
        ".ipynb_checkpoints/explore-checkpoint.ipynb": raw,
    })
    assert [f.file for f in hardcoded_secrets(project)] == ["explore.ipynb"]


def test_an_oversized_notebook_is_not_loaded(tmp_path, monkeypatch):
    import langdoctor.analysis as analysis

    raw = _notebook(_cell(
        "code", "from langchain_community.document_loaders import EverNoteLoader",
    ))
    project = _write(tmp_path, {"app.py": "import os\n", "big.ipynb": raw})
    monkeypatch.setattr(analysis, "MAX_NOTEBOOK_BYTES", 10)
    result = assess(project, (EVERNOTE,))
    assert (result.reachable, result.files_unparsed) == (None, 1)


IMPORT = "from langchain_community.document_loaders import EverNoteLoader"


def _reachable(tmp_path, *cells):
    project = _write(tmp_path, {"n.ipynb": _notebook(*cells)})
    return assess(project, (EVERNOTE,)).reachable


def test_a_magic_looking_line_inside_a_string_cannot_hide_an_import(tmp_path):
    # Valid Python as it stands: the "%" line is inside the string, the import after it.
    plain = _cell("code", 'x = """', f'%"""; {IMPORT}; q = """', '"""')
    assert _reachable(tmp_path / "a", plain) is True

    # With a real magic in the same cell the lines have to be rewritten. The
    # rewrite would swallow the import into the string — that must be noticed,
    # and the answer becomes "unknown", never "not imported".
    mixed = _cell("code", "%pip install x", 'x = """', f'%"""; {IMPORT}; q = """', '"""')
    notebook = read_notebook(_notebook(mixed))
    assert notebook.partial is True
    assert _reachable(tmp_path / "b", mixed) is None


def test_cell_magics_whose_body_is_python_are_read(tmp_path):
    for index, magic in enumerate((
        "%%python", "%%python3", "%%script python3", "%%capture out", "%%time -n 1",
        "%%some_unknown_magic", "%%writefile agent.py",
    )):
        cell = _cell("code", magic, IMPORT)
        assert _reachable(tmp_path / str(index), cell) is True, magic


def test_cell_magics_that_are_not_python_are_left_alone(tmp_path):
    for index, (magic, body) in enumerate((
        ("%%bash", "pip install langchain-community && echo done"),
        ("%%html", "<b>from here import nothing</b>"),
        ("%%sql", "SELECT * FROM runs WHERE id = 1"),
        ("%%script bash", "echo hi; ls | wc -l"),
        ("%%writefile notes.txt", "to do: fix the loader, then (maybe ship"),
    )):
        notebook = read_notebook(_notebook(_cell("code", magic, body)))
        assert (notebook.partial, notebook.tree.body) == (False, []), magic
        assert _reachable(tmp_path / str(index), _cell("code", magic, body)) is False, magic


def test_an_unknown_magic_with_a_body_that_does_not_parse_is_unknown(tmp_path):
    for index, cell in enumerate((
        _cell("code", "%%some_unknown_magic", "this is ) not python"),
        _cell("code", "%%writefile agent.py", "def (:"),
    )):
        assert read_notebook(_notebook(cell)).partial is True
        assert _reachable(tmp_path / str(index), cell) is None


def test_line_numbers_follow_newlines_only():
    # Jupyter writes non-ASCII raw. str.splitlines() would also break on these
    # separators and shift every later line.
    odd = _cell("code", "print('a\u2028b\x0cc\x85d')")
    odd["outputs"] = [{"name": "stdout", "output_type": "stream", "text": ["a\u2028b\u2029c\n"]}]
    raw = _notebook(odd, _cell("code", "import os"))
    notebook = read_notebook(raw)
    assert notebook.partial is False
    lines = raw.split("\n")
    assert [type(node).__name__ for node in notebook.tree.body] == ["Expr", "Import"]
    first, last = notebook.tree.body
    assert lines[first.lineno - 1].strip().startswith('"print(')
    assert lines[last.lineno - 1].strip() == '"import os"'
    assert notebook.lines[last.lineno - 1] == "import os"


def test_a_key_after_an_odd_separator_is_reported_on_its_own_line(tmp_path):
    raw = _notebook(
        _cell("code", "note = 'a\u2028b'"),
        _cell("code", f'KEY = "{FAKE_KEY}"  # langdoctor: ignore=LD401'),
        _cell("code", f'OTHER = "{FAKE_KEY}"'),
    )
    project = _write(tmp_path, {"n.ipynb": raw})
    result = run_scan(project)
    lines = raw.split("\n")
    assert [lines[f.line - 1].strip().startswith('"OTHER') for f in result.findings] == [True]
    assert result.suppressed == 1


def test_a_cell_the_parser_gives_up_on_is_unread_not_a_crash(tmp_path):
    hostile = _cell("code", "x = " + "-" * 900_000 + "1")
    assert read_notebook(_notebook(hostile, _cell("code", "import os"))).partial is True

    # A crash here used to be swallowed per check, which silently removed
    # every hardcoded-key finding of the project.
    project = _write(tmp_path, {
        "a.py": f'KEY = "{FAKE_KEY}"\n',
        "big.py": "x = " + "-" * 900_000 + "1\n",
        "n.ipynb": _notebook(hostile),
    })
    assert [f.file for f in hardcoded_secrets(project)] == ["a.py"]
    result = assess(project, (EVERNOTE,))
    assert (result.reachable, result.files_unparsed) == (None, 2)


def test_code_beyond_the_line_limit_is_not_read(monkeypatch):
    import langdoctor.notebooks as notebooks

    monkeypatch.setattr(notebooks, "MAX_CODE_LINES", 3)
    raw = _notebook(_cell("code", "a = 1", "b = 2"), _cell("code", "c = 3", "d = 4"))
    notebook = read_notebook(raw)
    assert notebook.partial is True
    assert len(notebook.tree.body) == 2
