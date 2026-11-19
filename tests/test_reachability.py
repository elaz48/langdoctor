"""Reachability: is an advisory's vulnerable API imported anywhere in the project?

The verdict is a fact about imports, never a conclusion about exposure, and a
wrong "not imported" is the dangerous direction — so the matcher only has to be
complete for what it claims to see: static imports and module-attribute access.
"""

import json
from dataclasses import replace
from io import StringIO

from langdoctor.advisories import load_db
from langdoctor.checks.versions import check_versions
from langdoctor.engine import run_scan
from langdoctor.reachability import assess
from langdoctor.scanner import scan

EVERNOTE = "langchain_community.document_loaders:EverNoteLoader"


def _project(tmp_path, files):
    for name, content in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return scan(tmp_path)


def _uses(tmp_path, code, *symbols):
    result = assess(_project(tmp_path, {"app.py": code}), symbols)
    return [(use.line, use.symbol) for use in result.uses]


def test_import_from_the_declared_module(tmp_path):
    code = "from langchain_community.document_loaders import EverNoteLoader\n"
    assert _uses(tmp_path, code, EVERNOTE) == [(1, EVERNOTE)]


def test_import_from_a_submodule_and_under_an_alias(tmp_path):
    code = (
        "import os\n"
        "from langchain_community.document_loaders.evernote import EverNoteLoader as Notes\n"
    )
    assert _uses(tmp_path, code, EVERNOTE) == [(2, EVERNOTE)]


def test_a_parent_module_is_not_the_declared_module(tmp_path):
    # `from langchain_core import load` imports the MODULE named load, not the
    # function langchain_core.load.load.
    code = "from langchain_core import load\nload.dumps({})\n"
    assert _uses(tmp_path, code, "langchain_core.load:load") == []


def test_attribute_access_through_an_imported_module(tmp_path):
    code = (
        "from langchain_core import load\n"
        "import langchain_core.load\n"
        "import langgraph.checkpoint.sqlite as sq\n"
        "a = load.loads(text)\n"
        "b = langchain_core.load.loads(text)\n"
        "c = sq.SqliteSaver(conn)\n"
    )
    assert _uses(tmp_path, code, "langchain_core.load:loads") == [
        (4, "langchain_core.load:loads"), (5, "langchain_core.load:loads"),
    ]
    assert _uses(tmp_path, code, "langgraph.checkpoint.sqlite:SqliteSaver") == [
        (6, "langgraph.checkpoint.sqlite:SqliteSaver"),
    ]


def test_module_symbols_match_any_import_of_the_module(tmp_path):
    code = (
        "from langgraph.store.sqlite import SqliteStore\n"
        "from langgraph.store import sqlite\n"
        "import langgraph.store.sqlite.aio\n"
        "import langgraph.store.memory\n"
        "from langgraph.store.base import BaseStore\n"
    )
    assert [line for line, _ in _uses(tmp_path, code, "langgraph.store.sqlite")] == [1, 2, 3]


def test_star_import_from_the_module_counts(tmp_path):
    code = "from langchain_community.document_loaders import *\n"
    assert _uses(tmp_path, code, EVERNOTE) == [(1, EVERNOTE)]


def test_same_name_elsewhere_is_not_a_use(tmp_path):
    code = (
        "from mylib.loaders import EverNoteLoader\n"
        "from langchain_community.vectorstores import EverNoteLoader\n"
        "from .document_loaders import EverNoteLoader\n"
        "from langchain_core.utils.json import loads\n"
        "# from langchain_community.document_loaders import EverNoteLoader\n"
        "text = 'from langchain_community.document_loaders import EverNoteLoader'\n"
    )
    assert _uses(tmp_path, code, EVERNOTE, "langchain_core.load:loads") == []


def test_not_imported_reports_how_much_was_searched(tmp_path):
    project = _project(tmp_path, {
        "app.py": "import os\n",
        "pkg/util.py": "x = 1\n",
        "broken.py": "def (:\n",
    })
    result = assess(project, (EVERNOTE,))
    assert (result.files_searched, result.files_unparsed) == (2, 1)
    assert result.symbols == (EVERNOTE,)
    # the file that could not be read may be the one that imports it
    assert result.reachable is None

    (tmp_path / "broken.py").unlink()
    assert assess(scan(tmp_path), (EVERNOTE,)).reachable is False


def test_nothing_is_claimed_without_python_sources_or_without_symbols(tmp_path):
    project = _project(tmp_path, {"requirements.txt": "langchain-community==0.3.20\n"})
    assert assess(project, (EVERNOTE,)) is None
    project = _project(tmp_path, {"app.py": "import os\n"})
    assert assess(project, ()) is None


def test_uses_are_ordered_and_not_repeated(tmp_path):
    project = _project(tmp_path, {
        "b.py": "from langchain_community.document_loaders import EverNoteLoader\n",
        "a.py": (
            "import langchain_community.document_loaders as dl\n"
            "x = dl.EverNoteLoader('n.enex'); y = dl.EverNoteLoader('m.enex')\n"
        ),
    })
    result = assess(project, (EVERNOTE,))
    assert [(u.file, u.line) for u in result.uses] == [("a.py", 2), ("b.py", 1)]


# --- wired into findings ----------------------------------------------------

def _db_with_symbols(advisory_id, *symbols):
    db = load_db()
    advisories = tuple(
        replace(a, symbols=tuple(symbols)) if a.id == advisory_id else replace(a, symbols=())
        for a in db.advisories
    )
    return replace(db, advisories=advisories)


def test_a_version_finding_carries_the_import_evidence(tmp_path):
    project = _project(tmp_path, {
        "requirements.txt": "langchain-community==0.3.20\n",
        "ingest.py": "from langchain_community.document_loaders import EverNoteLoader\n",
    })
    findings = {f.id: f for f in check_versions(project, _db_with_symbols("LD126", EVERNOTE))}
    evidence = findings["LD126"].reachability
    assert evidence.reachable is True
    assert [(u.file, u.line) for u in evidence.uses] == [("ingest.py", 1)]
    # an advisory that lists no entry points makes no claim either way
    assert findings["LD127"].reachability is None


def test_a_version_finding_says_when_the_api_is_not_imported(tmp_path):
    project = _project(tmp_path, {
        "requirements.txt": "langchain-community==0.3.20\n",
        "app.py": "from langchain_community.document_loaders import TextLoader\n",
    })
    findings = {f.id: f for f in check_versions(project, _db_with_symbols("LD126", EVERNOTE))}
    assert findings["LD126"].reachability.reachable is False
    assert findings["LD126"].severity == "high"  # reported at full severity all the same


def test_reachability_never_changes_the_exit_code(tmp_path, monkeypatch):
    from langdoctor import cli

    _project(tmp_path, {
        "requirements.txt": "langchain-community==0.3.20\n",
        "app.py": "import os\n",
    })
    monkeypatch.setattr(
        "langdoctor.checks.versions.load_db", lambda: _db_with_symbols("LD126", EVERNOTE)
    )
    assert cli.main([str(tmp_path), "--format", "json", "--ignore", "LD501"]) == 1


def test_not_imported_findings_sort_below_the_rest_of_their_severity(tmp_path, monkeypatch):
    project = _project(tmp_path, {
        "requirements.txt": "langchain-community==0.3.20\n",
        "app.py": "import os\n",
    })
    monkeypatch.setattr(
        "langdoctor.checks.versions.load_db", lambda: _db_with_symbols("LD126", EVERNOTE)
    )
    high = [f.id for f in run_scan(project).findings if f.severity == "high"]
    assert high.index("LD126") == len(high) - 1 and len(high) > 1


# --- outputs ----------------------------------------------------------------

def _findings(tmp_path, code):
    project = _project(tmp_path, {
        "requirements.txt": "langchain-community==0.3.20\n",
        "ingest.py": code,
    })
    found = check_versions(project, _db_with_symbols("LD126", EVERNOTE))
    return [f for f in found if f.id == "LD126"]


USED = "from langchain_community.document_loaders import EverNoteLoader\n"


def test_console_shows_where_the_api_is_imported(tmp_path):
    from rich.console import Console

    from langdoctor.output.console import render

    for code, expected in (
        (USED, "used at ingest.py:1 (EverNoteLoader)"),
        ("import os\n", "not imported in 1 Python file: EverNoteLoader"),
    ):
        buffer = StringIO()
        render(_findings(tmp_path, code), "/p", "2026-01-01",
               console=Console(file=buffer, no_color=True, width=200))
        assert expected in buffer.getvalue()


def test_json_and_sarif_carry_the_evidence(tmp_path):
    from langdoctor.output.json_out import render_json
    from langdoctor.output.sarif import render_sarif

    used = _findings(tmp_path, USED)
    payload = json.loads(render_json(used, "/p", "2026-01-01", 0))["findings"][0]["reachability"]
    assert payload == {
        "reachable": True,
        "symbols": [EVERNOTE],
        "uses": [{"file": "ingest.py", "line": 1, "symbol": EVERNOTE}],
        "total_uses": 1,
        "files_searched": 1,
        "files_unparsed": 0,
    }
    result = json.loads(render_sarif(used, "/p", "2026-01-01", 0))["runs"][0]["results"][0]
    assert result["properties"]["reachable"] is True
    related = result["relatedLocations"][0]
    assert related["physicalLocation"]["artifactLocation"]["uri"] == "ingest.py"
    assert related["physicalLocation"]["region"]["startLine"] == 1

    unused = _findings(tmp_path, "import os\n")
    assert json.loads(render_json(unused, "/p", "2026-01-01", 0))["findings"][0][
        "reachability"]["reachable"] is False
    result = json.loads(render_sarif(unused, "/p", "2026-01-01", 0))["runs"][0]["results"][0]
    assert result["properties"]["reachable"] is False and "relatedLocations" not in result


def test_markdown_mentions_the_evidence(tmp_path):
    from langdoctor.output.markdown import render_markdown

    assert "used at ingest.py:1" in render_markdown(_findings(tmp_path, USED), "/p", "2026-01-01")
    assert "not imported" in render_markdown(
        _findings(tmp_path, "import os\n"), "/p", "2026-01-01"
    )


def test_findings_without_evidence_serialise_as_before(tmp_path):
    from langdoctor.output.json_out import render_json

    project = _project(tmp_path, {"requirements.txt": "langflow==1.2.0\n"})
    found = check_versions(project)
    payload = json.loads(render_json(found, "/p", "2026-01-01", 0))["findings"][0]
    assert payload["reachability"] is None


# --- the data ----------------------------------------------------------------

def test_every_symbol_in_the_database_is_well_formed_and_belongs_to_its_package():
    import re

    top_level = {
        "langchain-core": {"langchain_core"},
        "langchain": {"langchain"},
        # langchain / langchain_classic re-export the community loaders
        "langchain-community": {"langchain_community", "langchain", "langchain_classic"},
        "langgraph": {"langgraph"},
        "langgraph-sdk": {"langgraph_sdk"},
        "langgraph-checkpoint": {"langgraph"},
        "langgraph-checkpoint-sqlite": {"langgraph"},
        "langgraph-checkpoint-postgres": {"langgraph"},
    }
    spec = re.compile(r"[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*(:[A-Za-z_][A-Za-z0-9_]*)?")
    for advisory in load_db().advisories:
        for symbol in advisory.symbols:
            assert spec.fullmatch(symbol), (advisory.id, symbol)
            assert symbol.split(".")[0].split(":")[0] in top_level[advisory.package], (
                advisory.id, symbol,
            )


def test_curated_entry_points_fire_on_real_imports(tmp_path):
    cases = [
        # (pin, an import a project would write, the advisory it makes reachable)
        ("langchain-community==0.3.20",
         "from langchain_community.document_loaders import EverNoteLoader", "LD126"),
        ("langchain-community==0.3.20",
         "from langchain.document_loaders import EverNoteLoader", "LD126"),  # legacy shim
        ("langchain-community==0.3.20",
         "from langchain_classic.document_loaders import EverNoteLoader", "LD126"),
        ("langchain-community==0.3.20",
         "from langchain_community.document_loaders import DocusaurusLoader", "LD127"),
        ("langgraph-checkpoint-sqlite==2.0.10",
         "from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver", "LD101"),
        ("langgraph-checkpoint-sqlite==2.0.10",
         "from langgraph.store.sqlite import AsyncSqliteStore", "LD110"),
        ("langgraph-checkpoint==3.0.1",
         "from langgraph.cache.memory import InMemoryCache", "LD107"),
        ("langgraph-sdk==0.4.3", "from langgraph_sdk import Auth", "LD132"),
    ]
    for index, (pin, code, advisory_id) in enumerate(cases):
        project = _project(tmp_path / str(index), {"requirements.txt": pin + "\n", "app.py": code})
        findings = {f.id: f for f in check_versions(project)}
        assert findings[advisory_id].reachability.reachable is True, (advisory_id, code)


def test_advisories_reached_through_defaults_make_no_claim(tmp_path):
    # LD105's vulnerable serialization runs inside astream_log() and
    # RunnableWithMessageHistory; LD119's store is instantiated by the hosting
    # platform. No import list would be complete, so none is given.
    project = _project(tmp_path, {
        "requirements.txt": "langchain-core==1.2.0\nlanggraph-checkpoint-postgres==3.1.0\n",
        "app.py": "import os\n",
    })
    findings = {f.id: f for f in check_versions(project)}
    assert findings["LD105"].reachability is None
    assert findings["LD119"].reachability is None


def test_an_absurdly_long_attribute_chain_is_not_resolved(tmp_path):
    code = "import pkg\nx = pkg" + ".a" * 40 + ".Name\ny = pkg.mod.Name\n"
    assert _uses(tmp_path, code, "pkg.a:Name") == []  # line 2 would match if resolved
    assert _uses(tmp_path, code, "pkg.mod:Name") == [(3, "pkg.mod:Name")]


def test_a_name_bound_by_two_imports_stands_for_both(tmp_path):
    # One flat name -> path table would let the later import hide the earlier.
    code = (
        "import langgraph.checkpoint.sqlite as s\n"
        "import os.path as s\n"
        "saver = s.SqliteSaver(conn)\n"
    )
    assert _uses(tmp_path, code, "langgraph.checkpoint.sqlite:SqliteSaver") == [
        (3, "langgraph.checkpoint.sqlite:SqliteSaver"),
    ]
    code = (
        "def f():\n"
        "    from langgraph.checkpoint import sqlite as s\n"
        "    return s.SqliteSaver(conn)\n"
        "def g():\n"
        "    import json as s\n"
    )
    saver = "langgraph.checkpoint.sqlite:SqliteSaver"
    assert [line for line, _ in _uses(tmp_path, code, saver)] == [3]


def test_notebooks_are_code_that_was_not_read(tmp_path):
    project = _project(tmp_path, {
        "app.py": "import os\n",
        "explore.ipynb": '{"cells": []}',
        "docs/demo.ipynb": '{"cells": []}',
    })
    result = assess(project, (EVERNOTE,))
    assert (result.files_searched, result.files_unparsed, result.reachable) == (1, 2, None)


def test_an_inconclusive_search_says_so_and_does_not_demote(tmp_path, monkeypatch):
    from rich.console import Console

    from langdoctor.output.console import render

    project = _project(tmp_path, {
        "requirements.txt": "langchain-community==0.3.20\n",
        "app.py": "import os\n",
        "legacy.py": (
            "from langchain_community.document_loaders import EverNoteLoader\nprint 'py2'\n"
        ),
    })
    monkeypatch.setattr(
        "langdoctor.checks.versions.load_db", lambda: _db_with_symbols("LD126", EVERNOTE)
    )
    findings = run_scan(project).findings
    high = [f.id for f in findings if f.severity == "high"]
    assert high == sorted(high)  # LD126 keeps its place by id; it is not pushed last

    buffer = StringIO()
    render([f for f in findings if f.id == "LD126"], "/p", "2026-01-01",
           console=Console(file=buffer, no_color=True, width=200))
    out = buffer.getvalue()
    assert "no import found in 1 Python file, but 1 more could not be read: EverNoteLoader" in out
    assert "not imported" not in out


def test_the_count_of_uses_survives_the_cap(tmp_path):
    from langdoctor.output import describe_reachability

    code = "import langchain_community.document_loaders as dl\n" + "".join(
        f"x{i} = dl.EverNoteLoader('n')\n" for i in range(40)
    )
    result = assess(_project(tmp_path, {"app.py": code}), (EVERNOTE,))
    assert (len(result.uses), result.total_uses) == (25, 40)
    assert describe_reachability(result) == "used at app.py:2 (EverNoteLoader, +39 more)"


def test_a_file_too_deeply_nested_to_parse_is_just_unread(tmp_path):
    project = _project(tmp_path, {
        "app.py": "import os\n",
        "hostile.py": "x = langgraph" + ".a" * 100_000 + "\n",
    })
    result = assess(project, (EVERNOTE,))
    assert (result.files_searched, result.files_unparsed) == (1, 1)
