from langdoctor.checks.checkpointer import (
    memory_saver_in_prod,
    missing_checkpointer_with_interrupts,
    sqlite_saver_concurrency,
)
from langdoctor.scanner import scan


def _write(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan(tmp_path)


def test_ld201_memory_saver_in_prod(tmp_path):
    project = _write(tmp_path, {
        "Dockerfile": "FROM python:3.12\n",
        "app.py": "from langgraph.checkpoint.memory import MemorySaver\nsaver = MemorySaver()\n",
    })
    findings = memory_saver_in_prod(project)
    assert [f.id for f in findings] == ["LD201"]
    assert findings[0].line == 2


def test_ld201_no_finding_without_prod_signals(tmp_path):
    project = _write(tmp_path, {
        "app.py": "from langgraph.checkpoint.memory import MemorySaver\nsaver = MemorySaver()\n",
    })
    assert memory_saver_in_prod(project) == []


def test_ld201_detects_k8s_manifest(tmp_path):
    project = _write(tmp_path, {
        "deploy/app.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
        "app.py": "from langgraph.checkpoint.memory import MemorySaver\nMemorySaver()\n",
    })
    assert [f.id for f in memory_saver_in_prod(project)] == ["LD201"]


def test_ld202_sqlite_saver(tmp_path):
    project = _write(tmp_path, {
        "app.py": "from langgraph.checkpoint.sqlite import SqliteSaver\ns = SqliteSaver(conn)\n",
    })
    findings = sqlite_saver_concurrency(project)
    assert [f.id for f in findings] == ["LD202"]
    assert findings[0].severity == "medium"


def test_ld202_clean(tmp_path):
    project = _write(tmp_path, {
        "app.py": (
            "from langgraph.checkpoint.postgres import PostgresSaver\n"
            "s = PostgresSaver(conn)\n"
        ),
    })
    assert sqlite_saver_concurrency(project) == []


def test_ld204_interrupts_without_checkpointer(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langgraph==1.2.7\n",
        "graph.py": "g = builder.compile(interrupt_before=['human'])\n",
    })
    findings = missing_checkpointer_with_interrupts(project)
    assert [f.id for f in findings] == ["LD204"]


def test_ld204_clean_when_checkpointer_passed(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langgraph==1.2.7\n",
        "graph.py": "g = builder.compile(interrupt_before=['human'], checkpointer=saver)\n",
    })
    assert missing_checkpointer_with_interrupts(project) == []


def test_ld204_clean_without_interrupts(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langgraph==1.2.7\n",
        "graph.py": "g = builder.compile()\n",
    })
    assert missing_checkpointer_with_interrupts(project) == []
