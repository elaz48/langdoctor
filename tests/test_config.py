from langdoctor.checks.config import (
    deprecated_imports,
    load_prompt_usage,
    no_llm_timeout,
    no_recursion_limit,
)
from langdoctor.scanner import scan


def _write(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan(tmp_path)


def test_ld301_no_recursion_limit(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langgraph==1.2.7\n",
        "run.py": "from langgraph.graph import StateGraph\nresult = app.invoke({'x': 1})\n",
    })
    assert [f.id for f in no_recursion_limit(project)] == ["LD301"]


def test_ld301_clean_when_limit_present(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langgraph==1.2.7\n",
        "run.py": "app.invoke({'x': 1}, config={'recursion_limit': 25})\n",
    })
    assert no_recursion_limit(project) == []


def test_ld301_no_finding_without_langgraph(tmp_path):
    project = _write(tmp_path, {"run.py": "app.invoke({'x': 1})\n"})
    assert no_recursion_limit(project) == []


def test_ld302_llm_without_timeout_is_heuristic(tmp_path):
    project = _write(tmp_path, {
        "llm.py": "from langchain_openai import ChatOpenAI\nm = ChatOpenAI(model='gpt-4o')\n",
    })
    findings = no_llm_timeout(project)
    assert [f.id for f in findings] == ["LD302"]
    assert findings[0].heuristic is True
    assert findings[0].severity == "low"


def test_ld302_clean_with_timeout(tmp_path):
    project = _write(tmp_path, {
        "llm.py": "from langchain_openai import ChatOpenAI\nm = ChatOpenAI(timeout=30)\n",
    })
    assert no_llm_timeout(project) == []


def test_ld303_deprecated_import(tmp_path):
    project = _write(tmp_path, {
        "agent.py": "from langchain.agents import AgentExecutor\n",
    })
    findings = deprecated_imports(project)
    assert [f.id for f in findings] == ["LD303"]
    assert findings[0].severity == "info"
    assert findings[0].line == 1


def test_ld303_clean_modern_import(tmp_path):
    project = _write(tmp_path, {"agent.py": "from langgraph.prebuilt import create_react_agent\n"})
    assert deprecated_imports(project) == []


def test_ld304_load_prompt(tmp_path):
    project = _write(tmp_path, {
        "prompts.py": "from langchain_core.prompts import load_prompt\np = load_prompt('x.yaml')\n",
    })
    findings = load_prompt_usage(project)
    assert [f.id for f in findings] == ["LD304"]
    assert findings[0].severity == "high"
    assert findings[0].cve == "CVE-2026-34070"


def test_ld304_clean(tmp_path):
    project = _write(tmp_path, {
        "prompts.py": "from langchain_core.prompts import ChatPromptTemplate\n",
    })
    assert load_prompt_usage(project) == []
