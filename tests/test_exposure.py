from langdoctor.checks.exposure import checkpoint_from_user_input, langflow_autologin
from langdoctor.scanner import scan


def _write(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan(tmp_path)


LD203_VULN = """\
from fastapi import FastAPI

app = FastAPI()


@app.get("/history")
def history(thread_id: str):
    return graph.get_state_history(thread_id)
"""

LD203_CLEAN = """\
from fastapi import FastAPI

app = FastAPI()


@app.get("/history")
def history(thread_id: str):
    validated = lookup(thread_id)
    return graph.get_state_history(validated_config)
"""


def test_ld203_user_input_flows_to_get_state_history(tmp_path):
    project = _write(tmp_path, {"api.py": LD203_VULN})
    findings = checkpoint_from_user_input(project)
    assert [f.id for f in findings] == ["LD203"]
    assert findings[0].heuristic is True
    assert findings[0].severity == "high"


def test_ld203_clean_when_arg_not_a_handler_param(tmp_path):
    project = _write(tmp_path, {"api.py": LD203_CLEAN})
    assert checkpoint_from_user_input(project) == []


def test_ld203_no_finding_without_web_framework(tmp_path):
    project = _write(tmp_path, {
        "api.py": "def history(thread_id):\n    return graph.get_state_history(thread_id)\n",
    })
    assert checkpoint_from_user_input(project) == []


def test_ld403_langflow_autologin_not_disabled(tmp_path):
    project = _write(tmp_path, {"requirements.txt": "langflow==1.10.1\n"})
    findings = langflow_autologin(project)
    assert [f.id for f in findings] == ["LD403"]
    assert findings[0].severity == "critical"


def test_ld403_clean_when_disabled_in_env(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langflow==1.10.1\n",
        ".env": "LANGFLOW_AUTO_LOGIN=false\n",
    })
    assert langflow_autologin(project) == []


def test_ld403_clean_when_disabled_in_compose(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langflow==1.10.1\n",
        "docker-compose.yml": (
            "services:\n  langflow:\n    environment:\n"
            "      LANGFLOW_AUTO_LOGIN: 'false'\n"
        ),
    })
    assert langflow_autologin(project) == []


def test_ld403_no_finding_without_langflow(tmp_path):
    project = _write(tmp_path, {"requirements.txt": "langgraph==1.2.7\n"})
    assert langflow_autologin(project) == []


def test_ld403_fires_for_a_langflow_container_image(tmp_path):
    project = _write(tmp_path, {
        "docker-compose.yml": "services:\n  lf:\n    image: langflowai/langflow:1.13.3\n",
    })
    assert [f.id for f in langflow_autologin(project)] == ["LD403"]


def test_ld403_clean_for_an_image_with_auto_login_disabled(tmp_path):
    project = _write(tmp_path, {
        "docker-compose.yml": (
            "services:\n"
            "  lf:\n"
            "    image: langflowai/langflow:1.13.3\n"
            "    environment:\n"
            "      - LANGFLOW_AUTO_LOGIN=false\n"
        ),
    })
    assert langflow_autologin(project) == []


def test_ld403_points_at_where_langflow_comes_from(tmp_path):
    project = _write(tmp_path, {
        "deploy/docker-compose.yml": "services:\n  lf:\n    image: langflowai/langflow:1.13.3\n",
    })
    finding = langflow_autologin(project)[0]
    assert (finding.file, finding.line) == ("deploy/docker-compose.yml", 3)


def test_ld403_has_no_location_when_langflow_is_only_imported(tmp_path):
    project = _write(tmp_path, {"flow.py": "import langflow\n"})
    finding = langflow_autologin(project)[0]
    assert (finding.file, finding.line) == (None, None)


def test_ld403_prefers_the_image_then_the_shallowest_manifest(tmp_path):
    project = _write(tmp_path, {
        "docs/requirements.txt": "langflow==1.13.3\n",
        "deploy/prod/docker-compose.yml": (
            "services:\n  lf:\n    image: langflowai/langflow:1.13.3\n"
        ),
    })
    assert langflow_autologin(project)[0].file == "deploy/prod/docker-compose.yml"

    project = _write(tmp_path / "second", {
        "a/b/requirements.txt": "langflow==1.13.3\n",
        "requirements.txt": "langflow==1.13.3\n",
    })
    assert langflow_autologin(project)[0].file == "requirements.txt"
