from langdoctor.checks.hygiene import unpinned_dependencies, unpinned_github_actions
from langdoctor.scanner import scan


def _write(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan(tmp_path)


def test_ld501_unpinned_without_lockfile(tmp_path):
    project = _write(tmp_path, {"requirements.txt": "langgraph>=1.0\nrich\n"})
    findings = unpinned_dependencies(project)
    assert [f.id for f in findings] == ["LD501"]
    assert findings[0].severity == "medium"


def test_ld501_clean_when_all_pinned(tmp_path):
    project = _write(tmp_path, {"requirements.txt": "langgraph==1.2.7\nrich==13.9.0\n"})
    assert unpinned_dependencies(project) == []


def test_ld501_clean_with_lockfile(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langgraph>=1.0\n",
        "uv.lock": '[[package]]\nname = "langgraph"\nversion = "1.2.7"\n',
    })
    assert unpinned_dependencies(project) == []


def test_ld502_unpinned_action(tmp_path):
    project = _write(tmp_path, {
        ".github/workflows/ci.yml": (
            "jobs:\n  x:\n    steps:\n      - uses: tj-actions/changed-files@v44\n"
        ),
    })
    findings = unpinned_github_actions(project)
    assert [f.id for f in findings] == ["LD502"]
    assert "tj-actions" in findings[0].detail


def test_ld502_clean_when_sha_pinned(tmp_path):
    sha = "a" * 40
    project = _write(tmp_path, {
        ".github/workflows/ci.yml": f"steps:\n  - uses: tj-actions/changed-files@{sha}\n",
    })
    assert unpinned_github_actions(project) == []


def test_ld502_ignores_first_party_actions(tmp_path):
    project = _write(tmp_path, {
        ".github/workflows/ci.yml": "steps:\n  - uses: actions/checkout@v4\n",
    })
    assert unpinned_github_actions(project) == []
