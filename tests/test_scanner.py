from pathlib import Path

import pytest

from langdoctor.scanner import parse_requirements, scan

FIX = Path(__file__).parent / "fixtures"


def test_scan_parses_exact_versions():
    project = scan(FIX / "vulnerable_project")
    by = {d.name.lower(): d for d in project.dependencies}
    assert by["langflow"].version == "1.2.0"
    assert by["langgraph-checkpoint-sqlite"].version == "2.0.5"
    assert by["langchain-core"].version == "1.0.5"
    assert by["langchain"].version == "1.3.0"


def test_scan_discovers_files():
    project = scan(FIX / "vulnerable_project")
    assert "requirements.txt" in project.present_files
    assert any(p.name == "app.py" for p in project.python_files)


def test_scan_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        scan(FIX / "does_not_exist")


def test_parse_requirements_handles_comments_specifiers_and_options(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text(
        "langgraph>=1.0\n"
        "# a comment\n"
        "\n"
        "langchain-core==1.2.0  # inline comment\n"
        "-r other.txt\n"
        "langflow==1.2.0 ; python_version >= '3.10'\n",
        encoding="utf-8",
    )
    deps = {d.name: d for d in parse_requirements(p, "requirements.txt")}
    assert deps["langchain-core"].version == "1.2.0"
    assert deps["langflow"].version == "1.2.0"
    assert deps["langgraph"].version is None
    assert deps["langgraph"].specifier is not None
    assert deps["langchain-core"].line == 4


def test_uv_lock_exact_versions(tmp_path):
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "langgraph"\nversion = "1.0.5"\n\n'
        '[[package]]\nname = "langflow"\nversion = "1.2.0"\n',
        encoding="utf-8",
    )
    project = scan(tmp_path)
    by = {d.name: d for d in project.dependencies}
    assert by["langgraph"].version == "1.0.5"
    assert by["langgraph"].source == "uv.lock"


def test_pyproject_pep621_and_poetry(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "demo"\n'
        'dependencies = ["langgraph==1.0.5", "langchain-core>=1.0"]\n\n'
        '[tool.poetry.dependencies]\n'
        'python = "^3.10"\n'
        'langflow = "^1.2.0"\n',
        encoding="utf-8",
    )
    project = scan(tmp_path)
    by = {d.name: d for d in project.dependencies}
    assert by["langgraph"].version == "1.0.5"
    assert by["langflow"].specifier == ">=1.2.0,<2.0.0"
    assert "python" not in by


def test_scan_does_not_descend_into_excluded_directories(tmp_path, monkeypatch):
    # A big node_modules/.venv must cost nothing: pruned, not walked and filtered.
    (tmp_path / "node_modules" / "pkg" / "lib").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "lib" / "index.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "vendored").mkdir()
    (tmp_path / "vendored" / "lib.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")

    import langdoctor.scanner as scanner_module

    visited: list[str] = []
    real_walk = scanner_module.os.walk

    def spying_walk(top, *args, **kwargs):
        for dirpath, dirnames, filenames in real_walk(top, *args, **kwargs):
            visited.append(Path(dirpath).relative_to(tmp_path).as_posix())
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(scanner_module.os, "walk", spying_walk)
    project = scan(tmp_path, excludes={"vendored"})

    # Tied to os.walk on purpose: "never entered" is not observable from the
    # result alone. If the walker changes, this must fail rather than pass idle.
    assert "src" in visited, "scan no longer goes through os.walk; update this spy"
    assert not [v for v in visited if v.startswith(("node_modules", "vendored"))]
    assert project.present_files == {"src/app.py"}
    assert [p.name for p in project.python_files] == ["app.py"]


def test_scan_keeps_a_file_named_like_an_excluded_directory(tmp_path):
    (tmp_path / "build").write_text("not a directory\n", encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "wheel.py").write_text("x = 1\n", encoding="utf-8")
    project = scan(tmp_path)
    assert project.present_files == {"build"}


def test_scan_file_order_is_deterministic(tmp_path):
    for name in ("b.py", "a.py", "pkg/z.py", "pkg/c.py"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x = 1\n", encoding="utf-8")
    project = scan(tmp_path)
    rel = [p.relative_to(project.root).as_posix() for p in project.python_files]
    assert rel == ["a.py", "b.py", "pkg/c.py", "pkg/z.py"]
