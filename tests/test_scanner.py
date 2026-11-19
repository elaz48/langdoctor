import contextlib
from pathlib import Path

import pytest

from langdoctor.scanner import parse_requirements, scan

FIX = Path(__file__).parent / "fixtures"


def test_scan_parses_exact_versions():
    project = scan(FIX / "vulnerable_project")
    by = {d.name.lower(): d for d in project.dependencies}
    assert by["langflow"].version == "1.2.0"
    assert by["langgraph-checkpoint-sqlite"].version == "2.0.10"
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


def _tree(root, files):
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _deps(project, *fields):
    return {tuple(getattr(d, f) for f in fields) for d in project.dependencies}


def test_scan_finds_manifests_in_subdirectories(tmp_path):
    _tree(tmp_path, {
        "services/api/requirements.txt": "langflow==1.2.0\n",
        "services/worker/pyproject.toml": '[project]\ndependencies = ["langgraph>=1.0"]\n',
        "services/worker/uv.lock": '[[package]]\nname = "langgraph"\nversion = "1.2.20"\n',
        "node_modules/pkg/requirements.txt": "langflow==0.0.1\n",
    })
    project = scan(tmp_path)
    assert _deps(project, "name", "version", "source") == {
        ("langflow", "1.2.0", "services/api/requirements.txt"),
        ("langgraph", None, "services/worker/pyproject.toml"),
        ("langgraph", "1.2.20", "services/worker/uv.lock"),
    }
    # only the root pyproject.toml is the project's own config
    assert project.pyproject is None


def test_scan_recognises_requirements_file_names(tmp_path):
    wanted = [
        "requirements.txt", "requirements-prod.txt", "requirements_dev.txt",
        "dev-requirements.txt", "requirements/base.txt", "requirements/prod.txt",
    ]
    ignored = ["notes.txt", "docs/readme.txt", "requirements.in", "constraints.txt"]
    _tree(tmp_path, {name: f"pkg{i}==1.0.{i}\n" for i, name in enumerate(wanted + ignored)})
    assert {d.source for d in scan(tmp_path).dependencies} == set(wanted)


def test_requirements_includes_are_followed_only_inside_the_project(tmp_path):
    (tmp_path / "outside.txt").write_text("langflow==0.0.1\n", encoding="utf-8")
    root = tmp_path / "project"
    _tree(root, {
        "requirements.txt": (
            "-r deps/common.txt\n"
            "--requirement=deps/extra.txt\n"
            "-r ../outside.txt\n"
            "-r missing.txt\n"
            "rich==13.9.0\n"
        ),
        "deps/common.txt": "langgraph==1.0.5\n-r ../requirements.txt\n",  # a cycle
        "deps/extra.txt": "langflow==1.2.0\n",
    })
    assert _deps(scan(root), "name", "version", "source", "line") == {
        ("langgraph", "1.0.5", "deps/common.txt", 1),
        ("langflow", "1.2.0", "deps/extra.txt", 1),
        ("rich", "13.9.0", "requirements.txt", 5),
    }


def test_pdm_pipfile_and_pylock_lockfiles(tmp_path):
    import json

    pipfile_lock = {
        "_meta": {"sources": []},
        "default": {"langflow": {"version": "==1.2.0"}, "local-package": {"path": "."}},
        "develop": {"pytest": {"version": "==8.0.0"}},
    }
    _tree(tmp_path, {
        "a/pdm.lock": '[[package]]\nname = "langgraph"\nversion = "1.0.5"\n',
        "b/Pipfile.lock": json.dumps(pipfile_lock),
        "c/pylock.toml": (
            'lock-version = "1.0"\n'
            '[[packages]]\nname = "langchain-core"\nversion = "1.2.0"\n'
            '[[packages]]\nname = "from-vcs"\n'
        ),
        "d/pylock.prod.toml": '[[packages]]\nname = "langgraph-sdk"\nversion = "0.4.3"\n',
        "e/Pipfile.lock": "{ not json",
    })
    assert _deps(scan(tmp_path), "name", "version", "source") == {
        ("langgraph", "1.0.5", "a/pdm.lock"),
        ("langflow", "1.2.0", "b/Pipfile.lock"),
        ("pytest", "8.0.0", "b/Pipfile.lock"),
        ("langchain-core", "1.2.0", "c/pylock.toml"),
        ("langgraph-sdk", "0.4.3", "d/pylock.prod.toml"),
    }


def test_scan_reads_langflow_images_from_dockerfiles_and_yaml(tmp_path):
    _tree(tmp_path, {
        "Dockerfile": "FROM python:3.12\nFROM langflowai/langflow:1.2.0\n",
        "deploy/docker-compose.yml": (
            "services:\n"
            "  lf:\n"
            "    image: docker.io/langflowai/langflow-backend:1.9.0-amd64\n"
            "  db:\n"
            "    image: postgres:16\n"
        ),
        "k8s/app.yaml": "containers:\n  - image: ghcr.io/langflow-ai/langflow:latest\n",
        "base.Dockerfile": "FROM langflowai/langflow:base-0.11.6\n",
        "web.Dockerfile": "FROM langflowai/langflow-frontend:1.2.0\n",
    })
    assert _deps(scan(tmp_path), "name", "version", "source", "line", "image") == {
        ("langflow", "1.2.0", "Dockerfile", 2, "langflowai/langflow"),
        ("langflow", "1.9.0", "deploy/docker-compose.yml", 3, "langflowai/langflow-backend"),
        ("langflow", None, "k8s/app.yaml", 2, "ghcr.io/langflow-ai/langflow"),
        ("langflow", None, "base.Dockerfile", 1, "langflowai/langflow"),
    }


def test_a_mirrored_or_proxied_langflow_image_is_still_langflow(tmp_path):
    _tree(tmp_path, {
        "a.Dockerfile": "FROM myreg.example.com/langflowai/langflow:1.2.0\n",
        "b.Dockerfile": "FROM artifactory.corp/docker-remote/langflowai/langflow:1.3.0\n",
        "c.Dockerfile": "FROM ${REGISTRY}/langflowai/langflow:1.4.0\n",
        "d.Dockerfile": "FROM mirror.corp:5000/langflow-ai/langflow-backend:1.9.0\n",
        "e.Dockerfile": "FROM someone/langflow:1.2.0\nFROM langflow:1.2.0\n",
    })
    assert _deps(scan(tmp_path), "name", "version", "source", "image") == {
        ("langflow", "1.2.0", "a.Dockerfile", "myreg.example.com/langflowai/langflow"),
        ("langflow", "1.3.0", "b.Dockerfile", "artifactory.corp/docker-remote/langflowai/langflow"),
        ("langflow", "1.4.0", "c.Dockerfile", "${registry}/langflowai/langflow"),
        ("langflow", "1.9.0", "d.Dockerfile", "mirror.corp:5000/langflow-ai/langflow-backend"),
    }


def test_a_malformed_pyproject_keeps_its_valid_parts_and_never_aborts_the_scan(tmp_path):
    _tree(tmp_path, {
        "a/pyproject.toml": (
            '[project]\ndependencies = ["langflow==1.2.0", 1, ["nested"]]\n'
            '[project.optional-dependencies]\nextra = "not-a-list"\n'
            "[tool.poetry]\ndependencies = [1]\n"
        ),
        "b/pyproject.toml": "project = [1]\ntool = 3\n",
        "c/pyproject.toml": '[project]\ndependencies = "x"\n[tool]\npoetry = "y"\n',
        "d/pyproject.toml": "[tool.poetry.dependencies]\nlanggraph = [1, 2]\n",
    })
    assert _deps(scan(tmp_path), "name", "version", "source") == {
        ("langflow", "1.2.0", "a/pyproject.toml"),
        ("langgraph", None, "d/pyproject.toml"),
    }


def test_manifest_parsers_accept_any_shape_of_data():
    # TOML/JSON from an untrusted repository can put any type anywhere. Rather
    # than wrap the parsers in a catch-all that would hide a real bug, they are
    # total: any structure in, a list of dependencies out.
    import random

    from langdoctor.scanner import parse_lock, parse_pyproject_deps

    rng = random.Random(751)
    keys = ["project", "dependencies", "optional-dependencies", "tool", "poetry", "package",
            "packages", "name", "version", "python", "langflow"]

    def shape(depth=0):
        kind = rng.choice(["str", "int", "none", "list", "dict", "bool"] if depth < 4 else ["str"])
        if kind == "list":
            return [shape(depth + 1) for _ in range(rng.randint(0, 3))]
        if kind == "dict":
            return {rng.choice(keys): shape(depth + 1) for _ in range(rng.randint(0, 4))}
        return {"str": rng.choice(["langflow==1.2.0", "", "^1.0", "*", "~1"]), "int": 7,
                "none": None, "bool": True}[kind]

    for _ in range(3000):
        data = {rng.choice(keys): shape() for _ in range(rng.randint(0, 5))}
        assert isinstance(parse_pyproject_deps(data, "pyproject.toml"), list)
        assert isinstance(parse_lock(data, "uv.lock"), list)
        assert isinstance(parse_lock(data, "pylock.toml", table="packages"), list)


def test_hostile_includes_and_documents_do_not_abort_the_scan(tmp_path):
    chain = {f"chain/r{i}.txt": f"pkg{i}==1.0\n-r r{i + 1}.txt\n" for i in range(1200)}
    _tree(tmp_path, {
        "requirements.txt": "-r chain/r0.txt\n-r bad\x00name.txt\n-r loop\nrich==13.9.0\n",
        **chain,
        "a/Pipfile.lock": "[" * 100_000,
        "b/uv.lock": "x = " + "[" * 5_000 + "\n",
        "c/pylock.toml": "x = " + "[" * 5_000 + "\n",
    })
    with contextlib.suppress(OSError):  # no symlink privilege (Windows)
        (tmp_path / "loop").symlink_to("loop")
    project = scan(tmp_path)
    assert len(project.dependencies) == 1201
    assert {d.source for d in project.dependencies} == {"requirements.txt", *chain}


def test_a_symlink_that_leaves_the_project_is_not_read(tmp_path):
    (tmp_path / "outside.txt").write_text("secretword\n", encoding="utf-8")
    root = tmp_path / "project"
    _tree(root, {"shared/base.txt": "rich==13.9.0\n"})
    try:
        (root / "requirements.txt").symlink_to(tmp_path / "outside.txt")
        (root / "requirements-shared.txt").symlink_to(root / "shared" / "base.txt")
    except OSError:
        pytest.skip("symlinks are not available here")
    project = scan(root)
    assert "requirements.txt" not in project.present_files
    assert _deps(project, "name", "source") == {("rich", "requirements-shared.txt")}
